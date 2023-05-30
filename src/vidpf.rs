// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.

//! Verifiable IDPF.

use crate::upstream::{
    eval_with_adjustment, gen_with_adjustment, IdpfCache, IdpfCorrectionWord, IdpfInput,
    IdpfOutputShare, IdpfPublicShare, IdpfValue,
};
use prio::{
    codec::{CodecError, Decode, Encode},
    field::{Field128, FieldElement},
    vdaf::{
        prg::{CoinToss, Prg, Seed, SeedStream},
        VdafError,
    },
};
use rand::prelude::*;
use std::{
    fmt::Debug,
    io::Cursor,
    ops::{Add, AddAssign, BitXor, BitXorAssign, Neg, Sub},
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

const VERIFIER_SIZE: usize = 64;

/// Generate VIDPF shares for the given input string and output values.
pub fn gen_verified<P, const SEED_SIZE: usize>(
    input: &IdpfInput,
    values: Vec<DoplarIdpfValue>,
) -> Result<
    (
        IdpfPublicShare<DoplarIdpfValue, DoplarIdpfValue, SEED_SIZE>,
        [Seed<SEED_SIZE>; 2],
    ),
    VdafError,
>
where
    P: Prg<SEED_SIZE>,
{
    // Split the values into the inner values and the leaf values. Poplar1 rquires a larger field
    // to be used at the leaf nodes of the IDPF tree than the inner nodes. This is not required for
    // Doplar. However, since this artificat of Poplar1 is baked into the [`Idpf`] API.
    let mut inner_values = values;
    let leaf_value = inner_values.pop().unwrap();

    gen_with_adjustment::<_, _, _, P, SEED_SIZE>(
        input,
        inner_values,
        leaf_value,
        adjust_correction_word::<P, SEED_SIZE>,
        adjust_correction_word::<P, SEED_SIZE>,
    )
}

/// Evaluate a VIDPF share at a given prefix.
///
/// The result is an output share, which includes a "verifier value": both Aggregators will compute
/// the same verifier value if the prefix is off-path or if the prefix is on-path and the
/// Aggregators hold a correct secret sharing of the value.
pub fn eval_verified<P, const SEED_SIZE: usize>(
    agg_id: usize,
    public_share: &IdpfPublicShare<DoplarIdpfValue, DoplarIdpfValue, SEED_SIZE>,
    key: &Seed<SEED_SIZE>,
    prefix: &IdpfInput,
    cache: &mut dyn IdpfCache<SEED_SIZE>,
) -> Result<DoplarIdpfValue, VdafError>
where
    P: Prg<SEED_SIZE>,
{
    let idpf_share = eval_with_adjustment::<_, _, P, SEED_SIZE>(
        agg_id,
        public_share,
        key,
        prefix,
        cache,
        apply_correction_word_adjustment::<P, SEED_SIZE>,
        apply_correction_word_adjustment::<P, SEED_SIZE>,
    )?;

    Ok(DoplarIdpfValue::from(idpf_share))
}

// Called by `prio::idpf::gen_with_adjustment()` on the value shares just after generating a
// correction word.
fn adjust_correction_word<P, const SEED_SIZE: usize>(
    correction_word: &mut IdpfCorrectionWord<DoplarIdpfValue, SEED_SIZE>,
    seeds_corrected: &[[u8; SEED_SIZE]; 2],
    value_0: DoplarIdpfValue,
    value_1: DoplarIdpfValue,
) where
    P: Prg<SEED_SIZE>,
{
    // Compute the first Aggregatoir's adjuster share. Each Aggregator computes a share of this
    // adjuster value when evaluating the IDPF.
    //
    // NOTE The spec (Figure 9, Appendix A) calls for the shares of the adjuster value to be bound
    // to the prefix being evaluated. We provide this binding via the "corrected seed" computed by
    // the underlying IDPF.
    let mut adjuster_share_0 = Verifier::zero();
    let mut prg_0 = P::init(&seeds_corrected[0], &[]);
    prg_0.update(&u128::from(value_0.s).to_be_bytes());
    prg_0.update(&u128::from(value_0.t).to_be_bytes());
    prg_0.update(&value_0.verifier.0);
    prg_0.into_seed_stream().fill(&mut adjuster_share_0.0);

    // Compute the second Aggregator's adjuster share.
    let mut adjuster_share_1 = Verifier::zero();
    let mut prg_1 = P::init(&seeds_corrected[1], &[]);
    prg_1.update(&u128::from(-value_1.s).to_be_bytes());
    prg_1.update(&u128::from(-value_1.t).to_be_bytes());
    prg_1.update(&value_1.verifier.0);
    prg_1.into_seed_stream().fill(&mut adjuster_share_1.0);

    // Compute the adjuster value. The "verifier value" is computing by XORing the adjuaster value
    // with the Aggregator's adjuster share durinv evaluation.
    correction_word.value.adjuster = Some(adjuster_share_0 ^ adjuster_share_1);
}

// Called by `prio::idpf::eval_with_adjustment()` just after deriving a value share.
fn apply_correction_word_adjustment<P, const SEED_SIZE: usize>(
    value_share: &mut DoplarIdpfValue,
    correction_word: &IdpfCorrectionWord<DoplarIdpfValue, SEED_SIZE>,
    seed_corrected: &[u8; SEED_SIZE],
    control_bit: Choice,
) where
    P: Prg<SEED_SIZE>,
{
    // Compute the Aggregator's adjuster share.
    let mut adjuster_share = Verifier::zero();
    let mut prg_share = P::init(seed_corrected, &[]);
    prg_share.update(&u128::from(value_share.s).to_be_bytes());
    prg_share.update(&u128::from(value_share.t).to_be_bytes());
    prg_share.update(&value_share.verifier.0);
    prg_share.into_seed_stream().fill(&mut adjuster_share.0);

    // If the prefix is off-path, then both Aggregators will compute the same adjuster share; if
    // the prefix is on-path, then they will compute different shares. In former case, exaclty one
    // Aggregator has `control_bit` set, so they both end up computing the same verification value;
    // in the latter case, both with have the same value for `control_bit`, so the adjuster values
    // cancels out.
    value_share.verifier = adjuster_share
        ^ Verifier::conditional_select(
            &Verifier::zero(),
            correction_word
                .value
                .adjuster
                .as_ref()
                .expect("adjuster should be set"),
            control_bit,
        );
}

#[derive(Debug, Clone, Copy)]
pub struct DoplarIdpfValue {
    // Values programmed into the IDPF.
    pub(crate) s: Field128,
    pub(crate) t: Field128,

    // Values for verifying the IDPF output.
    verifier: Verifier,
    adjuster: Option<Verifier>, // Set by `adjust_correction_word()`
}

impl DoplarIdpfValue {
    pub(crate) fn new(s: Field128, t: Field128) -> Self {
        let mut verifier_bytes = [0; VERIFIER_SIZE];
        thread_rng().fill(&mut verifier_bytes);
        Self {
            s,
            t,
            verifier: Verifier(verifier_bytes),
            adjuster: None,
        }
    }

    pub(crate) fn verifier(&self) -> &[u8] {
        &self.verifier.0
    }
}

impl IdpfValue for DoplarIdpfValue {
    fn zero() -> Self {
        Self {
            s: Field128::zero(),
            t: Field128::zero(),
            verifier: Verifier::zero(),
            adjuster: None,
        }
    }
}

impl From<IdpfOutputShare<DoplarIdpfValue, DoplarIdpfValue>> for DoplarIdpfValue {
    fn from(out_share: IdpfOutputShare<DoplarIdpfValue, DoplarIdpfValue>) -> DoplarIdpfValue {
        match out_share {
            IdpfOutputShare::Inner(val) => val,
            IdpfOutputShare::Leaf(val) => val,
        }
    }
}

impl Add for DoplarIdpfValue {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}

impl AddAssign for DoplarIdpfValue {
    fn add_assign(&mut self, rhs: Self) {
        assert!(
            self.adjuster.is_none() && rhs.adjuster.is_none(),
            "adjuster should not have been set yet"
        );
        self.s += rhs.s;
        self.t += rhs.t;
        self.verifier ^= rhs.verifier;
    }
}

impl Neg for DoplarIdpfValue {
    type Output = Self;

    fn neg(self) -> Self {
        assert!(
            self.adjuster.is_none(),
            "adjuster should not have been set yet"
        );
        Self {
            s: -self.s,
            t: -self.t,
            verifier: self.verifier,
            adjuster: None,
        }
    }
}

impl Sub for DoplarIdpfValue {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        assert!(
            self.adjuster.is_none() && rhs.adjuster.is_none(),
            "adjuster should not have been set yet"
        );
        Self {
            s: self.s - rhs.s,
            t: self.t - rhs.t,
            verifier: self.verifier ^ rhs.verifier,
            adjuster: None,
        }
    }
}

#[cfg(test)]
impl PartialEq for DoplarIdpfValue {
    fn eq(&self, rhs: &Self) -> bool {
        self.s == rhs.s && self.t == rhs.t && self.verifier.0 == rhs.verifier.0
    }
}

impl ConstantTimeEq for DoplarIdpfValue {
    fn ct_eq(&self, _rhs: &Self) -> Choice {
        unreachable!("this method is not required for the prototype")
    }
}

impl Encode for DoplarIdpfValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.s.encode(bytes);
        self.t.encode(bytes);
        bytes.extend_from_slice(&self.verifier.0);
        bytes.extend_from_slice(
            &self
                .adjuster
                .as_ref()
                .expect("adjuster should be set by now")
                .0,
        );
    }
}

impl Decode for DoplarIdpfValue {
    fn decode(_bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        unreachable!("serialization not required for prototype")
    }
}

impl CoinToss for DoplarIdpfValue {
    fn sample<S>(seed_stream: &mut S) -> Self
    where
        S: SeedStream,
    {
        Self {
            s: Field128::sample(seed_stream),
            t: Field128::sample(seed_stream),
            verifier: Verifier(<[u8; VERIFIER_SIZE]>::sample(seed_stream)),
            adjuster: None,
        }
    }
}

impl ConditionallySelectable for DoplarIdpfValue {
    fn conditional_select(lhs: &Self, rhs: &Self, choice: subtle::Choice) -> Self {
        Self {
            s: Field128::conditional_select(&lhs.s, &rhs.s, choice),
            t: Field128::conditional_select(&lhs.t, &rhs.t, choice),
            verifier: Verifier::conditional_select(&lhs.verifier, &rhs.verifier, choice),
            // This may overwrite the value of the selected adjuster. This is not an immediate
            // concern, given how `DoplarIdpfValue` is used in the prototype. However this could
            // potentially lead to some headaches. Before productionizing, we'll need to reconsider
            // the code design here.
            adjuster: None,
        }
    }
}

impl ConditionallyNegatable for DoplarIdpfValue {
    fn conditional_negate(&mut self, choice: subtle::Choice) {
        Field128::conditional_negate(&mut self.s, choice);
        Field128::conditional_negate(&mut self.t, choice);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verifier([u8; VERIFIER_SIZE]);

impl Verifier {
    fn zero() -> Self {
        Self([0; VERIFIER_SIZE])
    }
}

impl BitXorAssign for Verifier {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (lhs, rhs) in self.0.iter_mut().zip(rhs.0.into_iter()) {
            *lhs ^= rhs;
        }
    }
}

impl BitXor for Verifier {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self ^= rhs;
        self
    }
}

impl ConditionallySelectable for Verifier {
    fn conditional_select(lhs: &Self, rhs: &Self, choice: subtle::Choice) -> Self {
        let mut selected = [0; VERIFIER_SIZE];
        for (i, (lhs, rhs)) in lhs.0.iter().zip(rhs.0.iter()).enumerate() {
            selected[i] = u8::conditional_select(lhs, rhs, choice);
        }
        Self(selected)
    }
}

#[cfg(test)]
mod tests {
    use crate::upstream::NoCache;

    use super::*;
    use bitvec::{bitbox, prelude::Lsb0};
    use prio::{
        field::{Field128, FieldElement},
        vdaf::prg::PrgAes128,
    };

    fn check_eval_verified<P, const SEED_SIZE: usize>(
        public_share: &IdpfPublicShare<DoplarIdpfValue, DoplarIdpfValue, SEED_SIZE>,
        keys: &[Seed<SEED_SIZE>; 2],
        prefix: &IdpfInput,
        expected_s: u128,
        expected_t: u128,
    ) where
        P: Prg<SEED_SIZE>,
    {
        let mut cache_0 = NoCache::new();
        let mut cache_1 = NoCache::new();
        let share_0 =
            eval_verified::<P, SEED_SIZE>(0, public_share, &keys[0], prefix, &mut cache_0).unwrap();
        let share_1 =
            eval_verified::<P, SEED_SIZE>(1, public_share, &keys[1], prefix, &mut cache_1).unwrap();
        assert_eq!(share_0.s + share_1.s, Field128::from(expected_s));
        assert_eq!(share_0.t + share_1.t, Field128::from(expected_t));
        assert_eq!(share_0.verifier, share_1.verifier, "verifier mismatch");
        assert_ne!(share_0.verifier, Verifier::zero(), "verifier is zero");
    }

    #[test]
    fn onehot_verification_on_path() {
        let input = bitbox![1, 1, 1].into();
        let values = vec![DoplarIdpfValue::new(Field128::one(), Field128::one()); 3];
        let (public_share, keys) = gen_verified::<PrgAes128, 16>(&input, values).unwrap();

        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1].into(), 1, 1);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 1].into(), 1, 1);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 1, 1].into(), 1, 1);

        // Try a longer value.
        let input = IdpfInput::from(bitbox![1; 128]);
        let values = vec![DoplarIdpfValue::new(Field128::one(), Field128::one()); input.len()];
        let (public_share, keys) = gen_verified::<PrgAes128, 16>(&input, values).unwrap();
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &input, 1, 1);
    }

    #[test]
    fn onehot_verification_off_path() {
        let input = bitbox![1, 1, 1].into();
        let values = vec![DoplarIdpfValue::new(Field128::one(), Field128::one()); 3];
        let (public_share, keys) = gen_verified::<PrgAes128, 16>(&input, values).unwrap();

        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![0].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![0, 1].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 0].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![0, 0, 1].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![0, 1, 0].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![0, 1, 1].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 0, 0].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 0, 1].into(), 0, 0);
        check_eval_verified::<PrgAes128, 16>(&public_share, &keys, &bitbox![1, 1, 0].into(), 0, 0);
    }

    // This test had previously triggered a bug in how the value shares passed to
    // `adjust_correction_word()` were corrected. The bug occured whenever the IDPF prefix ended
    // with a zero.
    #[test]
    fn onehot_verification_input_ending_with_zero() {
        let input = IdpfInput::from(bitbox![1, 0, 0]);
        let values = vec![DoplarIdpfValue::new(Field128::one(), Field128::one()); input.len()];
        let (public_share, keys) = gen_verified::<PrgAes128, 16>(&input, values).unwrap();

        let prefix = IdpfInput::from(bitbox![1, 0]);
        let share_0 = eval_verified::<PrgAes128, 16>(
            0,
            &public_share,
            &keys[0],
            &prefix,
            &mut NoCache::new(),
        )
        .unwrap();
        let share_1 = eval_verified::<PrgAes128, 16>(
            1,
            &public_share,
            &keys[1],
            &prefix,
            &mut NoCache::new(),
        )
        .unwrap();
        assert_eq!(share_0.s + share_1.s, Field128::one());
        assert_eq!(share_0.t + share_1.t, Field128::one());
        assert_eq!(share_0.verifier, share_1.verifier);
    }
}
