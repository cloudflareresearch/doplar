// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.

//! Implementation of the Doplar VDAF.

use crate::{
    upstream::{IdpfInput, IdpfPublicShare},
    vidpf::DoplarIdpfValue,
};
use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    field::{Field128, FieldElement},
    vdaf::{
        prg::{CoinToss, Prg, PrgAes128, Seed},
        Aggregatable, Aggregator, Client, Collector, PrepareTransition, Vdaf, VdafError,
    },
};
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};
use std::{fmt::Debug, io::Cursor, marker::PhantomData};

const DFLP_PROOF_LEN: usize = 18;

const DST_ENDOING_RAND: u16 = 1;
const DST_JOINT_RAND_PART: u16 = 2;
const DST_JOINT_RAND_SEED: u16 = 3;
const DST_JOINT_RAND: u16 = 4;
const DST_QUERY_RAND: u16 = 5;
const DST_PROOF_SHARE: u16 = 6;

/// Doplar with [`PrgAes128`](prio::vdaf::prg::PrgAes128) as the PRG.
pub type DoplarAes128 = Doplar<PrgAes128, 16>;

impl DoplarAes128 {
    /// Create an instance of [`DoplarAes128`]. The caller provides the bit length of each
    /// measurement.
    pub fn new_aes128(bits: usize) -> Self {
        Self {
            bits,
            phantom: PhantomData,
        }
    }
}

/// The base Doplar VDAF.
#[derive(Debug)]
pub struct Doplar<P, const SEED_SIZE: usize> {
    bits: usize,
    phantom: PhantomData<P>,
}

impl<P: Prg<SEED_SIZE>, const SEED_SIZE: usize> Doplar<P, SEED_SIZE> {
    fn delta_share(seed: &[u8; SEED_SIZE], nonce: &[u8], level: usize, agg_id: usize) -> Field128 {
        let mut prg = P::init(seed, &Self::custom(DST_ENDOING_RAND));
        prg.update(nonce);
        // NOTE the length of `level.to_be_bytes()` is machine-dependent. For this code to be
        // interperable, we will want to pick the number of bits to use to encode this.
        prg.update(&level.to_be_bytes());
        prg.update(&[agg_id.try_into().unwrap()]);
        Field128::sample(&mut prg.into_seed_stream())
    }

    fn joint_rand_part(
        seed: &[u8; SEED_SIZE],
        nonce: &[u8],
        encoded_idpf_pub: &[u8],
        encoded_idpf_key: &[u8],
        agg_id: usize,
    ) -> Seed<SEED_SIZE> {
        let mut prg = P::init(seed, &Self::custom(DST_JOINT_RAND_PART));
        prg.update(nonce);
        prg.update(&[agg_id.try_into().unwrap()]);
        prg.update(encoded_idpf_key);
        prg.update(encoded_idpf_pub);
        prg.into_seed()
    }

    fn joint_rand_seed(
        seed: &[u8; SEED_SIZE],
        joint_rand_part_0: &Seed<SEED_SIZE>,
        joint_rand_part_1: &Seed<SEED_SIZE>,
        level: usize,
    ) -> Seed<SEED_SIZE> {
        let mut prg = P::init(seed, &Self::custom(DST_JOINT_RAND_SEED));
        prg.update(&level.to_be_bytes());
        prg.update(joint_rand_part_0.as_ref());
        prg.update(joint_rand_part_1.as_ref());
        prg.into_seed()
    }

    fn joint_rand(seed: &[u8; SEED_SIZE], nonce: &[u8], level: usize) -> [Field128; 2] {
        let mut prg = P::init(seed, &Self::custom(DST_JOINT_RAND));
        prg.update(nonce);
        prg.update(&level.to_be_bytes());
        let mut seed_stream = prg.into_seed_stream();
        [
            Field128::sample(&mut seed_stream),
            Field128::sample(&mut seed_stream),
        ]
    }

    fn query_rand(seed: &[u8; SEED_SIZE], nonce: &[u8], level: usize) -> [Field128; 2] {
        let mut prg = P::init(seed, &Self::custom(DST_QUERY_RAND));
        prg.update(nonce);
        prg.update(&level.to_be_bytes());
        let mut seed_stream = prg.into_seed_stream();
        [
            Field128::sample(&mut seed_stream),
            Field128::sample(&mut seed_stream),
        ]
    }

    fn expand_proof_share(seed: &[u8; SEED_SIZE], nonce: &[u8], level: usize) -> Vec<Field128> {
        let mut prg = P::init(seed, &Self::custom(DST_PROOF_SHARE));
        prg.update(nonce);
        prg.update(&level.to_be_bytes());
        let mut seed_stream = prg.into_seed_stream();
        // NOTE It is noticeably more efficient to fill a buffer with the seed stream, then do
        // rejection sampling. (See the internal `Prng` struct in the `prio` crate.)
        let mut proof_share = Vec::with_capacity(DFLP_PROOF_LEN);
        for _ in 0..DFLP_PROOF_LEN {
            proof_share.push(Field128::sample(&mut seed_stream));
        }
        proof_share
    }
}

impl<P, const SEED_SIZE: usize> Clone for Doplar<P, SEED_SIZE> {
    fn clone(&self) -> Self {
        Self {
            bits: self.bits,
            phantom: PhantomData,
        }
    }
}

/// A "public share" accompanying the input shares generated by a Client. This corresponds the
/// Client's initial broadcast mesage in our syntax, which is called the public share in the VDAF
/// spec. This value includes the IDPF public share and the joint randomness parts used during the
/// range check.
#[derive(Clone, Debug)]
pub struct DoplarPublicShare<const SEED_SIZE: usize> {
    idpf_pub: IdpfPublicShare<DoplarIdpfValue, DoplarIdpfValue, SEED_SIZE>,
    joint_rand_parts: [Seed<SEED_SIZE>; 2],
}

impl<const SEED_SIZE: usize> Encode for DoplarPublicShare<SEED_SIZE> {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl<P, const SEED_SIZE: usize> ParameterizedDecode<Doplar<P, SEED_SIZE>>
    for DoplarPublicShare<SEED_SIZE>
{
    fn decode_with_param(
        _vdaf: &Doplar<P, SEED_SIZE>,
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

/// An input share. Comprised of an IDPF key share and a seed and proof shares used for verifying
/// IDPF output shares.
#[derive(Debug, Clone)]
pub struct DoplarInputShare<const SEED_SIZE: usize> {
    idpf_key: Seed<SEED_SIZE>,
    seed: Seed<SEED_SIZE>,
    // Set by the first Aggregator. The second Aggregator doesn't need to store the proof shares
    // explicitly; instead it generates them using `seed`.
    proof_shares: Option<Vec<Field128>>,
}

impl<const SEED_SIZE: usize> Encode for DoplarInputShare<SEED_SIZE> {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl<'a, P, const SEED_SIZE: usize> ParameterizedDecode<(&'a Doplar<P, SEED_SIZE>, usize)>
    for DoplarInputShare<SEED_SIZE>
{
    fn decode_with_param(
        (_vdaf, _agg_id): &(&'a Doplar<P, SEED_SIZE>, usize),
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

/// The per-report state of an Aggregator during preparation.
#[derive(Clone, Debug)]
pub struct DoplarPrepareState<const SEED_SIZE: usize> {
    // The seed is "early" in the sense that it was computed from the joint randomness parts
    // provided by the Client and has not been verified yet.
    early_joint_rand_seed: Seed<SEED_SIZE>,
    out_share: Vec<Field128>,
    level: usize,
}

/// A "preparation message", computed by combining the broadcast mesesages generated by each
/// Aggregator during the preparation phase. Note that type is an artificat of conforming to the
/// upstream [`Vdaf`](prio::vdaf::Vdaf) API.
#[derive(Clone, Debug)]
pub struct DoplarPrepareMessage<const SEED_SIZE: usize> {
    corrected_joint_rand_parts: [Seed<SEED_SIZE>; 2],
}

impl<const SEED_SIZE: usize> Encode for DoplarPrepareMessage<SEED_SIZE> {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl<const SEED_SIZE: usize> ParameterizedDecode<DoplarPrepareState<SEED_SIZE>>
    for DoplarPrepareMessage<SEED_SIZE>
{
    fn decode_with_param(
        _state: &DoplarPrepareState<SEED_SIZE>,
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

/// A "prepare share". This corresponds to the broadcast message generated by one of the
/// Aggregators during the preeparation phase. It consists of the Aggregator's corrected joint
/// randomness part (range check), DFLP verifier share (range check), and VIDPF verifier hash
/// (onehot check).
#[derive(Clone, Debug)]
pub struct DoplarPrepareShare<const SEED_SIZE: usize> {
    corrected_joint_rand_part: Seed<SEED_SIZE>,
    range_check_verifier_share: Vec<Field128>,
    onhot_check_verifier: [u8; 32],
}

impl<const SEED_SIZE: usize> Encode for DoplarPrepareShare<SEED_SIZE> {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl<const SEED_SIZE: usize> ParameterizedDecode<DoplarPrepareState<SEED_SIZE>>
    for DoplarPrepareShare<SEED_SIZE>
{
    fn decode_with_param(
        _state: &DoplarPrepareState<SEED_SIZE>,
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

/// The initial state for preparation in our syntax. The VDAF spec calls this the "aggregation
/// parameter".
#[derive(Clone, Debug)]
pub struct DoplarAggregationParam {
    pub level: usize,
    pub prefixes: Vec<IdpfInput>,
}

impl Encode for DoplarAggregationParam {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl Decode for DoplarAggregationParam {
    fn decode(_bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

impl<P: Prg<SEED_SIZE>, const SEED_SIZE: usize> Vdaf for Doplar<P, SEED_SIZE> {
    const ID: u32 = 0xFFFFFFFF;
    type Measurement = IdpfInput;
    type AggregateResult = Vec<u64>;
    type AggregationParam = DoplarAggregationParam;
    type PublicShare = DoplarPublicShare<SEED_SIZE>;
    type InputShare = DoplarInputShare<SEED_SIZE>;
    type OutputShare = DoplarFieldVec;
    type AggregateShare = DoplarFieldVec;

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl<P: Prg<SEED_SIZE>, const SEED_SIZE: usize> Client<16> for Doplar<P, SEED_SIZE> {
    fn shard(
        &self,
        input: &IdpfInput,
        nonce: &[u8; 16],
    ) -> Result<(Self::PublicShare, Vec<DoplarInputShare<SEED_SIZE>>), VdafError> {
        if input.len() != self.bits {
            return Err(VdafError::Uncategorized(format!(
                "unexpected input length: got {}; want {}",
                input.len(),
                self.bits
            )));
        }

        let seed_0 = Seed::generate()?;
        let seed_1 = Seed::generate()?;

        // Compute the encoding randomness used for each level of the IDPF tree.
        let mut encoding_rand = Vec::with_capacity(self.bits);
        for level in 0..self.bits {
            encoding_rand.push(
                Self::delta_share(seed_0.as_ref(), nonce, level, 0)
                    + Self::delta_share(seed_1.as_ref(), nonce, level, 1),
            );
        }

        // Generate the IDPF key shares.
        let idpf_values: Vec<_> = encoding_rand
            .iter()
            .map(|delta| DoplarIdpfValue::new(Field128::one(), *delta))
            .collect();
        let (idpf_pub, [idpf_key_0, idpf_key_1]) =
            vidpf::gen_verified::<P, SEED_SIZE>(input, idpf_values)?;

        // Derive the joint randomness parts.
        let encoded_idpf_pub = idpf_pub.get_encoded();
        let joint_rand_part_0 = Self::joint_rand_part(
            seed_0.as_ref(),
            nonce,
            &encoded_idpf_pub,
            idpf_key_0.as_ref(),
            0,
        );
        let joint_rand_part_1 = Self::joint_rand_part(
            seed_1.as_ref(),
            nonce,
            &encoded_idpf_pub,
            idpf_key_1.as_ref(),
            1,
        );

        // Range check: Generate the level proofs, splitting up proof generation across multiple
        // threads to improve throughputt.
        let mut proof_shares_0 = Vec::with_capacity(DFLP_PROOF_LEN * self.bits);
        proof_shares_0.par_extend(
            encoding_rand
                .into_par_iter()
                .enumerate()
                .map(|(level, delta)| {
                    let joint_rand_seed = Self::joint_rand_seed(
                        &[0; SEED_SIZE],
                        &joint_rand_part_0,
                        &joint_rand_part_1,
                        level,
                    );

                    let joint_rand = Self::joint_rand(joint_rand_seed.as_ref(), nonce, level);
                    let mut proof_share_0 = dflp::prove(delta, &joint_rand)
                        .expect("proof generation failed for level {level}");
                    let proof_share_1 = Self::expand_proof_share(seed_1.as_ref(), nonce, level);
                    for (left, right) in proof_share_0.iter_mut().zip(proof_share_1.into_iter()) {
                        *left -= right;
                    }
                    proof_share_0
                })
                .flatten_iter(),
        );

        Ok((
            DoplarPublicShare {
                idpf_pub,
                joint_rand_parts: [joint_rand_part_0, joint_rand_part_1],
            },
            vec![
                DoplarInputShare {
                    idpf_key: idpf_key_0,
                    seed: seed_0,
                    proof_shares: Some(proof_shares_0),
                },
                DoplarInputShare {
                    idpf_key: idpf_key_1,
                    seed: seed_1,
                    proof_shares: None,
                },
            ],
        ))
    }
}

impl<P: Prg<SEED_SIZE>, const SEED_SIZE: usize> Aggregator<SEED_SIZE, 16> for Doplar<P, SEED_SIZE> {
    type PrepareState = DoplarPrepareState<SEED_SIZE>;
    type PrepareShare = DoplarPrepareShare<SEED_SIZE>;
    type PrepareMessage = DoplarPrepareMessage<SEED_SIZE>;

    #[allow(clippy::type_complexity)]
    fn prepare_init(
        &self,
        verify_key: &[u8; SEED_SIZE],
        agg_id: usize,
        agg_param: &DoplarAggregationParam,
        nonce: &[u8; 16],
        public_share: &DoplarPublicShare<SEED_SIZE>,
        input_share: &DoplarInputShare<SEED_SIZE>,
    ) -> Result<(DoplarPrepareState<SEED_SIZE>, DoplarPrepareShare<SEED_SIZE>), VdafError> {
        // Compute corrected the joint randomness seed based on the joint randomness parts uplaoded
        // by the Client. In the next step, the Aggregators verify that they have both computed the
        // same seed.
        let owned_joint_rand_part = Self::joint_rand_part(
            input_share.seed.as_ref(),
            nonce,
            &public_share.idpf_pub.get_encoded(),
            &input_share.idpf_key.get_encoded(),
            agg_id,
        );
        let (corrected_joint_rand_part_0, corrected_joint_rand_part_1) = if agg_id == 0 {
            (&owned_joint_rand_part, &public_share.joint_rand_parts[1])
        } else {
            (&public_share.joint_rand_parts[0], &owned_joint_rand_part)
        };
        let early_joint_rand_seed = Self::joint_rand_seed(
            &[0; SEED_SIZE],
            corrected_joint_rand_part_0,
            corrected_joint_rand_part_1,
            agg_param.level,
        );

        // Expand the DFLP proof share.
        let owned_proof_share = if input_share.proof_shares.is_none() {
            Some(Self::expand_proof_share(
                input_share.seed.as_ref(),
                nonce,
                agg_param.level,
            ))
        } else {
            None
        };
        let proof_share = if let Some(ref proof_share) = input_share.proof_shares {
            &proof_share[agg_param.level * DFLP_PROOF_LEN..(agg_param.level + 1) * DFLP_PROOF_LEN]
        } else {
            owned_proof_share.as_ref().unwrap()
        };

        // Compute the encoding randomness share.
        let delta_share =
            Self::delta_share(input_share.seed.as_ref(), nonce, agg_param.level, agg_id);

        // Evaluate the IDPF share.
        let mut out_share = Vec::with_capacity(agg_param.prefixes.len());
        let mut s_share = Field128::zero();
        let mut t_share = Field128::zero();
        let mut onhot_check_verifier_hasher = Sha3_256::new();
        let mut idpf_eval_cache = upstream::RingBufferCache::new(agg_param.prefixes.len());
        for prefix in agg_param.prefixes.iter() {
            let share = vidpf::eval_verified::<P, SEED_SIZE>(
                agg_id,
                &public_share.idpf_pub,
                &input_share.idpf_key,
                prefix,
                &mut idpf_eval_cache,
            )?;

            out_share.push(share.s);

            // Range check
            s_share += share.s;
            t_share += share.t;

            // Onehot check
            onhot_check_verifier_hasher.update(share.verifier());
        }

        // Onehot check: Compute the verification value.
        let onhot_check_verifier = onhot_check_verifier_hasher.finalize().into();

        // Range check: Compute the verifier share.
        let joint_rand = Self::joint_rand(early_joint_rand_seed.as_ref(), nonce, agg_param.level);
        let query_rand = Self::query_rand(verify_key, nonce, agg_param.level);
        let range_check_verifier_share = dflp::query(
            s_share,
            t_share,
            delta_share,
            proof_share,
            &query_rand,
            &joint_rand,
            2,
        )?;

        Ok((
            DoplarPrepareState {
                early_joint_rand_seed,
                out_share,
                level: agg_param.level,
            },
            DoplarPrepareShare {
                corrected_joint_rand_part: owned_joint_rand_part,
                range_check_verifier_share,
                onhot_check_verifier,
            },
        ))
    }

    fn prepare_preprocess<M: IntoIterator<Item = DoplarPrepareShare<SEED_SIZE>>>(
        &self,
        inputs: M,
    ) -> Result<DoplarPrepareMessage<SEED_SIZE>, VdafError> {
        let mut inputs = inputs.into_iter();
        let prep_share_0 = inputs
            .next()
            .ok_or_else(|| VdafError::Uncategorized("insufficient number of prep shares".into()))?;
        let prep_share_1 = inputs
            .next()
            .ok_or_else(|| VdafError::Uncategorized("insufficient number of prep shares".into()))?;
        if inputs.next().is_some() {
            return Err(VdafError::Uncategorized(
                "more prep shares than expected".into(),
            ));
        }

        // NOTE In practice, the "prep messsage" output by this method is written to the wire. It
        // would be better to compute the corrected joint randomness seed here and write that to
        // the wire instead of the parts. However, this will require passing the level to
        // `prepare_process()`, which requires upstream API changes (probably just pass the state
        // here). For the purposes of our prototype, it's sufficient to just send the parts.
        let corrected_joint_rand_parts = [
            prep_share_0.corrected_joint_rand_part,
            prep_share_1.corrected_joint_rand_part,
        ];

        // Onehot check: Make sure the verification values are the same.
        if prep_share_0.onhot_check_verifier != prep_share_1.onhot_check_verifier {
            return Err(VdafError::Uncategorized("onehot check failed".into()));
        }

        // Range check: Compute verifier.
        let verifier: Vec<Field128> = prep_share_0
            .range_check_verifier_share
            .iter()
            .zip(prep_share_1.range_check_verifier_share.iter())
            .map(|(lhs, rhs)| *lhs + *rhs)
            .collect();
        if !dflp::decide(&verifier)? {
            return Err(VdafError::Uncategorized("range check failed".into()));
        }

        Ok(DoplarPrepareMessage {
            corrected_joint_rand_parts,
        })
    }

    fn prepare_step(
        &self,
        state: DoplarPrepareState<SEED_SIZE>,
        msg: DoplarPrepareMessage<SEED_SIZE>,
    ) -> Result<PrepareTransition<Self, SEED_SIZE, 16>, VdafError> {
        let [corrected_joint_rand_part_0, corrected_joint_rand_part_1] =
            msg.corrected_joint_rand_parts;
        let corrected_joint_rand_seed = Self::joint_rand_seed(
            &[0; SEED_SIZE],
            &corrected_joint_rand_part_0,
            &corrected_joint_rand_part_1,
            state.level,
        );

        if state.early_joint_rand_seed != corrected_joint_rand_seed {
            return Err(VdafError::Uncategorized(
                "joint randomness consistency check fialed".into(),
            ));
        }

        Ok(PrepareTransition::Finish(DoplarFieldVec(state.out_share)))
    }

    fn aggregate<M: IntoIterator<Item = DoplarFieldVec>>(
        &self,
        agg_param: &DoplarAggregationParam,
        out_shares: M,
    ) -> Result<DoplarFieldVec, VdafError> {
        let mut agg_share = vec![Field128::zero(); agg_param.prefixes.len()];
        for out_share in out_shares.into_iter() {
            if out_share.0.len() != agg_share.len() {
                return Err(VdafError::Uncategorized(format!(
                    "unexpected length of output share: got {}; want {}",
                    out_share.0.len(),
                    agg_share.len()
                )));
            }
            for (lhs, rhs) in agg_share.iter_mut().zip(out_share.0.into_iter()) {
                *lhs += rhs;
            }
        }

        Ok(DoplarFieldVec(agg_share))
    }
}

impl<P: Prg<SEED_SIZE>, const SEED_SIZE: usize> Collector for Doplar<P, SEED_SIZE> {
    fn unshard<M: IntoIterator<Item = DoplarFieldVec>>(
        &self,
        agg_param: &DoplarAggregationParam,
        agg_shares: M,
        _num_measurements: usize,
    ) -> Result<Vec<u64>, VdafError> {
        let mut agg_shares = agg_shares.into_iter();
        let agg_share_0 = agg_shares.next().ok_or_else(|| {
            VdafError::Uncategorized("insufficient number of aggregate shares".into())
        })?;
        let agg_share_1 = agg_shares.next().ok_or_else(|| {
            VdafError::Uncategorized("insufficient number of aggregate shares".into())
        })?;
        if agg_shares.next().is_some() {
            return Err(VdafError::Uncategorized(
                "more aggregate shares than expected".into(),
            ));
        }

        if agg_share_0.0.len() != agg_share_1.0.len() {
            return Err(VdafError::Uncategorized(
                "aggregate share length mismatch".into(),
            ));
        }

        if agg_share_0.0.len() != agg_param.prefixes.len() {
            return Err(VdafError::Uncategorized(format!(
                "unexpected number of prefixes: got {}; want {}",
                agg_share_0.0.len(),
                agg_param.prefixes.len()
            )));
        }

        let agg_result = agg_share_0
            .0
            .into_iter()
            .zip(agg_share_1.0.into_iter())
            .map(|(lhs, rhs)| u128::from(lhs + rhs).try_into())
            .collect::<Result<Vec<u64>, _>>()
            .map_err(|e| VdafError::Uncategorized(format!("count too large: {e}")))?;

        Ok(agg_result)
    }
}

/// A vector of field elements.
#[derive(Clone, Debug)]
pub struct DoplarFieldVec(Vec<Field128>);

impl Encode for DoplarFieldVec {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        todo!("serialization not required for prototype")
    }
}

impl<'a, P: Prg<SEED_SIZE>, const SEED_SIZE: usize>
    ParameterizedDecode<(&'a Doplar<P, SEED_SIZE>, &'a DoplarAggregationParam)> for DoplarFieldVec
{
    fn decode_with_param(
        (_vdaf, _agg_param): &(&'a Doplar<P, SEED_SIZE>, &'a DoplarAggregationParam),
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

impl<const SEED_SIZE: usize> ParameterizedDecode<DoplarPrepareState<SEED_SIZE>> for DoplarFieldVec {
    fn decode_with_param(
        _state: &DoplarPrepareState<SEED_SIZE>,
        _bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        todo!("serialization not required for prototype")
    }
}

impl Aggregatable for DoplarFieldVec {
    type OutputShare = Self;

    fn merge(&mut self, _agg_share: &Self) -> Result<(), VdafError> {
        todo!("this trait is not required by the prototype")
    }

    fn accumulate(&mut self, _out_share: &Self) -> Result<(), VdafError> {
        todo!("this trait is not required by the prototype")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use testing::{doplar_run_heavy_hitters, doplar_run_prepare};

    fn test_prepare<P: Prg<SEED_SIZE>, const SEED_SIZE: usize>(
        vdaf: &Doplar<P, SEED_SIZE>,
        public_share: &DoplarPublicShare<SEED_SIZE>,
        input_shares: &[DoplarInputShare<SEED_SIZE>],
        nonce: &[u8; 16],
        verify_key: &[u8; SEED_SIZE],
        agg_param: &DoplarAggregationParam,
        expected_result: Vec<u64>,
    ) {
        // Test preparation: Refine input shares into refined shares using `agg_param` as the
        // initial state.
        let (out_share_0, out_share_1) = doplar_run_prepare(
            vdaf,
            public_share,
            input_shares,
            nonce,
            verify_key,
            agg_param,
        );

        // Test aggregation consistency: Convert aggregate shares and unshard.
        let agg_share_0 = vdaf.aggregate(agg_param, [out_share_0]).unwrap();
        let agg_share_1 = vdaf.aggregate(agg_param, [out_share_1]).unwrap();
        let result = vdaf
            .unshard(agg_param, [agg_share_0, agg_share_1], 1)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn shard_prepare() {
        let mut rng = thread_rng();
        let verify_key = rng.gen();
        let vdaf = Doplar::new_aes128(128);
        let input = IdpfInput::from_bytes(b"1234123412341234");
        let nonce = rng.gen::<[u8; 16]>();
        let (public_share, input_shares) = vdaf.shard(&input, &nonce).unwrap();

        test_prepare(
            &vdaf,
            &public_share,
            &input_shares,
            &nonce,
            &verify_key,
            &DoplarAggregationParam {
                prefixes: vec![
                    IdpfInput::from_bytes(b"0"),
                    IdpfInput::from_bytes(b"1"),
                    IdpfInput::from_bytes(b"/"),
                    IdpfInput::from_bytes(b"f"),
                ],
                level: 7,
            },
            vec![0, 1, 0, 0],
        );
    }

    #[tokio::test]
    async fn heavy_hitters() {
        let mut rng = thread_rng();
        let verify_key = rng.gen();

        doplar_run_heavy_hitters(
            8,
            &verify_key,
            2, // threshold
            [
                "a", "b", "c", "d", "e", "f", "g", "g", "h", "i", "i", "i", "j", "j", "k", "l",
            ], // measurements
            ["g", "i", "j"], // heavy hitters
        )
        .await;
    }
}

pub mod dflp;
pub mod testing;
pub mod upstream;
pub mod vidpf;