// Copyright (c) 2021 ISRG. All rights reserved.
//
// This program has been modified from source code distributed under the terms of the Mozilla
// Public License, v. 2.0.

//! This module implements the incremental distributed point function (IDPF) described in
//! [[draft-irtf-cfrg-vdaf-03]]. It also includes callbacks for wiring up the verification logic in
//! the VIDPF module.
//!
//! [draft-irtf-cfrg-vdaf-03]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/03/

pub mod testing;

use bitvec::{bitvec, boxed::BitBox, prelude::Lsb0, slice::BitSlice, vec::BitVec, view::BitView};
use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    vdaf::{
        prg::{CoinToss, Prg, Seed, SeedStream},
        VdafError,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    io::{Cursor, Read},
    ops::{Add, AddAssign, Index, Neg, Sub},
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

/// NOTE This constant was copied from the `prio` crate.
const VERSION: u8 = 3;

type AdjustCorrectionWord<V, const L: usize> = fn(
    correction_word: &mut IdpfCorrectionWord<V, L>,
    seeds_corrected: &[[u8; L]; 2],
    value_0: V,
    value_1: V,
);

type ApplyCorrectionWordAdjustment<V, const L: usize> = fn(
    value_share: &mut V,
    correction_word: &IdpfCorrectionWord<V, L>,
    seed_corrected: &[u8; L],
    control_bit: Choice,
);

/// An index used as the input to an IDPF evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdpfInput {
    /// The index as a boxed bit slice.
    index: BitBox,
}

impl IdpfInput {
    /// Convert a slice of bytes into an IDPF input, where the bits of each byte are processed in
    /// LSB-to-MSB order. (Subsequent bytes are processed in their natural order.)
    pub fn from_bytes(bytes: &[u8]) -> IdpfInput {
        let bit_slice_u8_storage = bytes.view_bits::<Lsb0>();
        let mut bit_vec_usize_storage = bitvec![0; bit_slice_u8_storage.len()];
        bit_vec_usize_storage.clone_from_bitslice(bit_slice_u8_storage);
        IdpfInput {
            index: bit_vec_usize_storage.into_boxed_bitslice(),
        }
    }

    /// Convert a slice of booleans into an IDPF input.
    pub fn from_bools(bools: &[bool]) -> IdpfInput {
        let bits = bools.iter().collect::<BitVec>();
        IdpfInput {
            index: bits.into_boxed_bitslice(),
        }
    }

    /// Create a new IDPF input by appending to this input.
    pub fn clone_with_suffix(&self, suffix: &[bool]) -> IdpfInput {
        let mut vec = BitVec::with_capacity(self.index.len() + suffix.len());
        vec.extend_from_bitslice(&self.index);
        vec.extend(suffix);
        IdpfInput {
            index: vec.into_boxed_bitslice(),
        }
    }

    /// Get the length of the input in bits.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Check if the input is empty, i.e. it does not contain any bits.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Get an iterator over the bits that make up this input.
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        self.index.iter().by_vals()
    }

    /// Convert the IDPF into a byte slice. If the length of the underlying bit vector is not a
    /// multiple of `8`, then the last byte is `0`-padded.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = BitVec::<u8, Lsb0>::with_capacity(self.index.len());
        vec.extend_from_bitslice(&self.index);
        vec.set_uninitialized(false);
        vec.into_vec()
    }

    /// Return the `level`-bit prefix of this IDPF input.
    pub fn prefix(&self, level: usize) -> Self {
        Self {
            index: self.index[..=level].to_owned().into(),
        }
    }
}

impl From<BitVec<usize, Lsb0>> for IdpfInput {
    fn from(bit_vec: BitVec<usize, Lsb0>) -> Self {
        IdpfInput {
            index: bit_vec.into_boxed_bitslice(),
        }
    }
}

impl From<BitBox<usize, Lsb0>> for IdpfInput {
    fn from(bit_box: BitBox<usize, Lsb0>) -> Self {
        IdpfInput { index: bit_box }
    }
}

impl<I> Index<I> for IdpfInput
where
    BitSlice: Index<I>,
{
    type Output = <BitSlice as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.index[index]
    }
}

/// Trait for values to be programmed into an IDPF.
///
/// Values must form an Abelian group, so that they can be secret-shared, and the group operation
/// must be represented by [`Add`]. An implementation of [`CoinToss`] must be provided to randomly
/// select a value using PRG output. Values must be encodable and decodable, without need for a
/// decoding parameter.
pub trait IdpfValue:
    Add<Output = Self>
    + AddAssign
    + Neg<Output = Self>
    + Sub<Output = Self>
    + ConditionallySelectable
    + ConditionallyNegatable
    + CoinToss
    + Encode
    + Decode
    + Sized
{
    /// Returns the additive identity.
    fn zero() -> Self;
}

/// An output from evaluation of an IDPF at some level and index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdpfOutputShare<VI, VL> {
    /// An IDPF output share corresponding to an inner tree node.
    Inner(VI),
    /// An IDPF output share corresponding to a leaf tree node.
    Leaf(VL),
}

impl<VI, VL> IdpfOutputShare<VI, VL>
where
    VI: IdpfValue,
    VL: IdpfValue,
{
    /// Combine two output share values into one.
    pub fn merge(self, other: Self) -> Result<IdpfOutputShare<VI, VL>, VdafError> {
        match (self, other) {
            (IdpfOutputShare::Inner(mut self_value), IdpfOutputShare::Inner(other_value)) => {
                self_value += other_value;
                Ok(IdpfOutputShare::Inner(self_value))
            }
            (IdpfOutputShare::Leaf(mut self_value), IdpfOutputShare::Leaf(other_value)) => {
                self_value += other_value;
                Ok(IdpfOutputShare::Leaf(self_value))
            }
            (_, _) => Err(VdafError::Uncategorized("mismatched levels".to_string())),
        }
    }
}

fn extend<P, const L: usize>(seed: &[u8; L]) -> ([[u8; L]; 2], [Choice; 2])
where
    P: Prg<L>,
{
    let custom = [
        VERSION, 1, /* algorithm class */
        0, 0, 0, 0, /* algorithm ID */
        0, 0, /* usage */
    ];
    let mut seed_stream = P::init(seed, &custom).into_seed_stream();

    let mut seeds = [[0u8; L], [0u8; L]];
    seed_stream.fill(&mut seeds[0]);
    seed_stream.fill(&mut seeds[1]);

    let mut byte = [0u8];
    seed_stream.fill(&mut byte);
    let control_bits = [(byte[0] & 1).into(), ((byte[0] >> 1) & 1).into()];

    (seeds, control_bits)
}

fn convert<V, P, const L: usize>(seed: &[u8; L]) -> ([u8; L], V)
where
    V: IdpfValue,
    P: Prg<L>,
{
    let custom = [
        VERSION, 1, /* algorithm class */
        0, 0, 0, 0, /* algorithm ID */
        0, 1, /* usage */
    ];
    let mut seed_stream = P::init(seed, &custom).into_seed_stream();

    let mut next_seed = [0u8; L];
    seed_stream.fill(&mut next_seed);

    (next_seed, V::sample(&mut seed_stream))
}

/// Helper method to update seeds, update control bits, and output the correction word for one level
/// of the IDPF key generation process.
fn generate_correction_word<V, P, const L: usize>(
    input_bit: Choice,
    value: V,
    keys: &mut [[u8; L]; 2],
    control_bits: &mut [Choice; 2],
    adjust_correction_word: AdjustCorrectionWord<V, L>,
) -> IdpfCorrectionWord<V, L>
where
    V: IdpfValue,
    P: Prg<L>,
{
    // Expand both keys into two seeds and two control bits each.
    let (seed_0, control_bits_0) = extend::<P, L>(&keys[0]);
    let (seed_1, control_bits_1) = extend::<P, L>(&keys[1]);

    let (keep, lose) = (input_bit, !input_bit);

    let cw_seed = xor_seeds(
        &conditional_select_seed(lose, &seed_0),
        &conditional_select_seed(lose, &seed_1),
    );
    let cw_control_bits = [
        control_bits_0[0] ^ control_bits_1[0] ^ input_bit ^ Choice::from(1),
        control_bits_0[1] ^ control_bits_1[1] ^ input_bit,
    ];
    let cw_control_bits_keep =
        Choice::conditional_select(&cw_control_bits[0], &cw_control_bits[1], keep);

    let previous_control_bits = *control_bits;
    let control_bits_0_keep =
        Choice::conditional_select(&control_bits_0[0], &control_bits_0[1], keep);
    let control_bits_1_keep =
        Choice::conditional_select(&control_bits_1[0], &control_bits_1[1], keep);
    control_bits[0] = control_bits_0_keep ^ (cw_control_bits_keep & previous_control_bits[0]);
    control_bits[1] = control_bits_1_keep ^ (cw_control_bits_keep & previous_control_bits[1]);

    let seed_0_keep = conditional_select_seed(keep, &seed_0);
    let seed_1_keep = conditional_select_seed(keep, &seed_1);
    let seeds_corrected = [
        conditional_xor_seeds(&seed_0_keep, &cw_seed, previous_control_bits[0]),
        conditional_xor_seeds(&seed_1_keep, &cw_seed, previous_control_bits[1]),
    ];

    let (new_key_0, mut value_0) = convert::<V, P, L>(&seeds_corrected[0]);
    let (new_key_1, mut value_1) = convert::<V, P, L>(&seeds_corrected[1]);

    keys[0] = new_key_0;
    keys[1] = new_key_1;

    let mut cw_value = value - value_0 + value_1;
    cw_value.conditional_negate(control_bits[1]);

    let mut correction_word = IdpfCorrectionWord {
        seed: cw_seed,
        control_bits: cw_control_bits,
        value: cw_value,
    };

    value_0 += V::conditional_select(&V::zero(), &cw_value, control_bits[0]);
    value_1 += V::conditional_select(&V::zero(), &cw_value, control_bits[1]);
    adjust_correction_word(&mut correction_word, &seeds_corrected, value_0, -value_1);
    correction_word
}

/// Helper function to evaluate one level of an IDPF. This updates the seed and control bit
/// arguments that are passed in.
fn eval_next<V, P, const L: usize>(
    is_leader: bool,
    key: &mut [u8; L],
    control_bit: &mut Choice,
    correction_word: &IdpfCorrectionWord<V, L>,
    input_bit: Choice,
    apply_correction_word_adjustment: ApplyCorrectionWordAdjustment<V, L>,
) -> V
where
    V: IdpfValue,
    P: Prg<L>,
{
    let (mut seeds, mut control_bits) = extend::<P, L>(key);

    seeds[0] = conditional_xor_seeds(&seeds[0], &correction_word.seed, *control_bit);
    control_bits[0] ^= correction_word.control_bits[0] & *control_bit;
    seeds[1] = conditional_xor_seeds(&seeds[1], &correction_word.seed, *control_bit);
    control_bits[1] ^= correction_word.control_bits[1] & *control_bit;

    let seed_corrected = conditional_select_seed(input_bit, &seeds);
    *control_bit = Choice::conditional_select(&control_bits[0], &control_bits[1], input_bit);

    let (new_key, mut value) = convert::<V, P, L>(&seed_corrected);
    *key = new_key;

    value += V::conditional_select(&V::zero(), &correction_word.value, *control_bit);
    apply_correction_word_adjustment(&mut value, correction_word, &seed_corrected, *control_bit);
    if !is_leader {
        value = -value;
    }
    value
}

/// The IDPF key generation algorithm.
///
/// Generate and return a sequence of IDPF shares for `input`. The parameters `inner_values`
/// and `leaf_value` provide the output values for each successive level of the prefix tree.
pub fn gen_with_adjustment<VI, VL, M: IntoIterator<Item = VI>, P, const L: usize>(
    input: &IdpfInput,
    inner_values: M,
    leaf_value: VL,
    inner_adjust_correction_word: AdjustCorrectionWord<VI, L>,
    leaf_adjust_correction_word: AdjustCorrectionWord<VL, L>,
) -> Result<(IdpfPublicShare<VI, VL, L>, [Seed<L>; 2]), VdafError>
where
    VI: IdpfValue,
    VL: IdpfValue,
    P: Prg<L>,
{
    if input.is_empty() {
        return Err(VdafError::Uncategorized(
            "invalid number of bits: 0".to_string(),
        ));
    }

    let bits = input.len();
    let initial_keys: [Seed<L>; 2] = [Seed::generate()?, Seed::generate()?];

    let mut keys = [*initial_keys[0].as_ref(), *initial_keys[1].as_ref()];
    let mut control_bits = [Choice::from(0u8), Choice::from(1u8)];
    let mut inner_correction_words = Vec::with_capacity(bits - 1);

    for (level, value) in inner_values.into_iter().enumerate() {
        if level >= bits - 1 {
            return Err(VdafError::Uncategorized(
                "too many values were supplied".to_string(),
            ));
        }
        inner_correction_words.push(generate_correction_word::<VI, P, L>(
            Choice::from(input[level] as u8),
            value,
            &mut keys,
            &mut control_bits,
            inner_adjust_correction_word,
        ));
    }
    if inner_correction_words.len() != bits - 1 {
        return Err(VdafError::Uncategorized(
            "too few values were supplied".to_string(),
        ));
    }
    let leaf_correction_word = generate_correction_word::<VL, P, L>(
        Choice::from(input[bits - 1] as u8),
        leaf_value,
        &mut keys,
        &mut control_bits,
        leaf_adjust_correction_word,
    );
    let public_share = IdpfPublicShare {
        inner_correction_words,
        leaf_correction_word,
    };

    Ok((public_share, initial_keys))
}

/// Evaluate an IDPF share on `prefix`, starting from a particular tree level with known
/// intermediate values.
#[allow(clippy::too_many_arguments)]
fn eval_from_node<VI, VL, P, const L: usize>(
    is_leader: bool,
    public_share: &IdpfPublicShare<VI, VL, L>,
    start_level: usize,
    mut key: [u8; L],
    mut control_bit: Choice,
    prefix: &IdpfInput,
    cache: &mut dyn IdpfCache<L>,
    inner_apply_correction_word_adjustment: ApplyCorrectionWordAdjustment<VI, L>,
    leaf_apply_correction_word_adjustment: ApplyCorrectionWordAdjustment<VL, L>,
) -> Result<IdpfOutputShare<VI, VL>, VdafError>
where
    VI: IdpfValue,
    VL: IdpfValue,
    P: Prg<L>,
{
    let bits = public_share.inner_correction_words.len() + 1;
    let mut last_inner_output = None;
    for ((correction_word, input_bit), level) in public_share.inner_correction_words[start_level..]
        .iter()
        .zip(prefix[start_level..].iter())
        .zip(start_level..)
    {
        last_inner_output = Some(eval_next::<_, P, L>(
            is_leader,
            &mut key,
            &mut control_bit,
            correction_word,
            Choice::from(*input_bit as u8),
            inner_apply_correction_word_adjustment,
        ));
        let cache_key = &prefix[..=level];
        cache.insert(cache_key, &(key, control_bit.unwrap_u8()));
    }

    if prefix.len() == bits {
        let leaf_output = eval_next::<_, P, L>(
            is_leader,
            &mut key,
            &mut control_bit,
            &public_share.leaf_correction_word,
            Choice::from(prefix[bits - 1] as u8),
            leaf_apply_correction_word_adjustment,
        );
        // Note: there's no point caching this node's key, because we will always run the
        // eval_next() call for the leaf level.
        Ok(IdpfOutputShare::Leaf(leaf_output))
    } else {
        Ok(IdpfOutputShare::Inner(last_inner_output.unwrap()))
    }
}

/// The IDPF key evaluation algorithm.
///
/// Evaluate an IDPF share on `prefix`.
pub fn eval_with_adjustment<VI, VL, P, const L: usize>(
    agg_id: usize,
    public_share: &IdpfPublicShare<VI, VL, L>,
    key: &Seed<L>,
    prefix: &IdpfInput,
    cache: &mut dyn IdpfCache<L>,
    inner_apply_correction_word_adjustment: ApplyCorrectionWordAdjustment<VI, L>,
    leaf_apply_correction_word_adjustment: ApplyCorrectionWordAdjustment<VL, L>,
) -> Result<IdpfOutputShare<VI, VL>, VdafError>
where
    VI: IdpfValue,
    VL: IdpfValue,
    P: Prg<L>,
{
    let bits = public_share.inner_correction_words.len() + 1;
    if agg_id > 1 {
        return Err(VdafError::Uncategorized(format!(
            "invalid aggregator ID {agg_id}"
        )));
    }
    let is_leader = agg_id == 0;
    if prefix.is_empty() {
        return Err(VdafError::Uncategorized("empty prefix".to_string()));
    }
    if prefix.len() > bits {
        return Err(VdafError::Uncategorized(format!(
            "prefix length ({}) exceeds configured number of bits ({})",
            prefix.len(),
            bits,
        )));
    }

    // Check for cached keys first, starting from the end of our desired path down the tree, and
    // walking back up. If we get a hit, stop there and evaluate the remainder of the tree path
    // going forward.
    if prefix.len() > 1 {
        // Skip checking for `prefix` in the cache, because we don't store field element
        // values along with keys and control bits. Instead, start looking one node higher
        // up, so we can recompute everything for the last level of `prefix`.
        let mut cache_key = &prefix[..prefix.len() - 1];
        while !cache_key.is_empty() {
            if let Some((key, control_bit)) = cache.get(cache_key) {
                // Evaluate the IDPF starting from the cached data at a previously-computed
                // node, and return the result.
                return eval_from_node::<VI, VL, P, L>(
                    is_leader,
                    public_share,
                    /* start_level */ cache_key.len(),
                    key,
                    Choice::from(control_bit),
                    prefix,
                    cache,
                    inner_apply_correction_word_adjustment,
                    leaf_apply_correction_word_adjustment,
                );
            }
            cache_key = &cache_key[..cache_key.len() - 1];
        }
    }
    // Evaluate starting from the root node.
    eval_from_node::<VI, VL, P, L>(
        is_leader,
        public_share,
        /* start_level */ 0,
        *key.as_ref(),
        /* control_bit */ Choice::from((!is_leader) as u8),
        prefix,
        cache,
        inner_apply_correction_word_adjustment,
        leaf_apply_correction_word_adjustment,
    )
}

/// An IDPF public share. This contains the list of correction words used by all parties when
/// evaluating the IDPF.
#[derive(Debug, Clone)]
pub struct IdpfPublicShare<VI, VL, const L: usize> {
    /// Correction words for each inner node level.
    inner_correction_words: Vec<IdpfCorrectionWord<VI, L>>,
    /// Correction word for the leaf node level.
    leaf_correction_word: IdpfCorrectionWord<VL, L>,
}

impl<VI, VL, const L: usize> ConstantTimeEq for IdpfPublicShare<VI, VL, L>
where
    VI: ConstantTimeEq,
    VL: ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner_correction_words
            .ct_eq(&other.inner_correction_words)
            & self.leaf_correction_word.ct_eq(&other.leaf_correction_word)
    }
}

impl<VI, VL, const L: usize> PartialEq for IdpfPublicShare<VI, VL, L>
where
    VI: ConstantTimeEq,
    VL: ConstantTimeEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<VI, VL, const L: usize> Eq for IdpfPublicShare<VI, VL, L>
where
    VI: ConstantTimeEq,
    VL: ConstantTimeEq,
{
}

impl<VI, VL, const L: usize> Encode for IdpfPublicShare<VI, VL, L>
where
    VI: Encode,
    VL: Encode,
{
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Control bits need to be written within each byte in LSB-to-MSB order, and assigned into
        // bytes in big-endian order. Thus, the first four levels will have their control bits
        // encoded in the last byte, and the last levels will have their control bits encoded in the
        // first byte.
        let mut control_bits: BitVec<u8, Lsb0> =
            BitVec::with_capacity(self.inner_correction_words.len() * 2 + 2);
        for correction_words in self.inner_correction_words.iter() {
            control_bits.extend(correction_words.control_bits.iter().map(|x| bool::from(*x)));
        }
        control_bits.extend(
            self.leaf_correction_word
                .control_bits
                .iter()
                .map(|x| bool::from(*x)),
        );
        control_bits.set_uninitialized(false);
        let mut packed_control = control_bits.into_vec();
        // Flip the byte order from `bitvec`'s native order to the required big-endian order.
        packed_control.reverse();
        bytes.append(&mut packed_control);

        for correction_words in self.inner_correction_words.iter() {
            bytes.extend_from_slice(&correction_words.seed);
            correction_words.value.encode(bytes);
        }
        bytes.extend_from_slice(&self.leaf_correction_word.seed);
        self.leaf_correction_word.value.encode(bytes);
    }
}

impl<VI, VL, const L: usize> ParameterizedDecode<usize> for IdpfPublicShare<VI, VL, L>
where
    VI: Decode + Copy,
    VL: Decode + Copy,
{
    fn decode_with_param(bits: &usize, bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let packed_control_len = (bits + 3) / 4;
        let mut packed = vec![0u8; packed_control_len];
        bytes.read_exact(&mut packed)?;
        packed.reverse();
        let unpacked_control_bits: BitVec<u8, Lsb0> = BitVec::from_vec(packed);

        let mut inner_correction_words = Vec::with_capacity(bits - 1);
        for chunk in unpacked_control_bits[0..(bits - 1) * 2].chunks(2) {
            let control_bits = [(chunk[0] as u8).into(), (chunk[1] as u8).into()];
            let mut seed = [0; L];
            bytes.read_exact(&mut seed)?;
            let value = VI::decode(bytes)?;
            inner_correction_words.push(IdpfCorrectionWord {
                seed,
                control_bits,
                value,
            })
        }

        let control_bits = [
            (unpacked_control_bits[(bits - 1) * 2] as u8).into(),
            (unpacked_control_bits[bits * 2 - 1] as u8).into(),
        ];
        let mut seed = [0; L];
        bytes.read_exact(&mut seed)?;
        let value = VL::decode(bytes)?;
        let leaf_correction_word = IdpfCorrectionWord {
            seed,
            control_bits,
            value,
        };

        // Check that unused packed bits are zero.
        if unpacked_control_bits[bits * 2..].any() {
            return Err(CodecError::UnexpectedValue);
        }

        Ok(IdpfPublicShare {
            inner_correction_words,
            leaf_correction_word,
        })
    }
}

/// An IDPF correction word.
#[derive(Debug, Clone)]
pub struct IdpfCorrectionWord<V, const L: usize> {
    pub(crate) seed: [u8; L],
    pub(crate) control_bits: [Choice; 2],
    pub(crate) value: V,
}

impl<V, const L: usize> ConstantTimeEq for IdpfCorrectionWord<V, L>
where
    V: ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
            & self.control_bits.ct_eq(&other.control_bits)
            & self.value.ct_eq(&other.value)
    }
}

impl<V, const L: usize> PartialEq for IdpfCorrectionWord<V, L>
where
    V: ConstantTimeEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<V, const L: usize> Eq for IdpfCorrectionWord<V, L> where V: ConstantTimeEq {}

fn xor_seeds<const L: usize>(left: &[u8; L], right: &[u8; L]) -> [u8; L] {
    let mut seed = [0u8; L];
    for (a, (b, c)) in left.iter().zip(right.iter().zip(seed.iter_mut())) {
        *c = a ^ b;
    }
    seed
}

fn and_seeds<const L: usize>(left: &[u8; L], right: &[u8; L]) -> [u8; L] {
    let mut seed = [0u8; L];
    for (a, (b, c)) in left.iter().zip(right.iter().zip(seed.iter_mut())) {
        *c = a & b;
    }
    seed
}

fn or_seeds<const L: usize>(left: &[u8; L], right: &[u8; L]) -> [u8; L] {
    let mut seed = [0u8; L];
    for (a, (b, c)) in left.iter().zip(right.iter().zip(seed.iter_mut())) {
        *c = a | b;
    }
    seed
}

/// Take a control bit, and fan it out into a byte array that can be used as a mask for PRG seeds,
/// without branching. If the control bit input is 0, all bytes will be equal to 0, and if the
/// control bit input is 1, all bytes will be equal to 255.
fn control_bit_to_seed_mask<const L: usize>(control: Choice) -> [u8; L] {
    let mask = -(control.unwrap_u8() as i8) as u8;
    [mask; L]
}

/// Take two seeds and a control bit, and return the first seed if the control bit is zero, or the
/// XOR of the two seeds if the control bit is one. This does not branch on the control bit.
fn conditional_xor_seeds<const L: usize>(
    normal_input: &[u8; L],
    switched_input: &[u8; L],
    control: Choice,
) -> [u8; L] {
    xor_seeds(
        normal_input,
        &and_seeds(switched_input, &control_bit_to_seed_mask(control)),
    )
}

/// Returns one of two seeds, depending on the value of a selector bit. Does not branch on the
/// selector input or make selector-dependent memory accesses.
fn conditional_select_seed<const L: usize>(select: Choice, seeds: &[[u8; L]; 2]) -> [u8; L] {
    or_seeds(
        &and_seeds(&control_bit_to_seed_mask(!select), &seeds[0]),
        &and_seeds(&control_bit_to_seed_mask(select), &seeds[1]),
    )
}

/// An interface that provides memoization of IDPF computations.
///
/// Each instance of a type implementing `IdpfCache` should only be used with one IDPF key and
/// public share.
///
/// In typical use, IDPFs will be evaluated repeatedly on inputs of increasing length, as part of a
/// protocol executed by multiple participants. Each IDPF evaluation computes keys and control
/// bits corresponding to tree nodes along a path determined by the input to the IDPF. Thus, the
/// values from nodes further up in the tree may be cached and reused in evaluations of subsequent
/// longer inputs. If one IDPF input is a prefix of another input, then the first input's path down
/// the tree is a prefix of the other input's path.
pub trait IdpfCache<const L: usize> {
    /// Fetch cached values for the node identified by the IDPF input.
    fn get(&self, input: &BitSlice) -> Option<([u8; L], u8)>;

    /// Store values corresponding to the node identified by the IDPF input.
    fn insert(&mut self, input: &BitSlice, values: &([u8; L], u8));
}

/// A no-op [`IdpfCache`] implementation that always reports a cache miss.
#[derive(Default)]
pub struct NoCache {}

impl NoCache {
    /// Construct a `NoCache` object.
    #[allow(dead_code)]
    pub fn new() -> NoCache {
        NoCache::default()
    }
}

impl<const L: usize> IdpfCache<L> for NoCache {
    fn get(&self, _: &BitSlice) -> Option<([u8; L], u8)> {
        None
    }

    fn insert(&mut self, _: &BitSlice, _: &([u8; L], u8)) {}
}

/// A simple [`IdpfCache`] implementation that caches intermediate results in an in-memory hash map,
/// with no eviction.
#[derive(Default)]
pub struct HashMapCache<const L: usize> {
    map: HashMap<BitBox, ([u8; L], u8)>,
}

impl<const L: usize> HashMapCache<L> {
    /// Create a new unpopulated `HashMapCache`.
    #[allow(dead_code)]
    pub fn new() -> HashMapCache<L> {
        HashMapCache::default()
    }

    /// Create a new unpopulated `HashMapCache`, with a set pre-allocated capacity.
    #[allow(dead_code)]
    pub fn with_capacity(capacity: usize) -> HashMapCache<L> {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }
}

impl<const L: usize> IdpfCache<L> for HashMapCache<L> {
    fn get(&self, input: &BitSlice) -> Option<([u8; L], u8)> {
        self.map.get(input).cloned()
    }

    fn insert(&mut self, input: &BitSlice, values: &([u8; L], u8)) {
        if !self.map.contains_key(input) {
            self.map
                .insert(input.to_owned().into_boxed_bitslice(), *values);
        }
    }
}

/// A simple [`IdpfCache`] implementation that caches intermediate results in memory, with
/// least-recently-used eviction, and lookups via linear probing.
pub struct RingBufferCache<const L: usize> {
    ring: VecDeque<(BitBox, [u8; L], u8)>,
}

impl<const L: usize> RingBufferCache<L> {
    /// Create a new unpopulated `RingBufferCache`.
    pub fn new(capacity: usize) -> RingBufferCache<L> {
        Self {
            ring: VecDeque::with_capacity(std::cmp::max(capacity, 1)),
        }
    }
}

impl<const L: usize> IdpfCache<L> for RingBufferCache<L> {
    fn get(&self, input: &BitSlice) -> Option<([u8; L], u8)> {
        // iterate back-to-front, so that we check the most recently pushed entry first.
        for entry in self.ring.iter().rev() {
            if input == entry.0 {
                return Some((entry.1, entry.2));
            }
        }
        None
    }

    fn insert(&mut self, input: &BitSlice, values: &([u8; L], u8)) {
        // evict first (to avoid growing the storage)
        if self.ring.len() == self.ring.capacity() {
            self.ring.pop_front();
        }
        self.ring
            .push_back((input.to_owned().into_boxed_bitslice(), values.0, values.1));
    }
}
