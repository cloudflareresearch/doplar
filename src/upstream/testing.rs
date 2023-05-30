// Copyright (c) 2021 ISRG. All rights reserved.
//
// This program has been copied from source code distributed under the terms of the Mozilla Public
// License, v. 2.0.

use super::*;
use rand::prelude::*;
use zipf::ZipfDistribution;

/// Generate a set of measurements with the given bit length `bits`. They are sampled according to
/// the Zipf distribution with parameters `zipf_support` and `zipf_exponent`. Return the
/// measurements, along with the prefix tree for the desired threshold.
///
/// The prefix tree consists of a sequence of candidate prefixes for each level. For a given level,
/// the candidate prefixes are computed from the hit counts of the prefixes at the previous level:
/// For any prefix `p` whose hit count is at least the desired threshold, add `p || 0` and `p || 1`
/// to the list.
pub fn generate_zipf_distributed_batch(
    rng: &mut impl Rng,
    bits: usize,
    threshold: usize,
    measurement_count: usize,
    zipf_support: usize,
    zipf_exponent: f64,
) -> (Vec<IdpfInput>, Vec<Vec<IdpfInput>>) {
    // Generate random inputs.
    let mut inputs = Vec::with_capacity(zipf_support);
    for _ in 0..zipf_support {
        let bools: Vec<bool> = (0..bits).map(|_| rng.gen()).collect();
        inputs.push(IdpfInput::from_bools(&bools));
    }

    // Sample a number of inputs according to the Zipf distribution.
    let mut samples = Vec::with_capacity(measurement_count);
    let zipf = ZipfDistribution::new(zipf_support, zipf_exponent).unwrap();
    for _ in 0..measurement_count {
        samples.push(inputs[zipf.sample(rng) - 1].clone());
    }

    // Compute the prefix tree for the desired threshold.
    let mut prefix_tree = Vec::with_capacity(bits);
    prefix_tree.push(vec![
        IdpfInput::from_bools(&[false]),
        IdpfInput::from_bools(&[true]),
    ]);

    for level in 0..bits - 1 {
        // Compute the hit count of each prefix from the previous level.
        let mut hit_counts = vec![0; prefix_tree[level].len()];
        for (hit_count, prefix) in hit_counts.iter_mut().zip(prefix_tree[level].iter()) {
            for sample in samples.iter() {
                let mut is_prefix = true;
                for j in 0..prefix.len() {
                    if prefix[j] != sample[j] {
                        is_prefix = false;
                        break;
                    }
                }
                if is_prefix {
                    *hit_count += 1;
                }
            }
        }

        // Compute the next set of candidate prefixes.
        let mut next_prefixes = Vec::new();
        for (hit_count, prefix) in hit_counts.iter().zip(prefix_tree[level].iter()) {
            if *hit_count >= threshold {
                next_prefixes.push(prefix.clone_with_suffix(&[false]));
                next_prefixes.push(prefix.clone_with_suffix(&[true]));
            }
        }
        prefix_tree.push(next_prefixes);
    }

    (samples, prefix_tree)
}
