// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.

//! Utilities for testing.

use crate::{
    upstream::IdpfInput, Doplar, DoplarAggregationParam, DoplarFieldVec, DoplarInputShare,
    DoplarPublicShare,
};
use prio::vdaf::{prg::Prg, Aggregator, Client, Collector, PrepareTransition};
use rand::prelude::*;
use rayon::prelude::*;
use std::collections::HashSet;

/// Use Doplar to compute the set of heavy hitters among the set of measurements.
// Sharding and preparation for each measurement happens in parallel.
pub async fn doplar_run_heavy_hitters<B: AsRef<[u8]> + Send>(
    bits: usize,
    verify_key: &[u8; 16],
    threshold: usize,
    measurements: impl IntoParallelIterator<Item = B>,
    expected_result: impl IntoParallelIterator<Item = B>,
) {
    let vdaf = Doplar::new_aes128(bits);

    // Sharding step
    let reports: Vec<([u8; 16], DoplarPublicShare<16>, Vec<DoplarInputShare<16>>)> = measurements
        .into_par_iter()
        .map(|measurement| {
            let nonce = rand::thread_rng().gen();
            let (public_share, input_shares) = vdaf
                .shard(&IdpfInput::from_bytes(measurement.as_ref()), &nonce)
                .unwrap();
            (nonce, public_share, input_shares)
        })
        .collect();

    let mut agg_param = DoplarAggregationParam {
        prefixes: vec![
            IdpfInput::from_bools(&[false]),
            IdpfInput::from_bools(&[true]),
        ],
        level: 0,
    };

    let mut agg_result = Vec::new();
    for level in 0..bits {
        let mut out_shares_0 = Vec::with_capacity(reports.len());
        let mut out_shares_1 = Vec::with_capacity(reports.len());

        // Preparation step
        let prepared_shares: Vec<(_, _)> = reports
            .par_iter()
            .map(|(nonce, public_share, input_shares)| {
                doplar_run_prepare(
                    &vdaf,
                    public_share,
                    input_shares,
                    nonce,
                    verify_key,
                    &agg_param,
                )
            })
            .collect();
        for (out_share_0, out_share_1) in prepared_shares {
            out_shares_0.push(out_share_0);
            out_shares_1.push(out_share_1);
        }

        // Aggregation step
        let agg_share_0 = vdaf.aggregate(&agg_param, out_shares_0).unwrap();
        let agg_share_1 = vdaf.aggregate(&agg_param, out_shares_1).unwrap();

        // Unsharding step
        agg_result = vdaf
            .unshard(&agg_param, [agg_share_0, agg_share_1], reports.len())
            .unwrap();

        // Unless this is the last level of the tree, construct the next set of candidate
        // prefixes.
        if level < bits - 1 {
            let mut next_prefixes = Vec::new();
            for (prefix, count) in agg_param.prefixes.iter().zip(agg_result.iter()) {
                if *count >= threshold as u64 {
                    next_prefixes.push(prefix.clone_with_suffix(&[false]));
                    next_prefixes.push(prefix.clone_with_suffix(&[true]));
                }
            }

            agg_param = DoplarAggregationParam {
                prefixes: next_prefixes,
                level: level + 1,
            };
        }
    }

    let got: HashSet<IdpfInput> = agg_param
        .prefixes
        .iter()
        .zip(agg_result.iter())
        .filter(|(_prefix, count)| **count >= threshold as u64)
        .map(|(prefix, _count)| prefix.clone())
        .collect();

    let want: HashSet<IdpfInput> = expected_result
        .into_par_iter()
        .map(|bytes| IdpfInput::from_bytes(bytes.as_ref()))
        .collect();

    assert_eq!(got, want);
}

pub(crate) fn doplar_run_prepare<P: Prg<SEED_SIZE>, const SEED_SIZE: usize>(
    vdaf: &Doplar<P, SEED_SIZE>,
    public_share: &DoplarPublicShare<SEED_SIZE>,
    input_shares: &[DoplarInputShare<SEED_SIZE>],
    nonce: &[u8; 16],
    verify_key: &[u8; SEED_SIZE],
    agg_param: &DoplarAggregationParam,
) -> (DoplarFieldVec, DoplarFieldVec) {
    let (prep_state_0, prep_share_0) = vdaf
        .prepare_init(
            verify_key,
            0,
            agg_param,
            nonce,
            public_share,
            &input_shares[0],
        )
        .unwrap();

    let (prep_state_1, prep_share_1) = vdaf
        .prepare_init(
            verify_key,
            1,
            agg_param,
            nonce,
            public_share,
            &input_shares[1],
        )
        .unwrap();

    let prep_msg = vdaf
        .prepare_preprocess([prep_share_0, prep_share_1])
        .unwrap();

    let out_share_0 = match vdaf.prepare_step(prep_state_0, prep_msg.clone()).unwrap() {
        PrepareTransition::Finish(share) => share,
        _ => panic!("expected finish"),
    };

    let out_share_1 = match vdaf.prepare_step(prep_state_1, prep_msg).unwrap() {
        PrepareTransition::Finish(share) => share,
        _ => panic!("expected finish"),
    };

    (out_share_0, out_share_1)
}
