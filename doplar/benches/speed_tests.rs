// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.

//! Speed tests for Poplar1 and Doplar.
//!
//! These benchmarks are based on:
//! https://github.com/divviup/libprio-rs/blob/c1ac67982d168bdac1fe6bda84ded7aad41ebb61/benches/speed_tests.rs
//!
//! Many functions have been copied verbatim.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use doplar::{
    upstream::{testing::generate_zipf_distributed_batch, IdpfInput},
    Doplar, DoplarAggregationParam,
};
use prio::vdaf::{
    poplar1::{Poplar1, Poplar1AggregationParam},
    Aggregator, Client,
};
use rand::prelude::*;
use std::{iter, time::Duration};

const SIZE_MIN: usize = 32;
const SIZE_MAX: usize = 512 + SIZE_STEP;
const SIZE_STEP: usize = 32;

pub fn shard(c: &mut Criterion) {
    let mut group = c.benchmark_group("doplar_shard");
    for size in (SIZE_MIN..SIZE_MAX).step_by(SIZE_STEP) {
        group.throughput(Throughput::Bytes(size as u64 / 8));
        group.measurement_time(Duration::from_secs(30)); // slower benchmark
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let vdaf = Doplar::new_aes128(size);
            let mut rng = thread_rng();
            let nonce = rng.gen::<[u8; 16]>();

            b.iter_batched(
                || {
                    let bits = iter::repeat_with(|| rng.gen())
                        .take(size)
                        .collect::<Vec<bool>>();
                    IdpfInput::from_bools(&bits)
                },
                |measurement| {
                    vdaf.shard(&measurement, &nonce).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("poplar1_shard");
    for size in (SIZE_MIN..SIZE_MAX).step_by(SIZE_STEP) {
        group.throughput(Throughput::Bytes(size as u64 / 8));
        group.measurement_time(Duration::from_secs(30)); // slower benchmark
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let vdaf = Poplar1::new_aes128(size);
            let mut rng = thread_rng();
            let nonce = rng.gen::<[u8; 16]>();

            b.iter_batched(
                || {
                    let bits = iter::repeat_with(|| rng.gen())
                        .take(size)
                        .collect::<Vec<bool>>();
                    prio::idpf::IdpfInput::from_bools(&bits)
                },
                |measurement| {
                    vdaf.shard(&measurement, &nonce).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

pub fn prep(c: &mut Criterion) {
    let mut rng = thread_rng();

    struct TestCase {
        size: usize,
        measurements: Vec<IdpfInput>,
        prefix_tree: Vec<Vec<IdpfInput>>,
    }

    let test_cases = (SIZE_MIN..SIZE_MAX)
        .step_by(SIZE_STEP)
        .map(|size| {
            // Genearate measurements from a Zipf distribution.
            let (measurements, prefix_tree) = generate_zipf_distributed_batch(
                &mut rng, // rng
                size,     // bits
                10,       // threshold
                1000,     // number of measurements
                128,      // Zipf support
                1.03,     // Zipf exponent
            );

            TestCase {
                size,
                measurements,
                prefix_tree,
            }
        })
        .collect::<Vec<TestCase>>();

    let verify_key: [u8; 16] = rng.gen();
    let nonce: [u8; 16] = rng.gen();

    let mut group = c.benchmark_group("doplar_prep_init");
    for test_case in test_cases.iter() {
        let size = test_case.size;

        group.measurement_time(Duration::from_secs(30)); // slower benchmark
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let vdaf = Doplar::new_aes128(size);

            b.iter_batched(
                || {
                    // We are benchmarking preparation of a single report. For this test, it doesn't matter
                    // which measurement we generate a report for, so pick the first measurement
                    // arbitrarily.
                    let (public_share, input_shares) =
                        vdaf.shard(&test_case.measurements[0], &nonce).unwrap();

                    // For the aggregation paramter, we use the candidate prefixes from the prefix tree
                    // for the sampled measurements. Run preparation for the last step, which ought to
                    // represent the worst-case performance.
                    let agg_param = DoplarAggregationParam {
                        prefixes: test_case.prefix_tree[size - 1].clone(),
                        level: size - 1,
                    };

                    (
                        verify_key,
                        nonce,
                        agg_param,
                        public_share,
                        input_shares.into_iter().next().unwrap(),
                    )
                },
                |(verify_key, nonce, agg_param, public_share, input_share)| {
                    vdaf.prepare_init(
                        &verify_key,
                        0,
                        &agg_param,
                        &nonce,
                        &public_share,
                        &input_share,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("poplar1_prep_init");
    for test_case in test_cases.iter() {
        let size = test_case.size;

        group.measurement_time(Duration::from_secs(30)); // slower benchmark
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let vdaf = Poplar1::new_aes128(size);

            b.iter_batched(
                || {
                    // We need to convert our `IdpfInput` into a `prio::idpf::IdpfInput`. This is an
                    // unfortunate consequence of having copy `prio`'s IDPF implementation into
                    // this crate so that it could be modiffied.
                    let measurement =
                        prio::idpf::IdpfInput::from_bytes(&test_case.measurements[0].to_bytes());
                    let prefixes: Vec<_> = test_case.prefix_tree[size - 1]
                        .iter()
                        .map(|input| prio::idpf::IdpfInput::from_bytes(&input.to_bytes()))
                        .collect();

                    // We are benchmarking preparation of a single report. For this test, it doesn't matter
                    // which measurement we generate a report for, so pick the first measurement
                    // arbitrarily.
                    let (public_share, input_shares) = vdaf.shard(&measurement, &nonce).unwrap();

                    // For the aggregation paramter, we use the candidate prefixes from the prefix tree
                    // for the sampled measurements. Run preparation for the last step, which ought to
                    // represent the worst-case performance.
                    let agg_param = Poplar1AggregationParam::try_from_prefixes(prefixes).unwrap();

                    (
                        verify_key,
                        nonce,
                        agg_param,
                        public_share,
                        input_shares.into_iter().next().unwrap(),
                    )
                },
                |(verify_key, nonce, agg_param, public_share, input_share)| {
                    vdaf.prepare_init(
                        &verify_key,
                        0,
                        &agg_param,
                        &nonce,
                        &public_share,
                        &input_share,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, shard, prep);
criterion_main!(benches);
