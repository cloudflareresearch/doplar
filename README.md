# Doplar prototype

This repository implements a prototype of Doplar, a VDAF designed and analyzed
in a [paper presented at PETS 2023](https://eprint.iacr.org/2023/130). Doplar
is fullfills the same use case as Poplar1 (one of the algorithms in the
[current version of the
standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/03/)), but has
reduced round complexity (at the cost of higher overall communication cost).

The code is written in Rust. Our starting point is the `prio` crate maintained
by the ISRG ("Internet Security Research Group",
https://www.abetterinternet.org/), which includes Rust implementations of the
current crop of VDAF candidates (Prio3 and Poplar1). We will work from the
current development branch, which at the time of writing is:
https://github.com/divviup/libprio-rs/tree/0d3db3b5b62005a2fb28b40237ffd0f888399b62

The `prio` crate implements the two main primtives needed for Doplar, namely FLP
(``Fully Linear Proof'') and IDPF (``Incremental Distributed Point Function'').
In order to lift the latter into verifiable IDPF, some minor modifications to
the upstream code were required. See "IDPF Modifications" below for details.

## Usage

To use the code, you will first need to install the rust toolchain
(https://www.rust-lang.org/learn/get-started). This code has been tested with
rustc version 1.67.1 (2023-02-07). To run unit tests:

```
cargo test
```

It may be helpful to view the crate's documentation. To open in your system's
default web browser:

```
cargo doc --open
```

## Running the Benchmarks

The `cargo-criterion` tool is required to reproduce the benchamrks:

```
cargo install cargo-criterion
```

The file `compute-comparison.json` in this directory contains results for the
benchmarks run on a 2019 MacBook Pro (2.6 GHz 6-Core Intel Core i7):

```
cargo-criterion --message-format=json > compute-comparison.json
```

Version 1.1.0 of cargo-criterion was used.

## IDPF Modifications

The crate includes a module `upstream` containing code from the `prio` crate.
It has been modified slightly to allow us to wire up the verifification logic
in our own VIDPF module. Namely, callbacks have been added for IDPF generation
and evaluation for adjusting the correction word and applying correction word
adjustments respectively. In addition, some of the code has been tweaked so
that our code can use `prio`'s public API.

The changes are summarized in `upstream.patch`. To verify them, check out the
development branch, apply the patch, and compare the files:

```
git clone https://github.com/divviup/libprio-rs
cd libprio-rs
gt checkout 0d3db3b5b62005a2fb28b40237ffd0f888399b62
patch -u src/idpf.rs -i <PATH_TO_DOPLAR>/upstream.patch # should succeed
diff -u src/idpf.rs <PATH_TO_DOPLAR>/src/upstream/mod.rs # should be empty
```

## Contributing

This repository includes code that was copied from the original `prio` crate
and retains the license of that crate (see `src/upstream/LICENSE`). All other
code will be distributed under the standard BSD 3-clause license (see
`LICENSE`).

This code is intended primarily as a prototype and is not expected to be
maintained long-term.
