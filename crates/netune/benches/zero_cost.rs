//! Deterministic instruction-count benchmarks for the observation primitives.
//!
//! `cargo bench --bench zero_cost` runs these under Callgrind. The `NoTap`
//! benchmark is the zero-cost reference: it must be indistinguishable from an
//! empty loop except for the `black_box` barrier. `Counters` is the L0 floor:
//! arithmetic only, no clock and no allocation.
//!
//! The wall-clock measurements in `tests/overhead.rs` remain diagnostic; this
//! bench is the deterministic gate.

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use netune_trace::{Counters, NoTap, Tap, TimeSource};

#[library_benchmark]
fn no_tap_read() {
    let mut tap = NoTap;
    tap.read(1448, TimeSource::Syscall);
    black_box(&tap);
}

#[library_benchmark]
fn counters_read() {
    let mut tap = Counters::default();
    tap.read(1448, TimeSource::Syscall);
    black_box(&tap);
}

#[library_benchmark]
fn counters_wrote() {
    let mut tap = Counters::default();
    tap.wrote(1448);
    black_box(&tap);
}

library_benchmark_group!(
    name = zero_cost;
    benchmarks = no_tap_read, counters_read, counters_wrote
);

main!(library_benchmark_groups = zero_cost);
