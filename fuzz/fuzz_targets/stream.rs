//! Structure-aware: the input builds a stream of ST 0601 packets with
//! nested ST 0102, ST 0806, ST 0903, Segment and Amend sets, SDCC-FLPs,
//! other keys and damage, decoded under tight limits.
#![no_main]

#[path = "../../tests/harness/mod.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::stream(data));
