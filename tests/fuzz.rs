//! Fuzzing on the stable toolchain. Replays the saved inputs in
//! `tests/fuzz_regressions/<target>/`, then runs each harness on randomly
//! mutated inputs. Coverage-guided fuzzing of the same harnesses is in
//! `fuzz/` (cargo-fuzz).
//!
//! Longer runs:
//!
//!     MISB_FUZZ_ITERATIONS=200000 cargo test --release --test fuzz
//!
//! `MISB_FUZZ_SEED=<n>` picks a different random sequence. A failing input
//! is saved under `target/fuzz-failures/`; once fixed, copy it into
//! `tests/fuzz_regressions/<target>/` so it is replayed from then on.
#![cfg_attr(not(feature = "capi"), forbid(unsafe_code))]
mod harness;

use harness::common::*;
use misb::{Config, Packet, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

fn iterations(default: usize) -> usize {
    std::env::var("MISB_FUZZ_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("MISB_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5EED_0601) | 1
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Saved inputs for `target`, in name order.
fn regressions(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = root().join("tests/fuzz_regressions").join(target);
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot open {}: {e}", dir.display()));
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("cannot read entry in {}: {e}", dir.display()));
        if entry.file_name() != ".gitkeep" {
            let path = entry.path();
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            files.push((path, bytes));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn random_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.next() as u8).collect()
}

/// A few byte-level edits, the kind a mutation fuzzer makes.
fn mutate(rng: &mut Rng, v: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(8) {
        let len = v.len();
        match rng.below(9) {
            0 if len > 0 => v[rng.below(len)] ^= 1 << rng.below(8),
            1 if len > 0 => {
                v[rng.below(len)] = [0x00, 0xFF, 0x06, 0x0E, 0x2B, 0x34, 0x80, 0x7F, 0x81, 0x01, 0x02][rng.below(11)]
            }
            2 => {
                let at = rng.below(len + 1);
                let n = 1 + rng.below(16);
                let junk = random_bytes(rng, n);
                v.splice(at..at, junk);
            }
            3 if len > 0 => {
                let at = rng.below(len);
                let n = 1 + rng.below((len - at).min(400));
                v.drain(at..at + n);
            }
            4 if len > 1 => {
                let from = rng.below(len);
                let n = 1 + rng.below((len - from).min(400));
                let at = rng.below(len + 1);
                let part = v[from..from + n].to_vec();
                v.splice(at..at, part);
            }
            5 => {
                let n = 1 + rng.below(64);
                let junk = random_bytes(rng, n);
                v.extend(junk);
            }
            6 if len > 0 => v.truncate(rng.below(len)),
            7 => {
                // A key prefix, the start of every KLV packet.
                let at = rng.below(len + 1);
                let n = 4 + rng.below(13);
                v.splice(at..at, KEY[..n].iter().copied());
            }
            _ => {}
        }
    }
}

fn fuzz(target: &str, harness: fn(&[u8]), seeds: Vec<Vec<u8>>, default_iterations: usize) {
    for (path, data) in regressions(target) {
        if catch_unwind(AssertUnwindSafe(|| harness(&data))).is_err() {
            panic!("{target}: saved input {} fails again", path.display());
        }
    }
    let mut rng = Rng(seed() ^ target.len() as u64);
    let mut corpus = seeds;
    for i in 0..iterations(default_iterations) {
        let mut input = if rng.below(8) == 0 {
            let n = rng.below(3000);
            random_bytes(&mut rng, n)
        } else {
            corpus[rng.below(corpus.len())].clone()
        };
        mutate(&mut rng, &mut input);
        if catch_unwind(AssertUnwindSafe(|| harness(&input))).is_err() {
            let dir = root().join("target/fuzz-failures");
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{target}-{i}.bin"));
            std::fs::write(&path, &input).unwrap();
            panic!("{target}: iteration {i} failed; input saved to {}", path.display());
        }
        // Keep some mutants, so edits stack up over the run.
        if i % 8 == 0 && corpus.len() < 512 {
            corpus.push(input);
        }
    }
}

/// Valid streams to mutate: the published packets, packets with every
/// nested standard, damage of every kind, and access unit cells. The first
/// byte is the harness's control byte.
fn decode_seeds() -> Vec<Vec<u8>> {
    let mut many = Vec::new();
    for i in 0..8 {
        many.extend(rich(i));
        many.extend(sample(i));
    }
    let cells = [au_cell(0, 0, 3, &sample(0)), au_cell(0, 1, 2, &rich(1)[..100]), au_cell(0, 2, 1, &rich(1)[100..])].concat();
    let with = |control: u8, body: &[u8]| [&[control][..], body].concat();
    vec![
        with(0x00, &mixed_stream()),
        with(0x00, &[spec_packet_a(), spec_packet_b()].concat()),
        with(0x04, &many),
        with(0x02, &mixed_stream()),
        with(0x18, &mixed_stream()),
        with(0x69, &rich(3)),
        with(0x10, &many),
        with(0x00, &cells),
        with(0x00, &St0601::new().set(100, nest(40, &[100, 101], Set::new().set(74, vmti_set()))).build()),
    ]
}

fn random_seeds(lens: &[usize]) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed());
    lens.iter().map(|&n| random_bytes(&mut rng, n)).collect()
}

#[test]
fn fuzz_decode() {
    fuzz("decode", harness::decode, decode_seeds(), 1500);
}

#[test]
fn fuzz_stream() {
    fuzz("stream", harness::stream, random_seeds(&[64, 256, 1024, 4096]), 1500);
}

#[cfg(feature = "capi")]
#[test]
fn fuzz_capi() {
    fuzz("capi", harness::capi::run, random_seeds(&[64, 512, 2048]), 1000);
}

/// The generator is only useful if what it builds gets past framing and
/// into the set decoders. Check that most inputs give packets, with nested
/// sets of every standard and valid checksums.
#[test]
fn generator_reaches_deep_paths() {
    let mut rng = Rng(seed());
    let runs = 300;
    let (mut with_packets, mut valid, mut nested, mut vmti_targets, mut rvt, mut security, mut segments) =
        (0, 0, 0, 0, 0, 0, 0);
    for _ in 0..runs {
        let n = 200 + rng.below(3000);
        let data = random_bytes(&mut rng, n);
        let s = harness::generate(&mut harness::Input::new(&data));
        let packets = misb::decode_all(&s);
        with_packets += usize::from(!packets.is_empty());
        valid += usize::from(packets.iter().any(|p| p.checksum == misb::Checksum::Valid));
        let sets: Vec<&Packet> = packets.iter().flat_map(|p| p.items.iter()).filter_map(|i| i.value.as_set()).collect();
        nested += usize::from(!sets.is_empty());
        security += usize::from(sets.iter().any(|s| s.standard == misb::Standard::St0102 && !s.items.is_empty()));
        rvt += usize::from(sets.iter().any(|s| s.standard == misb::Standard::St0806 && !s.items.is_empty()));
        segments += usize::from(sets.iter().any(|s| s.standard == misb::Standard::St0601 && !s.items.is_empty()));
        vmti_targets += usize::from(sets.iter().any(|s| {
            s.get(misb::st0903::Tag::VTargetSeries).and_then(Value::as_list).map_or(false, |l| {
                l.iter().any(|t| t.as_fields().map_or(false, |f| f.len() > 1))
            })
        }));
    }
    assert!(with_packets * 10 > runs * 9, "only {with_packets}/{runs} streams gave a packet");
    assert!(valid * 4 > runs * 3, "only {valid}/{runs} gave a packet with a valid checksum");
    assert!(nested * 4 > runs * 3, "only {nested}/{runs} gave a nested set");
    for (name, n) in [("ST 0102", security), ("ST 0806", rvt), ("Segment/Amend", segments), ("VTarget", vmti_targets)] {
        assert!(n * 3 > runs, "only {n}/{runs} gave a {name} set with items");
    }
}

/// The harnesses accept the configs they build and the seeds pass.
#[test]
fn seeds_pass() {
    for s in decode_seeds() {
        harness::decode(&s);
    }
    for s in random_seeds(&[0, 1, 64, 4096]) {
        harness::stream(&s);
        #[cfg(feature = "capi")]
        harness::capi::run(&s);
    }
    harness::check_stream(&mixed_stream(), &Config::default(), 1);
}
