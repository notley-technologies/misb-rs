//! The stream decoder: results that do not depend on how the input is
//! split, `finish` and `reset`, independent decoders, and the counters.
#![forbid(unsafe_code)]
mod common;

use common::*;
use misb::{Config, Decoder, Packet, Received, Stats};

/// Push `stream` in chunks of the sizes `next` gives, draining after every
/// push, then finish and drain.
fn run(stream: &[u8], cfg: &Config, mut next: impl FnMut() -> usize) -> (Vec<Received>, Stats) {
    let mut d = Decoder::with_config(cfg.clone()).unwrap();
    let mut out = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        let n = next().clamp(1, rest.len());
        d.push(&rest[..n]);
        rest = &rest[n..];
        out.extend(std::iter::from_fn(|| d.next_received()));
        check_counters(&d, &out);
    }
    d.finish();
    out.extend(std::iter::from_fn(|| d.next_received()));
    let stats = d.stats().clone();
    assert_eq!(stats.bytes, stream.len() as u64);
    assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped, "every byte accounted for after finish");
    (out, stats)
}

/// The counters that describe the packets taken so far.
fn check_counters(d: &Decoder, taken: &[Received]) {
    let s = d.stats();
    assert_eq!(s.packets, taken.len() as u64);
    assert_eq!(s.packet_bytes, taken.iter().map(|r| r.bytes.len() as u64).sum::<u64>());
    assert_eq!(s.malformed, taken.iter().filter(|r| r.packet.error.is_some()).count() as u64);
    assert!(s.packet_bytes + s.bytes_skipped <= s.bytes);
    for r in taken {
        assert_eq!(&r.bytes[..4], &KEY[..4]);
    }
}

fn reference(stream: &[u8], cfg: &Config) -> (Vec<Packet>, Stats) {
    misb::decode_all_with(stream, cfg).unwrap()
}

fn packets(rs: &[Received]) -> Vec<Packet> {
    rs.iter().map(|r| r.packet.clone()).collect()
}

/// A config under which some of the sample packets are oversized.
fn tight() -> Config {
    let mut c = Config::default();
    c.max_packet_bytes = 400;
    c.max_skip_bytes = 2000;
    c
}

#[test]
fn every_split_point_gives_the_same_result() {
    let stream = mixed_stream();
    for cfg in [Config::default(), tight()] {
        let (want, want_stats) = reference(&stream, &cfg);
        assert!(want.len() >= 8, "{} packets", want.len());
        let (whole, _) = run(&stream, &cfg, || usize::MAX);
        for at in 0..=stream.len() {
            let mut d = Decoder::with_config(cfg.clone()).unwrap();
            let mut got: Vec<Received> = Vec::new();
            for part in [&stream[..at], &stream[at..]] {
                d.push(part);
                got.extend(std::iter::from_fn(|| d.next_received()));
            }
            d.finish();
            got.extend(std::iter::from_fn(|| d.next_received()));
            assert_eq!(got, whole, "split at {at}");
            assert_eq!(d.stats(), &want_stats, "split at {at}");
        }
        assert_eq!(packets(&whole), want);
    }
}

#[test]
fn every_pair_of_split_points_gives_the_same_result() {
    let mut stream = vec![0x06, 0x0E];
    stream.extend(sample(0));
    stream.extend(other_key(b"skip me"));
    // A false key with a reserved category byte: damage.
    stream.extend([0x06, 0x0E, 0x2B, 0x34, 0x99]);
    stream.extend(sample(1));
    let cfg = Config::default();
    let (whole, stats) = run(&stream, &cfg, || usize::MAX);
    assert_eq!(whole.len(), 2);
    for a in 0..=stream.len() {
        for b in a..=stream.len() {
            let mut d = Decoder::new();
            let mut got = Vec::new();
            for part in [&stream[..a], &stream[a..b], &stream[b..]] {
                d.push(part);
                got.extend(std::iter::from_fn(|| d.next_received()));
            }
            d.finish();
            got.extend(std::iter::from_fn(|| d.next_received()));
            assert_eq!(got, whole, "splits at {a} and {b}");
            assert_eq!(d.stats(), &stats);
        }
    }
}

#[test]
fn random_chunkings_and_single_bytes() {
    let mut stream = Vec::new();
    for i in 0..20 {
        stream.extend(mixed_stream());
        stream.extend(rich(i));
    }
    for cfg in [Config::default(), tight()] {
        let (want, want_stats) = reference(&stream, &cfg);
        let (single, stats) = run(&stream, &cfg, || 1);
        assert_eq!(packets(&single), want);
        assert_eq!(stats, want_stats);
        for seed in 1..=8u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let (got, stats) = run(&stream, &cfg, || if rng.below(5) == 0 { 1 + rng.below(4) } else { 1 + rng.below(3000) });
            assert_eq!(got, single, "seed {seed}");
            assert_eq!(stats, want_stats, "seed {seed}");
        }
    }
}

#[test]
fn offsets_and_bytes_match_the_input() {
    let stream = mixed_stream();
    let (got, _) = run(&stream, &Config::default(), || 7);
    let mut last = 0u64;
    for r in &got {
        let at = r.offset as usize;
        assert!(r.offset >= last, "offsets go forward");
        assert_eq!(&stream[at..at + r.bytes.len()], &r.bytes[..]);
        let (p, used) = misb::decode_prefix(&r.bytes, &Config::default()).unwrap();
        assert_eq!((p, used), (r.packet.clone(), r.bytes.len()), "the decoder decodes like decode_prefix");
        last = r.offset + r.bytes.len() as u64;
    }
}

#[test]
fn finish_semantics() {
    let a = sample(0);
    let b = rich(1);

    // A complete packet stays available after finish.
    let mut d = Decoder::new();
    d.push(&a);
    d.finish();
    assert_eq!(d.next_packet(), Some(misb::decode(&a).unwrap()));
    assert_eq!(d.stats().truncated_at_finish, 0);

    // A partial packet is dropped and counted, once.
    let mut d = Decoder::new();
    d.push(&b[..b.len() - 1]);
    assert!(d.next_packet().is_none());
    d.finish();
    d.finish();
    let s = d.stats().clone();
    assert_eq!(s.truncated_at_finish, 1);
    assert_eq!(s.bytes_skipped, (b.len() - 1) as u64);
    assert_eq!(s.bytes, s.bytes_skipped);
    assert!(d.next_packet().is_none());

    // A partial key is counted too: its key could not be checked.
    let mut d = Decoder::new();
    d.push(&KEY[..10]);
    d.finish();
    assert_eq!(d.stats().truncated_at_finish, 1);
    assert_eq!(d.stats().bytes_skipped, 10);

    // Garbage that is not a key is not a truncated packet.
    let mut d = Decoder::new();
    d.push(&[0x55; 40]);
    d.finish();
    assert_eq!(d.stats().truncated_at_finish, 0);
    assert_eq!(d.stats().bytes_skipped, 40);

    // The decoder can be fed again: the packet split by finish is lost,
    // the next one is found.
    let mut d = Decoder::new();
    d.push(&b[..50]);
    d.finish();
    d.push(&b[50..]);
    d.push(&a);
    d.finish();
    let got: Vec<Packet> = d.packets().collect();
    assert_eq!(got, [misb::decode(&a).unwrap()]);
    let s = d.stats();
    assert_eq!(s.packets, 1);
    assert_eq!(s.bytes, s.packet_bytes + s.bytes_skipped);
    assert_eq!(s.truncated_at_finish, 1);
}

#[test]
fn reset_forgets_everything_but_the_config() {
    let mut d = Decoder::with_config(tight()).unwrap();
    d.push(&sample(0));
    d.push(&sample(1)[..30]);
    assert!(d.stats().bytes > 0);
    d.reset();
    assert_eq!(d.stats(), &Stats::default());
    assert_eq!(d.config(), &tight());
    assert!(d.next_packet().is_none(), "queued packets are gone");
    // The partial packet is gone too: its tail is garbage now.
    d.push(&sample(1)[30..]);
    d.push(&sample(2));
    let r = d.next_received().unwrap();
    assert_eq!(r.packet, misb::decode(&sample(2)).unwrap());
    assert_eq!(r.offset, (sample(1).len() - 30) as u64, "offsets restart at the reset");
    assert!(d.next_received().is_none());
}

#[test]
fn decoders_are_independent() {
    // One decoder per PID, fed interleaved on one thread, gives what each
    // gives on its own.
    let s1 = mixed_stream();
    let mut s2 = Vec::new();
    for i in 0..10 {
        s2.extend(rich(i));
        s2.extend([0xFF; 3]);
    }
    let mut cfg2 = tight();
    cfg2.max_total_items = 30;
    cfg2.max_depth = 1;
    let (alone1, stats1) = run(&s1, &Config::default(), || 97);
    let (alone2, stats2) = run(&s2, &cfg2, || 61);
    let mut d1 = Decoder::new();
    let mut d2 = Decoder::with_config(cfg2.clone()).unwrap();
    let (mut got1, mut got2) = (Vec::new(), Vec::new());
    let mut rest1: &[u8] = &s1;
    let mut rest2: &[u8] = &s2;
    while !rest1.is_empty() || !rest2.is_empty() {
        let n = 97.min(rest1.len());
        d1.push(&rest1[..n]);
        rest1 = &rest1[n..];
        let n = 61.min(rest2.len());
        d2.push(&rest2[..n]);
        rest2 = &rest2[n..];
        // Take alternately, so that decoding interleaves too.
        loop {
            let a = d1.next_received();
            let b = d2.next_received();
            if a.is_none() && b.is_none() {
                break;
            }
            got1.extend(a);
            got2.extend(b);
        }
    }
    d1.finish();
    d2.finish();
    got1.extend(std::iter::from_fn(|| d1.next_received()));
    got2.extend(std::iter::from_fn(|| d2.next_received()));
    assert_eq!((got1, d1.stats().clone()), (alone1.clone(), stats1));
    assert_eq!((got2, d2.stats().clone()), (alone2.clone(), stats2));

    // And on separate threads.
    let handles: Vec<_> = [(s1, Config::default()), (s2, cfg2)]
        .into_iter()
        .map(|(s, c)| std::thread::spawn(move || run(&s, &c, || 33).0))
        .collect();
    let results: Vec<Vec<Received>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results, [alone1, alone2]);
}

#[test]
fn counters() {
    let mut s = Vec::new();
    s.extend([0x01, 0x02, 0x03]); // garbage
    s.extend(sample(0));
    s.extend(other_key(&[0xAB; 50])); // other key
    s.extend(St0601::new().time(1).item(3, &[b'x'; 500]).build()); // oversized with tight()
    let mut bad = sample(1);
    corrupt_checksum(&mut bad);
    s.extend(&bad);
    s.extend(St0601::new().time(2).set(100, Set::new().raw(&[3, 9])).build()); // nested error
    // A tag that overflows: the item walk stops, and the checksum item it
    // hides cannot be trusted (Missing).
    s.extend(St0601::new().time(3).raw(&[0xFF; 10]).build());
    s.extend(St0601::new().time(4).no_checksum().build());
    s.extend(KEY);
    s.extend([0xFF, 0, 0]); // reserved length: damage
    s.extend(sample(2));
    let (got, st) = run(&s, &tight(), || 13);
    assert_eq!(st.packets, got.len() as u64);
    assert_eq!(got.len(), 6);
    assert_eq!(st.skipped_keys, 1);
    assert_eq!(st.oversized, 1);
    assert_eq!(st.checksum_errors, 1);
    assert_eq!(st.checksum_missing, 2);
    assert_eq!(st.nested_errors, 1);
    assert_eq!(st.malformed, 1);
    assert_eq!(st.bad_lengths, 1);
    assert!(st.resyncs >= 1);
    assert_eq!(st.dropped, 0);
    assert_eq!(st.truncated_at_finish, 0);
    assert_eq!(st.bytes, s.len() as u64);
    assert_eq!(st.bytes, st.packet_bytes + st.bytes_skipped);
}

#[test]
fn oversized_and_unskippable_lengths() {
    let big = St0601::new().time(1).item(3, &vec![b'x'; 5000]).build();
    let after = sample(9);
    let mut s = big.clone();
    s.extend(&after);
    // Over max_packet_bytes, but short enough to skip by its length.
    let mut cfg = Config::default();
    cfg.max_packet_bytes = 1000;
    cfg.max_skip_bytes = 10_000;
    let (got, st) = run(&s, &cfg, || 100);
    assert_eq!(packets(&got), [misb::decode(&after).unwrap()]);
    assert_eq!((st.oversized, st.bad_lengths), (1, 0));
    assert_eq!(st.bytes_skipped, big.len() as u64);
    // Longer than max_skip_bytes too: damage, scanned through.
    cfg.max_skip_bytes = 1000;
    let (got, st) = run(&s, &cfg, || 100);
    assert_eq!(packets(&got), [misb::decode(&after).unwrap()]);
    assert_eq!((st.oversized, st.bad_lengths), (0, 1));
    // decode_with rejects it as soon as the length is read.
    assert!(matches!(misb::decode_with(&big[..20], &cfg), Err(misb::Error::TooLarge { .. })));
}

#[test]
fn packets_inside_another_key_are_skipped_with_it() {
    let inner = sample(0);
    let mut s = other_key(&inner);
    s.extend(sample(1));
    let (got, st) = run(&s, &Config::default(), || 5);
    assert_eq!(packets(&got), [misb::decode(&sample(1)).unwrap()]);
    assert_eq!(st.skipped_keys, 1);
    assert_eq!(st.bytes_skipped, other_key(&inner).len() as u64);
}

#[test]
fn one_large_push_can_drop_but_push_with_does_not() {
    let stream = sample(0).repeat(2000);
    let mut cfg = Config::default();
    cfg.max_buffer_bytes = 8 * 1024;
    cfg.max_packet_bytes = 1024;
    let mut d = Decoder::with_config(cfg.clone()).unwrap();
    d.push(&stream);
    let taken = d.packets().count() as u64;
    let s = d.stats();
    assert!(s.dropped > 0);
    assert_eq!(taken + s.dropped, 2000);
    assert_eq!(s.bytes, s.packet_bytes + s.bytes_skipped, "dropped packets count as skipped bytes");
    // Slices of a safe size, drained after each, lose nothing.
    let safe = (cfg.max_buffer_bytes - cfg.max_packet_bytes - 1024) / 8;
    let (got, st) = run(&stream, &cfg, || safe);
    assert_eq!((got.len(), st.dropped), (2000, 0));
    let mut d = Decoder::with_config(cfg).unwrap();
    let mut n = 0;
    d.push_with(&stream, |_| n += 1);
    assert_eq!((n, d.stats().dropped), (2000, 0));
}

#[test]
fn version_byte_and_long_lengths_are_accepted_in_a_stream() {
    let mut s = Vec::new();
    for v in [1u8, 2, 0x0A, 0xFF] {
        s.extend(St0601::new().time(u64::from(v)).version_byte(v).build());
    }
    for w in [1, 2, 4, 8, 16] {
        s.extend(St0601::new().time(w as u64).long_length(w).build());
    }
    let (got, st) = run(&s, &Config::default(), || 3);
    assert_eq!(got.len(), 9);
    assert!(got.iter().all(|r| r.packet.is_ok()));
    assert_eq!(st.bytes_skipped, 0);
}

#[path = "../examples/common/mod.rs"]
mod example_reader;

#[test]
fn example_reader_stops_at_each_cell_and_reports_incomplete_input() {
    use std::io::Cursor;

    let cells = [au_cell(4, 1, 3, &[]), au_cell(7, 2, 3, &[0x55; 257])].concat();
    let mut buf = Vec::new();
    for end in 0..=cells.len() {
        let mut input = Cursor::new(&cells[..end]);
        for expected in misb::au_cells(&cells[..end]) {
            let result = example_reader::read_cell(&mut input, &mut buf);
            match expected {
                Ok(cell) => assert_eq!(result.unwrap(), Some(cell)),
                Err(error) => {
                    let actual = result.unwrap_err();
                    assert_eq!(actual.get_ref().unwrap().downcast_ref::<misb::Error>(), Some(&error));
                }
            }
        }
        assert_eq!(example_reader::read_cell(&mut input, &mut buf).unwrap(), None);
    }
}
