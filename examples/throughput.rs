//! Decoding throughput with run statistics.
//!
//!     cargo run --release --example throughput -- [FILE] [options]
//!
//! FILE              raw KLV to measure (default: about 30 MB of synthetic
//!                   ST 0601 packets with nested sets, see `synthetic`)
//! --runs N          measured runs per chunk size (default 10)
//! --warmup N        unmeasured runs before measuring (default 1)
//! --chunk LIST      comma-separated push sizes in bytes, or `whole`
//!                   (default: whole,188,1316,65536; 1316 bytes is one UDP
//!                   datagram of seven transport packets)
//! --no-raw          decode with `Config::keep_raw` off
//!
//! `whole` hands the buffer to `Decoder::push_with`; the other sizes push
//! chunk by chunk and drain after each push, as a live feed does. The input
//! is read into memory first, so disk speed is not measured. Every run must
//! decode the same packets; the benchmark stops if one does not.

use misb::{checksum, st0601, Config, Decoder, Stats};
use std::time::{Duration, Instant};
use std::{env, fs, process};

struct Options {
    file: Option<String>,
    runs: usize,
    warmup: usize,
    chunks: Vec<Option<usize>>,
    keep_raw: bool,
}

fn usage(msg: &str) -> ! {
    eprintln!("{msg}\nusage: throughput [FILE] [--runs N] [--warmup N] [--chunk whole,188,...] [--no-raw]");
    process::exit(2);
}

fn parse_args() -> Options {
    let mut o = Options {
        file: None,
        runs: 10,
        warmup: 1,
        chunks: vec![None, Some(188), Some(1316), Some(65536)],
        keep_raw: true,
    };
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().unwrap_or_else(|| usage(&format!("{name} needs a value")));
        match a.as_str() {
            "--runs" => o.runs = value("--runs").parse().unwrap_or_else(|_| usage("--runs must be a number")),
            "--warmup" => o.warmup = value("--warmup").parse().unwrap_or_else(|_| usage("--warmup must be a number")),
            "--chunk" => {
                o.chunks = value("--chunk")
                    .split(',')
                    .map(|c| match c.trim() {
                        "whole" => None,
                        n => match n.parse::<usize>() {
                            Ok(n) if n > 0 => Some(n),
                            _ => usage("--chunk sizes must be positive numbers or `whole`"),
                        },
                    })
                    .collect()
            }
            "--no-raw" => o.keep_raw = false,
            "-h" | "--help" => usage("Measures KLV decoding throughput."),
            f if !f.starts_with('-') && o.file.is_none() => o.file = Some(f.to_string()),
            other => usage(&format!("unknown argument {other}")),
        }
    }
    if o.runs == 0 {
        usage("--runs must be at least 1");
    }
    o
}

/// One full pass over `data`: the time, the counters, and the number of
/// items decoded (so that nothing is optimised away).
fn run(data: &[u8], cfg: &Config, chunk: Option<usize>) -> (Duration, Stats, u64) {
    let mut d = Decoder::with_config(cfg.clone()).expect("valid config");
    let mut items = 0u64;
    let start = Instant::now();
    match chunk {
        None => d.push_with(data, |p| items += p.items.len() as u64),
        Some(n) => {
            for c in data.chunks(n) {
                d.push(c);
                while let Some(p) = d.next_packet() {
                    items += p.items.len() as u64;
                }
            }
        }
    }
    d.finish();
    while let Some(p) = d.next_packet() {
        items += p.items.len() as u64;
    }
    (start.elapsed(), d.stats().clone(), items)
}

/// Nearest-rank percentile of sorted values.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn main() {
    let o = parse_args();
    let (data, label) = match &o.file {
        Some(path) => (
            fs::read(path).unwrap_or_else(|e| {
                eprintln!("{path}: {e}");
                process::exit(1)
            }),
            path.clone(),
        ),
        None => (synthetic(), "synthetic ST 0601 packets".to_string()),
    };
    let mut cfg = Config::default();
    cfg.keep_raw = o.keep_raw;
    let mb = data.len() as f64 / 1e6;
    println!("input: {label} ({mb:.1} MB)");
    println!("runs: {} measured + {} warmup per chunk size, keep_raw: {}", o.runs, o.warmup, o.keep_raw);

    let passes = o.warmup.checked_add(o.runs).unwrap_or_else(|| usage("too many runs"));
    let mut reference = None;
    let mut last = Stats::default();
    for &chunk in &o.chunks {
        let name = chunk.map_or("whole buffer (push_with)".to_string(), |n| format!("{n}-byte chunks"));
        let mut times = Vec::with_capacity(o.runs);
        for i in 0..passes {
            let (t, stats, items) = run(&data, &cfg, chunk);
            if stats.dropped != 0 {
                eprintln!("{name}: the queue dropped {} packets. Use a smaller chunk.", stats.dropped);
                process::exit(1);
            }
            match &reference {
                None => reference = Some((stats.clone(), items)),
                Some((expected, count)) if &stats != expected || items != *count => {
                    eprintln!("{name}: run {i} produced different decoder counters or item counts");
                    process::exit(1);
                }
                Some(_) => {}
            }
            if i >= o.warmup {
                times.push(t.as_secs_f64() * 1e3);
            }
            last = stats;
        }
        times.sort_by(f64::total_cmp);
        let mean = times.iter().sum::<f64>() / times.len() as f64;
        let packets = last.packets as f64;
        println!("\n{name}");
        println!("  {:<8} {:>12} {:>12} {:>14}", "", "time (ms)", "MB/s", "packets/s");
        for (label, ms) in [
            ("min", times[0]),
            ("mean", mean),
            ("median", percentile(&times, 50.0)),
            ("p95", percentile(&times, 95.0)),
            ("max", times[times.len() - 1]),
        ] {
            let secs = ms / 1e3;
            println!("  {label:<8} {ms:>12.3} {:>12.1} {:>14.0}", mb / secs, packets / secs);
        }
    }

    println!(
        "\n{} packets, {} bytes skipped, {} checksum errors, {} malformed",
        last.packets, last.bytes_skipped, last.checksum_errors, last.malformed
    );
}

// ---------------------------------------------------------------- synthetic input

/// One local set item: BER-OID tag, BER length, value.
fn item(out: &mut Vec<u8>, tag: u64, value: &[u8]) {
    let mut oid = vec![(tag & 0x7F) as u8];
    let mut rest = tag >> 7;
    while rest > 0 {
        oid.push(0x80 | (rest & 0x7F) as u8);
        rest >>= 7;
    }
    oid.reverse();
    out.extend(oid);
    let n = value.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(value);
}

/// A packet like a full-motion video feed sends every frame: time stamp,
/// platform and sensor attitude and position, frame corners, and every
/// tenth packet the constant items, a security set and a VMTI set with a
/// few targets. Values follow the ST 0601.19 examples.
fn packet(i: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);
    item(&mut body, 2, &(1_224_807_209_913_000 + i * 33_367).to_be_bytes());
    for (tag, value) in [
        (5u64, &[0x71, 0xC2][..]),
        (6, &[0xFD, 0x3D]),
        (7, &[0x08, 0xB8]),
        (13, &[0x55, 0x95, 0xB6, 0x6D]),
        (14, &[0x5B, 0x53, 0x60, 0xC4]),
        (15, &[0xC2, 0x21]),
        (16, &[0xCD, 0x9C]),
        (17, &[0xD9, 0x17]),
        (18, &[0x72, 0x4A, 0x0A, 0x20]),
        (19, &[0x87, 0xF8, 0x4B, 0x86]),
        (20, &[0x7D, 0xC5, 0x5E, 0xCE]),
        (21, &[0x03, 0x83, 0x09, 0x26]),
        (22, &[0x12, 0x81]),
        (23, &[0xF1, 0x01, 0xA2, 0x29]),
        (24, &[0x14, 0xBC, 0x08, 0x2B]),
        (25, &[0x34, 0xF3]),
        (26, &[0x17, 0x50]),
        (27, &[0x06, 0x3F]),
        (28, &[0xF9, 0xC1]),
        (29, &[0x17, 0x50]),
        (30, &[0xED, 0x1F]),
        (31, &[0xF7, 0x32]),
        (32, &[0x01, 0xD0]),
        (33, &[0xEB, 0x3F]),
        (47, &[0x31]),
        (56, &[0x8C]),
        (75, &[0xC2, 0x21]),
        (104, &[0x2F, 0x92, 0x1E]),
        (112, &[0x1F, 0x40]),
        (117, &[0x3E, 0x90]),
    ] {
        item(&mut body, tag, value);
    }
    if i % 10 == 0 {
        item(&mut body, 3, b"MISSION01");
        item(&mut body, 10, b"MQ1-B");
        item(&mut body, 11, b"EO Nose");
        item(&mut body, 12, b"Geodetic WGS84");
        let mut security = Vec::new();
        for (tag, value) in [(1u64, &b"\x01"[..]), (2, b"\x07"), (3, b"//USA"), (12, b"\x07"), (13, b"\0U\0S\0A"), (22, b"\0\x0C")] {
            item(&mut security, tag, value);
        }
        item(&mut body, 48, &security);
        let mut vmti = Vec::new();
        item(&mut vmti, 4, &[6]);
        item(&mut vmti, 5, &[3]);
        let mut series = Vec::new();
        for id in 1..=3u8 {
            let mut target = vec![id];
            item(&mut target, 1, &[0x06, 0x40, id]);
            item(&mut target, 5, &[80]);
            item(&mut target, 10, &[0x3A, 0x66, 0x67]);
            item(&mut target, 11, &[0x3E, 0x66, 0x67]);
            series.push(target.len() as u8);
            series.extend(target);
        }
        item(&mut vmti, 101, &series);
        item(&mut body, 74, &vmti);
    }
    item(&mut body, 65, &[19]);
    let mut out = st0601::KEY.to_vec();
    let len = body.len() + 4;
    if len < 0x80 {
        out.push(len as u8);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend(body);
    out.extend([1, 2]);
    let sum = checksum::st0601_checksum(&out);
    out.extend(sum.to_be_bytes());
    out
}

/// About 30 MB of packets.
fn synthetic() -> Vec<u8> {
    let mut data = Vec::with_capacity(32_000_000);
    let mut i = 0;
    while data.len() < 30_000_000 {
        data.extend(packet(i));
        i += 1;
    }
    data
}
