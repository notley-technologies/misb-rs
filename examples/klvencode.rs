//! Encode NDJSON authoring records (or lines of the decoder's JSON) into ST
//! 0601 packets, one record per line. Needs the `json` feature.
//!
//!     cargo run --features json --example klvencode -- records.ndjson > out.klv
//!     cargo run --features json --example json -- in.klv | cargo run --features json --example klvencode > out.klv
//!     cargo run --features json --example klvencode -- --schema
//!     cargo run --features json --example klvencode -- --control-schema
//!
//! FILE       NDJSON; `-` or nothing reads standard input
//! --schema   print the JSON Schema of the authoring format and exit
//! --control-schema
//!            print the JSON Schema of the live control commands and exit
//! --clamp    clamp out-of-range values instead of rejecting them
//!
//! The format is described in the documentation of `misb::json`. Warnings
//! and errors go to standard error with their line number; a line that
//! fails stops the run with exit status 1.
#![forbid(unsafe_code)]

use misb::encode::{EncodeOptions, Policy};
use misb::LeapSeconds;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process;

fn main() {
    let mut file = None;
    let mut opts = EncodeOptions::default();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--schema" => {
                println!("{}", serde_json::to_string_pretty(&misb::json::schema()).expect("schema serializes"));
                return;
            }
            "--control-schema" => {
                println!("{}", serde_json::to_string_pretty(&misb::json::control_schema()).expect("schema serializes"));
                return;
            }
            "--clamp" => opts.policy = Policy::Clamp,
            "-" => file = None,
            f if !f.starts_with("--") && file.is_none() => file = Some(f.to_string()),
            other => {
                eprintln!("unknown argument {other}\nusage: klvencode [FILE|-] [--schema|--control-schema] [--clamp]");
                process::exit(2);
            }
        }
    }
    let input: Box<dyn BufRead> = match &file {
        Some(f) => Box::new(BufReader::new(File::open(f).unwrap_or_else(|e| {
            eprintln!("{f}: {e}");
            process::exit(1)
        }))),
        None => Box::new(BufReader::new(io::stdin().lock())),
    };
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut count = 0u64;
    for (n, line) in input.lines().enumerate() {
        let line = line.unwrap_or_else(|e| {
            eprintln!("read failed: {e}");
            process::exit(1)
        });
        if line.trim().is_empty() {
            continue;
        }
        match misb::json::encode_line(&line, &opts, LeapSeconds::builtin()) {
            Ok(packet) => {
                count += 1;
                if let Err(e) = out.write_all(&packet) {
                    eprintln!("write failed: {e}");
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("line {}: {e}", n + 1);
                process::exit(1);
            }
        }
    }
    let _ = out.flush();
    eprintln!("{count} packets");
}
