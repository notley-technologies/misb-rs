//! Print every ST 0601 packet of a KLV stream with its items as a tree,
//! then the decoder's counters.
//!
//!     cargo run --release --example klvdump -- packets.klv
//!     cargo run --release --example klvdump -- cells.bin --sync
//!     producer | cargo run --release --example klvdump
//!
//! FILE      raw KLV, such as a `.klv` file or the payload of an asynchronous
//!           KLV elementary stream (MISB ST 1402); `-` or nothing reads
//!           standard input, which is decoded as it arrives
//! --sync    the input is metadata access unit cells (ISO/IEC 13818-1
//!           section 2.12.4), as carried by synchronous KLV (stream type
//!           0x15); each metadata service gets its own decoder
//! --quiet   print only the counters
#![forbid(unsafe_code)]

mod common;

use misb::{Decoder, Item, Received, Stats, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::process;

struct Options {
    file: Option<String>,
    sync: bool,
    quiet: bool,
}

fn usage(msg: &str) -> ! {
    eprintln!("{msg}\nusage: klvdump [FILE|-] [--sync] [--quiet]");
    process::exit(2);
}

fn parse_args() -> Options {
    let mut o = Options { file: None, sync: false, quiet: false };
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--sync" => o.sync = true,
            "--quiet" | "-q" => o.quiet = true,
            "-h" | "--help" => usage("Prints the MISB ST 0601 packets of a KLV stream."),
            "-" if o.file.is_none() => o.file = Some(a),
            f if !f.starts_with('-') && o.file.is_none() => o.file = Some(a),
            other => usage(&format!("unknown argument {other}")),
        }
    }
    o
}

fn main() {
    let o = parse_args();
    let mut input: Box<dyn Read> = match o.file.as_deref() {
        None | Some("-") => Box::new(io::stdin().lock()),
        Some(path) => match File::open(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("{path}: {e}");
                process::exit(1);
            }
        },
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let result = if o.sync { dump_cells(&mut input, &mut out, o.quiet) } else { dump_stream(&mut input, &mut out, o.quiet) };
    match result.and_then(|()| out.flush()) {
        Ok(()) => {}
        // The reader went away (`klvdump file | head`): not an error.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
        Err(e) => {
            eprintln!("klvdump: {e}");
            process::exit(1);
        }
    }
}

/// Raw KLV, pushed as it is read. Chunks of 64 KiB, drained after each,
/// never fill the default queue.
fn dump_stream(input: &mut dyn Read, out: &mut dyn Write, quiet: bool) -> io::Result<()> {
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        decoder.push(&buf[..n]);
        drain(&mut decoder, out, quiet, &mut count)?;
    }
    decoder.finish();
    drain(&mut decoder, out, quiet, &mut count)?;
    writeln!(out)?;
    print_stats(out, decoder.stats())
}

/// Metadata access unit cells: the cells of each service, fragments
/// included, are pushed in order into that service's decoder, which joins
/// fragmented access units.
fn dump_cells(input: &mut dyn Read, out: &mut dyn Write, quiet: bool) -> io::Result<()> {
    let mut input = io::BufReader::new(input);
    let mut data = Vec::new();
    let mut decoders: BTreeMap<u8, Decoder> = BTreeMap::new();
    let mut count = 0u64;
    let mut cells = 0u64;
    while let Some(cell) = common::read_cell(&mut input, &mut data)? {
        cells += 1;
        if !quiet {
            const FRAGMENTS: [&str; 4] = ["middle fragment", "last fragment", "first fragment", "complete"];
            writeln!(
                out,
                "cell {cells}: service {}, sequence {}, {}, {} bytes{}{}",
                cell.service_id,
                cell.sequence_number,
                FRAGMENTS[usize::from(cell.fragment & 3)],
                cell.data.len(),
                if cell.random_access { ", random access" } else { "" },
                if cell.decoder_config { ", decoder config" } else { "" },
            )?;
        }
        let decoder = decoders.entry(cell.service_id).or_default();
        decoder.push(cell.data);
        drain(decoder, out, quiet, &mut count)?;
    }
    writeln!(out, "\n{cells} access unit cells")?;
    for (service, decoder) in &mut decoders {
        decoder.finish();
        drain(decoder, out, quiet, &mut count)?;
        writeln!(out, "\nservice {service}:")?;
        print_stats(out, decoder.stats())?;
    }
    Ok(())
}

fn drain(decoder: &mut Decoder, out: &mut dyn Write, quiet: bool, count: &mut u64) -> io::Result<()> {
    while let Some(r) = decoder.next_received() {
        *count += 1;
        if !quiet {
            print_packet(out, *count, &r)?;
        }
    }
    Ok(())
}

fn print_packet(out: &mut dyn Write, n: u64, r: &Received) -> io::Result<()> {
    let p = &r.packet;
    let checksum = match p.checksum {
        misb::Checksum::Valid => "checksum ok".to_string(),
        misb::Checksum::Mismatch { expected, computed } => {
            format!("checksum MISMATCH (carried {expected:04X}, computed {computed:04X})")
        }
        misb::Checksum::Missing => "checksum MISSING".to_string(),
        _ => "checksum not checked".to_string(),
    };
    writeln!(
        out,
        "\npacket {n} at byte {} ({} bytes): {} {}, {checksum}",
        r.offset,
        r.bytes.len(),
        p.standard.name(),
        p.standard.title(),
    )?;
    for item in &p.items {
        print_item(out, item, 1)?;
    }
    if let Some(e) = &p.error {
        writeln!(out, "    error: {e}")?;
    }
    Ok(())
}

fn print_item(out: &mut dyn Write, item: &Item, depth: usize) -> io::Result<()> {
    let pad = "    ".repeat(depth);
    match &item.value {
        Value::Set(set) => {
            writeln!(out, "{pad}{:>3} {}: {} {}", item.tag, item.name, set.standard.name(), set.standard.title())?;
            for i in &set.items {
                print_item(out, i, depth + 1)?;
            }
            if let Some(e) = &set.error {
                writeln!(out, "{pad}    error: {e}")?;
            }
            Ok(())
        }
        v @ (Value::List(_) | Value::Struct(_)) if !is_empty(v) => {
            let units = if item.units.is_empty() { String::new() } else { format!(" ({})", item.units) };
            writeln!(out, "{pad}{:>3} {}{units}:", item.tag, item.name)?;
            print_children(out, v, depth + 1)
        }
        _ => writeln!(out, "{pad}{item}"),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::List(l) => l.is_empty(),
        Value::Struct(f) => f.is_empty(),
        _ => false,
    }
}

/// The elements of a list or the fields of a pack, one per line.
fn print_children(out: &mut dyn Write, v: &Value, depth: usize) -> io::Result<()> {
    match v {
        Value::List(l) => {
            for (i, e) in l.iter().enumerate() {
                print_named(out, &format!("[{i}]"), e, depth)?;
            }
        }
        Value::Struct(fields) => {
            for f in fields {
                print_named(out, f.name, &f.value, depth)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn print_named(out: &mut dyn Write, name: &str, v: &Value, depth: usize) -> io::Result<()> {
    let pad = "    ".repeat(depth);
    match v {
        Value::List(_) | Value::Struct(_) if !is_empty(v) => {
            writeln!(out, "{pad}{name}:")?;
            print_children(out, v, depth + 1)
        }
        Value::Set(set) => {
            writeln!(out, "{pad}{name}: {} {}", set.standard.name(), set.standard.title())?;
            for i in &set.items {
                print_item(out, i, depth + 1)?;
            }
            Ok(())
        }
        _ => writeln!(out, "{pad}{name}: {v}"),
    }
}

fn print_stats(out: &mut dyn Write, s: &Stats) -> io::Result<()> {
    let rows = [
        ("packets", s.packets),
        ("bytes", s.bytes),
        ("bytes in packets", s.packet_bytes),
        ("bytes skipped", s.bytes_skipped),
        ("resyncs", s.resyncs),
        ("other keys skipped", s.skipped_keys),
        ("oversized packets", s.oversized),
        ("malformed lengths", s.bad_lengths),
        ("checksum mismatches", s.checksum_errors),
        ("checksums missing", s.checksum_missing),
        ("malformed packets", s.malformed),
        ("nested set errors", s.nested_errors),
        ("truncated at end", s.truncated_at_finish),
        ("dropped (queue full)", s.dropped),
    ];
    for (name, n) in rows {
        writeln!(out, "{name:>22}: {n}")?;
    }
    Ok(())
}
