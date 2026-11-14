//! Decode a KLV stream to JSON: one object per packet per line (JSON Lines),
//! `{"offset": .., "packet": {..}}`, then the decoder's counters as one
//! object on standard error. Needs the `serde` feature.
//!
//!     cargo run --release --features serde --example json -- packets.klv
//!     cargo run --release --features serde --example json -- cells.bin --sync
//!     producer | cargo run --release --features serde --example json
//!
//! FILE      raw KLV; `-` or nothing reads standard input as it arrives
//! --sync    the input is metadata access unit cells (ISO/IEC 13818-1
//!           section 2.12.4); each line also carries the cell's service id
//! --bytes   add each packet's bytes as received, in hex
//!
//! The JSON shape is described in the documentation of `misb::Value`.
#![forbid(unsafe_code)]

mod common;

fn main() {
    imp::main();
}

mod imp {
    use misb::{Decoder, Packet, Received};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{self, BufWriter, Read, Write};
    use std::process;

    struct Options {
        file: Option<String>,
        sync: bool,
        bytes: bool,
    }

    fn usage(msg: &str) -> ! {
        eprintln!("{msg}\nusage: json [FILE|-] [--sync] [--bytes]");
        process::exit(2);
    }

    fn parse_args() -> Options {
        let mut o = Options { file: None, sync: false, bytes: false };
        for a in std::env::args().skip(1) {
            match a.as_str() {
                "--sync" => o.sync = true,
                "--bytes" => o.bytes = true,
                "-h" | "--help" => usage("Decodes MISB ST 0601 packets to JSON Lines."),
                "-" if o.file.is_none() => o.file = Some(a),
                f if !f.starts_with('-') && o.file.is_none() => o.file = Some(a),
                other => usage(&format!("unknown argument {other}")),
            }
        }
        o
    }

    pub fn main() {
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
        let result = run(&mut input, &mut out, &o).and_then(|()| out.flush());
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
            Err(e) => {
                if let Some(error) = e.get_ref().and_then(|e| e.downcast_ref::<misb::Error>()) {
                    eprintln!("{}", to_json(&Failure { error }));
                } else {
                    eprintln!("json: {e}");
                }
                process::exit(1);
            }
        }
    }

    fn run(input: &mut dyn Read, out: &mut dyn Write, o: &Options) -> io::Result<()> {
        if !o.sync {
            let mut decoder = Decoder::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match input.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                decoder.push(&buf[..n]);
                drain(&mut decoder, out, o, None)?;
            }
            decoder.finish();
            drain(&mut decoder, out, o, None)?;
            eprintln!("{}", to_json(&Summary { stats: decoder.stats() }));
            return Ok(());
        }
        let mut input = io::BufReader::new(input);
        let mut data = Vec::new();
        let mut decoders: BTreeMap<u8, Decoder> = BTreeMap::new();
        while let Some(cell) = super::common::read_cell(&mut input, &mut data)? {
            let decoder = decoders.entry(cell.service_id).or_default();
            decoder.push(cell.data);
            drain(decoder, out, o, Some(cell.service_id))?;
        }
        let mut stats = BTreeMap::new();
        for (service, decoder) in &mut decoders {
            decoder.finish();
            drain(decoder, out, o, Some(*service))?;
            stats.insert(service.to_string(), decoder.stats().clone());
        }
        eprintln!("{}", to_json(&Summary { stats }));
        Ok(())
    }

    fn drain(decoder: &mut Decoder, out: &mut dyn Write, o: &Options, service: Option<u8>) -> io::Result<()> {
        while let Some(r) = decoder.next_received() {
            writeln!(out, "{}", line(&r, o.bytes, service))?;
        }
        Ok(())
    }

    /// One output line. Serialized directly, not through
    /// `serde_json::Value`, so that fields keep the library's order.
    #[derive(Serialize)]
    struct Line<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        service: Option<u8>,
        offset: u64,
        packet: &'a Packet,
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes: Option<String>,
    }

    #[derive(Serialize)]
    struct Summary<T: Serialize> {
        stats: T,
    }

    #[derive(Serialize)]
    struct Failure<'a> {
        error: &'a misb::Error,
    }

    fn to_json<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).expect("the decoded types always serialize")
    }

    fn line(r: &Received, bytes: bool, service: Option<u8>) -> String {
        let bytes = bytes.then(|| r.bytes.iter().map(|b| format!("{b:02x}")).collect());
        to_json(&Line { service, offset: r.offset, packet: &r.packet, bytes })
    }
}
