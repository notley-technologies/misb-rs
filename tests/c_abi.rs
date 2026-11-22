//! The C ABI as a C compiler sees it: header constants, struct layout,
//! exported symbols, and C programs (tests/c/abi_test.c and the shipped
//! example) linked against the shared library. What the C programs print
//! is compared with what the Rust API decodes from the same bytes, so the
//! check holds whatever the standards modules make of each tag.

use misb::capi::*;
use misb::st0604::TimeStatus;
use misb::{Checksum, Error, Item, Packet, Standard, Value};
use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

// ---------------------------------------------------------------- input

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
}

/// An ST 0601 packet from raw local set bytes, with a correct checksum
/// appended.
fn packet_from_body(mut body: Vec<u8>) -> Vec<u8> {
    body.extend([1, 2]);
    let mut out = misb::st0601::KEY.to_vec();
    push_len(&mut out, body.len() + 2);
    out.extend(&body);
    let sum = misb::checksum::st0601_checksum(&out);
    out.extend(sum.to_be_bytes());
    out
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    push_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// MISB ST 0601 tag 2 example value: 2008-10-24T00:13:29.913 MISP.
const TIME: [u8; 8] = [0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8];

/// A nested ST 0102 set for tag 48, built by hand: classification,
/// coding method, classifying country and version.
fn security() -> Vec<u8> {
    [tlv(&[1], &[1]), tlv(&[2], &[7]), tlv(&[3], b"//USA"), tlv(&[22], &[0, 12])].concat()
}

/// MISB ST 0902.8 Annex C Table 10: a complete ST 0601 packet published by
/// MISB, with a nested ST 0102 set in tag 48.
const ST0902_TABLE_10: &str = "
    06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 81 D2 02 08 00 04 60 50 58 4E 01 80 03 0A 4D 69
    73 73 69 6F 6E 20 31 32 05 02 71 C2 06 02 FD 3D 07 02 08 B8 0A 08 50 72 65 64 61 74 6F 72 0B 07
    45 4F 20 4E 6F 73 65 0C 0E 47 65 6F 64 65 74 69 63 20 57 47 53 38 34 0D 04 55 95 B6 6D 0E 04 5B
    53 60 C4 0F 02 C2 21 10 02 CD 9C 11 02 D9 17 12 04 72 4A 0A 20 13 04 87 F8 4B 86 14 04 7D C5 5E
    CE 15 04 03 83 09 26 16 02 12 81 17 04 F1 01 A2 29 18 04 14 BC 08 2B 19 02 34 F3 30 1C 01 01 01
    02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00 55 00 53 00 41 16 02 00 0A 41 01 06 5E 22 01 70
    F5 92 F0 23 73 36 4A F8 AA 91 62 C0 0F 2E B2 DA 16 B7 43 41 00 08 41 A0 BE 36 5B 5A B9 6A 36 45
    01 02 3E 1E";

fn hex_bytes(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

/// Packets of many shapes, then bytes the one-shot decoder stops at.
fn input() -> Vec<u8> {
    let mut s = packet_from_body(
        [tlv(&[2], &TIME), tlv(&[3], b"MISSION01"), tlv(&[48], &security()), tlv(&[0x81, 0x48], &[0xEE]), tlv(&[13], &[]), tlv(&[65], &[])]
            .concat(),
    );
    s.extend(hex_bytes(ST0902_TABLE_10));
    s.extend(packet_from_body(tlv(&[3], &[b'x'; 200]))); // long-form lengths
    let mut other = misb::st0601::KEY.to_vec();
    other[12] = 0x55; // another key: skipped by the decoder
    other.extend([3, 1, 2, 3]);
    s.extend(other);
    s.extend([0x00, 0x06, 0x0E]); // garbage
    let mut bad = packet_from_body(tlv(&[3], b"BAD"));
    let n = bad.len();
    bad[n - 1] ^= 0xFF;
    s.extend(bad);
    // An item that runs past the end of the set: parsing stops there.
    let mut broken = misb::st0601::KEY.to_vec();
    broken.extend([7, 3, 2, b'a', b'b', 5, 9, 1]);
    s.extend(broken);
    // A nested set whose last item is cut short.
    let mut cut = security();
    cut.extend([4, 9, 1]);
    s.extend(packet_from_body(tlv(&[48], &cut)));
    let tail = packet_from_body(tlv(&[3], b"cut short"));
    s.extend(&tail[..tail.len() - 3]);
    s
}

// ---------------------------------------------------------------- what Rust decodes

fn c_str(p: *const c_char) -> String {
    unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string()
}

fn standard_code(s: Standard) -> u32 {
    match s {
        Standard::St0601 => MISB_STANDARD_ST0601,
        Standard::St0102 => MISB_STANDARD_ST0102,
        Standard::St0806 => MISB_STANDARD_ST0806,
        Standard::St0903 => MISB_STANDARD_ST0903,
        other => panic!("no C code for {other:?}"),
    }
}

fn error_code(e: &Option<Error>) -> u32 {
    match e {
        None => MISB_ERROR_NONE,
        Some(Error::Truncated { .. }) => MISB_ERROR_TRUNCATED,
        Some(Error::BadLength) => MISB_ERROR_BAD_LENGTH,
        Some(Error::BadTag) => MISB_ERROR_BAD_TAG,
        Some(Error::TooLarge { .. }) => MISB_ERROR_TOO_LARGE,
        Some(Error::NotSt0601) => MISB_ERROR_NOT_ST0601,
        Some(Error::TooDeep) => MISB_ERROR_TOO_DEEP,
        Some(Error::TooManyItems { .. }) => MISB_ERROR_TOO_MANY_ITEMS,
        Some(Error::InvalidConfig(_)) => MISB_ERROR_INVALID_CONFIG,
        Some(other) => panic!("no C code for {other:?}"),
    }
}

fn checksum_fields(c: Checksum) -> (u32, u16, u16) {
    match c {
        Checksum::NotApplicable => (MISB_CHECKSUM_NOT_APPLICABLE, 0, 0),
        Checksum::Valid => (MISB_CHECKSUM_VALID, 0, 0),
        Checksum::Mismatch { expected, computed } => (MISB_CHECKSUM_MISMATCH, expected, computed),
        Checksum::Missing => (MISB_CHECKSUM_MISSING, 0, 0),
        other => panic!("no C code for {other:?}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn kind(v: &Value) -> u32 {
    match v {
        Value::Uint(_) => MISB_VALUE_UINT,
        Value::Int(_) => MISB_VALUE_INT,
        Value::Float(_) => MISB_VALUE_FLOAT,
        Value::Text(_) => MISB_VALUE_TEXT,
        Value::Bytes(_) => MISB_VALUE_BYTES,
        Value::Time(_) => MISB_VALUE_TIME,
        Value::Enum { .. } => MISB_VALUE_ENUM,
        Value::OutOfRange => MISB_VALUE_OUT_OF_RANGE,
        Value::Set(_) => MISB_VALUE_SET,
        Value::List(_) => MISB_VALUE_LIST,
        Value::Struct(_) => MISB_VALUE_STRUCT,
        Value::Invalid(_) => MISB_VALUE_INVALID,
        Value::Unknown => MISB_VALUE_UNKNOWN,
        other => panic!("no C kind for {other:?}"),
    }
}

fn children(v: &Value) -> usize {
    match v {
        Value::Set(p) => p.items.len(),
        Value::List(l) => l.len(),
        Value::Struct(f) => f.len(),
        _ => 0,
    }
}

/// The line tests/c/abi_test.c prints for a packet, then its items.
fn packet_lines(p: &Packet, out: &mut Vec<String>) {
    let (checksum, expected, computed) = checksum_fields(p.checksum);
    let error = error_code(&p.error);
    out.push(format!(
        "PACKET std={} checksum={checksum} expected={expected} computed={computed} error={error} ({}) items={} msg={}",
        standard_code(p.standard),
        c_str(misb_error_name(error)),
        p.items.len(),
        p.error.as_ref().map_or("-".to_string(), |e| e.to_string())
    ));
    for item in &p.items {
        item_lines(1, item.tag, item.name, item.units, Some(&item.raw), &item.value, out);
    }
}

fn item_lines(depth: usize, tag: u64, name: &str, units: &str, raw: Option<&[u8]>, v: &Value, out: &mut Vec<String>) {
    let mut line = format!(
        "ITEM {depth} tag={tag} kind={} name={name} units={units} children={} raw={}",
        kind(v),
        children(v),
        raw.map_or("-".to_string(), hex)
    );
    match v {
        Value::Uint(u) => line += &format!(" u={u}"),
        Value::Int(i) => line += &format!(" i={i}"),
        Value::Float(f) => line += &format!(" f={:016x}", f.to_bits()),
        Value::Text(t) => line += &format!(" text={} nul=1", hex(t.as_bytes())),
        Value::Bytes(b) => line += &format!(" bytes={}", hex(b)),
        Value::Time(t) => line += &format!(" time={t}"),
        Value::Enum { code, label } => line += &format!(" code={code} label={}", label.unwrap_or("-")),
        Value::Set(p) => {
            let (checksum, _, _) = checksum_fields(p.checksum);
            line += &format!(
                " std={} ({}) checksum={checksum} error={} msg={}",
                standard_code(p.standard),
                p.standard.name(),
                error_code(&p.error),
                p.error.as_ref().map_or("-".to_string(), |e| e.to_string())
            );
        }
        Value::Invalid(why) => line += &format!(" reason={why}"),
        _ => {}
    }
    out.push(line);
    match v {
        Value::Set(p) => {
            for Item { tag, name, units, value, raw, .. } in &p.items {
                item_lines(depth + 1, *tag, name, units, Some(raw), value, out);
            }
        }
        Value::List(l) => {
            for (i, e) in l.iter().enumerate() {
                item_lines(depth + 1, i as u64, "", "", None, e, out);
            }
        }
        Value::Struct(fields) => {
            for (i, f) in fields.iter().enumerate() {
                item_lines(depth + 1, i as u64, f.name, "", None, &f.value, out);
            }
        }
        _ => {}
    }
}

/// Size of the KLV triplet at the start of `buf`: 16-byte key, BER length
/// (SMPTE ST 336 section 6.3) and value.
fn triplet_size(buf: &[u8]) -> usize {
    let first = buf[16];
    if first < 0x80 {
        17 + usize::from(first)
    } else {
        let n = usize::from(first & 0x7F);
        let len = buf[17..17 + n].iter().fold(0usize, |v, &b| (v << 8) | usize::from(b));
        17 + n + len
    }
}

/// Everything tests/c/abi_test.c should print after the layout lines.
fn expected_behaviour(data: &[u8]) -> Vec<String> {
    let mut out = vec![format!("ABI 1 VERSION {}", env!("CARGO_PKG_VERSION"))];
    let mut d = misb::Decoder::new();
    for chunk in data.chunks(7) {
        d.push(chunk);
        for p in d.packets() {
            packet_lines(&p, &mut out);
        }
    }
    d.finish();
    for p in d.packets() {
        packet_lines(&p, &mut out);
    }
    let s = d.stats();
    out.push(format!(
        "STATS packets={} bytes={} skipped={} resyncs={} keys={} oversized={} checksum_errors={} malformed={} truncated={} dropped={} \
         missing={} nested={} packet_bytes={} bad_lengths={}",
        s.packets,
        s.bytes,
        s.bytes_skipped,
        s.resyncs,
        s.skipped_keys,
        s.oversized,
        s.checksum_errors,
        s.malformed,
        s.truncated_at_finish,
        s.dropped,
        s.checksum_missing,
        s.nested_errors,
        s.packet_bytes,
        s.bad_lengths
    ));
    let mut at = 0;
    loop {
        match misb::decode(&data[at..]) {
            Ok(_) => {
                let used = triplet_size(&data[at..]);
                out.push(format!("DECODE at={at} consumed={used}"));
                at += used;
            }
            Err(e) => {
                let code = error_code(&Some(e));
                out.push(format!("DECODE_END status=-4 error={code} ({}) at={at}", c_str(misb_error_name(code))));
                break;
            }
        }
    }
    let first = triplet_size(data);
    out.push(format!("CELL service=0 seq=5 fragment=3 config=0 random=1 len={first} same=1"));
    out.push(format!("CELL_END status=1 offset={}", first + 5));
    out.push("STATUS not a complete ST 0601 packet|unknown status".into());
    out.push("DONE".into());
    out
}

// ---------------------------------------------------------------- header

/// `#define NAME VALUE` pairs from the header.
fn header_defines() -> HashMap<String, i64> {
    let text = std::fs::read_to_string(root().join("include/misb.h")).unwrap();
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            (parts.next()? == "#define").then_some(())?;
            let name = parts.next()?.to_string();
            let raw = parts.next()?.trim_matches(|c| c == '(' || c == ')');
            let value = match raw.strip_prefix("0x") {
                Some(hex) => i64::from_str_radix(hex, 16).ok()?,
                None => raw.parse().ok()?,
            };
            Some((name, value))
        })
        .collect()
}

#[test]
fn header_constants_match_rust() {
    let defs = header_defines();
    let get = |name: &str| *defs.get(name).unwrap_or_else(|| panic!("{name} missing from header"));
    let groups: [(&str, &[(&str, i64)]); 12] = [
        (
            "MISB_VALUE_",
            &[
                ("MISB_VALUE_UINT", MISB_VALUE_UINT.into()),
                ("MISB_VALUE_INT", MISB_VALUE_INT.into()),
                ("MISB_VALUE_FLOAT", MISB_VALUE_FLOAT.into()),
                ("MISB_VALUE_TEXT", MISB_VALUE_TEXT.into()),
                ("MISB_VALUE_BYTES", MISB_VALUE_BYTES.into()),
                ("MISB_VALUE_TIME", MISB_VALUE_TIME.into()),
                ("MISB_VALUE_ENUM", MISB_VALUE_ENUM.into()),
                ("MISB_VALUE_OUT_OF_RANGE", MISB_VALUE_OUT_OF_RANGE.into()),
                ("MISB_VALUE_SET", MISB_VALUE_SET.into()),
                ("MISB_VALUE_LIST", MISB_VALUE_LIST.into()),
                ("MISB_VALUE_STRUCT", MISB_VALUE_STRUCT.into()),
                ("MISB_VALUE_INVALID", MISB_VALUE_INVALID.into()),
                ("MISB_VALUE_UNKNOWN", MISB_VALUE_UNKNOWN.into()),
            ],
        ),
        (
            "MISB_STANDARD_",
            &[
                ("MISB_STANDARD_ST0601", standard_code(Standard::St0601).into()),
                ("MISB_STANDARD_ST0102", standard_code(Standard::St0102).into()),
                ("MISB_STANDARD_ST0806", standard_code(Standard::St0806).into()),
                ("MISB_STANDARD_ST0903", standard_code(Standard::St0903).into()),
            ],
        ),
        (
            "MISB_CHECKSUM_",
            &[
                ("MISB_CHECKSUM_NOT_APPLICABLE", MISB_CHECKSUM_NOT_APPLICABLE.into()),
                ("MISB_CHECKSUM_VALID", MISB_CHECKSUM_VALID.into()),
                ("MISB_CHECKSUM_MISMATCH", MISB_CHECKSUM_MISMATCH.into()),
                ("MISB_CHECKSUM_MISSING", MISB_CHECKSUM_MISSING.into()),
            ],
        ),
        (
            "MISB_ERROR_",
            &[
                ("MISB_ERROR_NONE", MISB_ERROR_NONE.into()),
                ("MISB_ERROR_TRUNCATED", MISB_ERROR_TRUNCATED.into()),
                ("MISB_ERROR_BAD_LENGTH", MISB_ERROR_BAD_LENGTH.into()),
                ("MISB_ERROR_BAD_TAG", MISB_ERROR_BAD_TAG.into()),
                ("MISB_ERROR_TOO_LARGE", MISB_ERROR_TOO_LARGE.into()),
                ("MISB_ERROR_NOT_ST0601", MISB_ERROR_NOT_ST0601.into()),
                ("MISB_ERROR_TOO_DEEP", MISB_ERROR_TOO_DEEP.into()),
                ("MISB_ERROR_TOO_MANY_ITEMS", MISB_ERROR_TOO_MANY_ITEMS.into()),
                ("MISB_ERROR_INVALID_CONFIG", MISB_ERROR_INVALID_CONFIG.into()),
            ],
        ),
        (
            "MISB_ERR_",
            &[
                ("MISB_ERR_NULL", MISB_ERR_NULL.into()),
                ("MISB_ERR_INVALID", MISB_ERR_INVALID.into()),
                ("MISB_ERR_RANGE", MISB_ERR_RANGE.into()),
                ("MISB_ERR_PARSE", MISB_ERR_PARSE.into()),
                ("MISB_ERR_PANIC", MISB_ERR_PANIC.into()),
                ("MISB_ERR_POISONED", MISB_ERR_POISONED.into()),
                ("MISB_ERR_ENCODE", MISB_ERR_ENCODE.into()),
                ("MISB_ERR_TOO_SMALL", MISB_ERR_TOO_SMALL.into()),
            ],
        ),
        (
            "MISB_POLICY_",
            &[("MISB_POLICY_STRICT", MISB_POLICY_STRICT.into()), ("MISB_POLICY_CLAMP", MISB_POLICY_CLAMP.into())],
        ),
        (
            "MISB_ORDER_",
            &[("MISB_ORDER_ASCENDING", MISB_ORDER_ASCENDING.into()), ("MISB_ORDER_CALLER", MISB_ORDER_CALLER.into())],
        ),
        (
            "MISB_SPECIAL_",
            &[
                ("MISB_SPECIAL_OFF_EARTH", MISB_SPECIAL_OFF_EARTH.into()),
                ("MISB_SPECIAL_OUT_OF_RANGE", MISB_SPECIAL_OUT_OF_RANGE.into()),
                ("MISB_SPECIAL_BELOW_MINIMUM", MISB_SPECIAL_BELOW_MINIMUM.into()),
                ("MISB_SPECIAL_ABOVE_MAXIMUM", MISB_SPECIAL_ABOVE_MAXIMUM.into()),
            ],
        ),
        (
            "MISB_ENCODE_ERR_",
            &[
                ("MISB_ENCODE_ERR_UNKNOWN_TAG", MISB_ENCODE_ERR_UNKNOWN_TAG.into()),
                ("MISB_ENCODE_ERR_NOT_ALLOWED", MISB_ENCODE_ERR_NOT_ALLOWED.into()),
                ("MISB_ENCODE_ERR_WRONG_TYPE", MISB_ENCODE_ERR_WRONG_TYPE.into()),
                ("MISB_ENCODE_ERR_OUT_OF_RANGE", MISB_ENCODE_ERR_OUT_OF_RANGE.into()),
                ("MISB_ENCODE_ERR_NOT_FINITE", MISB_ENCODE_ERR_NOT_FINITE.into()),
                ("MISB_ENCODE_ERR_INVALID_CODE", MISB_ENCODE_ERR_INVALID_CODE.into()),
                ("MISB_ENCODE_ERR_TOO_LONG", MISB_ENCODE_ERR_TOO_LONG.into()),
                ("MISB_ENCODE_ERR_DUPLICATE", MISB_ENCODE_ERR_DUPLICATE.into()),
                ("MISB_ENCODE_ERR_MISSING", MISB_ENCODE_ERR_MISSING.into()),
                ("MISB_ENCODE_ERR_TOO_LARGE", MISB_ENCODE_ERR_TOO_LARGE.into()),
                ("MISB_ENCODE_ERR_INVALID_OPTIONS", MISB_ENCODE_ERR_INVALID_OPTIONS.into()),
                ("MISB_ENCODE_ERR_UNSUPPORTED", MISB_ENCODE_ERR_UNSUPPORTED.into()),
            ],
        ),
        (
            "MISB_ST0604_ID_",
            &[
                ("MISB_ST0604_ID_MICROSEC", MISB_ST0604_ID_MICROSEC.into()),
                ("MISB_ST0604_ID_HEVC_MICROSEC", MISB_ST0604_ID_HEVC_MICROSEC.into()),
                ("MISB_ST0604_ID_HEVC_NANOSEC", MISB_ST0604_ID_HEVC_NANOSEC.into()),
            ],
        ),
        (
            "MISB_ST0604_STATUS_",
            &[
                ("MISB_ST0604_STATUS_LOCKED", TimeStatus::LOCKED.byte().into()),
                ("MISB_ST0604_STATUS_LOCK_UNKNOWN", TimeStatus::LOCK_UNKNOWN.byte().into()),
                ("MISB_ST0604_STATUS_LOCKED_FORWARD_JUMP", TimeStatus::LOCKED_FORWARD_JUMP.byte().into()),
                ("MISB_ST0604_STATUS_LOCKED_BACKWARD_JUMP", TimeStatus::LOCKED_BACKWARD_JUMP.byte().into()),
                ("MISB_ST0604_STATUS_LOCK_UNKNOWN_FORWARD_JUMP", TimeStatus::LOCK_UNKNOWN_FORWARD_JUMP.byte().into()),
                ("MISB_ST0604_STATUS_LOCK_UNKNOWN_BACKWARD_JUMP", TimeStatus::LOCK_UNKNOWN_BACKWARD_JUMP.byte().into()),
            ],
        ),
        (
            "MISB_ST0604_WARN_",
            &[
                ("MISB_ST0604_WARN_SEPARATOR", MISB_ST0604_WARN_SEPARATOR.into()),
                ("MISB_ST0604_WARN_RESERVED", MISB_ST0604_WARN_RESERVED.into()),
                ("MISB_ST0604_WARN_REVERSE", MISB_ST0604_WARN_REVERSE.into()),
                ("MISB_ST0604_WARN_TRAILING", MISB_ST0604_WARN_TRAILING.into()),
            ],
        ),
    ];
    for (prefix, members) in groups {
        for (name, value) in members {
            assert_eq!(get(name), *value, "{name}");
        }
        let in_header = defs.keys().filter(|k| k.starts_with(prefix)).count();
        assert_eq!(in_header, members.len(), "{prefix}* in the header and in Rust differ");
        let codes: BTreeSet<_> = members.iter().map(|(_, v)| v).collect();
        assert_eq!(codes.len(), members.len(), "{prefix}* codes are distinct");
    }
    for (name, value) in [
        ("MISB_ST0604_STATUS_LOCKED", i64::from(MISB_ST0604_STATUS_LOCKED)),
        ("MISB_ST0604_STATUS_LOCK_UNKNOWN", i64::from(MISB_ST0604_STATUS_LOCK_UNKNOWN)),
        ("MISB_ST0604_STATUS_LOCKED_FORWARD_JUMP", i64::from(MISB_ST0604_STATUS_LOCKED_FORWARD_JUMP)),
        ("MISB_ST0604_STATUS_LOCKED_BACKWARD_JUMP", i64::from(MISB_ST0604_STATUS_LOCKED_BACKWARD_JUMP)),
        ("MISB_ST0604_STATUS_LOCK_UNKNOWN_FORWARD_JUMP", i64::from(MISB_ST0604_STATUS_LOCK_UNKNOWN_FORWARD_JUMP)),
        ("MISB_ST0604_STATUS_LOCK_UNKNOWN_BACKWARD_JUMP", i64::from(MISB_ST0604_STATUS_LOCK_UNKNOWN_BACKWARD_JUMP)),
        ("MISB_ABI_VERSION", i64::from(MISB_ABI_VERSION)),
        ("MISB_OK", MISB_OK.into()),
        ("MISB_EMPTY", MISB_EMPTY.into()),
        ("MISB_ENCODE_WARNING", MISB_ENCODE_WARNING.into()),
        ("MISB_VERSION_MAJOR", env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap()),
        ("MISB_VERSION_MINOR", env!("CARGO_PKG_VERSION_MINOR").parse().unwrap()),
        ("MISB_VERSION_PATCH", env!("CARGO_PKG_VERSION_PATCH").parse().unwrap()),
    ] {
        assert_eq!(get(name), value, "{name}");
    }
    let header = std::fs::read_to_string(root().join("include/misb.h")).unwrap();
    let version = format!("#define MISB_VERSION_STRING \"{}\"", env!("CARGO_PKG_VERSION"));
    assert!(header.contains(&version), "header version string is not {}", env!("CARGO_PKG_VERSION"));
    assert!(!header.contains(['\u{2013}', '\u{2014}']), "dashes in the header");
    // The Makefile reads the ABI version from this exact line.
    let abi = format!("#define MISB_ABI_VERSION {MISB_ABI_VERSION}");
    assert!(header.lines().any(|line| line == abi));
}

/// Function names the header declares.
fn header_functions() -> BTreeSet<String> {
    declared_functions(&root().join("include/misb.h"), "misb_")
}

/// Function names starting with `prefix` that the header `path` declares.
fn declared_functions(path: &Path, prefix: &str) -> BTreeSet<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut names = BTreeSet::new();
    for line in text.lines().filter(|l| !l.trim_start().starts_with(['#', '*', '/'])) {
        let mut rest = line;
        while let Some(at) = rest.find(prefix) {
            let tail = &rest[at..];
            let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(tail.len());
            if tail[end..].starts_with('(') {
                names.insert(tail[..end].to_string());
            }
            rest = &tail[end..];
        }
    }
    names
}

#[test]
fn exported_symbols_match_header() {
    // `nm -D` reads ELF dynamic symbols, so Linux only.
    if !cfg!(target_os = "linux") || Command::new("nm").arg("--version").output().is_err() {
        eprintln!("skipping: needs Linux and nm");
        return;
    }
    let lib = library_dir().join("libmisb.so");
    let out = Command::new("nm").args(["-D", "--defined-only"]).arg(&lib).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let exported: BTreeSet<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| s.trim_start_matches('_').to_string())
        .collect();
    let declared = header_functions();
    assert_eq!(declared.len(), 55, "header functions: {declared:?}");
    let missing: Vec<_> = declared.difference(&exported).collect();
    let extra: Vec<_> = exported.difference(&declared).collect();
    assert!(missing.is_empty(), "declared in the header but not exported: {missing:?}");
    assert!(extra.is_empty(), "exported but not in the header: {extra:?}");
}

/// Defined text symbols of a library: dynamic symbols of a shared library,
/// all global ones of a static library.
fn defined_symbols(lib: &Path) -> BTreeSet<String> {
    let mut nm = Command::new("nm");
    nm.arg("--defined-only");
    if lib.extension().map_or(false, |e| e == "so") {
        nm.arg("-D");
    }
    let out = nm.arg(lib).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().rev();
            let (name, kind) = (f.next()?, f.next()?);
            (kind == "T").then(|| name.trim_start_matches('_').to_string())
        })
        .collect()
}

/// With `mux`, the C library also exports the mpegts C API, so a C program
/// that demuxes, muxes and decodes links one library (MUXING_PLAN.md
/// section 3; two Rust static libraries cannot share one program). Both
/// the shared and the static library export exactly what misb.h and the
/// pinned mpegts's mpegts.h declare.
#[cfg(feature = "mux")]
#[test]
fn mux_library_exports_the_mpegts_api() {
    if !cfg!(target_os = "linux") || Command::new("nm").arg("--version").output().is_err() {
        eprintln!("skipping: needs Linux and nm");
        return;
    }
    let target = root().join("target/c-abi/mux");
    let mut cargo = Command::new(env!("CARGO"));
    cargo.current_dir(root()).args(["build", "--locked", "--offline", "--lib", "--features", "capi,mux", "--message-format=json"]);
    let output = cargo.env("CARGO_TARGET_DIR", &target).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let mut libs = Vec::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let message: serde_json::Value = serde_json::from_str(line).unwrap();
        if message["target"]["name"] == "misb" {
            for file in message["filenames"].as_array().into_iter().flatten() {
                let path = PathBuf::from(file.as_str().unwrap());
                if matches!(path.extension().and_then(|e| e.to_str()), Some("so" | "a")) {
                    libs.push(path);
                }
            }
        }
    }
    assert_eq!(libs.len(), 2, "shared and static library: {libs:?}");

    // The mpegts checkout Cargo resolved, for its header.
    let meta = Command::new(env!("CARGO"))
        .current_dir(root())
        .args(["metadata", "--locked", "--offline", "--format-version", "1", "--features", "mux"])
        .output()
        .unwrap();
    assert!(meta.status.success(), "{}", String::from_utf8_lossy(&meta.stderr));
    let meta: serde_json::Value = serde_json::from_slice(&meta.stdout).unwrap();
    let manifest = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "mpegts")
        .and_then(|p| p["manifest_path"].as_str())
        .expect("mpegts in cargo metadata");
    let mpegts_h = Path::new(manifest).parent().unwrap().join("include/mpegts.h");
    let mut declared = header_functions();
    let live = declared_functions(&root().join("include/misb_live.h"), "misb_");
    assert_eq!(live.len(), 18, "misb_live.h functions: {live:?}");
    declared.extend(live);
    let mpegts = declared_functions(&mpegts_h, "mpegts_");
    assert!(mpegts.len() >= 60, "mpegts.h functions: {mpegts:?}");
    declared.extend(mpegts);

    for lib in libs {
        let exported: BTreeSet<String> =
            defined_symbols(&lib).into_iter().filter(|s| s.starts_with("misb_") || s.starts_with("mpegts_")).collect();
        let missing: Vec<_> = declared.difference(&exported).collect();
        let extra: Vec<_> = exported.difference(&declared).collect();
        assert!(missing.is_empty(), "{}: declared but not exported: {missing:?}", lib.display());
        assert!(extra.is_empty(), "{}: exported but not declared: {extra:?}", lib.display());
    }
}

/// misb_live.h lays its structs out as the library does.
#[cfg(feature = "mux")]
#[test]
fn live_header_layout_matches() {
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    if cfg!(target_env = "msvc") {
        eprintln!("skipping: the layout program uses cc options");
        return;
    }
    macro_rules! live_fields {
        ($($t:ident . $f:ident),* $(,)?) => {{
            let mut c = String::from("#include <stdio.h>\n#include <stddef.h>\n#include \"misb_live.h\"\nint main(void) {\n");
            let mut rust = Vec::new();
            for (t, size) in [("misb_live_config", std::mem::size_of::<misb_live_config>()), ("misb_live_counters", std::mem::size_of::<misb_live_counters>())] {
                c.push_str(&format!("    printf(\"S {t} %zu\\n\", sizeof({t}));\n"));
                rust.push(format!("S {t} {size}"));
            }
            $(
                c.push_str(&format!("    printf(\"L {0}.{1} %zu\\n\", offsetof({0}, {1}));\n", stringify!($t), stringify!($f)));
                let v = std::mem::MaybeUninit::<$t>::uninit();
                let base = v.as_ptr();
                // SAFETY: only the address is taken, nothing is read.
                let at = unsafe { std::ptr::addr_of!((*base).$f) } as usize - base as usize;
                rust.push(format!("L {}.{} {at}", stringify!($t), stringify!($f)));
            )*
            (c, rust)
        }};
    }
    let (mut source, mut rust) = live_fields!(
        misb_live_config.carriage, misb_live_config.flags, misb_live_config.rate, misb_live_config.rate_value,
        misb_live_config.anchor, misb_live_config.timestamps, misb_live_config.anchor_pts,
        misb_live_config.anchor_misp_us, misb_live_config.max_age_us, misb_live_config.program,
        misb_live_config.existing_klv, misb_live_config.pid, misb_live_config.service_id,
        misb_live_config.psi_interval_ms, misb_live_counters.packets_in, misb_live_counters.held_packets,
        misb_live_counters.timestamps_written, misb_live_counters.psi_packets,
    );
    for (name, value) in [
        ("MISB_LIVE_VIDEO_ANCHOR", MISB_LIVE_VIDEO_ANCHOR),
        ("MISB_LIVE_LOCKED", MISB_LIVE_LOCKED),
        ("MISB_LIVE_NANOSECONDS", MISB_LIVE_NANOSECONDS),
        ("MISB_LIVE_STALE_UNKNOWN", MISB_LIVE_STALE_UNKNOWN),
        ("MISB_LIVE_CBR", MISB_LIVE_CBR),
        ("MISB_LIVE_CBR_DROP", MISB_LIVE_CBR_DROP),
        ("MISB_LIVE_HAS_PID", MISB_LIVE_HAS_PID),
        ("MISB_LIVE_HAS_SERVICE_ID", MISB_LIVE_HAS_SERVICE_ID),
        ("MISB_LIVE_CELLS_PER_AU", MISB_LIVE_CELLS_PER_AU),
    ] {
        source.push_str(&format!("    printf(\"C {name} %u\\n\", (unsigned){name});\n"));
        rust.push(format!("C {name} {value}"));
    }
    source.push_str("    return 0;\n}\n");
    let dir = std::env::temp_dir().join(format!("misb-live-layout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, exe) = (dir.join("layout.c"), dir.join("layout"));
    std::fs::write(&src, source).unwrap();
    let mut cmd = Command::new(cc);
    if cfg!(all(target_arch = "x86", target_os = "linux")) {
        cmd.arg("-m32");
    }
    let status = cmd
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root().join("include"))
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()
        .unwrap();
    assert!(status.success(), "misb_live.h failed to compile");
    let out = Command::new(&exe).output().unwrap();
    let c: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(String::from).collect();
    assert_eq!(c, rust);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------- layout

macro_rules! size {
    ($t:ident) => {
        (format!("S {}", stringify!($t)), std::mem::size_of::<$t>())
    };
}

macro_rules! field {
    ($t:ident, $f:ident) => {{
        let v = std::mem::MaybeUninit::<$t>::uninit();
        let base = v.as_ptr();
        // SAFETY: only the address is taken, nothing is read.
        let at = unsafe { std::ptr::addr_of!((*base).$f) } as usize - base as usize;
        (format!("L {}.{}", stringify!($t), stringify!($f)), at)
    }};
}

fn rust_layout() -> Vec<(String, usize)> {
    vec![
        size!(misb_config),
        size!(misb_stats),
        size!(misb_packet_info),
        size!(misb_item),
        size!(misb_au_cell),
        size!(misb_encode_options),
        size!(misb_encode_error),
        size!(misb_security),
        size!(misb_utc),
        size!(misb_st0604),
        field!(misb_config, struct_size),
        field!(misb_config, verify_checksum),
        field!(misb_config, reject_bad_checksum),
        field!(misb_config, reserved),
        field!(misb_config, max_packet_bytes),
        field!(misb_config, max_buffer_bytes),
        field!(misb_config, max_depth),
        field!(misb_config, max_items),
        field!(misb_config, max_skip_bytes),
        field!(misb_config, max_total_items),
        field!(misb_config, keep_raw),
        field!(misb_config, reserved2),
        field!(misb_stats, struct_size),
        field!(misb_stats, reserved),
        field!(misb_stats, packets),
        field!(misb_stats, bytes),
        field!(misb_stats, bytes_skipped),
        field!(misb_stats, resyncs),
        field!(misb_stats, skipped_keys),
        field!(misb_stats, oversized),
        field!(misb_stats, checksum_errors),
        field!(misb_stats, malformed),
        field!(misb_stats, truncated_at_finish),
        field!(misb_stats, dropped),
        field!(misb_stats, checksum_missing),
        field!(misb_stats, nested_errors),
        field!(misb_stats, packet_bytes),
        field!(misb_stats, bad_lengths),
        field!(misb_packet_info, struct_size),
        field!(misb_packet_info, standard),
        field!(misb_packet_info, checksum),
        field!(misb_packet_info, checksum_expected),
        field!(misb_packet_info, checksum_computed),
        field!(misb_packet_info, error),
        field!(misb_packet_info, reserved),
        field!(misb_packet_info, item_count),
        field!(misb_packet_info, error_message),
        field!(misb_item, struct_size),
        field!(misb_item, kind),
        field!(misb_item, packet),
        field!(misb_item, id),
        field!(misb_item, tag),
        field!(misb_item, name),
        field!(misb_item, units),
        field!(misb_item, child_count),
        field!(misb_item, uint_value),
        field!(misb_item, int_value),
        field!(misb_item, float_value),
        field!(misb_item, time_us),
        field!(misb_item, enum_code),
        field!(misb_item, enum_label),
        field!(misb_item, data),
        field!(misb_item, data_len),
        field!(misb_item, raw),
        field!(misb_item, raw_len),
        field!(misb_item, invalid_reason),
        field!(misb_item, standard),
        field!(misb_item, reserved),
        field!(misb_au_cell, struct_size),
        field!(misb_au_cell, service_id),
        field!(misb_au_cell, sequence_number),
        field!(misb_au_cell, fragment),
        field!(misb_au_cell, decoder_config),
        field!(misb_au_cell, random_access),
        field!(misb_au_cell, reserved),
        field!(misb_au_cell, data),
        field!(misb_au_cell, data_len),
        field!(misb_encode_options, struct_size),
        field!(misb_encode_options, policy),
        field!(misb_encode_options, order),
        field!(misb_encode_options, allow_legacy),
        field!(misb_encode_options, ascii_only),
        field!(misb_encode_options, reserved),
        field!(misb_encode_options, max_packet_bytes),
        field!(misb_encode_error, struct_size),
        field!(misb_encode_error, standard),
        field!(misb_encode_error, tag),
        field!(misb_encode_error, kind),
        field!(misb_encode_error, reserved),
        field!(misb_encode_error, reason),
        field!(misb_security, struct_size),
        field!(misb_security, classification),
        field!(misb_security, country_coding_method),
        field!(misb_security, object_country_coding_method),
        field!(misb_security, version),
        field!(misb_security, partial),
        field!(misb_security, classifying_country),
        field!(misb_security, sci_shi),
        field!(misb_security, caveats),
        field!(misb_security, releasing_instructions),
        field!(misb_security, classified_by),
        field!(misb_security, derived_from),
        field!(misb_security, classification_reason),
        field!(misb_security, declassification_date),
        field!(misb_security, marking_system),
        field!(misb_security, object_country_codes),
        field!(misb_security, comments),
        field!(misb_security, country_coding_method_date),
        field!(misb_security, object_country_coding_method_date),
        field!(misb_utc, struct_size),
        field!(misb_utc, year),
        field!(misb_utc, month),
        field!(misb_utc, day),
        field!(misb_utc, hour),
        field!(misb_utc, minute),
        field!(misb_utc, second),
        field!(misb_utc, micros),
        field!(misb_st0604, struct_size),
        field!(misb_st0604, identifier),
        field!(misb_st0604, status),
        field!(misb_st0604, warnings),
        field!(misb_st0604, value),
        field!(misb_st0604, misp_us),
    ]
}

// ---------------------------------------------------------------- building

fn compiler() -> Option<&'static str> {
    if cfg!(target_env = "msvc") {
        return Command::new("cl").arg("/?").output().is_ok().then_some("cl");
    }
    ["cc", "gcc", "clang"].into_iter().find(|c| Command::new(c).arg("--version").output().is_ok())
}

/// Build once per test process. Cargo reports the shared library's actual
/// location for the chosen target, profile and compiler version.
fn library_dir() -> &'static Path {
    static LIB: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    LIB.get_or_init(|| {
        let mut cargo = Command::new(env!("CARGO"));
        cargo.current_dir(root()).args(["build", "--locked", "--offline", "--lib", "--message-format=json"])
            .env("CARGO_TARGET_DIR", root().join("target/c-abi/build"));
        if cfg!(feature = "serde") {
            cargo.args(["--features", "serde"]);
        }
        if cfg!(all(target_arch = "x86", target_os = "linux", target_env = "gnu")) {
            cargo.args(["--target", "i686-unknown-linux-gnu"]);
        }
        let output = cargo.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        for line in String::from_utf8(output.stdout).unwrap().lines() {
            let message: serde_json::Value = serde_json::from_str(line).unwrap();
            if message["target"]["name"] == "misb" {
                if let Some(files) = message["filenames"].as_array() {
                    for file in files {
                        let path = Path::new(file.as_str().unwrap());
                        if path.extension().and_then(|ext| ext.to_str()) == Some(std::env::consts::DLL_EXTENSION) {
                            return path.parent().unwrap().to_owned();
                        }
                    }
                }
            }
        }
        panic!("Cargo did not report the misb shared library");
    })
}

fn compile(cc: &str, lib: &Path, source: &Path, exe: &Path) {
    if cfg!(target_env = "msvc") {
        let status = Command::new(cc)
            .args(["/nologo", "/std:c11", "/D_CRT_SECURE_NO_WARNINGS", "/W4", "/WX", "/I"])
            .arg(root().join("include"))
            .arg(source)
            .arg(lib.join("misb.dll.lib"))
            .arg(format!("/Fe{}", exe.display()))
            .arg(format!("/Fo{}", exe.with_extension("obj").display()))
            .status()
            .unwrap();
        assert!(status.success(), "{} failed to compile", source.display());
        return;
    }
    let mut cmd = Command::new(cc);
    if cfg!(all(target_arch = "x86", target_os = "linux")) {
        cmd.arg("-m32");
    }
    let compiled = cmd
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I"])
        .arg(root().join("include"))
        .arg(source)
        .arg("-L")
        .arg(lib)
        .arg("-lmisb")
        .arg(format!("-Wl,-rpath,{}", lib.display()))
        .arg("-o")
        .arg(exe)
        .status()
        .unwrap();
    assert!(compiled.success(), "{} failed to compile", source.display());
}

/// What `encoder()` in tests/c/abi_test.c must print, built with the Rust
/// API.
fn expected_encoder() -> Vec<String> {
    use misb::encode::{Classification, Input, Security, St0601Builder};
    use misb::st0601::Tag;
    use misb::{LeapSeconds, MispTime};
    let hexu = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    let set = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US").encode().unwrap();
    let misp = MispTime::from_utc("2022-07-12T09:05:03.000700Z".parse().unwrap(), LeapSeconds::builtin()).unwrap();
    let mut b = St0601Builder::new(misp);
    b.set(Tag::MissionId, "MISSION01").unwrap();
    b.set(Tag::SensorLatitude, 60.176_822_966_978_335).unwrap();
    b.set(Tag::FrameCenterLatitude, Input::OffEarth).unwrap();
    b.set(Tag::IcingDetected, Input::Code(2)).unwrap();
    b.set_imapb(Tag::SensorAzimuthRate, 1.0, 2).unwrap();
    b.set(Tag::EventStartTime, misp).unwrap();
    b.set(Tag::LeapSeconds, 29i64).unwrap();
    b.set(Tag::TimeAirborne, 19_887u64).unwrap();
    b.unknown(Tag::SlantRange).unwrap();
    b.set(Tag::SecurityLocalSet, Input::Bytes(set.clone())).unwrap();
    b.set_raw(200, b"private").unwrap();
    b.set(Tag::PlatformPitchAngle, 25.0).unwrap();
    let packet = b.finish().unwrap();
    let mut empty = St0601Builder::new(MispTime::from_micros(1));
    empty.version(6);
    let leap = MispTime::from_utc("2016-12-31T23:59:60.5Z".parse().unwrap(), LeapSeconds::builtin()).unwrap();
    let posix = MispTime::from_posix_utc_micros(1_657_616_703_000_700, LeapSeconds::builtin()).unwrap();
    vec![
        format!("ENC OPTIONS policy=0 order=0 max={}", misb::encode::DEFAULT_MAX_PACKET_BYTES),
        format!("ENC SECURITY {}", hexu(&set)),
        format!("ENC SECURITY_ERROR std={MISB_STANDARD_ST0102} tag=3 kind={MISB_ENCODE_ERR_MISSING}"),
        format!("ENC MISP {}", misp.as_micros()),
        format!("ENC ERROR std={MISB_STANDARD_ST0601} tag=14 kind={MISB_ENCODE_ERR_OUT_OF_RANGE} reason=value outside the item's range"),
        format!("ENC DUPLICATE kind={MISB_ENCODE_ERR_DUPLICATE}"),
        format!("ENC WARNINGS {}", b.warnings().len()),
        format!("ENC WARNING tag=6 kind={MISB_ENCODE_WARNING}"),
        format!("ENC PACKET {}", hexu(&packet)),
        format!("ENC EMPTY {}", hexu(&empty.finish().unwrap())),
        format!("ENC LEAP {} 2016-12-31T23:59:60.500000", leap.as_micros()),
        format!("ENC POSIX {}", posix.as_micros()),
        format!("ENC VALID_UNTIL {}", LeapSeconds::builtin().valid_until()),
        "ENC STATUS value or packet rejected by the encoder|output buffer too small".to_string(),
    ]
}

/// What `st0604()` in tests/c/abi_test.c must print, built with the Rust
/// API.
fn expected_st0604() -> Vec<String> {
    use misb::st0604::{self, Identifier, Timestamp};
    use misb::MispTime;
    let hexu = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    let time = MispTime::from_micros(1_657_616_732_000_618);
    let micro = Timestamp::from_misp(Identifier::MispMicrosectime, TimeStatus::LOCK_UNKNOWN, time).unwrap();
    let nano = Timestamp::from_misp(Identifier::HevcNanoseconds, TimeStatus::LOCKED, time).unwrap();
    let mut damaged = micro.to_bytes().unwrap();
    damaged[16] = 0x80;
    damaged[19] = 0x00;
    let d = st0604::decode(&damaged).unwrap();
    vec![
        format!("T0604 DECODE id={MISB_ST0604_ID_MICROSEC} status=9F warnings=0 value={0} misp={0}", time.as_micros()),
        format!("T0604 NANO {}", hexu(&nano.to_bytes().unwrap())),
        format!("T0604 PAYLOAD {}", hexu(&nano.payload().unwrap())),
        format!(
            "T0604 TOLERATED status=80 warnings={} value={}",
            MISB_ST0604_WARN_SEPARATOR | MISB_ST0604_WARN_RESERVED,
            d.timestamp.value
        ),
        format!("T0604 HEVC_NANO misp={}", time.as_micros()),
    ]
}

#[test]
fn c_program_layout_and_behaviour() {
    if cfg!(all(windows, not(target_env = "msvc"))) {
        eprintln!("skipping: the Windows test uses MSVC");
        return;
    }
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let lib = library_dir();
    let work = root().join(format!("target/c-abi/work-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    if cfg!(windows) {
        std::fs::copy(lib.join("misb.dll"), work.join("misb.dll")).unwrap();
    }
    let exe = work.join(format!("abi_test{}", std::env::consts::EXE_SUFFIX));
    compile(cc, lib, &root().join("tests/c/abi_test.c"), &exe);
    let data = input();
    let path = work.join("input.klv");
    std::fs::write(&path, &data).unwrap();
    let run = Command::new(&exe).arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&exe);
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(run.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&run.stderr));

    // Layout: every struct size and field offset as C computes them.
    let c: HashMap<&str, usize> = stdout
        .lines()
        .filter(|l| l.starts_with("S ") || l.starts_with("L "))
        .map(|l| {
            let (k, v) = l.rsplit_once(' ').unwrap();
            (k, v.parse().unwrap())
        })
        .collect();
    let rust = rust_layout();
    assert_eq!(c.len(), rust.len());
    for (key, offset) in &rust {
        assert_eq!(c.get(key.as_str()), Some(offset), "{key}");
    }

    // The encoder, as C drives it, writes what the Rust builder writes.
    let enc: Vec<&str> = stdout.lines().filter(|l| l.starts_with("ENC ")).collect();
    assert_eq!(enc, expected_encoder(), "C encoder output");
    let st0604: Vec<&str> = stdout.lines().filter(|l| l.starts_with("T0604 ")).collect();
    assert_eq!(st0604, expected_st0604(), "C ST 0604 output");

    // Behaviour: the C view of every packet is the Rust view.
    let lines: Vec<&str> =
        stdout.lines().filter(|l| !["S ", "L ", "ENC ", "T0604 "].iter().any(|p| l.starts_with(p))).collect();
    let expected = expected_behaviour(&data);
    for (i, (got, want)) in lines.iter().zip(&expected).enumerate() {
        assert_eq!(got, want, "line {i}");
    }
    assert_eq!(lines.len(), expected.len());

    // The input exercises what it is meant to.
    let packets = lines.iter().filter(|l| l.starts_with("PACKET ")).count();
    assert_eq!(packets, 6);
    assert!(lines.iter().any(|l| l.starts_with("PACKET std=1 checksum=2 ")), "a checksum mismatch");
    assert!(lines.iter().any(|l| l.starts_with("PACKET std=1 checksum=3 expected=0 computed=0 error=1 ")), "a set cut short");
    assert!(lines.iter().any(|l| l.starts_with("ITEM 1 tag=200 ")), "a two-byte tag");
    assert!(lines.iter().any(|l| l.starts_with("ITEM 1 tag=13 kind=13 name=Sensor Latitude units=deg children=0 raw=")), "a zero-length item");
    assert!(lines.iter().any(|l| l.starts_with("ITEM 1 tag=65 kind=12 ")), "a zero-length mandatory item");
    let nested: Vec<_> = lines.iter().filter(|l| l.starts_with("ITEM 1 tag=48 kind=9 ")).collect();
    assert_eq!(nested.len(), 3, "tag 48 decodes as a nested set: {nested:#?}");
    assert!(nested.iter().all(|l| l.contains(" std=2 (ST 0102) ")));
    assert!(nested.iter().any(|l| l.contains(" error=1 msg=truncated")), "a nested set cut short");
    assert!(lines.iter().any(|l| l.starts_with("ITEM 2 tag=22 ")), "items inside the nested set");
    assert_eq!(lines.iter().filter(|l| l.starts_with("DECODE at=")).count(), 3);
    assert!(lines.iter().any(|l| l.starts_with("DECODE_END status=-4 error=5 (not an ST 0601 packet) ")));

    // The shipped C example builds cleanly and walks the same trees.
    let example = work.join(format!("misb_dump{}", std::env::consts::EXE_SUFFIX));
    compile(cc, lib, &root().join("examples/c/misb_dump.c"), &example);
    let dump = Command::new(&example).arg(&path).output().unwrap();
    assert!(dump.status.success(), "{}", String::from_utf8_lossy(&dump.stderr));
    let text = String::from_utf8(dump.stdout).unwrap();
    let want = dump_outline(&data);
    let got: Vec<&str> = text.lines().collect();
    assert_eq!(got.len(), want.len(), "{text}");
    for (line, prefix) in got.iter().zip(&want) {
        assert!(line.starts_with(prefix.as_str()), "{line:?} does not start with {prefix:?}");
    }
    assert!(String::from_utf8_lossy(&dump.stderr).contains("6 packets"));

    // Standard input gives the same; empty input is fine.
    let mut child = Command::new(&example).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&data).unwrap();
    }
    let piped = child.wait_with_output().unwrap();
    assert!(piped.status.success());
    assert_eq!(String::from_utf8(piped.stdout).unwrap(), text);
    let empty_path = work.join("empty.klv");
    std::fs::write(&empty_path, []).unwrap();
    let empty = Command::new(&example).arg(empty_path).output().unwrap();
    assert!(empty.status.success());
    assert!(empty.stdout.is_empty());
    let missing = Command::new(&example).arg(work.join("no such file")).output().unwrap();
    assert!(!missing.status.success());
    std::fs::remove_dir_all(work).unwrap();
}

/// What each line of misb_dump's output starts with: the packet header
/// line in full, and for every item its indentation and label.
fn dump_outline(data: &[u8]) -> Vec<String> {
    fn walk(depth: usize, label: String, v: &Value, out: &mut Vec<String>) {
        out.push(format!("{}{label}", " ".repeat(4 * depth - 2)));
        match v {
            Value::Set(p) => {
                for i in &p.items {
                    walk(depth + 1, format!("{:>3} {}: ", i.tag, i.name), &i.value, out);
                }
            }
            Value::List(l) => {
                for (n, e) in l.iter().enumerate() {
                    walk(depth + 1, format!("[{n}] "), e, out);
                }
            }
            Value::Struct(fields) => {
                for f in fields {
                    walk(depth + 1, format!("{}: ", f.name), &f.value, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (n, p) in misb::decode_all(data).iter().enumerate() {
        let checksum = match p.checksum {
            Checksum::Valid => "checksum ok".to_string(),
            Checksum::Mismatch { expected, computed } => {
                format!("checksum MISMATCH (carried {expected:04X}, computed {computed:04X})")
            }
            Checksum::Missing => "checksum missing".to_string(),
            _ => "checksum not checked".to_string(),
        };
        let error = p.error.as_ref().map_or(String::new(), |e| format!(", error: {e}"));
        out.push(format!("packet {}: ST 0601 {}, {checksum}, {} items{error}", n + 1, p.standard.title(), p.items.len()));
        for i in &p.items {
            walk(1, format!("{:>3} {}: ", i.tag, i.name), &i.value, &mut out);
        }
    }
    out
}

#[test]
fn header_compiles_as_cpp() {
    if cfg!(windows) || Command::new("c++").arg("--version").output().is_err() {
        eprintln!("skipping: no C++ compiler");
        return;
    }
    let status = Command::new("c++")
        .args(["-std=c++11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-fsyntax-only", "-x", "c++"])
        .arg(root().join("include/misb.h"))
        .status()
        .unwrap();
    assert!(status.success());
}
