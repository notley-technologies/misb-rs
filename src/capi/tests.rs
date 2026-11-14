//! Behaviour of the C ABI, exercised from Rust. Layout and header checks
//! against a real C compiler live in tests/c_abi.rs.

use super::*;
use crate::checksum::st0601_checksum;
use crate::st0601;
use std::ffi::CStr;

// ---------------------------------------------------------------- helpers

fn push_len(out: &mut Vec<u8>, n: usize) {
    smpte_klv::ber::encode_length(n as u64, smpte_klv::ber::BerForm::Minimal, out).unwrap();
}

/// An ST 0601 packet of (tag, value) items with a correct checksum last.
fn st0601_packet(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, v) in items {
        body.push(*tag);
        push_len(&mut body, v.len());
        body.extend_from_slice(v);
    }
    body.extend([1, 2]);
    let mut out = st0601::KEY.to_vec();
    push_len(&mut out, body.len() + 2);
    out.extend(&body);
    let sum = st0601_checksum(&out);
    out.extend(sum.to_be_bytes());
    out
}

/// MISB ST 0601 tag 2 example value (ST 0601 section 8): 2008-10-24T00:13:29.913 MISP.
const TIME: [u8; 8] = [0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8];

/// A nested ST 0102 security set for tag 48, built by hand: tags 1
/// (classification), 2 (coding method), 3 (country) and 22 (version).
const SECURITY: [u8; 15] = [1, 1, 1, 2, 1, 7, 3, 5, b'/', b'/', b'U', b'S', b'A', 22, 0];

fn security_set() -> Vec<u8> {
    let mut v = SECURITY.to_vec();
    v[14] = 2; // tag 22 length
    v.extend([0, 12]);
    v
}

/// MISB ST 0902.8 Annex C Table 10, "Dynamic & Constant": a complete ST
/// 0601 packet published by MISB, with a nested ST 0102 set in tag 48.
const ST0902_TABLE_10: &str = "
    06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00
    81 D2 02 08 00 04 60 50 58 4E 01 80 03 0A 4D 69
    73 73 69 6F 6E 20 31 32 05 02 71 C2 06 02 FD 3D
    07 02 08 B8 0A 08 50 72 65 64 61 74 6F 72 0B 07
    45 4F 20 4E 6F 73 65 0C 0E 47 65 6F 64 65 74 69
    63 20 57 47 53 38 34 0D 04 55 95 B6 6D 0E 04 5B
    53 60 C4 0F 02 C2 21 10 02 CD 9C 11 02 D9 17 12
    04 72 4A 0A 20 13 04 87 F8 4B 86 14 04 7D C5 5E
    CE 15 04 03 83 09 26 16 02 12 81 17 04 F1 01 A2
    29 18 04 14 BC 08 2B 19 02 34 F3 30 1C 01 01 01
    02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00
    55 00 53 00 41 16 02 00 0A 41 01 06 5E 22 01 70
    F5 92 F0 23 73 36 4A F8 AA 91 62 C0 0F 2E B2 DA
    16 B7 43 41 00 08 41 A0 BE 36 5B 5A B9 6A 36 45
    01 02 3E 1E";

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

/// A stream with garbage, another key, a bad checksum and a truncated tail
/// around packets with tags 2, 3 and a nested set in 48.
fn stream() -> Vec<u8> {
    let mut s = vec![0x00, 0x11];
    s.extend(st0601_packet(&[(2, &TIME), (3, b"MISSION01")]));
    s.extend(st0601_packet(&[(48, &security_set())]));
    let mut other = st0601::KEY.to_vec();
    other[12] = 0x55;
    other.extend([3, 1, 2, 3]);
    s.extend(other);
    let mut bad = st0601_packet(&[(3, b"BAD")]);
    let n = bad.len();
    bad[n - 1] ^= 0xFF;
    s.extend(bad);
    s.extend(hex(ST0902_TABLE_10));
    let cut = st0601_packet(&[(3, b"cut short")]);
    s.extend(&cut[..cut.len() - 4]);
    s
}

fn item(tag: u64, name: &'static str, units: &'static str, value: Value, raw: &[u8]) -> Item {
    Item { tag, name, units, value, raw: raw.to_vec() }
}

fn field(name: &'static str, value: Value) -> Field {
    Field { name, value }
}

/// A packet with every kind of value, built by hand so that it does not
/// depend on how the standards modules decode particular tags.
fn every_kind() -> Packet {
    let mut nested = Packet::new(Standard::St0102);
    nested.items.push(item(1, "Security Classification", "", Value::Enum { code: 1, label: Some("UNCLASSIFIED//") }, &[1]));
    nested.items.push(item(3, "Classifying Country", "", Value::Text("//USA".into()), b"//USA"));
    nested.error = Some(Error::Truncated { needed: 5, available: 2 });
    let mut p = Packet::new(Standard::St0601);
    p.checksum = Checksum::Mismatch { expected: 0x1234, computed: 0xABCD };
    p.error = Some(Error::BadLength);
    let items = vec![
        item(2, "Precision Time Stamp", "us", Value::Time(1_224_807_209_913_000), &TIME),
        item(3, "Mission ID", "", Value::Text("MI\0SSION".into()), b"MI\0SSION"),
        item(5, "Platform Heading Angle", "deg", Value::Float(159.974_365_224_689), &[0x71, 0xC2]),
        item(6, "Platform Pitch Angle", "deg", Value::Int(-5), &[0xFB]),
        item(7, "Count", "m", Value::Uint(42), &[42]),
        item(8, "Empty", "", Value::Bytes(Vec::new()), &[]),
        item(9, "Some Bytes", "", Value::Bytes(vec![1, 2, 3]), &[1, 2, 3]),
        item(10, "Code", "", Value::Enum { code: 9, label: None }, &[9]),
        item(11, "Range", "m", Value::OutOfRange, &[0x80, 0x00]),
        item(12, "Broken", "", Value::Invalid("wrong length"), &[1, 2, 3, 4, 5]),
        item(48, "Security Local Set", "", Value::Set(Box::new(nested)), &SECURITY),
        item(
            13,
            "A List",
            "deg",
            Value::List(vec![
                Value::Uint(1),
                Value::List(vec![Value::Float(f64::NAN), Value::Text(String::new())]),
                Value::Struct(vec![field("x", Value::Int(-1))]),
            ]),
            &[0xAA],
        ),
        item(
            14,
            "A Struct",
            "",
            Value::Struct(vec![
                field("lat", Value::Float(1.5)),
                field("lon", Value::Float(-2.5)),
                field("lat", Value::Uint(7)),
                field("", Value::Enum { code: 0, label: Some("") }),
            ]),
            &[0xBB],
        ),
        item(200, "Unknown", "", Value::Bytes(vec![0xEE]), &[0xEE]),
        item(1, "Checksum", "", Value::Uint(0x1234), &[0x12, 0x34]),
        item(15, "Not Known", "m", Value::Unknown, &[]),
    ];
    p.items = items;
    p
}

fn handle(p: Packet) -> *mut misb_packet {
    Box::into_raw(misb_packet::new(p))
}

// Shorter ABI versions begin with a u32 size. Keep the backing storage
// aligned for all supported ABI structs and mark the unwritten tail.
#[repr(align(8))]
struct ShortOutput([u32; 16]);

impl ShortOutput {
    const UNWRITTEN: u32 = 0xEEEE_EEEE;

    fn new(size: u32) -> Self {
        let mut words = [Self::UNWRITTEN; 16];
        words[0] = size;
        Self(words)
    }

    fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.0.as_mut_ptr().cast()
    }
}

fn new_item() -> misb_item {
    misb_item { struct_size: size_of_u32::<misb_item>(), ..misb_item::empty() }
}

fn new_stats() -> misb_stats {
    misb_stats { struct_size: size_of_u32::<misb_stats>(), ..misb_stats::default() }
}

fn new_info() -> misb_packet_info {
    misb_packet_info {
        struct_size: size_of_u32::<misb_packet_info>(),
        standard: 0,
        checksum: 0,
        checksum_expected: 0,
        checksum_computed: 0,
        error: 0,
        reserved: 0,
        item_count: 0,
        error_message: ptr::null(),
    }
}

fn new_cell() -> misb_au_cell {
    misb_au_cell {
        struct_size: size_of_u32::<misb_au_cell>(),
        service_id: 0,
        sequence_number: 0,
        fragment: 0,
        decoder_config: 0,
        random_access: 0,
        reserved: [0; 7],
        data: ptr::null(),
        data_len: 0,
    }
}

fn s(p: *const c_char) -> String {
    assert!(!p.is_null());
    unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned()
}

fn opt_s(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| s(p))
}

unsafe fn bytes<'a>(p: *const u8, len: u64) -> &'a [u8] {
    assert!(!p.is_null());
    slice::from_raw_parts(p, len as usize)
}

fn root(p: *const misb_packet) -> misb_item {
    let mut it = new_item();
    assert_eq!(unsafe { misb_packet_root(p, &mut it) }, MISB_OK);
    it
}

fn child(parent: &misb_item, i: usize) -> misb_item {
    let mut it = new_item();
    assert_eq!(unsafe { misb_item_child(parent, i, &mut it) }, MISB_OK);
    it
}

fn info_of(set: &misb_item) -> misb_packet_info {
    let mut info = new_info();
    assert_eq!(unsafe { misb_set_info_get(set, &mut info) }, MISB_OK);
    info
}

fn new_decoder(config: Option<&misb_config>) -> *mut misb_decoder {
    let mut d = ptr::null_mut();
    let cfg: *const misb_config = config.map_or(ptr::null(), |c| c);
    assert_eq!(unsafe { misb_decoder_new(cfg, &mut d) }, MISB_OK);
    assert!(!d.is_null());
    d
}

/// Every packet waiting in the decoder.
fn drain(d: *mut misb_decoder) -> Vec<*mut misb_packet> {
    let mut out = Vec::new();
    loop {
        let mut p = ptr::null_mut();
        match unsafe { misb_decoder_next(d, &mut p) } {
            MISB_EMPTY => {
                assert!(p.is_null());
                return out;
            }
            MISB_OK => out.push(p),
            other => panic!("status {other}"),
        }
    }
}

/// Check that the C view of a set node matches the Rust packet, all the
/// way down, including the fields every kind leaves unset.
fn check_set(c: &misb_item, p: &Packet, error_message: Option<String>) {
    assert_eq!(c.kind, MISB_VALUE_SET);
    assert_eq!(c.standard, standard_code(p.standard));
    assert_eq!(c.child_count, p.items.len() as u64);
    let info = info_of(c);
    assert_eq!(info.standard, standard_code(p.standard));
    assert_eq!(info.item_count, p.items.len() as u64);
    assert_eq!(info.error, p.error.as_ref().map_or(MISB_ERROR_NONE, error_code));
    assert_eq!(opt_s(info.error_message), error_message);
    let (code, expected, computed) = match p.checksum {
        Checksum::NotApplicable => (MISB_CHECKSUM_NOT_APPLICABLE, 0, 0),
        Checksum::Valid => (MISB_CHECKSUM_VALID, 0, 0),
        Checksum::Mismatch { expected, computed } => (MISB_CHECKSUM_MISMATCH, expected, computed),
        Checksum::Missing => (MISB_CHECKSUM_MISSING, 0, 0),
    };
    assert_eq!((info.checksum, info.checksum_expected, info.checksum_computed), (code, expected, computed));
    for (i, item) in p.items.iter().enumerate() {
        let k = child(c, i);
        assert_eq!((k.tag, s(k.name).as_str(), s(k.units).as_str()), (item.tag, item.name, item.units));
        assert_eq!(unsafe { bytes(k.raw, k.raw_len) }, &item.raw[..]);
        check_value(&k, &item.value);
    }
    let mut past = new_item();
    assert_eq!(unsafe { misb_item_child(c, p.items.len(), &mut past) }, MISB_ERR_RANGE);
}

fn check_value(c: &misb_item, v: &Value) {
    assert_eq!(c.kind, kind_code(v), "{v:?}");
    let k = c.kind;
    assert!(k == MISB_VALUE_UINT || c.uint_value == 0);
    assert!(k == MISB_VALUE_INT || c.int_value == 0);
    assert!(k == MISB_VALUE_FLOAT || c.float_value.to_bits() == 0);
    assert!(k == MISB_VALUE_TIME || c.time_us == 0);
    assert!(k == MISB_VALUE_ENUM || (c.enum_code == 0 && c.enum_label.is_null()));
    assert!(k == MISB_VALUE_TEXT || k == MISB_VALUE_BYTES || (c.data.is_null() && c.data_len == 0));
    assert!(k == MISB_VALUE_INVALID || c.invalid_reason.is_null());
    assert!(k == MISB_VALUE_SET || c.standard == 0);
    assert!(k == MISB_VALUE_SET || k == MISB_VALUE_LIST || k == MISB_VALUE_STRUCT || c.child_count == 0);
    if k != MISB_VALUE_SET {
        let mut info = new_info();
        assert_eq!(unsafe { misb_set_info_get(c, &mut info) }, MISB_ERR_INVALID);
    }
    match v {
        Value::Uint(u) => assert_eq!(c.uint_value, *u),
        Value::Int(i) => assert_eq!(c.int_value, *i),
        Value::Float(f) => assert_eq!(c.float_value.to_bits(), f.to_bits()),
        Value::Text(t) => {
            let data = unsafe { bytes(c.data, c.data_len + 1) };
            assert_eq!(&data[..t.len()], t.as_bytes());
            assert_eq!(data[t.len()], 0, "NUL-terminated");
        }
        Value::Bytes(b) => assert_eq!(unsafe { bytes(c.data, c.data_len) }, &b[..]),
        Value::Time(t) => assert_eq!(c.time_us, *t),
        Value::Enum { code, label } => {
            assert_eq!(c.enum_code, *code);
            assert_eq!(opt_s(c.enum_label).as_deref(), *label);
        }
        Value::OutOfRange | Value::Unknown => {}
        Value::Set(p) => check_set(c, p, p.error.as_ref().map(|e| e.to_string())),
        Value::List(list) => {
            assert_eq!(c.child_count, list.len() as u64);
            for (i, e) in list.iter().enumerate() {
                let k = child(c, i);
                assert_eq!((k.tag, s(k.name).as_str(), s(k.units).as_str()), (i as u64, "", ""));
                assert!(k.raw.is_null() && k.raw_len == 0);
                check_value(&k, e);
            }
        }
        Value::Struct(fields) => {
            assert_eq!(c.child_count, fields.len() as u64);
            for (i, f) in fields.iter().enumerate() {
                let k = child(c, i);
                assert_eq!((k.tag, s(k.name).as_str(), s(k.units).as_str()), (i as u64, f.name, ""));
                assert!(k.raw.is_null() && k.raw_len == 0);
                check_value(&k, &f.value);
            }
        }
        Value::Invalid(why) => assert_eq!(s(c.invalid_reason), *why),
    }
}

/// The whole C view of a packet handle against the Rust packet.
fn check_packet(h: *const misb_packet, p: &Packet) {
    let r = root(h);
    assert_eq!((r.tag, s(r.name).as_str(), s(r.units).as_str()), (0, p.standard.title(), ""));
    assert!(r.raw.is_null());
    check_set(&r, p, p.error.as_ref().map(|e| e.to_string()));
    let mut info = new_info();
    assert_eq!(unsafe { misb_packet_info_get(h, &mut info) }, MISB_OK);
    let from_root = info_of(&r);
    assert_eq!((info.checksum, info.error, info.item_count), (from_root.checksum, from_root.error, from_root.item_count));
    assert_eq!(info.error_message, from_root.error_message, "same pointer every time");
    for i in 0..p.items.len() {
        let mut a = new_item();
        assert_eq!(unsafe { misb_packet_item(h, i, &mut a) }, MISB_OK);
        let b = child(&r, i);
        assert_eq!((a.id, a.kind, a.name, a.data), (b.id, b.kind, b.name, b.data));
    }
}

// ---------------------------------------------------------------- tests

#[test]
fn names_and_versions() {
    assert_eq!(misb_abi_version(), 1);
    assert_eq!(s(misb_version()), env!("CARGO_PKG_VERSION"));
    for (status, text) in [
        (MISB_OK, "ok"),
        (MISB_EMPTY, "nothing to return"),
        (MISB_ERR_NULL, "null pointer"),
        (MISB_ERR_INVALID, "invalid argument"),
        (MISB_ERR_RANGE, "index out of range"),
        (MISB_ERR_PARSE, "not a complete ST 0601 packet"),
        (MISB_ERR_PANIC, "internal error"),
        (MISB_ERR_POISONED, "decoder unusable after an internal error"),
        (12345, "unknown status"),
        (-7, "unknown status"),
    ] {
        assert_eq!(s(misb_status_string(status)), text);
    }
    let kinds = [
        "uint", "int", "float", "text", "bytes", "time", "enum", "out of range", "set", "list", "struct", "invalid", "unknown",
    ];
    for (i, name) in kinds.iter().enumerate() {
        assert_eq!(s(misb_value_kind_name(i as u32 + 1)), *name);
    }
    assert!(misb_value_kind_name(0).is_null());
    assert!(misb_value_kind_name(14).is_null());
    for std in [Standard::St0601, Standard::St0102, Standard::St0806, Standard::St0903] {
        assert_eq!(s(misb_standard_name(standard_code(std))), std.name());
    }
    assert!(misb_standard_name(0).is_null());
    assert!(misb_standard_name(5).is_null());
    assert_eq!(s(misb_error_name(MISB_ERROR_NONE)), "no error");
    for e in [
        Error::Truncated { needed: 1, available: 0 },
        Error::BadLength,
        Error::BadTag,
        Error::TooLarge { size: 2, limit: 1 },
        Error::NotSt0601,
        Error::TooDeep,
        Error::TooManyItems { count: 2, limit: 1 },
        Error::InvalidConfig("max_items is 0"),
    ] {
        let name = s(misb_error_name(error_code(&e)));
        assert!(e.to_string().starts_with(&name), "{e}: {name}");
    }
    assert_eq!((error_code(&Error::TooManyItems { count: 2, limit: 1 }), error_code(&Error::InvalidConfig("x"))), (7, 8));
    assert!(misb_error_name(9).is_null());
}

#[test]
fn config_default_and_versioning() {
    unsafe {
        let mut cfg = misb_config {
            verify_checksum: 0,
            max_items: 7,
            keep_raw: 0,
            ..misb_config::from(&Config::default())
        };
        assert_eq!(misb_config_default(&mut cfg), MISB_OK);
        assert_eq!((cfg.verify_checksum, cfg.reject_bad_checksum), (1, 0));
        assert_eq!((cfg.max_packet_bytes, cfg.max_buffer_bytes, cfg.max_depth, cfg.max_items), (1 << 20, 4 << 20, 8, 65_536));
        assert_eq!((cfg.max_skip_bytes, cfg.max_total_items, cfg.keep_raw, cfg.reserved2), (1 << 20, 65_536, 1, 0));
        assert_eq!(cfg.to_config(), Ok(Config::default()));
        // Every Config field round-trips through the C struct.
        let mut rust = Config::default();
        rust.max_skip_bytes = 77;
        rust.max_total_items = 99;
        rust.keep_raw = false;
        rust.reject_bad_checksum = true;
        assert_eq!(misb_config::from(&rust).to_config(), Ok(rust));

        // An older caller that only knows the first two fields.
        let mut buf = ShortOutput::new(8);
        assert_eq!(misb_config_default(buf.as_mut_ptr()), MISB_OK);
        assert_eq!(&buf.0[..2], &[8, 1]);
        assert!(buf.0[2..].iter().all(|&word| word == ShortOutput::UNWRITTEN));

        // A newer caller with a bigger struct: the tail is untouched.
        #[repr(C)]
        struct Newer {
            cfg: misb_config,
            extra: u64,
        }
        let mut n = Newer { cfg, extra: 0xABCD };
        n.cfg.struct_size = mem::size_of::<Newer>() as u32;
        assert_eq!(misb_config_default(&mut n.cfg), MISB_OK);
        assert_eq!(n.cfg.struct_size as usize, mem::size_of::<misb_config>());
        assert_eq!(n.extra, 0xABCD);

        assert_eq!(misb_config_default(ptr::null_mut()), MISB_ERR_NULL);
        let mut tiny = misb_config { struct_size: 3, ..cfg };
        assert_eq!(misb_config_default(&mut tiny), MISB_ERR_INVALID);
    }
}

#[test]
fn invalid_config_is_rejected() {
    unsafe {
        let good = misb_config::from(&Config::default());
        let mut d = ptr::null_mut();
        for bad in [
            misb_config { verify_checksum: 2, ..good },
            misb_config { reject_bad_checksum: u32::MAX, ..good },
            misb_config { struct_size: 2, ..good },
            misb_config { struct_size: 0, ..good },
            misb_config { keep_raw: 2, ..good },
            // Limits Config::validate refuses.
            misb_config { max_items: 0, ..good },
            misb_config { max_packet_bytes: 0, ..good },
            misb_config { max_buffer_bytes: 0, ..good },
            misb_config { max_skip_bytes: 0, ..good },
            misb_config { max_total_items: 0, ..good },
            misb_config { max_depth: Config::MAX_DEPTH_LIMIT as u64 + 1, ..good },
        ] {
            d = 1 as *mut misb_decoder; // must be cleared
            assert_eq!(misb_decoder_new(&bad, &mut d), MISB_ERR_INVALID);
            assert!(d.is_null());
        }
        // Reserved is ignored, and any size fits a 64-bit size_t.
        let odd = misb_config { reserved: 99, max_packet_bytes: u64::MAX, max_depth: 0, ..good };
        if usize::BITS == 64 {
            assert_eq!(misb_decoder_new(&odd, &mut d), MISB_OK);
            assert!(!d.is_null());
            assert_eq!(odd.to_config().unwrap().max_packet_bytes, usize::MAX);
            misb_decoder_free(d);
        } else {
            assert_eq!(misb_decoder_new(&odd, &mut d), MISB_ERR_INVALID);
        }
    }
}

#[test]
fn decoder_flow_matches_rust() {
    compare_decoder(None, Config::default());
}

#[test]
fn decoder_honours_the_config_prefix() {
    let defaults = misb_config::from(&Config::default());
    let mut expected = Config::default();
    expected.verify_checksum = false;
    let old = misb_config { struct_size: 8, verify_checksum: 0, max_items: 1, ..defaults };
    compare_decoder(Some(&old), expected);

    let mut expected = Config::default();
    expected.max_items = 5;
    let v1 = misb_config { struct_size: 56, max_items: 5, max_total_items: 0, keep_raw: 7, ..defaults };
    compare_decoder(Some(&v1), expected);

    let mut expected = Config::default();
    expected.keep_raw = false;
    expected.max_total_items = 9;
    let full = misb_config { keep_raw: 0, max_total_items: 9, ..defaults };
    compare_decoder(Some(&full), expected);
}

fn compare_decoder(config: Option<&misb_config>, expected: Config) {
    let data = stream();
    let mut rust = Decoder::with_config(expected).unwrap();
    rust.push(&data);
    let mid: Vec<Packet> = rust.packets().collect();
    rust.finish();
    let tail: Vec<Packet> = rust.packets().collect();
    assert_eq!((mid.len(), tail.len()), (4, 0));

    for chunk in [1, 7, 100, data.len()] {
        let d = new_decoder(config);
        let mut got = Vec::new();
        unsafe {
            for c in data.chunks(chunk) {
                assert_eq!(misb_decoder_push(d, c.as_ptr(), c.len()), MISB_OK);
                got.extend(drain(d));
            }
            assert_eq!(misb_decoder_finish(d), MISB_OK);
            got.extend(drain(d));
        }
        assert_eq!(got.len(), mid.len(), "chunks of {chunk}");
        for (h, p) in got.iter().zip(&mid) {
            check_packet(*h, p);
        }
        let mut stats = new_stats();
        unsafe { assert_eq!(misb_decoder_stats(d, &mut stats), MISB_OK) };
        let r = rust.stats();
        assert_eq!(
            (stats.packets, stats.bytes, stats.bytes_skipped, stats.resyncs, stats.skipped_keys),
            (r.packets, r.bytes, r.bytes_skipped, r.resyncs, r.skipped_keys)
        );
        assert_eq!(
            (stats.oversized, stats.checksum_errors, stats.malformed, stats.truncated_at_finish, stats.dropped),
            (r.oversized, r.checksum_errors, r.malformed, r.truncated_at_finish, r.dropped)
        );
        assert_eq!(
            (stats.checksum_missing, stats.nested_errors, stats.packet_bytes, stats.bad_lengths),
            (r.checksum_missing, r.nested_errors, r.packet_bytes, r.bad_lengths)
        );
        assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
        assert_eq!((stats.packets, stats.skipped_keys, stats.truncated_at_finish), (4, 1, 1));

        unsafe {
            // Packets outlive the decoder, and reset leaves them alone.
            assert_eq!(misb_decoder_push(d, data.as_ptr(), data.len()), MISB_OK);
            assert_eq!(misb_decoder_reset(d), MISB_OK);
            assert!(drain(d).is_empty());
            let mut stats = new_stats();
            assert_eq!(misb_decoder_stats(d, &mut stats), MISB_OK);
            assert_eq!((stats.packets, stats.bytes), (0, 0));
            misb_decoder_free(d);
        }
        for (h, p) in got.iter().zip(&mid) {
            check_packet(*h, p);
            unsafe { misb_packet_free(*h) };
        }
    }
}

/// misb.h: drained after each one, slices of up to 64 KiB with the default
/// limits, and of (max_buffer_bytes - max_packet_bytes - 1024) / 8 bytes in
/// general, never drop a packet; one large push can.
#[test]
fn push_slices_documented_in_the_header_never_drop() {
    let push_all = |cfg: Option<&misb_config>, data: &[u8], slice: usize| {
        let d = new_decoder(cfg);
        let mut n = 0u64;
        for c in data.chunks(slice) {
            unsafe { assert_eq!(misb_decoder_push(d, c.as_ptr(), c.len()), MISB_OK) };
            for h in drain(d) {
                unsafe { misb_packet_free(h) };
                n += 1;
            }
        }
        let mut stats = new_stats();
        unsafe {
            assert_eq!(misb_decoder_stats(d, &mut stats), MISB_OK);
            misb_decoder_free(d);
        }
        (n, stats.dropped)
    };
    // The smallest packets (17 bytes: key and a zero length) cost the queue
    // the most per input byte; a partial large packet waits before them.
    let tiny = {
        let mut t = st0601::KEY.to_vec();
        t.push(0);
        t
    };
    let stream = |big: usize, tiny_count: usize, rounds: usize| {
        let mut s = Vec::new();
        for _ in 0..rounds {
            let packet = st0601_packet(&[(3, &vec![b'x'; big])]);
            let (_, used) = crate::decode_prefix(&packet, &Config::default()).unwrap();
            assert_eq!(used, packet.len());
            s.extend(packet);
            for _ in 0..tiny_count {
                s.extend(&tiny);
            }
        }
        s
    };
    let data = stream((1 << 20) - 16, 20_000, 3);
    let total = 3 * 20_001;
    for slice in [65_536, 65_536 - 7, 40_000] {
        assert_eq!(push_all(None, &data, slice), (total, 0), "slices of {slice}");
    }
    let (n, dropped) = push_all(None, &data, data.len());
    assert!(dropped > 0 && n + dropped == total, "one push can drop");

    let good = misb_config::from(&Config::default());
    let small = misb_config { max_buffer_bytes: 100_000, max_packet_bytes: 10_000, ..good };
    let slice = (100_000 - 10_000 - 1024) / 8;
    let data = stream(10_000 - 16, 3_000, 4);
    for s in [slice, slice - 13, slice / 3] {
        assert_eq!(push_all(Some(&small), &data, s), (4 * 3_001, 0), "slices of {s}");
    }
}

#[test]
fn decoder_config_is_honoured() {
    let data = stream();
    let count = |cfg: misb_config| {
        let d = new_decoder(Some(&cfg));
        unsafe {
            misb_decoder_push(d, data.as_ptr(), data.len());
            misb_decoder_finish(d);
        }
        let got = drain(d);
        let mut stats = new_stats();
        unsafe { assert_eq!(misb_decoder_stats(d, &mut stats), MISB_OK) };
        let mut checksums = Vec::new();
        for h in got {
            let mut info = new_info();
            unsafe {
                assert_eq!(misb_packet_info_get(h, &mut info), MISB_OK);
                misb_packet_free(h);
                checksums.push(info.checksum);
            }
        }
        unsafe { misb_decoder_free(d) };
        (checksums, stats)
    };
    let good = misb_config::from(&Config::default());
    let (sums, _) = count(good);
    assert_eq!(sums, [1, 1, 2, 1]);
    let (sums, stats) = count(misb_config { reject_bad_checksum: 1, ..good });
    assert_eq!((sums, stats.checksum_errors), (vec![1, 1, 1], 1));
    let (sums, _) = count(misb_config { verify_checksum: 0, ..good });
    assert_eq!(sums, [0, 0, 0, 0]);
    let (sums, stats) = count(misb_config { max_packet_bytes: 40, ..good });
    assert_eq!((sums.len(), stats.oversized), (3, 1));
}

#[test]
fn null_pointers_are_rejected() {
    let buf = st0601_packet(&[(3, b"x")]);
    unsafe {
        let mut d = ptr::null_mut();
        let mut p = ptr::null_mut();
        let mut it = new_item();
        let mut info = new_info();
        let mut cell = new_cell();
        let mut stats = new_stats();
        let mut offset = 0usize;

        assert_eq!(misb_config_default(ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decoder_new(ptr::null(), ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decoder_push(ptr::null_mut(), ptr::null(), 0), MISB_ERR_NULL);
        assert_eq!(misb_decoder_finish(ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decoder_reset(ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decoder_next(ptr::null_mut(), &mut p), MISB_ERR_NULL);
        assert_eq!(misb_decoder_stats(ptr::null(), &mut stats), MISB_ERR_NULL);
        misb_decoder_free(ptr::null_mut());

        assert_eq!(misb_decoder_new(ptr::null(), &mut d), MISB_OK);
        assert_eq!(misb_decoder_push(d, ptr::null(), 10), MISB_ERR_NULL);
        assert_eq!(misb_decoder_push(d, ptr::null(), 0), MISB_OK);
        assert_eq!(misb_decoder_next(d, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decoder_stats(d, ptr::null_mut()), MISB_ERR_NULL);
        misb_decoder_free(d);

        assert_eq!(misb_decode(buf.as_ptr(), buf.len(), ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_decode(ptr::null(), 5, &mut p), MISB_ERR_NULL);
        let (mut used, mut error) = (9usize, 9u32);
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), ptr::null(), ptr::null_mut(), &mut used, &mut error), MISB_ERR_NULL);
        assert_eq!(misb_decode_ex(ptr::null(), 5, ptr::null(), &mut p, &mut used, &mut error), MISB_ERR_NULL);
        assert!(p.is_null());
        // The two trailing out pointers are optional.
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), ptr::null(), &mut p, ptr::null_mut(), ptr::null_mut()), MISB_OK);

        assert_eq!(misb_packet_info_get(ptr::null(), &mut info), MISB_ERR_NULL);
        assert_eq!(misb_packet_info_get(p, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_packet_root(ptr::null(), &mut it), MISB_ERR_NULL);
        assert_eq!(misb_packet_root(p, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_packet_item(ptr::null(), 0, &mut it), MISB_ERR_NULL);
        assert_eq!(misb_packet_item(p, 0, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_packet_item(p, 99, ptr::null_mut()), MISB_ERR_NULL, "NULL before range");
        assert_eq!(misb_packet_find(ptr::null(), 3, &mut it), MISB_ERR_NULL);
        assert_eq!(misb_packet_find(p, 3, ptr::null_mut()), MISB_ERR_NULL);
        let r = root(p);
        assert_eq!(misb_item_child(ptr::null(), 0, &mut it), MISB_ERR_NULL);
        assert_eq!(misb_item_child(&r, 0, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_item_find(ptr::null(), 3, &mut it), MISB_ERR_NULL);
        assert_eq!(misb_item_find(&r, 3, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_item_field(ptr::null(), b"Mission ID\0".as_ptr() as *const c_char, &mut it), MISB_ERR_NULL);
        assert_eq!(misb_item_field(&r, ptr::null(), &mut it), MISB_ERR_NULL);
        assert_eq!(misb_item_field(&r, b"x\0".as_ptr() as *const c_char, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_set_info_get(ptr::null(), &mut info), MISB_ERR_NULL);
        assert_eq!(misb_set_info_get(&r, ptr::null_mut()), MISB_ERR_NULL);
        misb_packet_free(p);
        misb_packet_free(ptr::null_mut());

        assert_eq!(misb_au_cell_next(ptr::null(), 0, ptr::null_mut(), &mut cell), MISB_ERR_NULL);
        assert_eq!(misb_au_cell_next(ptr::null(), 0, &mut offset, ptr::null_mut()), MISB_ERR_NULL);
        assert_eq!(misb_au_cell_next(ptr::null(), 4, &mut offset, &mut cell), MISB_ERR_NULL);
        assert_eq!(misb_au_cell_next(ptr::null(), 0, &mut offset, &mut cell), MISB_EMPTY);
    }
}

#[test]
fn poisoned_decoder_refuses_work() {
    let mut handle = misb_decoder { decoder: Decoder::new(), poisoned: false };
    let buf = st0601_packet(&[(3, b"x")]);
    handle.decoder.push(&buf);
    assert_eq!(guard_mut(&mut handle, |_| panic!("boom")), MISB_ERR_PANIC);
    assert!(handle.poisoned);
    let d: *mut misb_decoder = &mut handle;
    unsafe {
        assert_eq!(misb_decoder_push(d, [0u8].as_ptr(), 1), MISB_ERR_POISONED);
        assert_eq!(misb_decoder_finish(d), MISB_ERR_POISONED);
        assert_eq!(misb_decoder_reset(d), MISB_ERR_POISONED);
        let mut p = 1 as *mut misb_packet;
        assert_eq!(misb_decoder_next(d, &mut p), MISB_ERR_POISONED);
        assert!(p.is_null(), "out is cleared");
        let mut stats = new_stats();
        assert_eq!(misb_decoder_stats(d, &mut stats), MISB_ERR_POISONED);
    }
    assert_eq!(guard(|| panic!("boom")), MISB_ERR_PANIC);
}

#[test]
fn every_kind_of_value() {
    let p = every_kind();
    let h = handle(p.clone());
    check_packet(h, &p);
    let r = root(h);
    let mut info = new_info();
    unsafe { assert_eq!(misb_packet_info_get(h, &mut info), MISB_OK) };
    assert_eq!((info.standard, info.checksum, info.checksum_expected, info.checksum_computed), (1, 2, 0x1234, 0xABCD));
    assert_eq!((info.error, s(info.error_message).as_str(), info.item_count), (MISB_ERROR_BAD_LENGTH, "malformed BER length", 16));

    // A few fields spelled out, beyond the generic comparison.
    let time = child(&r, 0);
    assert_eq!((time.kind, time.time_us, s(time.units).as_str()), (MISB_VALUE_TIME, 1_224_807_209_913_000, "us"));
    let text = child(&r, 1);
    assert_eq!((text.kind, text.data_len), (MISB_VALUE_TEXT, 8));
    assert_eq!(unsafe { bytes(text.data, 9) }, b"MI\0SSION\0", "full text despite the NUL");
    let empty = child(&r, 5);
    assert_eq!((empty.kind, empty.data_len), (MISB_VALUE_BYTES, 0));
    assert!(!empty.data.is_null() && !empty.raw.is_null());
    let code = child(&r, 7);
    assert_eq!((code.enum_code, code.enum_label), (9, ptr::null()));
    assert_eq!(child(&r, 8).kind, MISB_VALUE_OUT_OF_RANGE);
    let broken = child(&r, 9);
    assert_eq!((broken.kind, s(broken.invalid_reason).as_str(), broken.raw_len), (MISB_VALUE_INVALID, "wrong length", 5));
    let set = child(&r, 10);
    assert_eq!((set.kind, set.standard, set.child_count), (MISB_VALUE_SET, MISB_STANDARD_ST0102, 2));
    let set_info = info_of(&set);
    assert_eq!((set_info.checksum, set_info.error), (MISB_CHECKSUM_NOT_APPLICABLE, MISB_ERROR_TRUNCATED));
    assert_eq!(s(set_info.error_message), "truncated: needed 5 bytes, 2 available");
    let class = child(&set, 0);
    assert_eq!((class.tag, s(class.name).as_str(), s(class.enum_label).as_str()), (1, "Security Classification", "UNCLASSIFIED//"));
    let list = child(&r, 11);
    let inner = child(&list, 1);
    assert_eq!((inner.kind, inner.child_count), (MISB_VALUE_LIST, 2));
    assert!(child(&inner, 0).float_value.is_nan());
    let empty_text = child(&inner, 1);
    assert_eq!(empty_text.data_len, 0);
    assert!(!empty_text.data.is_null());
    let x = child(&child(&list, 2), 0);
    assert_eq!((s(x.name).as_str(), x.int_value), ("x", -1));
    let blank = child(&child(&r, 12), 3);
    assert_eq!((s(blank.name).as_str(), s(blank.enum_label).as_str()), ("", ""), "an empty label is not NULL");
    // A zero-length item: kind UNKNOWN, no value fields, empty raw bytes.
    let unknown = child(&r, 15);
    assert_eq!((unknown.kind, unknown.tag, unknown.raw_len, unknown.child_count), (MISB_VALUE_UNKNOWN, 15, 0, 0));
    assert!(!unknown.raw.is_null() && unknown.data.is_null() && unknown.invalid_reason.is_null());
    assert_eq!(s(misb_value_kind_name(unknown.kind)), "unknown");
    unsafe { misb_packet_free(h) };
}

#[test]
fn find_field_and_navigation_errors() {
    let h = handle(every_kind());
    let r = root(h);
    unsafe {
        let mut it = new_item();
        assert_eq!(misb_packet_find(h, 48, &mut it), MISB_OK);
        assert_eq!(it.kind, MISB_VALUE_SET);
        let set = it;
        assert_eq!(misb_item_find(&set, 3, &mut it), MISB_OK);
        assert_eq!(s(it.name), "Classifying Country");
        assert_eq!(misb_item_find(&set, 2, &mut it), MISB_EMPTY);
        assert_eq!(misb_packet_find(h, 99, &mut it), MISB_EMPTY);
        assert_eq!(misb_item_find(&r, 1, &mut it), MISB_OK);
        assert_eq!(it.uint_value, 0x1234);

        // Fields by name: the first match wins; set items match by tag name.
        assert_eq!(misb_packet_find(h, 14, &mut it), MISB_OK);
        let st = it;
        assert_eq!(misb_item_field(&st, b"lat\0".as_ptr() as *const c_char, &mut it), MISB_OK);
        assert_eq!((it.tag, it.float_value), (0, 1.5));
        assert_eq!(misb_item_field(&st, b"lon\0".as_ptr() as *const c_char, &mut it), MISB_OK);
        assert_eq!(it.float_value, -2.5);
        assert_eq!(misb_item_field(&st, b"la\0".as_ptr() as *const c_char, &mut it), MISB_EMPTY);
        assert_eq!(misb_item_field(&st, b"\0".as_ptr() as *const c_char, &mut it), MISB_OK);
        assert_eq!(it.tag, 3);
        assert_eq!(misb_item_find(&st, 2, &mut it), MISB_OK, "struct children are found by index");
        assert_eq!(it.uint_value, 7);
        assert_eq!(misb_item_field(&r, b"Mission ID\0".as_ptr() as *const c_char, &mut it), MISB_OK);
        assert_eq!(it.tag, 3);

        // Kinds without children.
        assert_eq!(misb_packet_item(h, 0, &mut it), MISB_OK);
        let scalar = it;
        assert_eq!(misb_item_child(&scalar, 0, &mut it), MISB_ERR_RANGE);
        assert_eq!(misb_item_find(&scalar, 0, &mut it), MISB_EMPTY);
        assert_eq!(misb_item_field(&scalar, b"\0".as_ptr() as *const c_char, &mut it), MISB_EMPTY);
        assert_eq!(misb_packet_item(h, 16, &mut it), MISB_ERR_RANGE);
        assert_eq!(misb_packet_item(h, usize::MAX, &mut it), MISB_ERR_RANGE);
        assert_eq!(misb_item_child(&r, usize::MAX, &mut it), MISB_ERR_RANGE);

        // Items the library did not write.
        let mut forged = r;
        forged.id = 1_000_000;
        assert_eq!(misb_item_child(&forged, 0, &mut it), MISB_ERR_INVALID);
        forged.id = u64::MAX;
        assert_eq!(misb_item_find(&forged, 0, &mut it), MISB_ERR_INVALID);
        forged = r;
        forged.packet = ptr::null();
        assert_eq!(misb_item_child(&forged, 0, &mut it), MISB_ERR_INVALID);
        let mut info = new_info();
        assert_eq!(misb_set_info_get(&forged, &mut info), MISB_ERR_INVALID);
        // A caller struct too short to carry packet and id.
        forged = r;
        forged.struct_size = (item_ref_size() - 1) as u32;
        assert_eq!(misb_item_child(&forged, 0, &mut it), MISB_ERR_INVALID);
        forged.struct_size = 2;
        assert_eq!(misb_item_child(&forged, 0, &mut it), MISB_ERR_INVALID);
        forged.struct_size = item_ref_size() as u32;
        assert_eq!(misb_item_child(&forged, 0, &mut it), MISB_OK, "packet and id are enough");

        // Output structs too small to hold struct_size.
        let mut tiny = new_item();
        tiny.struct_size = 3;
        assert_eq!(misb_item_child(&r, 0, &mut tiny), MISB_ERR_INVALID);
        assert_eq!(misb_packet_item(h, 0, &mut tiny), MISB_ERR_INVALID);
        assert_eq!(misb_packet_find(h, 3, &mut tiny), MISB_ERR_INVALID);
        assert_eq!(misb_packet_root(h, &mut tiny), MISB_ERR_INVALID);
        misb_packet_free(h);
    }
}

#[test]
fn item_struct_size_and_aliasing() {
    let h = handle(every_kind());
    let r = root(h);
    unsafe {
        // An older caller with a smaller struct: only that much written.
        let mut buf = ShortOutput::new(8);
        assert_eq!(misb_item_child(&r, 4, buf.as_mut_ptr()), MISB_OK);
        assert_eq!(&buf.0[..2], &[8, MISB_VALUE_UINT]);
        assert!(buf.0[2..].iter().all(|&word| word == ShortOutput::UNWRITTEN));

        // A newer caller with a bigger struct: the tail is untouched.
        #[repr(C)]
        struct Newer {
            item: misb_item,
            extra: u64,
        }
        let mut n = Newer { item: new_item(), extra: 0xABCD };
        n.item.struct_size = mem::size_of::<Newer>() as u32;
        assert_eq!(misb_item_child(&r, 4, &mut n.item), MISB_OK);
        assert_eq!(n.item.struct_size as usize, mem::size_of::<misb_item>());
        assert_eq!((n.item.uint_value, n.extra), (42, 0xABCD));

        // Descending in place: out may be the parent.
        let mut it = r;
        let at: *mut misb_item = &mut it;
        assert_eq!(misb_item_child(at, 11, at), MISB_OK);
        assert_eq!(misb_item_child(at, 2, at), MISB_OK);
        assert_eq!(misb_item_find(at, 0, at), MISB_OK);
        assert_eq!((s(it.name).as_str(), it.int_value), ("x", -1));

        // Info structs follow the same rules.
        let mut buf = ShortOutput::new(12);
        assert_eq!(misb_packet_info_get(h, buf.as_mut_ptr()), MISB_OK);
        assert_eq!(&buf.0[..3], &[12, 1, 2]);
        assert!(buf.0[3..].iter().all(|&word| word == ShortOutput::UNWRITTEN));
        misb_packet_free(h);
    }
}

#[test]
fn pointers_are_owned_and_stable() {
    let h = handle(every_kind());
    let first = root(h);
    let a = child(&first, 1);
    let set = child(&first, 10);
    let info = info_of(&set);
    // Other packets come and go; nothing in this one moves or changes.
    for _ in 0..50 {
        let other = handle(every_kind());
        unsafe { misb_packet_free(other) };
    }
    let again = child(&root(h), 1);
    assert_eq!((a.name, a.units, a.data, a.raw), (again.name, again.units, again.data, again.raw));
    assert_eq!(info.error_message, info_of(&child(&first, 10)).error_message);
    assert_eq!(s(a.name), "Mission ID");
    assert_eq!(unsafe { bytes(a.data, a.data_len) }, b"MI\0SSION");
    // Strings live in the handle, not in the Rust tables.
    let hp = unsafe { &*h };
    let arena = hp.arena.as_ptr_range();
    for p in [a.name, a.data as *const c_char, info.error_message] {
        assert!(arena.contains(&(p as *const u8)), "pointer into the packet's own storage");
    }
    // One copy of each static string per packet.
    let units: Vec<_> = (0..15).map(|i| child(&first, i)).filter(|c| s(c.units) == "deg").map(|c| c.units).collect();
    assert_eq!(units.len(), 3);
    assert!(units.iter().all(|&u| u == units[0]));
    unsafe { misb_packet_free(h) };
}

#[test]
fn deep_and_wide_trees() {
    // A list nested 2000 deep: built without recursion, walked by index.
    let mut v = Value::Uint(7);
    for _ in 0..2000 {
        v = Value::List(vec![v]);
    }
    let mut p = Packet::new(Standard::St0601);
    p.items.push(item(5, "Deep", "", v, &[]));
    let wide: Vec<Value> = (0..100_000u64).map(Value::Uint).collect();
    p.items.push(item(6, "Wide", "", Value::List(wide), &[]));
    let h = handle(p);
    let mut it = child(&root(h), 0);
    let at: *mut misb_item = &mut it;
    for _ in 0..2000 {
        assert_eq!(unsafe { (*at).child_count }, 1);
        assert_eq!(unsafe { misb_item_child(at, 0, at) }, MISB_OK);
    }
    assert_eq!((it.kind, it.uint_value), (MISB_VALUE_UINT, 7));
    let wide = child(&root(h), 1);
    assert_eq!(wide.child_count, 100_000);
    assert_eq!(child(&wide, 99_999).uint_value, 99_999);
    let mut e = new_item();
    assert_eq!(unsafe { misb_item_find(&wide, 54_321, &mut e) }, MISB_OK);
    assert_eq!(e.uint_value, 54_321);
    assert_eq!(unsafe { (*h).nodes.len() }, 1 + 2 + 2000 + 100_000);
    // Dropping a 2000-deep Value recurses in Rust's drop glue; unwrap it
    // here by hand so the test does not depend on the thread's stack.
    let mut owned = unsafe { Box::from_raw(h) };
    let mut deep = mem::replace(&mut owned.packet.items[0].value, Value::OutOfRange);
    drop(owned);
    while let Value::List(mut l) = deep {
        deep = l.pop().unwrap_or(Value::OutOfRange);
    }
}

#[test]
fn thread_rules_hold() {
    // The header lets a decoder move between threads, and any number of
    // threads read one packet: what the handles wrap must allow both.
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<Decoder>();
    send::<Packet>();
    sync::<Packet>();
}

#[test]
fn packets_are_readable_from_many_threads() {
    struct Shared(*const misb_packet);
    impl Shared {
        fn get(&self) -> *const misb_packet {
            self.0
        }
    }
    // SAFETY: the header allows any number of threads to read a packet.
    unsafe impl Send for Shared {}
    unsafe impl Sync for Shared {}
    let p = every_kind();
    let h = handle(p.clone());
    let shared = Shared(h);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..200 {
                    check_packet(shared.get(), &p);
                }
            });
        }
    });
    unsafe { misb_packet_free(h) };
}

#[test]
fn decode_one_packet() {
    let mut buf = st0601_packet(&[(2, &TIME), (3, b"MISSION01")]);
    let len = buf.len();
    buf.extend([0xFF; 5]); // trailing bytes are ignored
    unsafe {
        let mut p = ptr::null_mut();
        assert_eq!(misb_decode(buf.as_ptr(), buf.len(), &mut p), MISB_OK);
        check_packet(p, &crate::decode(&buf).unwrap());
        misb_packet_free(p);

        let (mut used, mut error) = (0usize, 99u32);
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), ptr::null(), &mut p, &mut used, &mut error), MISB_OK);
        assert_eq!((used, error), (len, MISB_ERROR_NONE));
        check_packet(p, &crate::decode(&buf).unwrap());
        misb_packet_free(p);

        // Parse errors, with the reason.
        let cases: [(&[u8], u32); 5] = [
            (&[], MISB_ERROR_TRUNCATED),
            (&[0x00], MISB_ERROR_NOT_ST0601),
            (&buf[..len - 1], MISB_ERROR_TRUNCATED),
            (&buf[..10], MISB_ERROR_TRUNCATED),
            (&[0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0, 0, 0, 0x80], MISB_ERROR_BAD_LENGTH),
        ];
        for (input, why) in cases {
            p = 1 as *mut misb_packet;
            assert_eq!(misb_decode(input.as_ptr(), input.len(), &mut p), MISB_ERR_PARSE);
            assert!(p.is_null());
            used = 99;
            assert_eq!(misb_decode_ex(input.as_ptr(), input.len(), ptr::null(), &mut p, &mut used, &mut error), MISB_ERR_PARSE);
            assert_eq!((p, used, error), (ptr::null_mut(), 0, why), "{input:02X?}");
        }
        assert_eq!(misb_decode(ptr::null(), 0, &mut p), MISB_ERR_PARSE);
        assert_eq!(misb_decode(buf.as_ptr(), usize::MAX, &mut p), MISB_ERR_INVALID);
        assert_eq!(misb_decode_ex(buf.as_ptr(), usize::MAX, ptr::null(), &mut p, &mut used, &mut error), MISB_ERR_INVALID);

        // The config is honoured.
        let good = misb_config::from(&Config::default());
        let small = misb_config { max_packet_bytes: 10, ..good };
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), &small, &mut p, &mut used, &mut error), MISB_ERR_PARSE);
        assert_eq!(error, MISB_ERROR_TOO_LARGE);
        let off = misb_config { verify_checksum: 0, ..good };
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), &off, &mut p, &mut used, &mut error), MISB_OK);
        let mut info = new_info();
        assert_eq!(misb_packet_info_get(p, &mut info), MISB_OK);
        assert_eq!(info.checksum, MISB_CHECKSUM_NOT_APPLICABLE);
        misb_packet_free(p);
        let bad = misb_config { verify_checksum: 5, ..good };
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), &bad, &mut p, &mut used, &mut error), MISB_ERR_INVALID);
        assert!(p.is_null());
        let zero = misb_config { max_items: 0, ..good };
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), &zero, &mut p, &mut used, &mut error), MISB_ERR_INVALID);
        assert!(p.is_null());
        // A declared length over max_packet_bytes is TOO_LARGE even when
        // the buffer is cut short, as in decode_prefix.
        let mut huge = st0601::KEY.to_vec();
        huge.extend([0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0, 0]);
        assert_eq!(misb_decode_ex(huge.as_ptr(), huge.len(), ptr::null(), &mut p, &mut used, &mut error), MISB_ERR_PARSE);
        assert_eq!(error, MISB_ERROR_TOO_LARGE);
        // keep_raw is honoured.
        let lean = misb_config { keep_raw: 0, ..good };
        assert_eq!(misb_decode_ex(buf.as_ptr(), buf.len(), &lean, &mut p, &mut used, &mut error), MISB_OK);
        let mut it = new_item();
        assert_eq!(misb_packet_find(p, 3, &mut it), MISB_OK);
        assert_eq!((it.kind, it.raw_len, it.data_len), (MISB_VALUE_TEXT, 0, 9));
        misb_packet_free(p);

        // Walk a buffer of packets with `consumed`.
        let mut all = Vec::new();
        for i in 0..5u8 {
            all.extend(st0601_packet(&[(3, &vec![b'a' + i; 200 * usize::from(i)])]));
        }
        let mut at = 0;
        let mut n = 0;
        while at < all.len() {
            assert_eq!(misb_decode_ex(all[at..].as_ptr(), all.len() - at, ptr::null(), &mut p, &mut used, ptr::null_mut()), MISB_OK);
            misb_packet_free(p);
            at += used;
            n += 1;
        }
        assert_eq!((at, n), (all.len(), 5));
    }
}

#[test]
fn decode_ex_is_decode_prefix() {
    // misb_decode_ex is crate::decode_prefix behind the C types: the same
    // packets, sizes and errors on valid, damaged and foreign input.
    let mut inputs = vec![hex(ST0902_TABLE_10), st0601_packet(&[(48, &security_set())]), st0601::KEY.to_vec()];
    let base = st0601_packet(&[(2, &TIME), (3, b"MISSION01"), (48, &security_set())]);
    for cut in 0..=base.len() {
        inputs.push(base[..cut].to_vec());
    }
    let mut rng = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..500 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let mut b = base.clone();
        let i = rng as usize % b.len();
        b[i] ^= 1 << ((rng >> 32) % 8);
        inputs.push(b);
    }
    for buf in &inputs {
        let want = crate::decode_prefix(buf, &Config::default());
        let (mut p, mut used, mut error) = (ptr::null_mut(), 0usize, 0u32);
        let status = unsafe { misb_decode_ex(buf.as_ptr(), buf.len(), ptr::null(), &mut p, &mut used, &mut error) };
        match want {
            Ok((packet, n)) => {
                assert_eq!((status, used, error), (MISB_OK, n, MISB_ERROR_NONE));
                check_packet(p, &packet);
                unsafe { misb_packet_free(p) };
            }
            Err(e) => assert_eq!((status, used, error, p), (MISB_ERR_PARSE, 0, error_code(&e), ptr::null_mut())),
        }
    }
}

#[test]
fn au_cells_from_c() {
    let mut pes = vec![1, 9, 0b1010_0000, 0, 3, 0xA, 0xB, 0xC];
    pes.extend([2, 10, 0b1101_1111, 0, 0]);
    pes.extend([0, 0, 0xC0]); // cut short
    unsafe {
        let mut offset = 0usize;
        let mut cell = new_cell();
        assert_eq!(misb_au_cell_next(pes.as_ptr(), pes.len(), &mut offset, &mut cell), MISB_OK);
        assert_eq!((cell.service_id, cell.sequence_number, cell.fragment, cell.decoder_config, cell.random_access), (1, 9, 2, 1, 0));
        assert_eq!(bytes(cell.data, cell.data_len), &[0xA, 0xB, 0xC]);
        assert_eq!(cell.data, pes.as_ptr().add(5), "points into the input");
        assert_eq!(offset, 8);
        assert_eq!(misb_au_cell_next(pes.as_ptr(), pes.len(), &mut offset, &mut cell), MISB_OK);
        assert_eq!((cell.service_id, cell.fragment, cell.decoder_config, cell.random_access, cell.data_len), (2, 3, 0, 1, 0));
        assert!(!cell.data.is_null());
        assert_eq!(offset, 13);
        assert_eq!(misb_au_cell_next(pes.as_ptr(), pes.len(), &mut offset, &mut cell), MISB_ERR_PARSE);
        assert_eq!(offset, 13, "offset unchanged on error");
        assert_eq!(misb_au_cell_next(pes.as_ptr(), 13, &mut offset, &mut cell), MISB_EMPTY);
        offset = 14;
        assert_eq!(misb_au_cell_next(pes.as_ptr(), 13, &mut offset, &mut cell), MISB_ERR_RANGE);
        offset = usize::MAX;
        assert_eq!(misb_au_cell_next(pes.as_ptr(), 13, &mut offset, &mut cell), MISB_ERR_RANGE);

        // Struct size rules: too small is invalid and does not advance;
        // shorter is written only that far.
        offset = 0;
        let mut tiny = new_cell();
        tiny.struct_size = 2;
        assert_eq!(misb_au_cell_next(pes.as_ptr(), pes.len(), &mut offset, &mut tiny), MISB_ERR_INVALID);
        assert_eq!(offset, 0);
        let mut buf = ShortOutput::new(6);
        assert_eq!(misb_au_cell_next(pes.as_ptr(), pes.len(), &mut offset, buf.as_mut_ptr()), MISB_OK);
        assert_eq!(buf.0[0], 6);
        assert_eq!(buf.0[1].to_ne_bytes(), [1, 9, 0xEE, 0xEE]);
        assert!(buf.0[2..].iter().all(|&word| word == ShortOutput::UNWRITTEN));
        assert_eq!(offset, 8);
        assert_eq!(misb_au_cell_next(pes.as_ptr(), usize::MAX, &mut offset, &mut cell), MISB_ERR_INVALID);
    }
}

#[test]
fn published_example_through_the_c_view() {
    // Whatever the standards modules make of the ST 0902 example, the C
    // view shows exactly the same tree.
    let buf = hex(ST0902_TABLE_10);
    let rust = crate::decode(&buf).unwrap();
    assert_eq!(rust.checksum, Checksum::Valid);
    unsafe {
        let mut p = ptr::null_mut();
        assert_eq!(misb_decode(buf.as_ptr(), buf.len(), &mut p), MISB_OK);
        check_packet(p, &rust);
        let mut it = new_item();
        assert_eq!(misb_packet_find(p, 2, &mut it), MISB_OK);
        assert_eq!(bytes(it.raw, it.raw_len), &[0x00, 0x04, 0x60, 0x50, 0x58, 0x4E, 0x01, 0x80]);
        assert_eq!(misb_packet_find(p, 48, &mut it), MISB_OK);
        assert_eq!(it.raw_len, 28);
        misb_packet_free(p);
    }
}

#[test]
fn random_packets_through_the_c_view() {
    // Mutated packets, and random bytes in every tag 1 to 143 (nested sets
    // and packs included): the C view matches the Rust tree whatever the
    // standards modules make of them.
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let base = hex(ST0902_TABLE_10);
    for round in 0..3000 {
        let buf = if round % 2 == 0 {
            let mut b = base.clone();
            for _ in 0..1 + next() % 4 {
                let i = 17 + next() as usize % (b.len() - 17);
                b[i] = next() as u8;
            }
            b
        } else {
            let tag = 1 + (next() % 143) as u8;
            let len = (next() % 64) as usize;
            let value: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            st0601_packet(&[(2, &TIME), (tag, &value)])
        };
        let Ok(rust) = crate::decode(&buf) else { continue };
        let mut p = ptr::null_mut();
        assert_eq!(unsafe { misb_decode(buf.as_ptr(), buf.len(), &mut p) }, MISB_OK);
        check_packet(p, &rust);
        unsafe { misb_packet_free(p) };
    }
}
