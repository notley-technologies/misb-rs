//! The ST 0601 encoder against the published examples and the decoder.
//!
//! - Every ST 0601.19 section 8 example re-encodes byte for byte from its
//!   decoded value, with the recorded bytes thrown away (MUXING_PLAN.md
//!   6.1: "encode(decoded example) reproduces the published bytes").
//! - Both complete packets of ST 0902.8 Annex C re-encode byte for byte,
//!   through the builder and through `encode_packet`.
//! - decode(encode(code)) is the identity for every code of the 8- and
//!   16-bit mapped items and a million random codes of the 32-bit ones
//!   (st0601-encode.md 3.11), and IMAPB values decode within one LSB below.
//! - Strict mode rejects what ST 0601 forbids; clamp mode warns.
#![cfg(feature = "encode")]
#![forbid(unsafe_code)]
mod common;

use common::*;
use misb::encode::{
    encode_packet, Classification, EncodeOptions, ErrorKind, Input, ItemOrder, Policy, Security, St0601Builder,
};
use misb::st0601::Tag;
use misb::{Config, MispTime, Packet, Value};

const T: u64 = 1_224_807_209_913_000;

fn no_raw() -> Config {
    let mut cfg = Config::default();
    cfg.keep_raw = false;
    cfg
}

/// Decode one example item (tag, length, value as printed) with no raw
/// bytes kept, so re-encoding must work from the value alone.
fn decoded(tlv: &str) -> (u64, Value) {
    let bytes = St0601::new().raw(&hex(tlv)).build();
    let p = misb::decode_with(&bytes, &no_raw()).unwrap();
    let item = p.items.iter().find(|i| i.tag != 2 && i.tag != 65 && i.tag != 1).expect("the example item").clone();
    assert!(item.raw.is_empty() || !item.value.is_valid(), "{tlv}: raw kept");
    (item.tag, item.value)
}

/// The value bytes of item `tag` in an encoded packet.
fn item_bytes(packet: &[u8], tag: u64) -> Vec<u8> {
    let p = misb::decode(packet).expect("encoded packet decodes");
    assert!(p.is_ok(), "{p}");
    p.item(tag).unwrap_or_else(|| panic!("no tag {tag}")).raw.clone()
}

fn opts() -> EncodeOptions {
    let mut o = EncodeOptions::default();
    o.allow_legacy = true;
    o
}

/// IMAPB items and their maximum lengths (the example decides the length).
fn imapb_tag(tag: u64) -> bool {
    matches!(tag, 96 | 103 | 104 | 105 | 109 | 112 | 113 | 114 | 117 | 118 | 119 | 120 | 132 | 134)
}

/// Every ST 0601.19 section 8 example that is written from a value (tag 1
/// and 2 are the packet's own; tag 65 is the version).
const EXAMPLES: &[&str] = &[
    "03 09 4D49 5353 494F 4E30 31",
    "04 06 4146 2D31 3031",
    "05 02 71C2",
    "06 02 FD3D",
    "07 02 08B8",
    "08 01 93",
    "09 01 9F",
    "0A 05 4D51 312D 42",
    "0B 02 454F",
    "0C 0E 4765 6F64 6574 6963 2057 4753 3834",
    "0D 04 5595 B66D",
    "0E 04 5B53 60C4",
    "0F 02 C221",
    "10 02 CD9C",
    "11 02 D917",
    "12 04 724A 0A20",
    "13 04 87F8 4B86",
    "14 04 7DC5 5ECE",
    "15 04 0383 0926",
    "16 02 1281",
    "17 04 F101 A229",
    "18 04 14BC 082B",
    "19 02 34F3",
    "1A 02 1750",
    "1B 02 063F",
    "1C 02 F9C1",
    "1D 02 1750",
    "1E 02 ED1F",
    "1F 02 F732",
    "20 02 01D0",
    "21 02 EB3F",
    "22 01 02",
    "23 02 A7C4",
    "24 01 B2",
    "25 02 BEBA",
    "26 02 CA35",
    "27 01 54",
    "28 04 8F69 5262",
    "29 04 7654 57F2",
    "2A 02 F823",
    "2B 01 03",
    "2C 01 0F",
    "2D 02 1A95",
    "2E 02 2611",
    "2F 01 31",
    "31 02 3D07",
    "32 02 C883",
    "33 02 D3FE",
    "34 02 DF79",
    "35 02 6AF4",
    "36 02 7670",
    "37 01 81",
    "38 01 8C",
    "39 04 B38E ACF1",
    "3A 02 A45D",
    "3B 07 544F 5020 4755 4E",
    "3C 02 AFD8",
    "3D 01 BA",
    "3E 02 06CF",
    "3F 01 02",
    "40 02 DDC5",
    "43 04 85A1 5A39",
    "44 04 001C 501C",
    "45 02 0BB3",
    "46 06 4150 4143 4845",
    "47 02 172F",
    "48 08 0002 D5D0 2466 0180",
    "4B 02 C221",
    "4C 02 0BB3",
    "4D 01 01",
    "4E 02 0BB3",
    "4F 02 09FB",
    "50 02 04BC",
    "51 04 0024 3800",
    "52 04 F106 9B63",
    "53 04 14BC B2C0",
    "54 04 F100 4D00",
    "55 04 14BE 84C8",
    "56 04 F0FD 9B17",
    "57 04 14BB 17AF",
    "58 04 F102 052A",
    "59 04 14B9 D176",
    "5A 04 FF62 E2F2",
    "5B 04 04D8 04DF",
    "5C 04 F3AB 48EF",
    "5D 04 DE17 9323",
    "60 03 00D9 2A",
    "67 03 2F92 1E",
    "68 03 2F92 1E",
    "69 03 2F92 1E",
    "6A 04 424C 5545",
    "6B 06 4241 5345 3031",
    "6C 04 484F 4D45",
    "6D 03 0001 A0",
    "6E 02 4DAF",
    "6F 02 0BB8",
    "70 02 1F40",
    "71 03 05F5 00",
    "72 03 05F7 40",
    "73 13 0511 466C 7920 746F 2057 6179 706F 696E 7420 31",
    "74 02 0307",
    "75 02 3E90",
    "76 03 3E80 11",
    "77 02 3B60",
    "78 02 4800",
    "79 02 0103",
    "7A 0B 010E 0343 414E 0003 4652 41",
    "7B 01 07",
    "7C 01 03",
    "7D 01 09",
    "7E 01 05",
    "7F 05 83D4 6087 69",
    "8100 0E 0D15 0000 07D0 0000 0FA0 4E4E 4952",
    "8101 04 4131 3233",
    "8102 18 0B40 6BC2 0919 BDA5 5407 0E00 0B40 783C B819 A292 7407 C600",
    "8103 07 05 6F27 1B5E 41B7",
    "8104 03 0257 C0",
    "8105 02 2710",
    "8106 02 3700",
    "8107 14 4672 6571 7565 6E63 7920 4D6F 6475 6C61 7469 6F6E",
    "8108 01 1E",
    "8109 05 012B 8DC6 35",
    "810A 3F 0312 0000 0F56 4953 204E 6F73 6520 4361 6D65 7261 1501 0012 4143 4D45 2056 4953 204D 6F64 656C \
     2031 3233 1402 0011 4143 4D45 2049 5220 4D6F 6465 6C20 3435 36",
    "810B 01 0B",
    "810C 2C 0E01 0101 0382 0307 4861 7270 6F6F 6E0F 0101 0202 9E04 0848 656C 6C66 6972 650C 0102 0101 0306 \
     4742 552D 3135",
    "810D 40 0F00 0001 0340 71D8 9419 BDBF E708 9800 0F01 0002 0240 71D3 8819 BCCE 2408 FC00 0F02 7FFF 0140 \
     71E3 0819 BF2C 1B07 D000 0F03 FFFE 0040 71E5 AF19 BF5A A709 6000",
    "810E 0E 0634 8000 4B00 0006 1A40 000C 8000",
];

#[test]
fn every_item_example_re_encodes_from_its_value() {
    let mut failures = Vec::new();
    for tlv in EXAMPLES {
        let want = hex(tlv);
        let (tag, value) = decoded(tlv);
        let t = Tag::from_u64(tag).unwrap();
        let want_value = example_value(&want);
        let mut b = St0601Builder::with_options(MispTime::from_micros(T), opts());
        let r = if imapb_tag(tag) {
            b.set_imapb(t, &value, want_value.len()).map(|_| ())
        } else {
            b.set(t, &value).map(|_| ())
        };
        if let Err(e) = r {
            failures.push(format!("{tlv}: {e}"));
            continue;
        }
        let packet = b.finish().unwrap();
        let got = item_bytes(&packet, tag);
        if got != want_value {
            failures.push(format!("{tlv}: encoded {}", to_hex(&got)));
        }
    }
    assert!(failures.is_empty(), "{} of {} examples:\n{}", failures.len(), EXAMPLES.len(), failures.join("\n"));
}

/// The value bytes of a printed example (after its tag and length).
fn example_value(tlv: &[u8]) -> Vec<u8> {
    let tag_len = if tlv[0] & 0x80 != 0 { 2 } else { 1 };
    let (len, n) = match tlv[tag_len] {
        l if l < 0x80 => (usize::from(l), 1),
        0x81 => (usize::from(tlv[tag_len + 1]), 2),
        _ => unreachable!(),
    };
    tlv[tag_len + n..tag_len + n + len].to_vec()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

#[test]
fn st0902_annex_c_packets_re_encode_byte_for_byte() {
    for bytes in [spec_packet_a(), spec_packet_b()] {
        // From values only: the builder in ascending order with version 6.
        let p = misb::decode_with(&bytes, &no_raw()).unwrap();
        let time = MispTime::from_micros(p.get(Tag::PrecisionTimeStamp).unwrap().as_time().unwrap());
        let mut b = St0601Builder::new(time);
        b.version(6);
        for item in &p.items {
            match item.tag {
                1 | 2 | 65 => {}
                tag => {
                    b.set(Tag::from_u64(tag).unwrap(), &item.value).unwrap_or_else(|e| panic!("{e}"));
                }
            }
        }
        assert_eq!(to_hex(&b.finish().unwrap()), to_hex(&bytes));
        // encode_packet from values, and from values plus raw bytes.
        assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes);
        let p = misb::decode(&bytes).unwrap();
        assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes);
    }
}

#[test]
fn smallest_and_zero_length_packets_match_the_spec() {
    // st0601-encode.md 3.1 and 3.2 (version 19).
    let t = MispTime::from_micros(0x0004_59F4_A6AA_4AA8);
    let b = St0601Builder::new(t);
    assert_eq!(
        to_hex(&b.finish().unwrap()),
        "06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 11 02 08 00 04 59 F4 A6 AA 4A A8 41 01 13 01 02 AC F1"
    );
    let mut b = St0601Builder::new(t);
    b.unknown(Tag::SlantRange).unwrap();
    assert_eq!(
        to_hex(&b.finish().unwrap()),
        "06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 13 02 08 00 04 59 F4 A6 AA 4A A8 15 00 41 01 13 01 02 AF 06"
    );
}

/// Every code of an 8- or 16-bit item, or random codes of a 32-bit one,
/// decodes then encodes to itself (st0601-encode.md 3.11, D-06).
#[test]
fn mapped_codes_round_trip() {
    let mut rng = Rng(0x5EED_1234_5678_9ABC);
    // (tag, value length): one item per mapping.
    let items: &[(u64, usize)] = &[
        (5, 2), (6, 2), (7, 2), (13, 4), (14, 4), (15, 2), (16, 2), (18, 4), (19, 4), (21, 4), (22, 2), (23, 4),
        (24, 4), (26, 2), (36, 1), (37, 2), (45, 2), (51, 2), (55, 1), (79, 2), (90, 4), (93, 4),
    ];
    for &(tag, len) in items {
        let codes: Vec<u64> = if len <= 2 {
            (0..(1u64 << (8 * len))).collect()
        } else {
            (0..50_000).map(|_| rng.next() & 0xFFFF_FFFF).collect()
        };
        let t = Tag::from_u64(tag).unwrap();
        let mut b = St0601Builder::new(MispTime::from_micros(T));
        for code in codes {
            let bytes = &code.to_be_bytes()[8 - len..];
            let item = misb::decode_with(&St0601::new().item(tag, bytes).build(), &no_raw()).unwrap();
            let value = item.get(tag).unwrap().clone();
            // Signed items: the most negative code is the special value.
            b.clear();
            match b.set(t, &value) {
                Ok(_) => {}
                Err(e) if !value.is_valid() => {
                    assert_eq!(e.kind, ErrorKind::NotAllowed, "tag {tag} code {code:#x}: {e}");
                    continue;
                }
                Err(e) => panic!("tag {tag} code {code:#x} {value:?}: {e}"),
            }
            let got = item_bytes(&b.finish().unwrap(), tag);
            assert_eq!(got, bytes, "tag {tag} code {code:#x} decoded {value:?}");
        }
    }
}

/// IMAPB values decode to within one LSB below the input (ST 1201
/// truncates), at every length.
#[test]
fn imapb_values_round_trip_within_one_lsb() {
    let mut rng = Rng(42);
    for &(tag, min, max, max_len) in &[
        (96u64, 0.0, 1_500_000.0, 8usize),
        (104, -900.0, 40_000.0, 8),
        (112, 0.0, 360.0, 8),
        (117, -1000.0, 1000.0, 4),
        (132, 1.0, 99_999.0, 4),
    ] {
        let t = Tag::from_u64(tag).unwrap();
        for len in 1..=max_len {
            let map = misb::imapb::Imapb::new(min, max, len).unwrap();
            let lsb = map.int_to_real(1) - map.int_to_real(0);
            for _ in 0..2_000 {
                let x = min + (max - min) * (rng.next() as f64 / u64::MAX as f64);
                let mut b = St0601Builder::new(MispTime::from_micros(T));
                b.set_imapb(t, x, len).unwrap();
                let p = misb::decode(&b.finish().unwrap()).unwrap();
                let y = p.get(tag).unwrap().as_f64().unwrap();
                assert!(y <= x + 1e-9 * lsb.max(1.0) && y >= x - lsb * (1.0 + 1e-9), "tag {tag} len {len}: {x} -> {y}");
            }
        }
    }
}

fn kind(r: Result<&mut St0601Builder, misb::encode::EncodeError>) -> ErrorKind {
    r.err().expect("an error").kind
}

#[test]
fn strict_mode_rejects_what_st0601_forbids() {
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    assert_eq!(kind(b.set(Tag::SensorLatitude, 90.5)), ErrorKind::OutOfRange);
    assert_eq!(kind(b.set(Tag::SensorLatitude, f64::NAN)), ErrorKind::NotFinite);
    assert_eq!(kind(b.set(Tag::SensorLatitude, Input::OutOfRange)), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set(Tag::SensorLatitude, Input::OffEarth)), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set(Tag::SensorLatitude, "north")), ErrorKind::WrongType);
    assert_eq!(kind(b.set(Tag::SensorTrueAltitude, 19_000.5)), ErrorKind::OutOfRange);
    assert_eq!(kind(b.set(Tag::PlatformTrueAirspeed, 300)), ErrorKind::OutOfRange);
    assert_eq!(kind(b.set(Tag::OffsetCornerLatitudePoint1, 0.08)), ErrorKind::OutOfRange);
    assert_eq!(kind(b.set(Tag::IcingDetected, Input::Code(3))), ErrorKind::InvalidCode);
    assert_eq!(kind(b.set(Tag::OperationalMode, Input::Code(6))), ErrorKind::InvalidCode);
    assert_eq!(kind(b.set(Tag::LaserPrfCode, 1903)), ErrorKind::InvalidCode);
    assert_eq!(kind(b.set(Tag::GenericFlagData, 0x40)), ErrorKind::InvalidCode);
    assert_eq!(kind(b.set(Tag::Deprecated, Input::Bytes(vec![1]))), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set(Tag::WeaponLoad, Input::Bytes(vec![1, 2]))), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set(Tag::TargetId, "x".repeat(33))), ErrorKind::TooLong);
    assert_eq!(kind(b.set(Tag::MissionId, "m".repeat(128))), ErrorKind::TooLong);
    assert_eq!(kind(b.set_imapb(Tag::PlatformCourseAngle, 1.0, 9)), ErrorKind::OutOfRange);
    assert_eq!(kind(b.set_imapb(Tag::SensorLatitude, 1.0, 2)), ErrorKind::WrongType);
    assert_eq!(kind(b.unknown(Tag::UasDatalinkLsVersionNumber)), ErrorKind::NotAllowed);
    assert_eq!(kind(b.unknown(Tag::ControlCommand)), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set_raw(1, &[0, 0])), ErrorKind::NotAllowed);
    assert_eq!(kind(b.set_raw(143, &[1])), ErrorKind::NotAllowed);
    // Single use, and 75 / 104 exclusive.
    b.set(Tag::MissionId, "A").unwrap();
    assert_eq!(kind(b.set(Tag::MissionId, "B")), ErrorKind::Duplicate);
    assert_eq!(kind(b.set_raw(3, b"B")), ErrorKind::Duplicate);
    b.set(Tag::SensorEllipsoidHeight, 100.0).unwrap();
    assert_eq!(kind(b.set(Tag::SensorEllipsoidHeightExtended, 100.0)), ErrorKind::NotAllowed);
    // An SDCC-FLP needs caller order.
    assert_eq!(kind(b.set_raw(102, &[1])), ErrorKind::NotAllowed);
    // Errors leave nothing behind.
    let p = misb::decode(&b.finish().unwrap()).unwrap();
    let tags: Vec<u64> = p.iter().map(|i| i.tag).collect();
    assert_eq!(tags, [2, 3, 65, 75, 1]);
    // ASCII only.
    let mut o = EncodeOptions::default();
    o.ascii_only = true;
    let mut b = St0601Builder::with_options(MispTime::from_micros(T), o);
    assert_eq!(kind(b.set(Tag::MissionId, "Mission\u{e9}")), ErrorKind::WrongType);
}

#[test]
fn special_states_and_policies() {
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    // Out of Range indicator: written, with a warning (R-ST0601-ENCODE-37).
    b.set(Tag::PlatformPitchAngle, 25.0).unwrap();
    b.set(Tag::PlatformRollAngleFull, Input::OutOfRange).unwrap();
    b.set(Tag::FrameCenterLatitude, Input::OffEarth).unwrap();
    // IMAPB flags (R-ST0601-ENCODE-35).
    b.set(Tag::TargetWidthExtended, 2e6).unwrap();
    b.set(Tag::AltitudeAgl, Input::BelowMinimum).unwrap();
    // Full-circle angles wrap (D-07).
    b.set(Tag::PlatformHeadingAngle, 360.0 + 159.974_364_843_213_55).unwrap();
    b.set(Tag::SensorRelativeElevationAngle, 191.207_675_166_059_15).unwrap();
    assert_eq!(b.warnings().len(), 2, "{:?}", b.warnings());
    let packet = b.finish().unwrap();
    assert_eq!(item_bytes(&packet, 6), [0x80, 0x00]);
    assert_eq!(item_bytes(&packet, 91), [0x80, 0, 0, 0]);
    assert_eq!(item_bytes(&packet, 23), [0x80, 0, 0, 0]);
    assert_eq!(item_bytes(&packet, 96), [0xE1, 0, 0]);
    assert_eq!(item_bytes(&packet, 113), [0xE0, 0, 0]);
    assert_eq!(item_bytes(&packet, 5), [0x71, 0xC2]);
    assert_eq!(item_bytes(&packet, 19), hex("87F8 4B86"));
    let p = misb::decode(&packet).unwrap();
    assert_eq!(p.get(Tag::FrameCenterLatitude), Some(&Value::Enum { code: 0x8000_0000, label: Some("N/A (Off-Earth)") }));

    // Clamp mode.
    let mut o = EncodeOptions::default();
    o.policy = Policy::Clamp;
    let mut b = St0601Builder::with_options(MispTime::from_micros(T), o);
    b.set(Tag::SensorLatitude, 95.0).unwrap();
    b.set(Tag::TargetWidthExtended, 2e6).unwrap();
    b.set(Tag::PlatformTrueAirspeed, 300).unwrap();
    b.set(Tag::MissionId, "M".repeat(130)).unwrap();
    assert_eq!(b.warnings().len(), 4);
    let p = misb::decode(&b.finish().unwrap()).unwrap();
    assert_eq!(p.get(Tag::SensorLatitude), Some(&Value::Float(90.0)));
    assert_eq!(p.get(Tag::PlatformTrueAirspeed), Some(&Value::Uint(255)));
    assert_eq!(p.get(Tag::MissionId).and_then(Value::as_str).map(str::len), Some(127));
    assert_eq!(p.get(Tag::TargetWidthExtended).and_then(Value::as_f64), Some(1_500_000.0));
}

#[test]
fn strings_follow_st0107() {
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    b.set(Tag::MissionId, "").unwrap();
    b.set(Tag::PlatformTailNumber, "  AF\u{7}-101\t\n").unwrap();
    b.set(Tag::PlatformDesignation, "\u{0}\u{0}").unwrap();
    assert_eq!(b.warnings().len(), 2);
    let packet = b.finish().unwrap();
    assert_eq!(item_bytes(&packet, 3), [0]);
    assert_eq!(item_bytes(&packet, 4), b"AF-101");
    assert_eq!(item_bytes(&packet, 10), [0]);
    let p = misb::decode(&packet).unwrap();
    assert_eq!(p.get(Tag::MissionId), Some(&Value::Text(String::new())));
}

#[test]
fn order_version_reuse_and_size() {
    // Ascending by default, 65 in its place, whatever the set order.
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    b.set(Tag::TakeOffTime, MispTime::from_micros(5)).unwrap();
    b.set(Tag::MissionId, "M").unwrap();
    b.set(Tag::SensorLatitude, 1.0).unwrap();
    let tags = |bytes: &[u8]| misb::decode(bytes).unwrap().iter().map(|i| i.tag).collect::<Vec<_>>();
    let mut out = Vec::new();
    b.finish_into(&mut out).unwrap();
    assert_eq!(tags(&out), [2, 3, 13, 65, 131, 1]);
    // Caller order, explicit version in its place.
    let mut o = EncodeOptions::default();
    o.order = ItemOrder::Caller;
    let mut b = St0601Builder::with_options(MispTime::from_micros(T), o.clone());
    b.set(Tag::TakeOffTime, MispTime::from_micros(5)).unwrap();
    b.set(Tag::UasDatalinkLsVersionNumber, 17).unwrap();
    b.set(Tag::MissionId, "M").unwrap();
    b.finish_into(&mut out).unwrap();
    assert_eq!(tags(&out), [2, 131, 65, 3, 1]);
    assert_eq!(misb::decode(&out).unwrap().get(65u8), Some(&Value::Uint(17)));
    // Reuse after clear keeps capacity and starts empty.
    let cap = out.capacity();
    b.clear();
    b.finish_into(&mut out).unwrap();
    assert_eq!(tags(&out), [2, 65, 1]);
    assert!(out.capacity() >= cap);
    // Packet size limit (D-18).
    let mut o = EncodeOptions::default();
    o.max_packet_bytes = 40;
    let mut b = St0601Builder::with_options(MispTime::from_micros(T), o);
    b.set(Tag::MissionId, "0123456789").unwrap();
    assert_eq!(b.finish().unwrap_err().kind, ErrorKind::TooLarge);
    // Long-form packet length beyond 127 bytes.
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    for (tag, s) in [(Tag::MissionId, 'a'), (Tag::PlatformTailNumber, 'b'), (Tag::PlatformDesignation, 'c')] {
        b.set(tag, s.to_string().repeat(100)).unwrap();
    }
    let bytes = b.finish().unwrap();
    // 10 (tag 2) + 3 x 102 + 3 (tag 65) + 4 (tag 1) = 323 = 0x0143.
    assert_eq!(&bytes[16..19], &[0x82, 0x01, 0x43]);
    assert!(misb::decode(&bytes).unwrap().is_ok());
}

#[test]
fn encode_packet_keeps_what_the_model_cannot_tell_apart() {
    // IMAPB below/above flags and the Reserved code both decode to
    // OutOfRange; the recorded bytes carry them through (D-23).
    let bytes = St0601::new()
        .time(T)
        .item(96, &[0xE0, 0, 0])
        .item(117, &[0xE1, 0])
        .item(13, &[0x80, 0, 0, 0])
        .item(200, b"private")
        .item(65, &[19])
        .build();
    let p = misb::decode(&bytes).unwrap();
    assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes);
    // An edited value is encoded from the value; the rest stays as is.
    let mut p = misb::decode(&bytes).unwrap();
    p.items.iter_mut().find(|i| i.tag == 13).unwrap().value = Value::Float(45.0);
    let out = encode_packet(&p, &EncodeOptions::default()).unwrap();
    let q = misb::decode(&out).unwrap();
    assert!(q.is_ok());
    assert_eq!(q.item(96u8).unwrap().raw, [0xE0, 0, 0]);
    assert_eq!(q.item(200u8).unwrap().value, Value::Bytes(b"private".to_vec()));
    assert!((q.get(13u8).unwrap().as_f64().unwrap() - 45.0).abs() < 1e-7);
    // Not an ST 0601 packet, or no time stamp.
    assert_eq!(
        encode_packet(&Packet::new(misb::Standard::St0102), &EncodeOptions::default()).unwrap_err().kind,
        ErrorKind::WrongType
    );
}

#[test]
fn security_set_matches_st0902_annex_c() {
    // The tag 48 value of ST 0902.8 Annex C Table 10 (1059 three letter
    // codes, version 10).
    let mut s = Security::new(Classification::Unclassified, 0x07, "//USA", 0x07, "USA");
    s.version = Some(10);
    assert_eq!(
        to_hex(&s.encode().unwrap()),
        "01 01 01 02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00 55 00 53 00 41 16 02 00 0A"
    );
    // The same set re-encoded from the decoded packet, values only.
    let p = misb::decode_with(&spec_packet_a(), &no_raw()).unwrap();
    let set = p.get(Tag::SecurityLocalSet).unwrap().as_set().unwrap();
    assert_eq!(Security::from_set(set).unwrap(), s);
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    b.set(Tag::SecurityLocalSet, Input::Value(Value::Set(Box::new(set.clone())))).unwrap();
    assert_eq!(item_bytes(&b.finish().unwrap(), 48), s.encode().unwrap());
}

#[test]
fn security_set_rules() {
    let us = || Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
    let err = |s: Security| s.encode().unwrap_err().kind;
    // Default version 12, ascending tags, UTF-16BE country codes.
    assert_eq!(
        to_hex(&us().encode().unwrap()),
        "01 01 01 02 01 0D 03 04 2F 2F 55 53 0C 01 0D 0D 04 00 55 00 53 16 02 00 0C"
    );
    // "//" is added when missing.
    assert_eq!(Security::new(Classification::Secret, 0x0D, "US", 0x0D, "US").encode().unwrap()[6..12], hex("03 04 2F2F 5553"));
    // Required items (R-NESTED-ENCODE-048) unless partial.
    let mut s = us();
    s.classifying_country = None;
    assert_eq!(err(s.clone()), ErrorKind::Missing);
    let mut only_objects = Security::default();
    only_objects.object_country_coding_method = Some(0x0D);
    only_objects.object_country_codes = Some("US;CA".into());
    assert_eq!(to_hex(&only_objects.encode_partial().unwrap()), "0C 01 0D 0D 0A 00 55 00 53 00 3B 00 43 00 41");
    // Coding methods: Omitted Value codes and the wrong column.
    let mut s = us();
    s.country_coding_method = Some(0x08);
    assert_eq!(err(s), ErrorKind::InvalidCode);
    let mut s = us();
    s.object_country_coding_method = Some(0x10);
    assert_eq!(err(s), ErrorKind::InvalidCode);
    let mut s = us();
    s.object_country_coding_method = Some(0x40);
    assert!(s.encode().is_ok(), "GENC AdminSub is a tag 12 method");
    // FIPS is legacy: a warning.
    let mut s = us();
    s.country_coding_method = Some(0x03);
    let mut w = Vec::new();
    s.encode_with(&EncodeOptions::default(), &mut w, false).unwrap();
    assert_eq!(w.len(), 1);
    // Text, dates, separators.
    let mut s = us();
    s.caveats = Some("FOUO\u{e9}".into());
    assert_eq!(err(s), ErrorKind::WrongType);
    let mut s = us();
    s.sci_shi = Some("SI/TK".into());
    assert_eq!(err(s), ErrorKind::WrongType);
    let mut s = us();
    s.releasing_instructions = Some("USA  GBR".into());
    assert_eq!(err(s), ErrorKind::WrongType);
    let mut s = us();
    s.declassification_date = Some("20250230".into());
    assert_eq!(err(s), ErrorKind::WrongType);
    let mut s = us();
    s.object_country_codes = Some("US; CA".into());
    assert_eq!(err(s), ErrorKind::WrongType);
    let mut s = us();
    s.sci_shi = Some("SI/TK//".into());
    s.releasing_instructions = Some("USA GBR".into());
    s.declassification_date = Some("20351231".into());
    s.country_coding_method_date = Some("2024-02-29".into());
    let items = s.encode().unwrap();
    let p = misb::decode(&St0601::new().item(48, &items).build()).unwrap();
    let set = p.get(Tag::SecurityLocalSet).unwrap().as_set().unwrap();
    assert!(set.iter().all(|i| i.value.is_valid()), "{set}");
    // The decoded set states the version the builder defaulted.
    s.version = Some(12);
    assert_eq!(Security::from_set(set).unwrap(), s);
}

#[test]
fn time_stamps() {
    let t = MispTime::from_utc("2022-07-12T09:05:03.000700Z".parse().unwrap(), misb::LeapSeconds::builtin()).unwrap();
    let mut b = St0601Builder::new(t);
    b.set(Tag::EventStartTime, t).unwrap();
    b.set(Tag::LeapSeconds, misb::LeapSeconds::builtin().st0601_leap_seconds(1_657_616_703)).unwrap();
    let p = misb::decode(&b.finish().unwrap()).unwrap();
    assert_eq!(p.get(Tag::PrecisionTimeStamp), Some(&Value::Time(1_657_616_732_000_618)));
    assert_eq!(p.get(Tag::EventStartTime), Some(&Value::Time(1_657_616_732_000_618)));
    assert_eq!(p.get(Tag::LeapSeconds), Some(&Value::Int(29)));
}

/// R-NESTED-ENCODE-008, D-31: VMTI needs the parent's frame centre.
#[test]
fn vmti_needs_the_frame_centre() {
    use misb::encode::{VTarget, Vmti};
    let mut plain = Vmti::new();
    plain.frame_width = Some(1920);
    let mut t = VTarget::new(1);
    t.centroid = Some(409_600);
    plain.targets.push(t);
    let mut offsets = Vmti::new();
    let mut t = VTarget::new(1);
    t.location_offset = Some((0.01.into(), 0.02.into()));
    offsets.targets.push(t);
    let build = |vmti: &Vmti, policy: Policy, centre: bool| {
        let mut o = EncodeOptions::default();
        o.policy = policy;
        let mut b = St0601Builder::with_options(MispTime::from_micros(T), o);
        if centre {
            b.set(Tag::FrameCenterLatitude, 38.8).unwrap().set(Tag::FrameCenterLongitude, -77.0).unwrap();
        }
        b.set(Tag::VmtiLocalSet, Input::Set(vmti.encode().unwrap())).unwrap();
        b.finish()
    };
    assert_eq!(build(&plain, Policy::Strict, false).unwrap_err().kind, ErrorKind::Missing);
    assert!(build(&plain, Policy::Strict, true).is_ok());
    assert!(build(&plain, Policy::Clamp, false).is_ok(), "lenient: only offsets need the centre");
    assert_eq!(build(&offsets, Policy::Clamp, false).unwrap_err().kind, ErrorKind::Missing);
    // Re-encoding recorded packets does not apply it.
    let recorded = St0601::new().time(T).item(74, &plain.encode().unwrap()).item(65, &[19]).build();
    let p = misb::decode(&recorded).unwrap();
    assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), recorded);
}

/// Arbitrary inputs on arbitrary tags: the encoder never panics, and
/// whatever it accepts decodes with a valid checksum and no `Invalid`
/// value (bytes passed through aside, which are the caller's).
#[test]
fn random_inputs_never_produce_a_bad_packet() {
    let mut rng = Rng(0xD1CE_F00D);
    let floats = [0.0, -0.0, 1.5, -1.5, 90.0, -90.0, 180.0, 359.999, 360.0, 1e6, -1e6, 1e300, f64::NAN, f64::INFINITY];
    for round in 0..4_000 {
        let mut o = EncodeOptions::default();
        o.policy = if round % 2 == 0 { Policy::Strict } else { Policy::Clamp };
        o.allow_legacy = round % 3 == 0;
        let mut b = St0601Builder::with_options(MispTime::from_micros(rng.next() >> 8), o);
        for _ in 0..12 {
            let tag = 1 + rng.next() % 145;
            let Some(t) = Tag::from_u64(tag) else { continue };
            let input = match rng.next() % 10 {
                0 => Input::Float(floats[(rng.next() % floats.len() as u64) as usize]),
                1 => Input::Float((rng.next() as f64 / u64::MAX as f64 - 0.5) * 1e5),
                2 => Input::Uint(rng.next() >> (rng.next() % 64)),
                3 => Input::Int(rng.next() as i64 >> (rng.next() % 64)),
                4 => Input::Text((0..rng.next() % 140).map(|_| char::from((rng.next() % 128) as u8)).collect()),
                5 => Input::Code(rng.next() % 300),
                6 => [Input::OffEarth, Input::OutOfRange, Input::BelowMinimum, Input::AboveMaximum][(rng.next() % 4) as usize]
                    .clone(),
                7 => Input::Time(MispTime::from_micros(rng.next())),
                8 => Input::Bytes((0..rng.next() % 40).map(|_| rng.next() as u8).collect()),
                _ => Input::Value(Value::List(vec![Value::Uint(rng.next() % 30), Value::Uint(rng.next() % 30)])),
            };
            let _ = if rng.next() % 5 == 0 { b.unknown(t) } else { b.set(t, input) };
        }
        let Ok(bytes) = b.finish() else { continue };
        let p = misb::decode(&bytes).unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert!(p.is_ok(), "round {round}: {p}");
        for item in &p.items {
            // Bytes given for sets and items kept as bytes are written as
            // they are, like raw values.
            let passthrough = matches!(item.tag, 48 | 73 | 74 | 94 | 95 | 97 | 98 | 99 | 102);
            // OutOfRange is the indicator or IMAPB flag written on purpose.
            let bad = matches!(item.value, Value::Invalid(_));
            assert!(passthrough || !bad, "round {round}: tag {} {:?}", item.tag, item.value);
        }
    }
}

/// xorshift64*: deterministic test values without extra crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}
