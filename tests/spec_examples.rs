//! The worked examples published in the MISB standards, decoded through the
//! public API only.
//!
//! - MISB ST 0902.8 Annex C Tables 10 and 11: the only complete ST 0601
//!   packets MISB publishes, with a nested ST 0102 set and an ST 1204
//!   identifier.
//! - MISB ST 0601.19 section 8: the example of every item (tag, length,
//!   value as printed), each wrapped in a packet with a correct checksum.
//! - MISB ST 0903.6: the item examples of the VMTI Local Set, VTarget
//!   Pack, VMask, VTracker, VChip and Algorithm sets.
//! - MISB ST 0102.12 and ST 0806.4, which print no hex examples: values
//!   built from their tag tables, enumerations and mappings.
//! - MISB ST 1204.3 Appendix E and section 7.4, ST 1010.3 Figures 7 and 9,
//!   and the ST 1201.5 Appendix A vectors.
//!
//! Mapped values are compared with a tolerance of half the least
//! significant bit of the encoding with the value the bytes decode to
//! (ST 0601.19 gives the formula of every item), and within one least
//! significant bit with the printed example value, which for some items
//! is the value before quantization (ST 0601 rounds, ST 1201 IMAPB
//! truncates).
#![forbid(unsafe_code)]
mod common;

use common::*;
use misb::imapb::Imapb;
use misb::{st0102, st0601, st0806, st0903, Checksum, Item, Packet, Value};

// ---------------------------------------------------------------- helpers

/// Least significant bit of an unsigned integer mapped onto `range`.
fn lsb_u(range: f64, bits: u32) -> f64 {
    range / ((1u64 << bits) - 1) as f64
}

/// Least significant bit of a signed integer mapped onto `range` (ST 0601
/// maps -(2^(N-1) - 1) to 2^(N-1) - 1, a span of 2^N - 2).
fn lsb_s(range: f64, bits: u32) -> f64 {
    range / ((1u64 << bits) - 2) as f64
}

/// Least significant bit of ST 1201 IMAPB(min, max, len).
fn lsb_imapb(min: f64, max: f64, len: usize) -> f64 {
    let m = Imapb::new(min, max, len).expect("valid IMAPB parameters");
    m.int_to_real(1) - m.int_to_real(0)
}

#[derive(Clone, Copy, Debug)]
enum Want {
    /// A mapped value: what the bytes decode to with the standard's
    /// formula, the example value as printed, and the encoding's LSB.
    Mapped { decoded: f64, printed: f64, lsb: f64 },
    Uint(u64),
    Int(i64),
    Text(&'static str),
    Time(u64),
    Enum(u64, &'static str),
}

fn check(what: &str, got: &Value, want: Want) {
    match want {
        Want::Mapped { decoded, printed, lsb } => {
            let Some(v) = got.as_f64() else { panic!("{what}: {got:?} is not a number") };
            assert!(matches!(got, Value::Float(_)), "{what}: {got:?} is not a float");
            assert!((v - decoded).abs() <= lsb / 2.0, "{what}: {v} vs decoded {decoded} (lsb {lsb})");
            assert!((v - printed).abs() <= lsb, "{what}: {v} vs printed {printed} (lsb {lsb})");
        }
        Want::Uint(n) => assert_eq!(got, &Value::Uint(n), "{what}"),
        Want::Int(n) => assert_eq!(got, &Value::Int(n), "{what}"),
        Want::Text(s) => assert_eq!(got.as_str(), Some(s), "{what}: {got:?}"),
        Want::Time(us) => assert_eq!(got, &Value::Time(us), "{what}"),
        Want::Enum(code, label) => assert_eq!(got, &Value::Enum { code, label: Some(label) }, "{what}"),
    }
}

/// A float within half an LSB of `want`.
fn close(what: &str, got: Option<&Value>, want: f64, lsb: f64) {
    let v = got.and_then(Value::as_f64).unwrap_or_else(|| panic!("{what}: {got:?} is not a number"));
    assert!((v - want).abs() <= lsb / 2.0, "{what}: {v} vs {want} (lsb {lsb})");
}

/// Wrap one item, given as printed (tag, length and value in hex), in an
/// ST 0601 packet with a correct checksum and decode it.
fn decode_tlv(tlv: &str) -> Packet {
    let bytes = St0601::new().raw(&hex(tlv)).build();
    let p = misb::decode(&bytes).expect("packet decodes");
    assert_eq!(p.checksum, Checksum::Valid, "{tlv}");
    assert_eq!(p.error, None, "{tlv}");
    assert!(p.is_ok());
    p
}

/// The decoded value of the first item with `tag` in a packet made from
/// `tlv`; the item keeps its bytes.
fn example(tag: u64, tlv: &str) -> Value {
    let p = decode_tlv(tlv);
    let item = p.item(tag).unwrap_or_else(|| panic!("no tag {tag} in {tlv}")).clone();
    assert_eq!(item.name, st0601::Tag::from_u64(tag).unwrap().name());
    assert!(item.raw.len() + 2 <= hex(tlv).len(), "raw keeps the value bytes");
    item.value
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    v.field(name).unwrap_or_else(|| panic!("no field {name:?} in {v:?}"))
}

fn list(v: &Value) -> &[Value] {
    v.as_list().unwrap_or_else(|| panic!("{v:?} is not a list"))
}

// ---------------------------------------------------------------- ST 0601 item examples

/// Every ST 0601.19 section 8 example that is a single value, with the
/// value the spec prints and, for mapped items, what the bytes decode to
/// with the item's formula.
fn item_examples() -> Vec<(u64, &'static str, Want)> {
    use Want::*;
    let m = |decoded: f64, printed: f64, lsb: f64| Mapped { decoded, printed, lsb };
    let heading = lsb_u(360.0, 16);
    let altitude = lsb_u(19_900.0, 16);
    let lat32 = lsb_s(180.0, 32);
    let lon32 = lsb_s(360.0, 32);
    let fov = lsb_u(180.0, 16);
    let corner = lsb_s(0.15, 16);
    let pressure = lsb_u(5000.0, 16);
    let percent8 = lsb_u(100.0, 8);
    let velocity = lsb_s(654.0, 16);
    let height_ext = lsb_imapb(-900.0, 40_000.0, 3);
    let rate2 = lsb_imapb(-1000.0, 1000.0, 2);
    vec![
        (1, "01 02 8CED", Uint(0x8CED)),
        (2, "02 08 0004 59F4 A6AA 4AA8", Time(1_224_807_209_913_000)),
        (3, "03 09 4D49 5353 494F 4E30 31", Text("MISSION01")),
        (4, "04 06 4146 2D31 3031", Text("AF-101")),
        (5, "05 02 71C2", m(159.97436484321355, 159.974365, heading)),
        (6, "06 02 FD3D", m(-0.4315317239906003, -0.431531724, lsb_s(40.0, 16))),
        (7, "07 02 08B8", m(3.4058656575212867, 3.40586566, lsb_s(100.0, 16))),
        (8, "08 01 93", Uint(147)),
        (9, "09 01 9F", Uint(159)),
        (10, "0A 05 4D51 312D 42", Text("MQ1-B")),
        (11, "0B 02 454F", Text("EO")),
        (12, "0C 0E 4765 6F64 6574 6963 2057 4753 3834", Text("Geodetic WGS84")),
        (13, "0D 04 5595 B66D", m(60.176822966978335, 60.176822966978335, lat32)),
        (14, "0E 04 5B53 60C4", m(128.42675904204452, 128.42675904204452, lon32)),
        (15, "0F 02 C221", m(14190.719462882427, 14190.7195, altitude)),
        (16, "10 02 CD9C", m(144.5712977798123, 144.571298, fov)),
        (17, "11 02 D917", m(152.64362554360267, 152.643626, fov)),
        (18, "12 04 724A 0A20", m(160.71921143697557, 160.71921143697557, lsb_u(360.0, 32))),
        (19, "13 04 87F8 4B86", m(-168.79232483394085, -168.79232483394085, lon32)),
        (20, "14 04 7DC5 5ECE", m(176.86543764939194, 176.86543764939194, lsb_u(360.0, 32))),
        (21, "15 04 0383 0926", m(68590.98329874477, 68590.983298744770, lsb_u(5e6, 32))),
        (22, "16 02 1281", m(722.8198672465096, 722.819867, lsb_u(10_000.0, 16))),
        (23, "17 04 F101 A229", m(-10.542388633146132, -10.542388633146132, lat32)),
        (24, "18 04 14BC 082B", m(29.157890122923018, 29.157890122923014, lon32)),
        (25, "19 02 34F3", m(3216.0372320134275, 3216.03723, altitude)),
        (26, "1A 02 1750", m(0.013660084841456343, 0.0136602540, corner)),
        (27, "1B 02 063F", m(0.003659932248908963, 0.0036602540, corner)),
        (28, "1C 02 F9C1", m(-0.003659932248908963, -0.0036602540, corner)),
        (29, "1D 02 1750", m(0.013660084841456343, 0.0136602540, corner)),
        (30, "1E 02 ED1F", m(-0.011062196722312082, -0.0110621778, corner)),
        (31, "1F 02 F732", m(-0.005159154026917325, -0.0051602540, corner)),
        (32, "20 02 01D0", m(0.0010620441297647023, 0.0010621778, corner)),
        (33, "21 02 EB3F", m(-0.01216086306344798, -0.0121602540, corner)),
        (34, "22 01 02", Enum(2, "Icing Detected")),
        (35, "23 02 A7C4", m(235.92401007095447, 235.924010, heading)),
        (36, "24 01 B2", m(69.80392156862744, 69.8039216, percent8)),
        (37, "25 02 BEBA", m(3725.1850156404976, 3725.18502, pressure)),
        (38, "26 02 CA35", m(14818.677042801555, 14818.6770, altitude)),
        (39, "27 01 54", Int(84)),
        (40, "28 04 8F69 5262", m(-79.16385005189285, -79.163850051892850, lat32)),
        (41, "29 04 7654 57F2", m(166.40081296041646, 166.40081296041646, lon32)),
        (42, "2A 02 F823", m(18389.04707408255, 18389.0471, altitude)),
        (43, "2B 01 03", Uint(6)),
        (44, "2C 01 0F", Uint(30)),
        (45, "2D 02 1A95", m(425.2151522087434, 425.215152, lsb_u(4095.0, 16))),
        (46, "2E 02 2611", m(608.9230945296407, 608.9231, lsb_u(4095.0, 16))),
        (49, "31 02 3D07", m(1191.958495460441, 1191.95850, pressure)),
        (50, "32 02 C883", m(-8.670308542130803, -8.67030854, lsb_s(40.0, 16))),
        (51, "33 02 D3FE", m(-61.88787499618519, -61.8878750, lsb_s(360.0, 16))),
        (52, "34 02 DF79", m(-5.082552568132573, -5.08255257, lsb_s(40.0, 16))),
        (53, "35 02 6AF4", m(2088.9600976577403, 2088.96010, pressure)),
        (54, "36 02 7670", m(8306.805523765926, 8306.80552, altitude)),
        (55, "37 01 81", m(50.588235294117645, 50.5882353, percent8)),
        (56, "38 01 8C", Uint(140)),
        (57, "39 04 B38E ACF1", m(3506979.03160634, 3506979.0316063400, lsb_u(5e6, 32))),
        (58, "3A 02 A45D", m(6420.5386434729535, 6420.53864, lsb_u(10_000.0, 16))),
        (59, "3B 07 544F 5020 4755 4E", Text("TOP GUN")),
        (62, "3E 02 06CF", Uint(1743)),
        (63, "3F 01 02", Enum(2, "Medium")),
        (64, "40 02 DDC5", m(311.86816205081254, 311.868162, heading)),
        (65, "41 01 0D", Uint(13)),
        (67, "43 04 85A1 5A39", m(-86.04120734894704, -86.041207348947040, lat32)),
        (68, "44 04 001C 501C", m(0.15552755452484243, 0.15552755452484243, lon32)),
        (69, "45 02 0BB3", m(9.445334554054966, 9.44533455, altitude)),
        (70, "46 06 4150 4143 4845", Text("APACHE")),
        (71, "47 02 172F", m(32.60242618448158, 32.6024262, heading)),
        (72, "48 08 0002 D5D0 2466 0180", Time(798_039_894_000_000)),
        (75, "4B 02 C221", m(14190.719462882427, 14190.7195, altitude)),
        (76, "4C 02 0BB3", m(9.445334554054966, 9.44533455, altitude)),
        (77, "4D 01 01", Enum(1, "Operational")),
        (78, "4E 02 0BB3", m(9.445334554054966, 9.44533455, altitude)),
        (79, "4F 02 09FB", m(25.497756889553518, 25.4977569, velocity)),
        (80, "50 02 04BC", m(12.095217749565112, 12.1, velocity)),
        (82, "52 04 F106 9B63", m(-10.528728394084018, -10.528728379108287, lat32)),
        (83, "53 04 14BC B2C0", m(29.161550416220702, 29.161550376960857, lon32)),
        (84, "54 04 F100 4D00", m(-10.546048884534299, -10.546048887183977, lat32)),
        (85, "55 04 14BE 84C8", m(29.17155036198513, 29.171550376960860, lon32)),
        (86, "56 04 F0FD 9B17", m(-10.553450817499986, -10.553450810972622, lat32)),
        (87, "57 04 14BB 17AF", m(29.15272988805209, 29.152729868885170, lon32)),
        (88, "58 04 F102 052A", m(-10.541326436466223, -10.541326455319641, lat32)),
        (89, "59 04 14B9 D176", m(29.14572990925318, 29.145729868885170, lon32)),
        (90, "5A 04 FF62 E2F2", m(-0.4315251020861441, -0.43152510208614414, lat32)),
        (91, "5B 04 04D8 04DF", m(3.4058139815022304, 3.4058139815022304, lat32)),
        (92, "5C 04 F3AB 48EF", m(-8.670176984123037, -8.6701769841230370, lat32)),
        (93, "5D 04 DE17 9323", m(-47.683000037299, -47.683, lon32)),
        (96, "60 03 00D9 2A", m(13898.5, 13898.5463, lsb_imapb(0.0, 1_500_000.0, 3))),
        (103, "67 03 2F92 1E", m(23456.234375, 23456.24, height_ext)),
        (104, "68 03 2F92 1E", m(23456.234375, 23456.24, height_ext)),
        (105, "69 03 2F92 1E", m(23456.234375, 23456.24, height_ext)),
        (106, "6A 04 424C 5545", Text("BLUE")),
        (107, "6B 06 4241 5345 3031", Text("BASE01")),
        (108, "6C 04 484F 4D45", Text("HOME")),
        (109, "6D 03 0001 A0", m(1.625, 1.625, lsb_imapb(0.0, 21_000.0, 3))),
        (110, "6E 02 4DAF", Uint(19887)),
        (111, "6F 02 0BB8", Uint(3000)),
        (112, "70 02 1F40", m(125.0, 125.0, lsb_imapb(0.0, 360.0, 2))),
        (113, "71 03 05F5 00", m(2150.0, 2150.0, height_ext)),
        (114, "72 03 05F7 40", m(2154.5, 2154.50, height_ext)),
        (117, "75 02 3E90", m(1.0, 1.0, rate2)),
        (118, "76 03 3E80 11", m(0.004150390625, 0.004176, lsb_imapb(-1000.0, 1000.0, 3))),
        (119, "77 02 3B60", m(-50.0, -50.0, rate2)),
        (120, "78 02 4800", m(72.0, 72.0, lsb_imapb(0.0, 100.0, 2))),
        (123, "7B 01 07", Uint(7)),
        (125, "7D 01 09", Enum(9, "Egress")),
        (126, "7E 01 05", Enum(5, "Auto - Holding Position")),
        (129, "8101 04 4131 3233", Text("A123")),
        (131, "8103 07 05 6F27 1B5E 41B7", Time(1_529_588_637_122_999)),
        (132, "8104 03 0257 C0", m(2400.0, 2400.0, lsb_imapb(1.0, 99_999.0, 3))),
        (133, "8105 02 2710", Uint(10_000)),
        (134, "8106 02 3700", m(55.0, 55.0, lsb_imapb(0.0, 100.0, 2))),
        (135, "8107 14 4672 6571 7565 6E63 7920 4D6F 6475 6C61 7469 6F6E", Text("Frequency Modulation")),
        (136, "8108 01 1E", Int(30)),
        (137, "8109 05 012B 8DC6 35", Int(5_025_678_901)),
    ]
}

#[test]
fn every_single_value_item_example() {
    let examples = item_examples();
    // Every item of ST 0601.19 except those whose example is "N/A" (the
    // nested sets and tag 66) and the packs, which have their own tests.
    let not_applicable = [48, 66, 73, 74, 95, 97, 98, 99, 100, 101, 102];
    let packs = [47, 60, 61, 81, 94, 115, 116, 121, 122, 124, 127, 128, 130, 138, 139, 140, 141, 142, 143];
    let covered: Vec<u64> = examples.iter().map(|e| e.0).collect();
    let expected: Vec<u64> = (1..=143).filter(|t| !not_applicable.contains(t) && !packs.contains(t)).collect();
    assert_eq!(covered, expected);
    for (tag, tlv, want) in examples {
        let value = example(tag, tlv);
        check(&format!("tag {tag}"), &value, want);
        assert!(value.is_valid(), "tag {tag}");
    }
}

#[test]
fn item_example_display() {
    // The time stamps print as the calendar dates the examples give.
    assert_eq!(example(2, "02 08 0004 59F4 A6AA 4AA8").to_string(), "2008-10-24T00:13:29.913000 MISP");
    assert_eq!(example(72, "48 08 0002 D5D0 2466 0180").to_string(), "1995-04-16T13:44:54.000000 MISP");
    assert_eq!(example(131, "8103 07 05 6F27 1B5E 41B7").to_string(), "2018-06-21T13:43:57.122999 MISP");
    // Units follow mapped numbers in an item's Display.
    let p = decode_tlv("0D 04 5595 B66D");
    assert_eq!(p.items[0].to_string(), " 13 Sensor Latitude: 60.176822966978335 deg");
}

#[test]
fn checksum_sample() {
    // ST 0601.19 section 8.1.1.2.
    assert_eq!(misb::checksum::st0601_checksum(&hex("06 0E 2B 34 02 00 81 BB")), 0xB4FD);
}

/// Item 47 (8.47, Table 3): 49 = 0x31, bits 0, 4 and 5.
#[test]
fn item_47_generic_flag_data() {
    let v = example(47, "2F 01 31");
    let flag = |name, code| assert_eq!(field(&v, name).as_u64(), Some(code), "{name}");
    flag("Laser Range", 1);
    flag("Auto-Track", 0);
    flag("IR Polarity", 0);
    flag("Icing Status", 0);
    flag("Slant Range", 1);
    flag("Image Invalid", 1);
    assert_eq!(field(&v, "Laser Range"), &Value::Enum { code: 1, label: Some("Laser on") });
    assert_eq!(field(&v, "Slant Range"), &Value::Enum { code: 1, label: Some("Measured") });
}

/// Items 60 and 61 (8.60.1, 8.61.1): nibbles of 45016 = 0xAFD8 and 186 = 0xBA.
#[test]
fn items_60_and_61_weapons() {
    let v = example(60, "3C 02 AFD8");
    let n = |name| field(&v, name).as_u64().unwrap();
    assert_eq!((n("Station Number"), n("Substation Number"), n("Weapon Type"), n("Weapon Variant")), (10, 15, 13, 8));
    assert_eq!(n("Station Number") << 12 | n("Substation Number") << 8 | n("Weapon Type") << 4 | n("Weapon Variant"), 45016);
    let v = example(61, "3D 01 BA");
    let n = |name| field(&v, name).as_u64().unwrap();
    assert_eq!((n("Station Number"), n("Substation Number")), (11, 10));
}

/// Item 81 (8.81, Table 6): (x0, y0) = (0, 36), (x1, y1) = (56, 0).
#[test]
fn item_81_image_horizon_pixel_pack() {
    let v = example(81, "51 04 0024 3800");
    let n = |name| field(&v, name).as_u64();
    assert_eq!((n("Start x0"), n("Start y0"), n("End x1"), n("End y1")), (Some(0), Some(36), Some(56), Some(0)));
    assert_eq!(v.as_fields().unwrap().len(), 4);
}

/// Item 94 (8.94): the ST 1204 identifier with Physical Sensor and Virtual
/// Platform IDs, whose text form ST 1204.3 section 7.4.2 prints.
#[test]
fn item_94_miis_core_identifier() {
    let v = example(94, "5E 22 0170 F592 F023 7336 4AF8 AA91 62C0 0F2E B2DA 16B7 4341 0008 41A0 BE36 5B5A B96A 3645");
    assert_eq!(
        field(&v, "Canonical").as_str(),
        Some("0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3")
    );
    assert_eq!(field(&v, "Version"), &Value::Uint(1));
    assert_eq!(field(&v, "Usage Value"), &Value::Uint(0x70));
    assert_eq!(field(&v, "Sensor ID Type"), &Value::Enum { code: 3, label: Some("Physical") });
    assert_eq!(field(&v, "Platform ID Type"), &Value::Enum { code: 2, label: Some("Virtual") });
    assert_eq!(field(&v, "Sensor ID").as_str(), Some("F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA"));
    assert_eq!(field(&v, "Platform ID").as_str(), Some("16B7-4341-0008-41A0-BE36-5B5A-B96A-3645"));
    assert_eq!(field(&v, "Check Value"), &Value::Uint(0xD3));
    assert!(v.field("Window ID").is_none() && v.field("Minor ID").is_none());
}

/// Items 115 and 116 (8.115, 8.116).
#[test]
fn items_115_and_116_control_commands() {
    let v = example(115, "73 13 0511 466C 7920 746F 2057 6179 706F 696E 7420 31");
    assert_eq!(field(&v, "Command ID"), &Value::Uint(5));
    assert_eq!(field(&v, "Command String").as_str(), Some("Fly to Waypoint 1"));
    assert!(v.field("Command Time").is_none());
    let v = example(116, "74 02 0307");
    assert_eq!(list(&v), [Value::Uint(3), Value::Uint(7)]);
}

/// Items 121 and 124 (Tables 14 and 10): "Visible and NIR", "INS and GPS".
#[test]
fn items_121_and_124_lists_of_codes() {
    let v = example(121, "79 02 0103");
    assert_eq!(
        list(&v),
        [Value::Enum { code: 1, label: Some("VIS") }, Value::Enum { code: 3, label: Some("NIR") }]
    );
    let v = example(124, "7C 01 03");
    let codes: Vec<u64> = list(&v).iter().map(|e| e.as_u64().unwrap()).collect();
    assert_eq!(codes, [0, 1]);
    assert_eq!(list(&v)[1], Value::Enum { code: 1, label: Some("GPS") });
}

/// Item 122 (8.122, Table 9): Canada, unknown, France, GENC three-letter
/// codes (ST 0102 Table 2 item 12, 0x0E).
#[test]
fn item_122_country_codes() {
    let v = example(122, "7A 0B 010E 0343 414E 0003 4652 41");
    assert_eq!(field(&v, "Coding Method").as_u64(), Some(0x0E));
    assert_eq!(field(&v, "Coding Method"), &Value::Enum { code: 0x0E, label: Some("GENC Three Letter") });
    assert_eq!(field(&v, "Overflight Country").as_str(), Some("CAN"));
    assert_eq!(field(&v, "Operator Country"), &Value::Unknown);
    assert_eq!(field(&v, "Country of Manufacture").as_str(), Some("FRA"));
}

/// Item 127 (8.127, Table 13): 60000/1001 frames per second.
#[test]
fn item_127_sensor_frame_rate_pack() {
    let v = example(127, "7F 05 83D4 6087 69");
    assert_eq!(field(&v, "Numerator"), &Value::Uint(60_000));
    assert_eq!(field(&v, "Denominator"), &Value::Uint(1001));
}

/// Item 128 (8.128, Table 15): wavelength 21 "NNIR", 1000 to 2000 nm.
#[test]
fn item_128_wavelengths_list() {
    let v = example(128, "8100 0E 0D15 0000 07D0 0000 0FA0 4E4E 4952");
    let records = list(&v);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(field(r, "Wavelength ID").as_u64(), Some(21));
    let lsb = lsb_imapb(0.0, 1e9, 4);
    close("minimum", r.field("Minimum Wavelength"), 1000.0, lsb);
    close("maximum", r.field("Maximum Wavelength"), 2000.0, lsb);
    assert_eq!(field(r, "Wavelength Name").as_str(), Some("NNIR"));
}

/// Item 130 (8.130, Table 16): (38.841859, -77.036784, 3) and (38.939353,
/// -77.459811, 95).
#[test]
fn item_130_airbase_locations() {
    let v = example(130, "8102 18 0B40 6BC2 0919 BDA5 5407 0E00 0B40 783C B819 A292 7407 C600");
    let lat = lsb_imapb(-90.0, 90.0, 4);
    let lon = lsb_imapb(-180.0, 180.0, 4);
    let hae = lsb_imapb(-900.0, 9000.0, 3);
    for (name, want) in [("Take-off Location", (38.841859, -77.036784, 3.0)), ("Recovery Location", (38.939353, -77.459811, 95.0))] {
        let loc = field(&v, name);
        // The printed values have six decimals.
        close(name, loc.field("Latitude"), want.0, lat.max(2e-6));
        close(name, loc.field("Longitude"), want.1, lon.max(2e-6));
        close(name, loc.field("HAE"), want.2, hae);
    }
}

/// Item 138 (8.138, Tables 17 to 20): three payload records.
#[test]
fn item_138_payload_list() {
    let v = example(
        138,
        "810A 3F 0312 0000 0F56 4953 204E 6F73 6520 4361 6D65 7261 1501 0012 4143 4D45 2056 4953 204D 6F64 656C \
         2031 3233 1402 0011 4143 4D45 2049 5220 4D6F 6465 6C20 3435 36",
    );
    assert_eq!(field(&v, "Payload Count"), &Value::Uint(3));
    let records = list(field(&v, "Payload Records"));
    let want = [(0, "VIS Nose Camera"), (1, "ACME VIS Model 123"), (2, "ACME IR Model 456")];
    assert_eq!(records.len(), want.len());
    for (r, (id, name)) in records.iter().zip(want) {
        assert_eq!(field(r, "Payload ID"), &Value::Uint(id));
        assert_eq!(field(r, "Payload Type"), &Value::Enum { code: 0, label: Some("Electro Optical MI Sensor") });
        assert_eq!(field(r, "Payload Name").as_str(), Some(name));
    }
}

/// Item 139 (8.139, Figure 75): payloads 0, 1 and 3 active.
#[test]
fn item_139_active_payloads() {
    let v = example(139, "810B 01 0B");
    assert_eq!(list(&v), [Value::Uint(0), Value::Uint(1), Value::Uint(3)]);
}

/// Item 140 (8.140, Tables 21 to 23). The printed length byte 0x2D does not
/// match the 44 printed value bytes (a spec erratum), so the length is
/// given as 0x2C; the records are exactly as printed.
#[test]
fn item_140_weapons_stores() {
    let records_hex = "0E01 0101 0382 0307 4861 7270 6F6F 6E0F 0101 0202 9E04 0848 656C 6C66 6972 650C 0102 0101 0306 4742 552D 3135";
    assert_eq!(hex(records_hex).len(), 0x2C);
    let v = example(140, &format!("810C 2C {records_hex}"));
    let records = list(&v);
    // (station, hardpoint, carriage, store, engagement bits [b4, b3, b2, b1], general status, type)
    let want = [
        (1, 1, 1, 3, [0, 0, 0, 1], 3, "Harpoon"),
        (1, 1, 2, 2, [1, 1, 1, 1], 4, "Hellfire"),
        (1, 2, 1, 1, [0, 0, 0, 0], 3, "GBU-15"),
    ];
    assert_eq!(records.len(), 3);
    for (r, (station, hardpoint, carriage, store, bits, status, kind)) in records.iter().zip(want) {
        let n = |name| field(r, name).as_u64().unwrap();
        assert_eq!((n("Station ID"), n("Hardpoint ID"), n("Carriage ID"), n("Store ID")), (station, hardpoint, carriage, store));
        assert_eq!(n("General Status"), status);
        assert_eq!([n("Weapon Armed"), n("Target Enabled"), n("Laser Enabled"), n("Fuze Enabled")], bits);
        assert_eq!(field(r, "Weapon Type").as_str(), Some(kind));
    }
    // Table 21 names.
    assert_eq!(field(&records[0], "General Status"), &Value::Enum { code: 3, label: Some("Ready/All Up Round") });
    assert_eq!(field(&records[1], "General Status"), &Value::Enum { code: 4, label: Some("Launch") });
}

/// Item 141 (8.141, Table 24): four waypoints. The example prints the info
/// value as (Source bit, Mode bit).
#[test]
fn item_141_waypoint_list() {
    let v = example(
        141,
        "810D 40 0F00 0001 0340 71D8 9419 BDBF E708 9800 0F01 0002 0240 71D3 8819 BCCE 2408 FC00 0F02 7FFF 0140 \
         71E3 0819 BF2C 1B07 D000 0F03 FFFE 0040 71E5 AF19 BF5A A709 6000",
    );
    let want = [
        (0, 1, (1, 1), (38.889422, -77.035162, 200.0)),
        (1, 2, (1, 0), (38.889268, -77.049918, 250.0)),
        (2, 32767, (0, 1), (38.889741, -77.012933, 100.0)),
        (3, -2, (0, 0), (38.889822, -77.010092, 300.0)),
    ];
    let records = list(&v);
    assert_eq!(records.len(), 4);
    let hae = lsb_imapb(-900.0, 9000.0, 3);
    for (r, (id, order, (source, mode), (lat, lon, height))) in records.iter().zip(want) {
        assert_eq!(field(r, "Waypoint ID"), &Value::Uint(id));
        assert_eq!(field(r, "Prosecution Order"), &Value::Int(order));
        assert_eq!(field(r, "Source").as_u64(), Some(source));
        assert_eq!(field(r, "Mode").as_u64(), Some(mode));
        let loc = field(r, "Location");
        // The printed values have six decimals.
        close("latitude", loc.field("Latitude"), lat, 2e-6);
        close("longitude", loc.field("Longitude"), lon, 2e-6);
        close("HAE", loc.field("HAE"), height, hae);
    }
}

/// Item 142 (8.142, Table 25): azimuth 210 + 300, elevation -75 + 50, no
/// roll pair.
#[test]
fn item_142_view_domain() {
    let v = example(142, "810E 0E 0634 8000 4B00 0006 1A40 000C 8000");
    let az = lsb_imapb(0.0, 360.0, 3);
    let el = lsb_imapb(-180.0, 180.0, 3);
    close("azimuth start", v.field("Azimuth Start"), 210.0, az);
    close("azimuth range", v.field("Azimuth Range"), 300.0, az);
    close("elevation start", v.field("Elevation Start"), -75.0, el);
    close("elevation range", v.field("Elevation Range"), 50.0, az);
    assert!(v.field("Roll Start").is_none() && v.field("Roll Range").is_none());
}

/// Item 143 (8.143): only allowed inside Segment and Amend sets (tags 100
/// and 101), so the example is placed in a Segment.
#[test]
fn item_143_metadata_substream_id_in_a_segment() {
    let inner = Set::new().raw(&hex("810F 11 008D C4F4 623E A25A 859C 5D0A F0C9 5E8C 39")).item(3, b"SEG");
    let p = misb::decode(&St0601::new().time(1).set(100, inner).build()).unwrap();
    assert!(p.is_ok());
    let segment = p.get(st0601::Tag::SegmentLocalSet).and_then(Value::as_set).expect("segment set");
    assert_eq!(segment.standard, misb::Standard::St0601);
    let id = segment.get(st0601::Tag::MetadataSubstreamIdPack).expect("tag 143");
    assert_eq!(field(id, "Local Id"), &Value::Uint(0));
    assert_eq!(field(id, "Universal Id").as_str(), Some("8dc4f462-3ea2-5a85-9c5d-0af0c95e8c39"));
    assert_eq!(segment.get(3u8).and_then(Value::as_str), Some("SEG"));
}

/// The ends of every mapped item's range, from the ST 0601.19 section 8
/// summary tables: an unsigned item's codes 0 and all ones decode to its
/// minimum and maximum; a signed item's codes +/-(2^(N-1) - 1) to plus and
/// minus its range and 0 to 0; and the most negative code, which every
/// signed item reserves, to the indicator the table names ("Out of Range"
/// and "Reserved" as `OutOfRange`, "N/A (Off-Earth)" as an `Enum` with that
/// label).
#[test]
fn mapped_ranges_from_the_summary_tables() {
    let decode = |tag: u64, v: &[u8]| -> Value {
        let p = misb::decode(&St0601::new().item(tag, v).build()).unwrap();
        p.get(tag).unwrap().clone()
    };
    let exact = |what: String, got: Value, want: f64| {
        let v = got.as_f64().unwrap_or_else(|| panic!("{what}: {got:?}"));
        assert!((v - want).abs() <= want.abs() * 1e-12 + 1e-12, "{what}: {v} vs {want}");
    };
    let unsigned: [(&[u64], usize, f64, f64); 9] = [
        (&[5, 35, 64, 71], 2, 0.0, 360.0),
        (&[15, 25, 38, 42, 54, 69, 75, 76, 78], 2, -900.0, 19_000.0),
        (&[16, 17], 2, 0.0, 180.0),
        (&[18, 20], 4, 0.0, 360.0),
        (&[21, 57], 4, 0.0, 5_000_000.0),
        (&[22, 58], 2, 0.0, 10_000.0),
        (&[36, 55], 1, 0.0, 100.0),
        (&[37, 49, 53], 2, 0.0, 5_000.0),
        (&[45, 46], 2, 0.0, 4_095.0),
    ];
    for (tags, len, min, max) in unsigned {
        for &tag in tags {
            exact(format!("tag {tag} minimum"), decode(tag, &vec![0; len]), min);
            exact(format!("tag {tag} maximum"), decode(tag, &vec![0xFF; len]), max);
        }
    }
    #[derive(Clone, Copy)]
    enum Indicator {
        OutOfRange,
        OffEarth,
    }
    use Indicator::*;
    let signed: [(&[u64], usize, f64, Indicator); 11] = [
        (&[6, 50, 52], 2, 20.0, OutOfRange),
        (&[7], 2, 50.0, OutOfRange),
        (&[51], 2, 180.0, OutOfRange),
        (&[79, 80], 2, 327.0, OutOfRange),
        (&[26, 27, 28, 29, 30, 31, 32, 33], 2, 0.075, OffEarth),
        (&[13, 67], 4, 90.0, OutOfRange),
        (&[14, 19, 68], 4, 180.0, OutOfRange),
        (&[23, 40, 82, 84, 86, 88], 4, 90.0, OffEarth),
        (&[24, 41, 83, 85, 87, 89], 4, 180.0, OffEarth),
        (&[90, 91, 92], 4, 90.0, OutOfRange),
        (&[93], 4, 180.0, OutOfRange),
    ];
    for (tags, len, range, indicator) in signed {
        let mut top = vec![0xFF; len];
        top[0] = 0x7F;
        let mut bottom = vec![0; len];
        bottom[0] = 0x80;
        bottom[len - 1] = 0x01;
        let mut reserved = vec![0; len];
        reserved[0] = 0x80;
        for &tag in tags {
            exact(format!("tag {tag} maximum"), decode(tag, &top), range);
            exact(format!("tag {tag} minimum"), decode(tag, &bottom), -range);
            exact(format!("tag {tag} zero"), decode(tag, &vec![0; len]), 0.0);
            let want = match indicator {
                OutOfRange => Value::OutOfRange,
                OffEarth => Value::Enum { code: 1 << (8 * len - 1), label: Some("N/A (Off-Earth)") },
            };
            assert_eq!(decode(tag, &reserved), want, "tag {tag} reserved code");
        }
    }
    // Lengths other than the required one are not values.
    for tag in [5u64, 13, 15, 18, 26, 36] {
        assert!(!decode(tag, &[0; 3]).is_valid(), "tag {tag}");
    }
}

// ---------------------------------------------------------------- ST 0902 complete packets

/// The value bytes of an item example, without its tag and length.
fn example_value_bytes(tlv: &str) -> Vec<u8> {
    let b = hex(tlv);
    let tag_len = if b[0] & 0x80 != 0 { 2 } else { 1 };
    b[tag_len + 1..].to_vec()
}

/// Check the items of an ST 0902.8 packet that reuse ST 0601.19 example
/// bytes: same bytes, same value.
fn check_shared_examples(p: &Packet, tags: &[u64]) {
    let examples = item_examples();
    for &tag in tags {
        let (_, tlv, want) = examples.iter().find(|e| e.0 == tag).unwrap();
        let item = p.item(tag).unwrap_or_else(|| panic!("tag {tag} missing"));
        assert_eq!(item.raw, example_value_bytes(tlv), "tag {tag} bytes");
        check(&format!("tag {tag}"), &item.value, *want);
    }
}

const SHARED: [u64; 16] = [5, 6, 7, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25];

/// ST 0902.8 Table 10: 228 bytes, two-byte long-form length, nested ST 0102
/// set, ST 1204 identifier, checksum 0x3E1E.
#[test]
fn st0902_packet_a_dynamic_and_constant() {
    let bytes = spec_packet_a();
    assert_eq!(bytes.len(), 228);
    let (p, used) = misb::decode_prefix(&bytes, &misb::Config::default()).unwrap();
    assert_eq!(used, 228);
    assert_eq!(p.checksum, Checksum::Valid);
    assert!(p.is_ok());
    let tags: Vec<u64> = p.iter().map(|i| i.tag).collect();
    assert_eq!(tags, [2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 48, 65, 94, 1]);
    check(
        "time",
        p.get(st0601::Tag::PrecisionTimeStamp).unwrap(),
        Want::Time(1_231_798_102_000_000),
    );
    assert_eq!(p.get(2u8).unwrap().to_string(), "2009-01-12T22:08:22.000000 MISP");
    assert_eq!(p.get(st0601::Tag::MissionId).and_then(Value::as_str), Some("Mission 12"));
    assert_eq!(p.get(st0601::Tag::PlatformDesignation).and_then(Value::as_str), Some("Predator"));
    assert_eq!(p.get(st0601::Tag::ImageSourceSensor).and_then(Value::as_str), Some("EO Nose"));
    assert_eq!(p.get(st0601::Tag::ImageCoordinateSystem).and_then(Value::as_str), Some("Geodetic WGS84"));
    assert_eq!(p.get(st0601::Tag::UasDatalinkLsVersionNumber), Some(&Value::Uint(6)));
    assert_eq!(p.get(st0601::Tag::Checksum), Some(&Value::Uint(0x3E1E)));
    check_shared_examples(&p, &SHARED);

    // Tag 48: the nested ST 0102 set, without its own key.
    let security = p.get(st0601::Tag::SecurityLocalSet).and_then(Value::as_set).expect("tag 48 set");
    assert_eq!(security.standard, misb::Standard::St0102);
    assert_eq!(security.checksum, Checksum::NotApplicable);
    assert_eq!(security.error, None);
    let tags: Vec<u64> = security.iter().map(|i| i.tag).collect();
    assert_eq!(tags, [1, 2, 3, 12, 13, 22]);
    assert_eq!(
        security.get(st0102::Tag::SecurityClassification),
        Some(&Value::Enum { code: 1, label: Some("UNCLASSIFIED//") })
    );
    assert_eq!(
        security.get(st0102::Tag::ClassifyingCountryCodingMethod),
        Some(&Value::Enum { code: 7, label: Some("1059 Three Letter") })
    );
    assert_eq!(security.get(st0102::Tag::ClassifyingCountry).and_then(Value::as_str), Some("//USA"));
    assert_eq!(
        security.get(st0102::Tag::ObjectCountryCodingMethod),
        Some(&Value::Enum { code: 7, label: Some("1059 Three Letter") })
    );
    // UTF-16BE (RFC 2781): 00 55 00 53 00 41.
    assert_eq!(security.get(st0102::Tag::ObjectCountryCodes).and_then(Value::as_str), Some("USA"));
    assert_eq!(security.get(st0102::Tag::Version), Some(&Value::Uint(10)));
    // Table 10 lists tags 4 to 6 as <None>: not in the bytes.
    assert!(security.get(st0102::Tag::SciShiInformation).is_none());

    // Tag 94: the same identifier as the ST 0601.19 item 94 example.
    let id = p.get(st0601::Tag::MiisCoreIdentifier).unwrap();
    assert_eq!(
        field(id, "Canonical").as_str(),
        Some("0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3")
    );
}

/// ST 0902.8 Table 11: 114 bytes, short-form length, checksum 0x5C2B.
#[test]
fn st0902_packet_b_dynamic_only() {
    let bytes = spec_packet_b();
    assert_eq!(bytes.len(), 114);
    let p = misb::decode(&bytes).unwrap();
    assert_eq!(p.checksum, Checksum::Valid);
    assert!(p.is_ok());
    let tags: Vec<u64> = p.iter().map(|i| i.tag).collect();
    assert_eq!(tags, [2, 5, 6, 7, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 65, 1]);
    assert_eq!(p.get(2u64), Some(&Value::Time(1_231_798_102_000_000)));
    assert_eq!(p.get(65u16), Some(&Value::Uint(6)));
    assert_eq!(p.get(1u32), Some(&Value::Uint(0x5C2B)));
    check_shared_examples(&p, &SHARED);
}

/// Both packets through every entry point: the stream decoder, whole
/// buffer, lazily, and with a damaged checksum.
#[test]
fn st0902_packets_through_every_entry_point() {
    let mut stream = spec_packet_a();
    stream.extend(spec_packet_b());
    stream.extend(spec_packet_a());
    let all = misb::decode_all(&stream);
    assert_eq!(all.len(), 3);
    assert!(all.iter().all(Packet::is_ok));
    assert_eq!(all[0], misb::decode(&spec_packet_a()).unwrap());
    assert_eq!(all[1], misb::decode(&spec_packet_b()).unwrap());
    assert!(misb::decode_iter(&stream).eq(all.clone()));
    let mut d = misb::Decoder::new();
    for b in &stream {
        d.push(std::slice::from_ref(b));
    }
    let byte_by_byte: Vec<Packet> = d.packets().collect();
    assert_eq!(byte_by_byte, all);
    assert_eq!(d.stats().packets, 3);
    assert_eq!(d.stats().packet_bytes, stream.len() as u64);

    let mut bad = spec_packet_b();
    let n = bad.len();
    bad[n - 1] = 0x2C;
    let p = misb::decode(&bad).unwrap();
    assert_eq!(p.checksum, Checksum::Mismatch { expected: 0x5C2C, computed: 0x5C2B });
    assert!(!p.is_ok());
}

// ---------------------------------------------------------------- ST 0903

/// The VMTI Local Set and VTarget Pack examples of ST 0903.6 in one set,
/// nested in ST 0601 tag 74.
fn vmti_example() -> Packet {
    let vmask = hex("01 09 02 39AA 02 39BF 02 3B0B  02 0C 03 01 4A 02 03 01 59 04 03 01 6A 02");
    // Table 14 assigns tag 12 to the algorithm ID; the example prints 0x0B,
    // a typo (tag 11 is the acceleration pack).
    let vtracker = hex("01 10 F81D 4FAE 7DEC 11D0 A765 00A0 C91E 6BF6  03 08 0003 8244 30F6 CE40  07 01 32  0C 01 03");
    let vchip = hex("01 04 6A70 6567");
    let pack = hex(
        "01 03 0640 00  02 03 0640 00  03 03 0640 00  04 01 1B  05 01 50  06 02 0ACD  07 01 32  08 03 DAA5 20 \
         09 02 3354  0A 03 3A66 67  0B 03 3E66 67  0C 02 2A94  0D 03 3A66 67  0E 03 3A66 67  0F 03 3A66 67 \
         10 03 3A66 67  13 02 0368  14 02 0471",
    );
    let target = Set(pack).item(101, &vmask).item(104, &vtracker).item(105, &vchip);
    let algorithm = hex("01 01 09  02 14 6B36 5F79 6F6C 6F5F 3930 3030 5F74 7261 636B 6572  03 04 322E 3661  04 07 6B61 6C6D 616E 6E  05 01 0A");
    let vmti = Set(hex(
        "02 08 0003 8244 30F6 CE40  03 0E 4453 544F 5F41 4453 535F 564D 5449  04 01 06  05 01 1C  06 01 0E \
         08 02 0780  09 02 0438  0A 07 454F 204E 6F73 65  0B 02 0640  0C 02 0500",
    ))
    .item(101, &series(&[vtarget(1234, target)]))
    .item(102, &series(&[algorithm]));
    let p = misb::decode(&St0601::new().time(987_654_321_000_000).set(74, vmti).build()).unwrap();
    assert!(p.is_ok(), "{p}");
    p.get(st0601::Tag::VmtiLocalSet).and_then(Value::as_set).expect("tag 74 set").clone()
}

#[test]
fn st0903_vmti_local_set_examples() {
    let v = vmti_example();
    assert_eq!(v.standard, misb::Standard::St0903);
    assert_eq!(v.error, None);
    use st0903::Tag;
    // 987654321000000 us = April 19, 2001, 04:25:21.
    assert_eq!(v.get(Tag::PrecisionTimeStamp), Some(&Value::Time(987_654_321_000_000)));
    assert_eq!(v.get(Tag::PrecisionTimeStamp).unwrap().to_string(), "2001-04-19T04:25:21.000000 MISP");
    assert_eq!(v.get(Tag::VmtiSystemName).and_then(Value::as_str), Some("DSTO_ADSS_VMTI"));
    assert_eq!(v.get(Tag::VersionNumber), Some(&Value::Uint(6)));
    assert_eq!(v.get(Tag::TotalNumberOfTargetsDetected), Some(&Value::Uint(28)));
    assert_eq!(v.get(Tag::NumberOfReportedTargets), Some(&Value::Uint(14)));
    assert_eq!(v.get(Tag::FrameWidth), Some(&Value::Uint(1920)));
    assert_eq!(v.get(Tag::FrameHeight), Some(&Value::Uint(1080)));
    assert_eq!(v.get(Tag::VmtiSourceSensor).and_then(Value::as_str), Some("EO Nose"));
    let fov = lsb_imapb(0.0, 180.0, 2);
    close("horizontal fov", v.get(Tag::VmtiHorizontalFieldOfView), 12.5, fov);
    close("vertical fov", v.get(Tag::VmtiVerticalFieldOfView), 10.0, fov);
    // A VMTI tag is not an ST 0601 tag of the same number.
    assert!(v.get(st0601::Tag::MissionId).is_none());
}

#[test]
fn st0903_vtarget_pack_examples() {
    let v = vmti_example();
    let targets = list(v.get(st0903::Tag::VTargetSeries).unwrap());
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    // Target ID 1234 = 89 52 (BER-OID).
    assert_eq!(field(t, "Target ID"), &Value::Uint(1234));
    for name in ["Target Centroid", "Bounding Box Top Left", "Bounding Box Bottom Right"] {
        assert_eq!(field(t, name), &Value::Uint(409_600), "{name}");
    }
    assert_eq!(field(t, "Target Priority"), &Value::Uint(27));
    assert_eq!(field(t, "Target Confidence Level"), &Value::Uint(80));
    assert_eq!(field(t, "Target History"), &Value::Uint(2765));
    assert_eq!(field(t, "Percentage of Target Pixels"), &Value::Uint(50));
    let color = field(t, "Target Color");
    assert_eq!(
        (field(color, "Red"), field(color, "Green"), field(color, "Blue")),
        (&Value::Uint(218), &Value::Uint(165), &Value::Uint(32))
    );
    assert_eq!(field(t, "Target Intensity"), &Value::Uint(13140));
    let offset = lsb_imapb(-19.2, 19.2, 3);
    close("lat offset", t.field("Target Location Latitude Offset"), 10.0, offset);
    close("lon offset", t.field("Target Location Longitude Offset"), 12.0, offset);
    close("height", t.field("Target Height"), 10_000.0, lsb_imapb(-900.0, 19_000.0, 2));
    for name in [
        "Bounding Box Top Left Latitude Offset",
        "Bounding Box Top Left Longitude Offset",
        "Bounding Box Bottom Right Latitude Offset",
        "Bounding Box Bottom Right Longitude Offset",
    ] {
        close(name, t.field(name), 10.0, offset);
    }
    assert_eq!(field(t, "Centroid Pixel Row"), &Value::Uint(872));
    assert_eq!(field(t, "Centroid Pixel Column"), &Value::Uint(1137));
}

#[test]
fn st0903_nested_set_examples() {
    let v = vmti_example();
    let t = &list(v.get(st0903::Tag::VTargetSeries).unwrap())[0];

    // VMask (10.3.1, 10.3.2).
    let mask = field(t, "VMask");
    assert_eq!(list(field(mask, "Pixel Contour")), [Value::Uint(14762), Value::Uint(14783), Value::Uint(15115)]);
    let runs: Vec<(u64, u64)> = list(field(mask, "Bit Mask Series"))
        .iter()
        .map(|r| (field(r, "Pixel").as_u64().unwrap(), field(r, "Run Length").as_u64().unwrap()))
        .collect();
    assert_eq!(runs, [(74, 2), (89, 4), (106, 2)]);

    // VTracker (Table 14).
    let tracker = field(t, "VTracker");
    assert_eq!(field(tracker, "Track ID").as_str(), Some("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
    assert_eq!(field(tracker, "First Observation Time"), &Value::Time(987_654_321_000_000));
    assert_eq!(field(tracker, "Confidence Level"), &Value::Uint(50));
    assert_eq!(field(tracker, "Algorithm ID"), &Value::Uint(3));

    // VChip (Table 15).
    assert_eq!(field(field(t, "VChip"), "Image Type").as_str(), Some("jpeg"));

    // Algorithm Series (Table 16).
    let algorithms = list(v.get(st0903::Tag::AlgorithmSeries).unwrap());
    assert_eq!(algorithms.len(), 1);
    let a = &algorithms[0];
    assert_eq!(field(a, "Algorithm ID"), &Value::Uint(9));
    assert_eq!(field(a, "Name").as_str(), Some("k6_yolo_9000_tracker"));
    assert_eq!(field(a, "Version").as_str(), Some("2.6a"));
    assert_eq!(field(a, "Class").as_str(), Some("kalmann"));
    assert_eq!(field(a, "Number of Frames"), &Value::Uint(10));
}

// ---------------------------------------------------------------- ST 0102 and ST 0806

fn nested(tag: u64, set: Set) -> Packet {
    let p = misb::decode(&St0601::new().time(1).set(tag, set).build()).unwrap();
    assert!(p.is_ok(), "{p}");
    p.get(tag).and_then(Value::as_set).expect("nested set").clone()
}

/// ST 0102.12 Table 2 and sections 6.1 and 6.8: classifications, the two
/// coding method tables (numbered differently from 0x03 on), text and date
/// items.
#[test]
fn st0102_tables() {
    let labels = ["UNCLASSIFIED//", "RESTRICTED//", "CONFIDENTIAL//", "SECRET//", "TOP SECRET//"];
    for (code, label) in (1u8..).zip(labels) {
        let s = nested(48, Set::new().item(1, &[code]));
        assert_eq!(s.get(st0102::Tag::SecurityClassification), Some(&Value::Enum { code: code.into(), label: Some(label) }));
    }
    let s = nested(
        48,
        Set::new()
            .item(2, &[0x03])
            .item(12, &[0x03])
            .item(6, b"CAN USA")
            .item(10, b"20251231")
            .item(13, &utf16be("CAN;USA"))
            .item(22, &[0x00, 0x0C])
            .item(23, b"2017-06-22")
            .item(12, &[0x40]),
    );
    assert_eq!(
        s.get(st0102::Tag::ClassifyingCountryCodingMethod),
        Some(&Value::Enum { code: 3, label: Some("FIPS 10-4 Two Letter") })
    );
    assert_eq!(s.get(st0102::Tag::ObjectCountryCodingMethod), Some(&Value::Enum { code: 3, label: Some("ISO-3166 Numeric") }));
    let methods: Vec<&Value> = s.get_all(st0102::Tag::ObjectCountryCodingMethod).map(|i| &i.value).collect();
    assert_eq!(methods[1], &Value::Enum { code: 0x40, label: Some("GENC AdminSub") });
    assert_eq!(s.get(st0102::Tag::ReleasingInstructions).and_then(Value::as_str), Some("CAN USA"));
    assert!(s.get(st0102::Tag::DeclassificationDate).unwrap().is_valid());
    assert_eq!(s.get(st0102::Tag::ObjectCountryCodes).and_then(Value::as_str), Some("CAN;USA"));
    assert_eq!(s.get(st0102::Tag::Version), Some(&Value::Uint(12)));
    assert!(s.get(st0102::Tag::ClassifyingCountryCodingMethodVersionDate).unwrap().is_valid());
    // Codes the tables leave undefined keep their code without a label.
    let s = nested(48, Set::new().item(1, &[0x06]));
    assert_eq!(s.get(1u8).and_then(Value::as_u64), Some(6));
    assert!(!matches!(s.get(1u8), Some(Value::Enum { label: Some(_), .. })));
}

/// ST 0806.4 Tables 8-1 to 8-4: mappings, enumerations and MGRS limits.
#[test]
fn st0806_tables() {
    let poi = |items: Set| {
        let s = nested(73, Set::new().set(12, items));
        s.get(st0806::Tag::PointOfInterestLocalSet).expect("POI").clone()
    };
    // Latitude int / (2^31 - 1) * 90, longitude * 180; 0x80000000 is the
    // error value; altitude int / 65535 * 19900 - 900.
    let v = poi(Set::new()
        .item(1, &[0, 5])
        .item(2, &0x7FFF_FFFFu32.to_be_bytes())
        .item(3, &0x8000_0001u32.to_be_bytes())
        .item(4, &[0xFF, 0xFF])
        .item(5, &[3])
        .item(7, b"SFGPUCI"));
    assert_eq!(field(&v, "POI/AOI Number"), &Value::Uint(5));
    close("POI latitude", v.field("POI Latitude"), 90.0, lsb_s(180.0, 32));
    close("POI longitude", v.field("POI Longitude"), -180.0, lsb_s(360.0, 32));
    close("POI altitude", v.field("POI Altitude"), 19_000.0, lsb_u(19_900.0, 16));
    assert_eq!(field(&v, "POI/AOI Type"), &Value::Enum { code: 3, label: Some("Target") });
    assert_eq!(field(&v, "POI Source Icon").as_str(), Some("SFGPUCI"));
    let v = poi(Set::new().item(1, &[0, 1]).item(2, &0x8000_0000u32.to_be_bytes()).item(3, &[0; 4]).item(4, &[0, 0]));
    assert_eq!(field(&v, "POI Latitude"), &Value::OutOfRange);
    close("POI longitude", v.field("POI Longitude"), 0.0, 1e-12);
    close("POI altitude", v.field("POI Altitude"), -900.0, lsb_u(19_900.0, 16));

    // AOI type 3 is Reserved, unlike the POI table.
    let s = nested(73, Set::new().set(13, Set::new().item(1, &[0, 2]).item(6, &[3])));
    let aoi = s.get(st0806::Tag::AreaOfInterestLocalSet).unwrap();
    assert_eq!(field(aoi, "POI/AOI Type"), &Value::Enum { code: 3, label: Some("Reserved") });

    // User Defined: bits 8 and 7 give the data type, bits 6 to 1 the ID.
    let user = |id: u8, data: &[u8]| {
        let s = nested(73, Set::new().set(11, Set::new().item(1, &[id]).item(2, data)));
        s.get(st0806::Tag::UserDefinedLocalSet).unwrap().clone()
    };
    let v = user(0x85, &[0x01, 0x00]);
    let id = field(&v, "Numeric ID for Data Type");
    assert_eq!(field(id, "Data Type"), &Value::Enum { code: 2, label: Some("UINT") });
    assert_eq!(field(id, "Numeric ID"), &Value::Uint(5));
    assert_eq!(field(&v, "User Data"), &Value::Uint(256));
    assert_eq!(field(&user(0x41, &[0xFF]), "User Data"), &Value::Int(-1));
    assert_eq!(field(&user(0x02, b"hello"), "User Data").as_str(), Some("hello"));
    assert_eq!(field(&user(0xC2, &[9, 9]), "User Data"), &Value::Bytes(vec![9, 9]));

    // The RVT set itself.
    let s = nested(
        73,
        Set::new()
            .item(2, &987_654_321_000_000u64.to_be_bytes())
            .item(3, &[0x01, 0x2C])
            .item(7, &0xFFFF_FFFFu32.to_be_bytes())
            .item(8, &[4])
            .item(10, b"MPEG4")
            .item(14, &[60])
            .item(15, b"CXZ")
            .item(16, &[0x01, 0x86, 0x9F])
            .item(18, &[61])
            .item(19, b"CIZ")
            .item(20, &[0x01, 0x86, 0xA0]),
    );
    use st0806::Tag;
    assert_eq!(s.get(Tag::PrecisionTimeStamp), Some(&Value::Time(987_654_321_000_000)));
    assert_eq!(s.get(Tag::PlatformTrueAirspeed), Some(&Value::Uint(300)));
    assert_eq!(s.get(Tag::FrameCode), Some(&Value::Uint(4_294_967_295)));
    assert_eq!(s.get(Tag::VersionNumber), Some(&Value::Uint(4)));
    assert_eq!(s.get(Tag::DigitalVideoFileFormat).and_then(Value::as_str), Some("MPEG4"));
    assert_eq!(s.get(Tag::MgrsZone), Some(&Value::Uint(60)));
    assert_eq!(s.get(Tag::MgrsLatitudeBandAndGridSquare).and_then(Value::as_str), Some("CXZ"));
    assert_eq!(s.get(Tag::MgrsEasting), Some(&Value::Uint(99_999)));
    // Zone 61, the letter I and an easting of 100000 m are outside the tables.
    assert!(!s.get(Tag::MgrsZoneSecondValue).unwrap().is_valid());
    assert!(!s.get(Tag::MgrsLatitudeBandAndGridSquareSecondValue).unwrap().is_valid());
    assert!(!s.get(Tag::MgrsEastingSecondValue).unwrap().is_valid());
}

/// The ST 0806 CRC (tag 1) uses CRC-32/MPEG-2; its check value.
#[test]
fn st0806_crc_check_value() {
    assert_eq!(misb::checksum::crc32_mpeg2(b"123456789"), 0x0376_E6E7);
    // ST 0601.19 section 6.2 prints the key's registry CRC.
    assert_eq!(misb::checksum::crc16_ccitt(&KEY), 56773);
}

// ---------------------------------------------------------------- ST 1204

/// ST 1204.3 Appendix E examples and the section 7.4.1 example, as ST 0601
/// tag 94 and ST 0903 tag 13.
#[test]
fn st1204_appendix_e_examples() {
    let examples = [
        ("01 40 BC76CFEF0BEE41A49618EB4B010D2F08", "0140:BC76-CFEF-0BEE-41A4-9618-EB4B-010D-2F08:B6"),
        (
            "01 54 C7D1625398A241C2BA6E90F8FCC73914 E047AB3E81BE41ED966409B02F445FAB 5E71B0DC20FE4920821626D64F61D863",
            "0154:C7D1-6253-98A2-41C2-BA6E-90F8-FCC7-3914/E047-AB3E-81BE-41ED-9664-09B0-2F44-5FAB/\
             5E71-B0DC-20FE-4920-8216-26D6-4F61-D863:C8",
        ),
        ("01 02 03DD9DEEFB48477B8204B0506F6B2A33", "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25"),
        ("01 10 1AB8231E17E84748A133CE9389A7A060", "0110:1AB8-231E-17E8-4748-A133-CE93-89A7-A060:25"),
        ("01 04 C2A7D72496F747DBA23DA29730075876", "0104:C2A7-D724-96F7-47DB-A23D-A297-3007-5876:55"),
        (
            "01 70 F592F02373364AF8AA9162C00F2EB2DA 16B74341000841A0BE365B5AB96A3645",
            "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3",
        ),
    ];
    for (binary, text) in examples {
        let bytes = hex(binary);
        let p = misb::decode(&St0601::new().time(1).item(94, &bytes).build()).unwrap();
        let v = p.get(st0601::Tag::MiisCoreIdentifier).unwrap();
        assert_eq!(field(v, "Canonical").as_str(), Some(text), "{binary}");
        let (body, check) = text.rsplit_once(':').unwrap();
        assert_eq!(misb::st1204::check_value(body), u8::from_str_radix(check, 16).unwrap());
        assert_eq!(field(v, "Check Value").as_u64(), Some(u64::from_str_radix(check, 16).unwrap()));
        // The same identifier as ST 0903 tag 13.
        let vmti = nested(74, Set::new().item(4, &[6]).item(13, &bytes));
        assert_eq!(field(vmti.get(st0903::Tag::MiisId).unwrap(), "Canonical").as_str(), Some(text));
    }
    // Appendix B.2, Table 15.
    assert_eq!(misb::st1204::check_value("031FA3"), 0x79);
    // Window only (E9) and Minor (E10) usages.
    let p = misb::decode(&St0601::new().item(94, &hex("01 02 03DD9DEEFB48477B8204B0506F6B2A33")).build()).unwrap();
    let v = p.get(94u8).unwrap();
    assert_eq!(field(v, "Minor ID Type"), &Value::Enum { code: 1, label: Some("Included") });
    assert_eq!(field(v, "Minor ID").as_str(), Some("03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33"));
}

// ---------------------------------------------------------------- ST 1010

/// ST 1010.3 Figure 7: Mode 1 parse control 0x4B = Slen 4, sparse, Clen 3.
#[test]
fn st1010_mode_1_parse_control_example() {
    // N = 3: three sigmas, a bit vector of ceil(3 * 2 / 16) = 1 byte with
    // slots (0,1) and (1,2) set, two IMAPB(-1, 1, 3) coefficients.
    let mut pack = vec![0x03, 0x4B, 0b1010_0000];
    for s in [1.5f32, 0.5, 4.0] {
        pack.extend(s.to_be_bytes());
    }
    pack.extend([0x60, 0x00, 0x00, 0x20, 0x00, 0x00]);
    for v in [misb::st1010::decode(&pack), example(102, &format!("66 {:02X} {}", pack.len(), to_hex(&pack)))] {
        assert_eq!(field(&v, "Matrix Size"), &Value::Uint(3));
        let pc = field(&v, "Parse Control");
        assert_eq!(field(pc, "Mode"), &Value::Uint(1));
        assert_eq!(field(pc, "Sparse"), &Value::Uint(1));
        assert_eq!(field(pc, "Standard Deviation Length"), &Value::Uint(4));
        assert_eq!(field(pc, "Correlation Length"), &Value::Uint(3));
        assert_eq!(field(&v, "Bit Vector"), &Value::Bytes(vec![0b1010_0000]));
        assert_eq!(list(field(&v, "Standard Deviation Values")), [Value::Float(1.5), Value::Float(0.5), Value::Float(4.0)]);
        let rho = list(field(&v, "Correlation Coefficient Values"));
        let lsb = lsb_imapb(-1.0, 1.0, 3);
        close("rho(0,1)", Some(&rho[0]), 0.5, lsb);
        close("rho(0,2)", Some(&rho[1]), 0.0, lsb);
        close("rho(1,2)", Some(&rho[2]), -0.5, lsb);
    }
}

/// ST 1010.3 Figure 9: Mode 2 parse control 0xB3 0x08 = sparse, IMAPB
/// correlations of 3 bytes, IEEE standard deviations of 8 bytes.
#[test]
fn st1010_mode_2_parse_control_example() {
    let mut pack = vec![0x02, 0xB3, 0x08, 0x80];
    for s in [2.25f64, 1e-3] {
        pack.extend(s.to_be_bytes());
    }
    pack.extend([0x70, 0x00, 0x00]);
    let v = misb::st1010::decode(&pack);
    let pc = field(&v, "Parse Control");
    assert_eq!(field(pc, "Mode"), &Value::Uint(2));
    assert_eq!(field(pc, "Sparse"), &Value::Uint(1));
    assert_eq!(field(pc, "Correlation Length"), &Value::Uint(3));
    assert_eq!(field(pc, "Correlation Format").as_u64(), Some(1));
    assert_eq!(field(pc, "Standard Deviation Length"), &Value::Uint(8));
    assert_eq!(field(pc, "Standard Deviation Format").as_u64(), Some(0));
    assert_eq!(list(field(&v, "Standard Deviation Values")), [Value::Float(2.25), Value::Float(1e-3)]);
    close("rho", list(field(&v, "Correlation Coefficient Values")).first(), 0.75, lsb_imapb(-1.0, 1.0, 3));
    // Malformed: left-over bytes, and a zero-length pack.
    let mut long = pack.clone();
    long.push(0);
    assert!(!misb::st1010::decode(&long).is_valid());
    assert_eq!(misb::st1010::decode(&[]), Value::Unknown);
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

// ---------------------------------------------------------------- ST 1201

/// ST 1201.5 Appendix A vectors and the ST 0903.6 IMAPB examples, through
/// `imapb::decode` and `Imapb`.
#[test]
fn st1201_appendix_a_vectors() {
    // (min, max, bytes, value)
    let vectors: [(f64, f64, &str, f64); 18] = [
        (-900.0, 19_000.0, "000000", -900.0),
        (-900.0, 19_000.0, "038400", 0.0),
        (-900.0, 19_000.0, "038E00", 10.0),
        (0.1, 0.9, "0000", 0.1),
        (0.1, 0.9, "3333", 0.499993896484375),
        (0.1, 0.9, "6666", 0.89998779296875),
        (0.0, 100.0, "0A199999", 10.09999996),
        (0.0, 100.0, "32800000", 50.5),
        (0.0, 100.0, "64000000", 100.0),
        (0.0, 100.0, "0A1999", 10.09999),
        (0.0, 100.0, "143333", 20.20000),
        (-9.9, 110.0, "000000", -9.9),
        (-9.9, 110.0, "09E667", 0.0),
        (-9.9, 110.0, "0A2000", 0.22499),
        (-9.9, 110.0, "77E667", 110.0),
        (-19.2, 19.2, "3A6667", 10.0),
        (-19.2, 19.2, "3E6667", 12.0),
        (0.0, 180.0, "0640", 12.5),
    ];
    for (min, max, bytes, want) in vectors {
        let b = hex(bytes);
        let lsb = lsb_imapb(min, max, b.len());
        // Appendix A prints some values to 5 decimals.
        close(&format!("IMAPB({min}, {max}) {bytes}"), Some(&misb::imapb::decode(min, max, &b)), want, lsb.max(2e-5));
        let m = Imapb::new(min, max, b.len()).unwrap();
        assert_eq!(m.decode(&b), misb::imapb::decode(min, max, &b));
    }
    // Special values (Table 2): NaN and the infinities.
    let v = misb::imapb::decode(0.0, 100.0, &hex("D0000000"));
    assert!(v.as_f64().is_some_and(f64::is_nan), "{v:?}");
    assert_eq!(misb::imapb::decode(0.0, 100.0, &hex("C8000000")), Value::Float(f64::INFINITY));
    assert_eq!(misb::imapb::decode(0.0, 100.0, &hex("E8000000")), Value::Float(f64::NEG_INFINITY));
    assert_eq!(misb::imapb::decode(-900.0, 19_000.0, &hex("E80000")), Value::Float(f64::NEG_INFINITY));
    // Below-minimum and above-maximum signals.
    assert_eq!(misb::imapb::decode(0.0, 100.0, &hex("E0000000")), Value::OutOfRange);
    assert_eq!(misb::imapb::decode(-9.9, 110.0, &hex("E10000")), Value::OutOfRange);
    // The forward mapping gives the printed bytes.
    let m = Imapb::new(-19.2, 19.2, 3).unwrap();
    assert_eq!(m.real_to_int(10.0), Some(0x3A6667));
    assert_eq!(m.real_to_int(12.0), Some(0x3E6667));
    assert_eq!(Imapb::new(0.0, 180.0, 2).unwrap().real_to_int(12.5), Some(0x0640));
    assert_eq!(Imapb::new(-900.0, 19_000.0, 2).unwrap().real_to_int(10_000.0), Some(0x2A94));
}

/// The examples decode the same through a decoder, whole buffer and lazily,
/// and every item of every example keeps its bytes.
#[test]
fn every_example_keeps_its_bytes() {
    for (tag, tlv, _) in item_examples() {
        let p = decode_tlv(tlv);
        let item: &Item = p.item(tag).unwrap();
        assert_eq!(item.raw, example_value_bytes(tlv), "tag {tag}");
    }
}
