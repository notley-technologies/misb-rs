#![cfg(feature = "encode")]
//! The ST 0903 VMTI and ST 1204 Core Identifier encoders against the
//! published examples and the decoder.
//!
//! - Every ST 0903.6 example of `tests/spec_examples.rs` and every ST
//!   1204.3 example there re-encodes byte for byte, from the recorded bytes
//!   and from the decoded values alone (MUXING_PLAN.md 6.1).
//! - Random VMTI sets built with the typed builder decode to what was put
//!   in, IMAPB values within one LSB below (ST 1201 truncates, DECISIONS
//!   correction 3), and re-encode from their decoded values to the same
//!   bytes.
//! - Strict mode rejects what ST 0903.6 and the phase 0 decisions forbid.
//! - A VMTI set travels in a complete ST 0601 packet built with
//!   `St0601Builder` and decodes cleanly.
#![forbid(unsafe_code)]
mod common;

use common::*;
use misb::encode::{encode_packet, EncodeError, EncodeOptions, ErrorKind, Input, Policy, St0601Builder};
use misb::imapb::Special;
use misb::st0601::Tag;
use misb::st0903::encode::{
    Algorithm, DetectionStatus, ImageType, Imap, Location, Motion, Ontology, PixelRun, VChip, VFeature, VMask, VObject,
    VTarget, VTracker, Vmti,
};
use misb::st1204::encode::{CoreIdentifier, IdType};
use misb::{st0903, Config, MispTime, Packet, Value};

const T: u64 = 987_654_321_000_000;

fn no_raw() -> Config {
    let mut cfg = Config::default();
    cfg.keep_raw = false;
    cfg
}

fn opts(policy: Policy) -> EncodeOptions {
    let mut o = EncodeOptions::default();
    o.policy = policy;
    o
}

/// An ST 0601 packet with tag 2, the items, tag 65 and the checksum, in
/// the order `encode_packet` keeps.
fn packet(items: &[(u64, &[u8])]) -> Vec<u8> {
    let mut p = St0601::new().time(T);
    for (tag, v) in items {
        p = p.item(*tag, v);
    }
    p.item(65, &[19]).build()
}

/// Decode `bytes`, re-encode with `encode_packet` from the recorded bytes
/// and from the values alone, and check both give `bytes` back.
fn round_trip(bytes: &[u8]) {
    let p = misb::decode(bytes).unwrap();
    assert!(p.is_ok(), "{p}");
    assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes, "from the recorded bytes");
    let p = misb::decode_with(bytes, &no_raw()).unwrap();
    assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes, "from the values");
}

/// The VMTI set of ST 0601 tag 74 in a decoded packet.
fn vmti_of(p: &Packet) -> &Packet {
    p.get(Tag::VmtiLocalSet).and_then(Value::as_set).expect("tag 74 set")
}

// ---------------------------------------------------------------- (a) published examples

/// The VMTI Local Set and VTarget Pack examples of ST 0903.6 in one set,
/// as `tests/spec_examples.rs` builds them.
fn st0903_example() -> Vec<u8> {
    let vmask = hex("01 09 02 39AA 02 39BF 02 3B0B  02 0C 03 01 4A 02 03 01 59 04 03 01 6A 02");
    let vtracker = hex("01 10 F81D 4FAE 7DEC 11D0 A765 00A0 C91E 6BF6  03 08 0003 8244 30F6 CE40  07 01 32  0C 01 03");
    let vchip = hex("01 04 6A70 6567");
    let pack = hex(
        "01 03 0640 00  02 03 0640 00  03 03 0640 00  04 01 1B  05 01 50  06 02 0ACD  07 01 32  08 03 DAA5 20 \
         09 02 3354  0A 03 3A66 67  0B 03 3E66 67  0C 02 2A94  0D 03 3A66 67  0E 03 3A66 67  0F 03 3A66 67 \
         10 03 3A66 67  13 02 0368  14 02 0471",
    );
    let target = Set(pack).item(101, &vmask).item(104, &vtracker).item(105, &vchip);
    let algorithm = hex(
        "01 01 09  02 14 6B36 5F79 6F6C 6F5F 3930 3030 5F74 7261 636B 6572  03 04 322E 3661  04 07 6B61 6C6D 616E 6E  05 01 0A",
    );
    Set(hex(
        "02 08 0003 8244 30F6 CE40  03 0E 4453 544F 5F41 4453 535F 564D 5449  04 01 06  05 01 1C  06 01 0E \
         08 02 0780  09 02 0438  0A 07 454F 204E 6F73 65  0B 02 0640  0C 02 0500",
    ))
    .item(101, &series(&[vtarget(1234, target)]))
    .item(102, &series(&[algorithm]))
    .0
}

#[test]
fn st0903_examples_re_encode_byte_for_byte() {
    let vmti = st0903_example();
    let bytes = packet(&[(74, &vmti)]);
    round_trip(&bytes);
    // Through the builder, from the decoded set with and without its
    // recorded bytes.
    for cfg in [Config::default(), no_raw()] {
        let p = misb::decode_with(&bytes, &cfg).unwrap();
        let mut b = vmti_parent();
        b.set(Tag::VmtiLocalSet, Input::Value(Value::Set(Box::new(vmti_of(&p).clone())))).unwrap();
        let again = misb::decode(&b.finish().unwrap()).unwrap();
        assert_eq!(again.item(Tag::VmtiLocalSet).unwrap().raw, vmti);
    }
    // The sample set the decoder tests share, and the deprecated items.
    round_trip(&packet(&[(74, vmti_set().bytes())]));
}

/// ST 1204.3 section 7.4 and Appendix E examples, as ST 0601 tag 94 and
/// ST 0903 tag 13.
const ST1204: [(&str, &str); 6] = [
    ("01 40 BC76CFEF0BEE41A49618EB4B010D2F08", "0140:BC76-CFEF-0BEE-41A4-9618-EB4B-010D-2F08:B6"),
    (
        "01 54 C7D1625398A241C2BA6E90F8FCC73914 E047AB3E81BE41ED966409B02F445FAB 5E71B0DC20FE4920821626D64F61D863",
        "0154:C7D1-6253-98A2-41C2-BA6E-90F8-FCC7-3914/E047-AB3E-81BE-41ED-9664-09B0-2F44-5FAB/5E71-B0DC-20FE-4920-8216-26D6-4F61-D863:C8",
    ),
    ("01 02 03DD9DEEFB48477B8204B0506F6B2A33", "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25"),
    ("01 10 1AB8231E17E84748A133CE9389A7A060", "0110:1AB8-231E-17E8-4748-A133-CE93-89A7-A060:25"),
    ("01 04 C2A7D72496F747DBA23DA29730075876", "0104:C2A7-D724-96F7-47DB-A23D-A297-3007-5876:55"),
    (
        "01 70 F592F02373364AF8AA9162C00F2EB2DA 16B74341000841A0BE365B5AB96A3645",
        "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3",
    ),
];

#[test]
fn st1204_examples_re_encode_byte_for_byte() {
    for (binary, text) in ST1204 {
        let binary = hex(binary);
        round_trip(&packet(&[(94, &binary)]));
        let vmti = Set::new().item(4, &[6]).item(6, &[0]).item(13, &binary);
        round_trip(&packet(&[(74, vmti.bytes())]));
        // The identifier from its parts, its text and the builder.
        let id: CoreIdentifier = text.parse().unwrap();
        assert_eq!(id.encode().unwrap(), binary);
        assert_eq!(id.to_string(), text);
        assert_eq!(CoreIdentifier::from_bytes(&binary).unwrap(), id);
        let mut b = St0601Builder::new(MispTime::from_micros(T));
        b.set(Tag::MiisCoreIdentifier, text).unwrap();
        let p = misb::decode(&b.finish().unwrap()).unwrap();
        assert_eq!(p.item(Tag::MiisCoreIdentifier).unwrap().raw, binary);
        let mut vmti = Vmti::new();
        vmti.miis_id = Some(id);
        let p = vmti_packet(&vmti.encode().unwrap());
        assert_eq!(vmti_of(&p).item(st0903::Tag::MiisId).unwrap().raw, binary);
    }
}

#[test]
fn core_identifier_builder() {
    let uuid = |seed: u8| {
        let mut id = [seed; 16];
        id[6] = 0x40 | (seed & 0x0F);
        id[8] = 0x80 | (seed & 0x3F);
        id
    };
    let id = CoreIdentifier::new().with_sensor(IdType::Physical, uuid(1)).with_platform(IdType::Managed, uuid(2));
    let bytes = id.encode().unwrap();
    assert_eq!(&bytes[..2], &[0x01, 0x68]);
    assert_eq!(bytes.len(), 34);
    let p = misb::decode(&packet(&[(94, &bytes)])).unwrap();
    let v = p.get(Tag::MiisCoreIdentifier).unwrap();
    assert_eq!(v.field("Canonical").and_then(Value::as_str), Some(id.to_string().as_str()));
    assert_eq!(v.field("Platform ID Type"), Some(&Value::Enum { code: 1, label: Some("Managed") }));
    // D-29 rejections.
    let kind = |id: CoreIdentifier| id.encode().unwrap_err().kind;
    assert_eq!(kind(CoreIdentifier::new()), ErrorKind::Missing);
    assert_eq!(kind(CoreIdentifier::minor_id(uuid(3)).with_sensor(IdType::Virtual, uuid(4))), ErrorKind::NotAllowed);
    assert_eq!(kind(CoreIdentifier::new().with_window([0; 16])), ErrorKind::InvalidCode);
    assert_eq!(kind(CoreIdentifier::new().with_window([0x11; 16])), ErrorKind::InvalidCode);
}

// ---------------------------------------------------------------- (d) a complete ST 0601 packet

/// A builder with the frame centre a packet carrying VMTI needs (D-31).
fn vmti_parent() -> St0601Builder {
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    b.set(Tag::FrameCenterLatitude, 38.8).unwrap().set(Tag::FrameCenterLongitude, -77.0).unwrap();
    b
}

/// `vmti` in an ST 0601 packet with frame centre and security, decoded.
fn vmti_packet(vmti: &[u8]) -> Packet {
    let security = misb::encode::Security::new(misb::encode::Classification::Unclassified, 0x0E, "//USA", 0x0E, "USA");
    let mut b = St0601Builder::new(MispTime::from_micros(T));
    b.set(Tag::FrameCenterLatitude, 38.8)
        .unwrap()
        .set(Tag::FrameCenterLongitude, -77.0)
        .unwrap()
        .set(Tag::SecurityLocalSet, Input::Set(security.encode().unwrap()))
        .unwrap()
        .set(Tag::VmtiLocalSet, Input::Set(vmti.to_vec()))
        .unwrap();
    let bytes = b.finish().unwrap();
    let p = misb::decode(&bytes).unwrap();
    assert!(p.is_ok(), "{p}");
    // Unchanged packets re-encode from their recorded bytes.
    assert_eq!(encode_packet(&p, &EncodeOptions::default()).unwrap(), bytes);
    p
}

const TRACK: [u8; 16] = [0xF8, 0x1D, 0x4F, 0xAE, 0x7D, 0xEC, 0x11, 0xD0, 0xA7, 0x65, 0x00, 0xA0, 0xC9, 0x1E, 0x6B, 0xF6];
const PNG: [u8; 12] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D];

/// A set that uses every item the builder writes.
fn full() -> Vmti {
    let mut vmti = Vmti::new();
    vmti.time = Some(MispTime::from_micros(T + 33_000));
    vmti.parent_time = Some(MispTime::from_micros(T));
    vmti.frame_period_us = Some(33_366);
    vmti.vmti_mi_is_user_mi = false;
    vmti.system_name = Some("DSTO_ADSS_VMTI".into());
    vmti.total_targets_detected = Some(28);
    vmti.frame_width = Some(1920);
    vmti.frame_height = Some(1080);
    vmti.source_sensor = Some("EO Nose".into());
    vmti.horizontal_fov = Some(12.5.into());
    vmti.vertical_fov = Some(10.0.into());
    vmti.miis_id = Some(ST1204[5].1.parse().unwrap());
    let mut t = VTarget::new(1234);
    t.centroid = Some(409_600);
    t.bounding_box = Some((409_600, 448_030));
    t.priority = Some(27);
    t.confidence = Some(80);
    t.history = Some(2765);
    t.percentage_pixels = Some(50);
    t.color = Some([0xDA, 0xA5, 0x20]);
    t.intensity = Some(13_140);
    t.location_offset = Some((10.0.into(), 12.0.into()));
    t.hae = Some(10_000.0.into());
    t.bounding_box_offsets = Some([10.0.into(), 10.0.into(), 10.0.into(), 10.0.into()]);
    t.location = Some(Location::new(38.8, -77.0, 30.0).with_sigma(10.0, 10.0, 20.0).with_rho(0.5, 0.0, 0.0));
    t.contour = vec![Location::new(38.81, -77.01, 25.0), Location::new(38.79, -76.99, 35.0)];
    t.centroid_row_col = Some((872, 1137));
    t.algorithm_id = Some(9);
    t.status = Some(DetectionStatus::ActiveCoasting);
    let mut mask = VMask::polygon(vec![14762, 14783, 15115]);
    mask.bit_mask = vec![PixelRun::new(74, 2), PixelRun::new(89, 4), PixelRun::new(106, 2)];
    t.mask = Some(mask);
    let mut tracker = VTracker::default();
    tracker.track_id = Some(TRACK);
    tracker.first_observation = Some(MispTime::from_micros(T));
    tracker.latest_observation = Some(MispTime::from_micros(T + 2_000_000));
    tracker.boundary = vec![Location::new(38.8, -77.0, 30.0), Location::new(38.9, -76.9, 30.0)];
    tracker.confidence = Some(50);
    tracker.history = vec![Location::new(38.8, -77.0, 30.0), Location::new(38.81, -77.0, 30.0).with_sigma(1.0, 2.0, 3.0)];
    tracker.velocity = Some(Motion::new(10.0, -5.0, 0.0).with_sigma(0.5, 0.5, 0.5));
    tracker.acceleration = Some(Motion::new(0.1, -0.2, 0.0).with_sigma(0.1, 0.1, 0.1).with_rho(0.0, 0.25, -0.25));
    tracker.algorithm_id = Some(9);
    t.tracker = Some(tracker);
    t.chips = vec![VChip::embedded(ImageType::Png, PNG.to_vec()), VChip::iri(ImageType::Jpeg, "https://example.com/c.jpg")];
    let mut object = VObject::new(10, 90.0);
    object.features.push(VFeature::new(11, 80.0));
    t.objects.push(object);
    let mut t8 = VTarget::new(8);
    t8.location = Some(Location::new(-33.9, 151.2, 5.0));
    t8.status = Some(DetectionStatus::Inactive);
    vmti.targets = vec![t, t8];
    let mut a = Algorithm::new(9, "k6_yolo_9000_tracker", "2.6a");
    a.class = Some("kalmann".into());
    a.frames = Some(10);
    vmti.algorithms.push(a);
    let mut car = Ontology::new(10, "http://purl.obolibrary.org/obo/envo.owl", "http://purl.obolibrary.org/obo/ENVO_01000604");
    car.label = Some("car".into());
    car.version_iri = Some("http://purl.obolibrary.org/obo/envo/releases/2021-05-14/envo.owl".into());
    let mut antenna = Ontology::new(11, "https://example.com/features.owl", "https://example.com/features.owl#Antenna");
    antenna.parent_id = Some(10);
    vmti.ontologies = vec![car, antenna];
    vmti
}

#[test]
fn a_full_set_in_a_complete_st0601_packet() {
    let vmti = full();
    let mut warnings = Vec::new();
    let bytes = vmti.encode_with(&EncodeOptions::default(), &mut warnings).unwrap();
    // The only warning: Ontology parentId is discouraged.
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let p = vmti_packet(&bytes);
    let v = vmti_of(&p);
    check_vmti(&vmti, v);
    // Item 2 first, as the VMTI time differs from tag 2.
    assert_eq!(v.items[0].tag, 2);
    // Every value is valid.
    assert!(v.items.iter().all(|i| valid(&i.value)), "{v}");
    // From the decoded values alone the set encodes to the same bytes.
    let p = misb::decode_with(&encode_packet(&p, &EncodeOptions::default()).unwrap(), &no_raw()).unwrap();
    let mut b = vmti_parent();
    b.set(Tag::VmtiLocalSet, Input::Value(Value::Set(Box::new(vmti_of(&p).clone())))).unwrap();
    let again = misb::decode(&b.finish().unwrap()).unwrap();
    assert_eq!(again.item(Tag::VmtiLocalSet).unwrap().raw, bytes);
}

/// No `Invalid` value at any depth.
fn valid(v: &Value) -> bool {
    match v {
        Value::Invalid(_) => false,
        Value::List(l) => l.iter().all(valid),
        Value::Struct(f) => f.iter().all(|f| valid(&f.value)),
        Value::Set(p) => p.items.iter().all(|i| valid(&i.value)),
        _ => true,
    }
}

#[test]
fn item_2_and_the_parent_time() {
    let target = || {
        let mut t = VTarget::new(1);
        t.location_offset = Some((1.0.into(), 2.0.into()));
        t
    };
    let mut vmti = Vmti::new();
    vmti.targets.push(target());
    // Equal to tag 2: left out unless asked for (R-NESTED-ENCODE-053).
    vmti.time = Some(MispTime::from_micros(T));
    vmti.parent_time = Some(MispTime::from_micros(T));
    assert_eq!(vmti.encode().unwrap()[0], 4);
    vmti.always_write_time = true;
    assert_eq!(&vmti.encode().unwrap()[..10], &hex("02 08 0003 8244 30F6 CE40"));
    // Different: written first; offsets need the frame period.
    vmti.always_write_time = false;
    vmti.time = Some(MispTime::from_micros(T + 40_000));
    assert_eq!(vmti.encode().unwrap_err().kind, ErrorKind::NotAllowed);
    vmti.frame_period_us = Some(20_000);
    assert_eq!(vmti.encode().unwrap()[0], 2);
    vmti.frame_period_us = Some(19_999);
    assert_eq!(vmti.encode().unwrap_err().kind, ErrorKind::NotAllowed);
    // Lenient: written, with a warning.
    let mut w = Vec::new();
    assert!(vmti.encode_with(&opts(Policy::Clamp), &mut w).is_ok());
    assert_eq!(w.len(), 1);
    // Unknown parent time: offsets refused when strict.
    vmti.parent_time = None;
    assert_eq!(vmti.encode().unwrap_err().kind, ErrorKind::NotAllowed);
    vmti.targets[0].location_offset = None;
    vmti.targets[0].location = Some(Location::new(1.0, 2.0, 3.0));
    assert_eq!(vmti.encode().unwrap()[0], 2);
}

// ---------------------------------------------------------------- (c) strict rejections

fn kind_of(vmti: &Vmti) -> ErrorKind {
    match vmti.encode() {
        Ok(b) => panic!("accepted: {b:02X?}"),
        Err(e) => e.kind,
    }
}

#[test]
fn strict_mode_rejects_what_st0903_forbids() {
    type Edit = fn(&mut Vmti);
    let cases: Vec<(&str, Edit, ErrorKind)> = vec![
        ("duplicate target ids", |v| v.targets[1].id = 1234, ErrorKind::Duplicate),
        ("target id above 2^63 - 1", |v| v.targets[1].id = 1 << 63, ErrorKind::OutOfRange),
        ("target without items", |v| v.targets[1] = VTarget::new(8), ErrorKind::Missing),
        ("priority 0", |v| v.targets[0].priority = Some(0), ErrorKind::OutOfRange),
        ("confidence 101", |v| v.targets[0].confidence = Some(101), ErrorKind::OutOfRange),
        ("percentage 0", |v| v.targets[0].percentage_pixels = Some(0), ErrorKind::OutOfRange),
        ("percentage 101", |v| v.targets[0].percentage_pixels = Some(101), ErrorKind::OutOfRange),
        ("intensity 2^24", |v| v.targets[0].intensity = Some(1 << 24), ErrorKind::OutOfRange),
        ("algorithm id 2^24", |v| v.targets[0].algorithm_id = Some(1 << 24), ErrorKind::Missing),
        ("pixel items without frame width", |v| v.frame_width = None, ErrorKind::Missing),
        ("frame width 0", |v| v.frame_width = Some(0), ErrorKind::OutOfRange),
        ("frame width 2^24", |v| v.frame_width = Some(1 << 24), ErrorKind::OutOfRange),
        ("frame height 0", |v| v.frame_height = Some(0), ErrorKind::OutOfRange),
        ("centroid 0", |v| v.targets[0].centroid = Some(0), ErrorKind::OutOfRange),
        ("centroid outside the frame", |v| v.targets[0].centroid = Some(1920 * 1080 + 1), ErrorKind::OutOfRange),
        ("bounding box upside down", |v| v.targets[0].bounding_box = Some((448_030, 409_600)), ErrorKind::OutOfRange),
        ("row outside the frame", |v| v.targets[0].centroid_row_col = Some((1081, 1)), ErrorKind::OutOfRange),
        ("row 0", |v| v.targets[0].centroid_row_col = Some((0, 1)), ErrorKind::OutOfRange),
        (
            "active target without centroid",
            |v| {
                let t = &mut v.targets[1];
                t.status = Some(DetectionStatus::ActiveMoving);
            },
            ErrorKind::Missing,
        ),
        ("offset outside its range", |v| v.targets[0].location_offset = Some((20.0.into(), 0.0.into())), ErrorKind::OutOfRange),
        ("NaN", |v| v.targets[0].hae = Some(f64::NAN.into()), ErrorKind::NotFinite),
        ("infinite FOV", |v| v.horizontal_fov = Some(f64::INFINITY.into()), ErrorKind::NotFinite),
        ("FOV above 180", |v| v.vertical_fov = Some(180.5.into()), ErrorKind::OutOfRange),
        ("reserved IMAPB pattern", |v| v.vertical_fov = Some(Imap::Special(Special::Reserved(1))), ErrorKind::InvalidCode),
        (
            "rho without sigma",
            |v| {
                let mut l = Location::new(1.0, 2.0, 3.0);
                l.rho = Some([0.0.into(), 0.0.into(), 0.0.into()]);
                v.targets[1].location = Some(l);
            },
            ErrorKind::Missing,
        ),
        ("latitude 91", |v| v.targets[1].location = Some(Location::new(91.0, 0.0, 0.0)), ErrorKind::OutOfRange),
        ("one contour vertex", |v| v.targets[0].contour.truncate(1), ErrorKind::Missing),
        (
            "two contour vertices on one latitude",
            |v| v.targets[0].contour = vec![Location::new(1.0, 1.0, 0.0), Location::new(1.0, 2.0, 0.0)],
            ErrorKind::OutOfRange,
        ),
        ("unknown algorithm id", |v| v.targets[0].algorithm_id = Some(8), ErrorKind::Missing),
        ("unknown ontology id", |v| v.targets[0].objects[0].ontology_id = 12, ErrorKind::Missing),
        ("unknown feature ontology id", |v| v.targets[0].objects[0].features[0].ontology_id = 12, ErrorKind::Missing),
        ("confidence precision too fine", |v| v.targets[0].objects[0].confidence_precision = 1e-5, ErrorKind::OutOfRange),
        ("confidence precision zero", |v| v.targets[0].objects[0].confidence_precision = 0.0, ErrorKind::OutOfRange),
        ("confidence above 100", |v| v.targets[0].objects[0].confidence = 100.5.into(), ErrorKind::OutOfRange),
        ("duplicate algorithm ids", |v| v.algorithms.push(Algorithm::new(9, "b", "1")), ErrorKind::Duplicate),
        ("empty algorithm name", |v| v.algorithms[0].name.clear(), ErrorKind::Missing),
        ("blank algorithm version", |v| v.algorithms[0].version = " ".into(), ErrorKind::Missing),
        ("duplicate ontology ids", |v| v.ontologies.push(Ontology::new(10, "urn:a", "urn:a#b")), ErrorKind::Duplicate),
        ("relative ontology IRI", |v| v.ontologies[0].ontology_iri = "envo.owl".into(), ErrorKind::WrongType),
        ("IRI with a blank", |v| v.ontologies[0].entity_iri = "http://example.com/a b".into(), ErrorKind::WrongType),
        ("parent id of itself", |v| v.ontologies[1].parent_id = Some(11), ErrorKind::InvalidCode),
        ("unknown parent id", |v| v.ontologies[1].parent_id = Some(12), ErrorKind::Missing),
        ("empty VMask", |v| v.targets[0].mask = Some(VMask::default()), ErrorKind::Missing),
        ("two-point pixel contour", |v| v.targets[0].mask = Some(VMask::polygon(vec![1, 2])), ErrorKind::Missing),
        (
            "counter-clockwise pixel contour",
            |v| v.targets[0].mask = Some(VMask::polygon(vec![1, 1921, 1922])),
            ErrorKind::OutOfRange,
        ),
        ("pixel run past its row", |v| v.targets[0].mask = Some(VMask::runs(vec![PixelRun::new(1919, 3)])), ErrorKind::OutOfRange),
        ("empty pixel run", |v| v.targets[0].mask = Some(VMask::runs(vec![PixelRun::new(5, 0)])), ErrorKind::OutOfRange),
        ("contour point outside the frame", |v| v.targets[0].mask = Some(VMask::polygon(vec![1, 2, 1920 * 1080 + 1])), ErrorKind::OutOfRange),
        ("empty VTracker", |v| v.targets[0].tracker = Some(VTracker::default()), ErrorKind::Missing),
        (
            "first observation after the latest",
            |v| {
                let tr = v.targets[0].tracker.as_mut().unwrap();
                tr.first_observation = Some(MispTime::from_micros(T + 3_000_000));
            },
            ErrorKind::OutOfRange,
        ),
        (
            "velocity without an associated location",
            |v| {
                let t = &mut v.targets[0];
                t.location = None;
                t.tracker.as_mut().unwrap().history.clear();
            },
            ErrorKind::Missing,
        ),
        ("one-vertex track boundary", |v| v.targets[0].tracker.as_mut().unwrap().boundary.truncate(1), ErrorKind::Missing),
        ("tracker confidence 101", |v| v.targets[0].tracker.as_mut().unwrap().confidence = Some(101), ErrorKind::OutOfRange),
        ("tracker algorithm id unknown", |v| v.targets[0].tracker.as_mut().unwrap().algorithm_id = Some(1), ErrorKind::Missing),
        ("chip with no image", |v| v.targets[0].chips[1].iri = None, ErrorKind::Missing),
        ("chip signature mismatch", |v| v.targets[0].chips[0].image_type = ImageType::Jpeg, ErrorKind::WrongType),
        ("chip with an empty image", |v| v.targets[0].chips[0].image = Some(Vec::new()), ErrorKind::Missing),
        ("chip IRI without a scheme", |v| v.targets[0].chips[1].iri = Some("c.jpg".into()), ErrorKind::WrongType),
        ("system name of 33 characters", |v| v.system_name = Some("x".repeat(33)), ErrorKind::TooLong),
        ("source sensor of 129 characters", |v| v.source_sensor = Some("\u{e9}".repeat(129)), ErrorKind::TooLong),
        ("trailing blank", |v| v.system_name = Some("VMTI ".into()), ErrorKind::WrongType),
        ("control character", |v| v.source_sensor = Some("EO\u{7}Nose".into()), ErrorKind::WrongType),
        ("total below the reported count", |v| v.total_targets_detected = Some(1), ErrorKind::OutOfRange),
        ("total above 2^24 - 1", |v| v.total_targets_detected = Some(1 << 24), ErrorKind::OutOfRange),
        ("VMTI-MI differs without FOV", |v| v.horizontal_fov = None, ErrorKind::Missing),
        ("VMTI-MI differs without miisId", |v| v.miis_id = None, ErrorKind::Missing),
        ("nil MIIS ID", |v| v.miis_id = Some(CoreIdentifier::new().with_window([0; 16])), ErrorKind::InvalidCode),
    ];
    assert!(full().encode().is_ok());
    for (what, edit, want) in cases {
        let mut v = full();
        edit(&mut v);
        assert_eq!(kind_of(&v), want, "{what}");
    }
    // Errors name the VMTI item they are in.
    let mut v = full();
    v.targets[0].priority = Some(0);
    let e: EncodeError = v.encode().unwrap_err();
    assert_eq!((e.standard, e.tag), (misb::Standard::St0903, Some(101)));
    assert!(e.reason.contains("R-NESTED-ENCODE-089"), "{e}");
}

#[test]
fn lenient_mode_signals_and_cleans() {
    let mut v = full();
    v.targets[0].location_offset = Some((20.0.into(), (-20.0).into()));
    v.targets[0].hae = Some(f64::NAN.into());
    v.system_name = Some(" VMTI\u{7} ".into());
    v.targets[0].chips[0].image_type = ImageType::Jpeg;
    let mut w = Vec::new();
    let bytes = v.encode_with(&opts(Policy::Clamp), &mut w).unwrap();
    // Offsets above and below: E1 and E0; NaN: D0; the text cleaned.
    let p = vmti_packet(&bytes);
    let set = vmti_of(&p);
    assert_eq!(set.get(st0903::Tag::VmtiSystemName).and_then(Value::as_str), Some("VMTI"));
    let raw = &set.item(st0903::Tag::VTargetSeries).unwrap().raw;
    let has = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(has(&hex("0A 03 E1 00 00 0B 03 E0 00 00 0C 02 D0 00")));
    // Offsets twice, NaN, text, chip signature (and the parentId warning).
    assert_eq!(w.len(), 6, "{w:?}");
}

// ---------------------------------------------------------------- (b) random round trips

/// What a decoded value must be.
enum E {
    U(u64),
    Code(u64),
    Time(u64),
    Text(String),
    Bytes(Vec<u8>),
    /// An IMAPB value of range [min, max] in `len` bytes.
    F(Imap, f64, f64, usize),
    S(Vec<(&'static str, E)>),
    L(Vec<E>),
    /// A Core Identifier: its canonical text.
    Miis(String),
}

fn lsb(min: f64, max: f64, len: usize) -> f64 {
    let b_pow = (max - min).log2().ceil() as i32;
    2f64.powi(b_pow - (8 * len as i32 - 1))
}

fn check(path: &str, want: &E, got: &Value) {
    match (want, got) {
        (E::U(n), Value::Uint(m)) => assert_eq!(n, m, "{path}"),
        (E::Code(n), Value::Enum { code, .. }) => assert_eq!(n, code, "{path}"),
        (E::Time(n), Value::Time(m)) => assert_eq!(n, m, "{path}"),
        (E::Text(s), Value::Text(t)) => assert_eq!(s, t, "{path}"),
        (E::Bytes(s), Value::Bytes(t)) => assert_eq!(s, t, "{path}"),
        (E::F(Imap::Value(x), min, max, len), Value::Float(d)) => {
            // ST 1201 truncates: (x - 1 LSB, x], plus f64 slack.
            let slack = 1e-9 * x.abs().max(1.0);
            let step = lsb(*min, *max, *len);
            assert!(*d <= x + slack && *d > x - step - slack, "{path}: {x} decoded as {d} (LSB {step})");
        }
        (E::F(Imap::Invalid | Imap::BelowMinimum | Imap::AboveMaximum, ..), Value::OutOfRange) => {}
        (E::S(fields), Value::Struct(got)) => {
            let names: Vec<_> = got.iter().map(|f| f.name).collect();
            let want_names: Vec<_> = fields.iter().map(|(n, _)| *n).collect();
            assert_eq!(names, want_names, "{path}");
            for ((name, w), f) in fields.iter().zip(got) {
                check(&format!("{path}/{name}"), w, &f.value);
            }
        }
        (E::L(items), Value::List(got)) => {
            assert_eq!(items.len(), got.len(), "{path}");
            for (i, (w, g)) in items.iter().zip(got).enumerate() {
                check(&format!("{path}[{i}]"), w, g);
            }
        }
        (E::Miis(text), v) => assert_eq!(v.field("Canonical").and_then(Value::as_str), Some(text.as_str()), "{path}"),
        (_, got) => panic!("{path}: unexpected {got:?}"),
    }
}

fn e_location(l: &Location) -> E {
    let mut f = vec![
        ("Latitude", E::F(l.latitude, -90.0, 90.0, 4)),
        ("Longitude", E::F(l.longitude, -180.0, 180.0, 4)),
        ("Height", E::F(l.hae, -900.0, 19_000.0, 2)),
    ];
    if let Some([e, n, u]) = l.sigma {
        f.extend([("Sigma East", E::F(e, 0.0, 650.0, 2)), ("Sigma North", E::F(n, 0.0, 650.0, 2)), ("Sigma Up", E::F(u, 0.0, 650.0, 2))]);
    }
    if let Some([en, eu, nu]) = l.rho {
        f.extend([("Rho East-North", E::F(en, -1.0, 1.0, 2)), ("Rho East-Up", E::F(eu, -1.0, 1.0, 2)), ("Rho North-Up", E::F(nu, -1.0, 1.0, 2))]);
    }
    E::S(f)
}

fn e_motion(m: &Motion) -> E {
    let mut f = vec![
        ("East", E::F(m.east, -900.0, 900.0, 2)),
        ("North", E::F(m.north, -900.0, 900.0, 2)),
        ("Up", E::F(m.up, -900.0, 900.0, 2)),
    ];
    if let Some([e, n, u]) = m.sigma {
        f.extend([("Sigma East", E::F(e, 0.0, 650.0, 2)), ("Sigma North", E::F(n, 0.0, 650.0, 2)), ("Sigma Up", E::F(u, 0.0, 650.0, 2))]);
    }
    if let Some([en, eu, nu]) = m.rho {
        f.extend([("Rho East-North", E::F(en, -1.0, 1.0, 2)), ("Rho East-Up", E::F(eu, -1.0, 1.0, 2)), ("Rho North-Up", E::F(nu, -1.0, 1.0, 2))]);
    }
    E::S(f)
}

/// IMAPB length of a confidence for a precision (ST 1201.5 IMAPA, D-14).
fn confidence_len(g: f64) -> usize {
    let bits = 7 - g.log2().floor() as i32 + 1;
    ((bits.max(1) + 7) / 8) as usize
}

fn e_feature(f: &VFeature) -> E {
    E::S(vec![
        ("Ontology ID", E::U(f.ontology_id)),
        ("Confidence", E::F(f.confidence, 0.0, 100.0, confidence_len(f.confidence_precision))),
    ])
}

fn e_object(o: &VObject) -> E {
    let mut f = vec![
        ("Ontology ID", E::U(o.ontology_id)),
        ("Confidence", E::F(o.confidence, 0.0, 100.0, confidence_len(o.confidence_precision))),
    ];
    if !o.features.is_empty() {
        f.push(("VFeature Series", E::L(o.features.iter().map(e_feature).collect())));
    }
    E::S(f)
}

fn rfc_uuid(id: &[u8; 16]) -> String {
    let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn e_tracker(t: &VTracker) -> E {
    let mut f = Vec::new();
    if let Some(id) = &t.track_id {
        f.push(("Track ID", E::Text(rfc_uuid(id))));
    }
    if let Some(x) = t.first_observation {
        f.push(("First Observation Time", E::Time(x.as_micros())));
    }
    if let Some(x) = t.latest_observation {
        f.push(("Latest Observation Time", E::Time(x.as_micros())));
    }
    if !t.boundary.is_empty() {
        f.push(("Track Boundary Series", E::L(t.boundary.iter().map(e_location).collect())));
    }
    if let Some(c) = t.confidence {
        f.push(("Confidence Level", E::U(c.into())));
    }
    if !t.history.is_empty() {
        f.push(("Track History Series", E::L(t.history.iter().map(e_location).collect())));
    }
    if let Some(m) = &t.velocity {
        f.push(("Velocity", e_motion(m)));
    }
    if let Some(m) = &t.acceleration {
        f.push(("Acceleration", e_motion(m)));
    }
    if let Some(a) = t.algorithm_id {
        f.push(("Algorithm ID", E::U(a)));
    }
    E::S(f)
}

fn e_chip(c: &VChip) -> E {
    let mut f = vec![("Image Type", E::Text(c.image_type.as_str().into()))];
    if let Some(iri) = &c.iri {
        f.push(("Image IRI", E::Text(iri.clone())));
    }
    if let Some(b) = &c.image {
        f.push(("Embedded Image", E::Bytes(b.clone())));
    }
    E::S(f)
}

fn e_target(t: &VTarget) -> E {
    let mut f = vec![("Target ID", E::U(t.id))];
    let off = |x| E::F(x, -19.2, 19.2, 3);
    if let Some(p) = t.centroid {
        f.push(("Target Centroid", E::U(p)));
    }
    if let Some((a, b)) = t.bounding_box {
        f.push(("Bounding Box Top Left", E::U(a)));
        f.push(("Bounding Box Bottom Right", E::U(b)));
    }
    if let Some(x) = t.priority {
        f.push(("Target Priority", E::U(x.into())));
    }
    if let Some(x) = t.confidence {
        f.push(("Target Confidence Level", E::U(x.into())));
    }
    if let Some(x) = t.history {
        f.push(("Target History", E::U(x.into())));
    }
    if let Some(x) = t.percentage_pixels {
        f.push(("Percentage of Target Pixels", E::U(x.into())));
    }
    if let Some([r, g, b]) = t.color {
        f.push(("Target Color", E::S(vec![("Red", E::U(r.into())), ("Green", E::U(g.into())), ("Blue", E::U(b.into()))])));
    }
    if let Some(x) = t.intensity {
        f.push(("Target Intensity", E::U(x.into())));
    }
    if let Some((lat, lon)) = t.location_offset {
        f.push(("Target Location Latitude Offset", off(lat)));
        f.push(("Target Location Longitude Offset", off(lon)));
    }
    if let Some(h) = t.hae {
        f.push(("Target Height", E::F(h, -900.0, 19_000.0, 2)));
    }
    if let Some([a, b, c, d]) = t.bounding_box_offsets {
        f.push(("Bounding Box Top Left Latitude Offset", off(a)));
        f.push(("Bounding Box Top Left Longitude Offset", off(b)));
        f.push(("Bounding Box Bottom Right Latitude Offset", off(c)));
        f.push(("Bounding Box Bottom Right Longitude Offset", off(d)));
    }
    if let Some(l) = &t.location {
        f.push(("Target Location", e_location(l)));
    }
    if !t.contour.is_empty() {
        f.push(("Geospatial Contour Series", E::L(t.contour.iter().map(e_location).collect())));
    }
    if let Some((r, c)) = t.centroid_row_col {
        f.push(("Centroid Pixel Row", E::U(r.into())));
        f.push(("Centroid Pixel Column", E::U(c.into())));
    }
    if let Some(a) = t.algorithm_id {
        f.push(("Algorithm ID", E::U(a.into())));
    }
    if let Some(s) = t.status {
        f.push(("Detection Status", E::Code(s.code().into())));
    }
    if let Some(m) = &t.mask {
        let mut mf = Vec::new();
        if !m.contour.is_empty() {
            mf.push(("Pixel Contour", E::L(m.contour.iter().map(|&p| E::U(p)).collect())));
        }
        if !m.bit_mask.is_empty() {
            let runs = m.bit_mask.iter().map(|r| E::S(vec![("Pixel", E::U(r.pixel)), ("Run Length", E::U(r.run))]));
            mf.push(("Bit Mask Series", E::L(runs.collect())));
        }
        f.push(("VMask", E::S(mf)));
    }
    if let Some(tr) = &t.tracker {
        f.push(("VTracker", e_tracker(tr)));
    }
    match t.chips.as_slice() {
        [] => {}
        [c] => f.push(("VChip", e_chip(c))),
        chips => f.push(("VChip Series", E::L(chips.iter().map(e_chip).collect()))),
    }
    if !t.objects.is_empty() {
        f.push(("VObject Series", E::L(t.objects.iter().map(e_object).collect())));
    }
    E::S(f)
}

/// Check a decoded VMTI set against the builder's input.
fn check_vmti(v: &Vmti, got: &Packet) {
    use st0903::Tag as V;
    let mut want: Vec<(V, E)> = Vec::new();
    let time = match (v.time, v.parent_time) {
        (Some(t), Some(p)) if t == p && !v.always_write_time => None,
        (Some(t), _) => Some(t),
        (None, Some(p)) if v.always_write_time => Some(p),
        (None, _) => None,
    };
    if let Some(t) = time {
        want.push((V::PrecisionTimeStamp, E::Time(t.as_micros())));
    }
    if let Some(s) = &v.system_name {
        want.push((V::VmtiSystemName, E::Text(s.clone())));
    }
    want.push((V::VersionNumber, E::U(6)));
    let count = v.targets.len() as u64;
    if let Some(total) = v.total_targets_detected.filter(|&t| t != count) {
        want.push((V::TotalNumberOfTargetsDetected, E::U(total)));
    }
    want.push((V::NumberOfReportedTargets, E::U(count)));
    if let Some(w) = v.frame_width {
        want.push((V::FrameWidth, E::U(w)));
    }
    if let Some(h) = v.frame_height {
        want.push((V::FrameHeight, E::U(h)));
    }
    if let Some(s) = &v.source_sensor {
        want.push((V::VmtiSourceSensor, E::Text(s.clone())));
    }
    if let Some(x) = v.horizontal_fov {
        want.push((V::VmtiHorizontalFieldOfView, E::F(x, 0.0, 180.0, 2)));
    }
    if let Some(x) = v.vertical_fov {
        want.push((V::VmtiVerticalFieldOfView, E::F(x, 0.0, 180.0, 2)));
    }
    if let Some(id) = &v.miis_id {
        want.push((V::MiisId, E::Miis(id.to_string())));
    }
    if !v.targets.is_empty() {
        let mut targets: Vec<&VTarget> = v.targets.iter().collect();
        targets.sort_by_key(|t| t.id);
        want.push((V::VTargetSeries, E::L(targets.into_iter().map(e_target).collect())));
    }
    if !v.algorithms.is_empty() {
        let mut a: Vec<&Algorithm> = v.algorithms.iter().collect();
        a.sort_by_key(|a| a.id);
        let a = a.into_iter().map(|a| {
            let mut f = vec![("Algorithm ID", E::U(a.id)), ("Name", E::Text(a.name.clone())), ("Version", E::Text(a.version.clone()))];
            if let Some(c) = &a.class {
                f.push(("Class", E::Text(c.clone())));
            }
            if let Some(n) = a.frames {
                f.push(("Number of Frames", E::U(n)));
            }
            E::S(f)
        });
        want.push((V::AlgorithmSeries, E::L(a.collect())));
    }
    if !v.ontologies.is_empty() {
        let mut o: Vec<&Ontology> = v.ontologies.iter().collect();
        o.sort_by_key(|o| o.id);
        let o = o.into_iter().map(|o| {
            let mut f = vec![("Ontology ID", E::U(o.id))];
            if let Some(p) = o.parent_id {
                f.push(("Parent ID", E::U(p)));
            }
            f.push(("Ontology IRI", E::Text(o.ontology_iri.clone())));
            f.push(("Entity IRI", E::Text(o.entity_iri.clone())));
            if let Some(s) = &o.version_iri {
                f.push(("Version IRI", E::Text(s.clone())));
            }
            if let Some(s) = &o.label {
                f.push(("Label", E::Text(s.clone())));
            }
            E::S(f)
        });
        want.push((V::OntologySeries, E::L(o.collect())));
    }
    let tags: Vec<u64> = got.items.iter().map(|i| i.tag).collect();
    let want_tags: Vec<u64> = want.iter().map(|(t, _)| u64::from(*t)).collect();
    assert_eq!(tags, want_tags);
    for ((tag, w), item) in want.iter().zip(&got.items) {
        check(tag.name(), w, &item.value);
    }
}

/// Random values for the builder.
struct Gen {
    rng: Rng,
    /// An IMAPB signal was used: the decoded values alone cannot tell
    /// which (D-33).
    signals: bool,
    /// A confidence of a length other than 2: re-encoding from the values
    /// alone uses the nominal length.
    lengths: bool,
}

impl Gen {
    fn below(&mut self, n: u64) -> u64 {
        self.rng.next() % n.max(1)
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }

    fn unit(&mut self) -> f64 {
        (self.rng.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn real(&mut self, min: f64, max: f64) -> f64 {
        match self.below(10) {
            0 => min,
            1 => max,
            2 if min < 0.0 && max > 0.0 => 0.0,
            3 if min < 0.0 && max > 0.0 => -0.0,
            _ => min + (max - min) * self.unit(),
        }
    }

    fn imap(&mut self, min: f64, max: f64) -> Imap {
        match self.below(100) {
            0 => {
                self.signals = true;
                Imap::Invalid
            }
            1 => {
                self.signals = true;
                Imap::BelowMinimum
            }
            2 => {
                self.signals = true;
                Imap::AboveMaximum
            }
            _ => Imap::Value(self.real(min, max)),
        }
    }

    fn three(&mut self, min: f64, max: f64) -> [Imap; 3] {
        [self.imap(min, max), self.imap(min, max), self.imap(min, max)]
    }

    fn id(&mut self, bits: u32) -> u64 {
        let b = 1 + self.below(u64::from(bits)) as u32;
        self.rng.next() >> (64 - b)
    }

    fn text(&mut self, max: usize) -> String {
        const CHARS: [char; 8] = ['a', 'Z', '0', '_', '-', ' ', '\u{e9}', '\u{4e2d}'];
        let n = 1 + self.below(max as u64) as usize;
        let s: String = (0..n).map(|_| CHARS[self.below(8) as usize]).collect();
        let s = s.trim().to_string();
        if s.is_empty() {
            "x".into()
        } else {
            s
        }
    }

    fn uuid(&mut self) -> [u8; 16] {
        let mut id = [0u8; 16];
        for b in id.iter_mut() {
            *b = self.rng.next() as u8;
        }
        id[6] = 0x40 | (id[6] & 0x0F);
        id[8] = 0x80 | (id[8] & 0x3F);
        id
    }

    fn location(&mut self) -> Location {
        let mut l = Location::new(self.imap(-90.0, 90.0), self.imap(-180.0, 180.0), self.imap(-900.0, 19_000.0));
        if self.chance(2) {
            l.sigma = Some(self.three(0.0, 650.0));
            if self.chance(2) {
                l.rho = Some(self.three(-1.0, 1.0));
            }
        }
        l
    }

    fn motion(&mut self) -> Motion {
        let mut m = Motion::new(self.imap(-900.0, 900.0), self.imap(-900.0, 900.0), self.imap(-900.0, 900.0));
        if self.chance(2) {
            m.sigma = Some(self.three(0.0, 650.0));
            if self.chance(2) {
                m.rho = Some(self.three(-1.0, 1.0));
            }
        }
        m
    }

    /// Two vertices that are opposite corners of a box, or three or more.
    fn boundary(&mut self) -> Vec<Location> {
        if self.chance(2) {
            let lat = self.real(-89.0, 89.0);
            let lon = self.real(-179.0, 179.0);
            vec![Location::new(lat, lon, 0.0), Location::new(lat + 0.5, lon + 0.5, 10.0)]
        } else {
            (0..3 + self.below(3)).map(|_| self.location()).collect()
        }
    }

    fn precision(&mut self) -> f64 {
        match self.below(12) {
            0 => {
                self.lengths = true;
                1.0
            }
            1 => {
                self.lengths = true;
                0.001
            }
            _ => 0.1,
        }
    }

    fn target(&mut self, id: u64, w: u64, h: u64, algorithms: &[u64], ontologies: &[u64]) -> VTarget {
        let mut t = VTarget::new(id);
        let pixel = |r: u64, c: u64| c + (r - 1) * w;
        if self.chance(2) {
            let (r, c) = (1 + self.below(h), 1 + self.below(w));
            t.centroid = Some(pixel(r, c));
        }
        if self.chance(3) {
            let (r0, c0) = (1 + self.below(h), 1 + self.below(w));
            let (r1, c1) = (r0 + self.below(h - r0 + 1), c0 + self.below(w - c0 + 1));
            t.bounding_box = Some((pixel(r0, c0), pixel(r1, c1)));
        }
        if self.chance(2) {
            t.priority = Some(1 + self.below(255) as u8);
        }
        if self.chance(2) {
            t.confidence = Some(self.below(101) as u8);
        }
        if self.chance(3) {
            t.history = Some(self.rng.next() as u16);
        }
        if self.chance(3) {
            t.percentage_pixels = Some(1 + self.below(100) as u8);
        }
        if self.chance(3) {
            t.color = Some([self.rng.next() as u8, self.rng.next() as u8, self.rng.next() as u8]);
        }
        if self.chance(3) {
            t.intensity = Some(self.below(1 << 24) as u32);
        }
        if self.chance(3) {
            t.location_offset = Some((self.imap(-19.2, 19.2), self.imap(-19.2, 19.2)));
        }
        if self.chance(3) {
            t.hae = Some(self.imap(-900.0, 19_000.0));
        }
        if self.chance(4) {
            t.bounding_box_offsets = Some([self.imap(-19.2, 19.2), self.imap(-19.2, 19.2), self.imap(-19.2, 19.2), self.imap(-19.2, 19.2)]);
        }
        if self.chance(2) {
            t.location = Some(self.location());
        }
        if self.chance(4) {
            t.contour = self.boundary();
        }
        if self.chance(3) {
            t.centroid_row_col = Some((1 + self.below(h) as u32, 1 + self.below(w) as u32));
        }
        let small: Vec<u64> = algorithms.iter().copied().filter(|&a| a < 1 << 24).collect();
        if !small.is_empty() && self.chance(2) {
            t.algorithm_id = Some(small[self.below(small.len() as u64) as usize] as u32);
        }
        if self.chance(2) {
            let s = DetectionStatus::from_code(self.below(5) as u8).unwrap();
            if matches!(s, DetectionStatus::ActiveMoving | DetectionStatus::ActiveStopped) && t.centroid.is_none() {
                t.centroid = Some(pixel(1, 1));
            }
            t.status = Some(s);
        }
        if self.chance(3) {
            let mut m = VMask::default();
            if self.chance(2) && w > 2 && h > 2 {
                // Clockwise in image coordinates: right, then down.
                let (r, c) = (1 + self.below(h - 2), 1 + self.below(w - 2));
                let d = 1 + self.below((h - r).min(w - c).max(1));
                m.contour = vec![pixel(r, c), pixel(r, c + d), pixel(r + d, c + d)];
            }
            for _ in 0..self.below(4) {
                let (r, c) = (1 + self.below(h), 1 + self.below(w));
                let run = 1 + self.below(w - c + 1);
                m.bit_mask.push(PixelRun::new(pixel(r, c), run));
            }
            if m.contour.is_empty() && m.bit_mask.is_empty() {
                m.bit_mask.push(PixelRun::new(1, 1));
            }
            t.mask = Some(m);
        }
        if self.chance(3) {
            let mut tr = VTracker::default();
            if self.chance(2) {
                tr.track_id = Some(self.uuid());
            }
            let first = self.rng.next() >> 12;
            if self.chance(2) {
                tr.first_observation = Some(MispTime::from_micros(first));
            }
            if self.chance(2) {
                tr.latest_observation = Some(MispTime::from_micros(first + self.below(1 << 30)));
            }
            if self.chance(3) {
                tr.boundary = self.boundary();
            }
            if self.chance(2) {
                tr.confidence = Some(self.below(101) as u8);
            }
            if self.chance(2) {
                tr.history = (0..1 + self.below(4)).map(|_| self.location()).collect();
            }
            if t.location.is_some() || !tr.history.is_empty() {
                if self.chance(2) {
                    tr.velocity = Some(self.motion());
                }
                if self.chance(2) {
                    tr.acceleration = Some(self.motion());
                }
            }
            if !algorithms.is_empty() && self.chance(2) {
                tr.algorithm_id = Some(algorithms[self.below(algorithms.len() as u64) as usize]);
            }
            if tr == VTracker::default() {
                tr.confidence = Some(1);
            }
            t.tracker = Some(tr);
        }
        for _ in 0..self.below(4) {
            let kind = if self.chance(2) { ImageType::Png } else { ImageType::Jpeg };
            let chip = if self.chance(2) {
                VChip::iri(kind, &format!("https://example.com/chips/{}.img", self.rng.next()))
            } else {
                let sig: &[u8] = if kind == ImageType::Png { &PNG[..8] } else { &[0xFF, 0xD8, 0xFF, 0xE0] };
                let mut image = sig.to_vec();
                image.extend((0..self.below(300)).map(|_| self.rng.next() as u8));
                VChip::embedded(kind, image)
            };
            t.chips.push(chip);
        }
        if !ontologies.is_empty() {
            for _ in 0..self.below(3) {
                let pick = |g: &mut Gen| ontologies[g.below(ontologies.len() as u64) as usize];
                let mut o = VObject::new(pick(self), self.imap(0.0, 100.0));
                o.confidence_precision = self.precision();
                for _ in 0..self.below(3) {
                    let mut f = VFeature::new(pick(self), self.imap(0.0, 100.0));
                    f.confidence_precision = self.precision();
                    o.features.push(f);
                }
                t.objects.push(o);
            }
        }
        if t == VTarget::new(id) {
            t.priority = Some(1);
        }
        t
    }

    fn vmti(&mut self) -> Vmti {
        let mut v = Vmti::new();
        let w = 3 + self.below(4000);
        let h = 3 + self.below(3000);
        v.frame_width = Some(w);
        if self.chance(3) {
            v.frame_height = None;
        } else {
            v.frame_height = Some(h);
        }
        let parent = self.rng.next() >> 12;
        v.parent_time = Some(MispTime::from_micros(parent));
        match self.below(4) {
            0 => {}
            1 => v.time = Some(MispTime::from_micros(parent)),
            2 => {
                v.time = Some(MispTime::from_micros(parent.saturating_sub(self.below(60_000))));
                v.frame_period_us = Some(33_366);
            }
            _ => {
                v.time = Some(MispTime::from_micros(parent));
                v.always_write_time = true;
            }
        }
        if self.chance(2) {
            v.system_name = Some(self.text(32));
        }
        if self.chance(2) {
            v.source_sensor = Some(self.text(128));
        }
        if self.chance(2) {
            v.horizontal_fov = Some(self.imap(0.0, 180.0));
            v.vertical_fov = Some(self.imap(0.0, 180.0));
            v.miis_id = Some(CoreIdentifier::new().with_sensor(IdType::Physical, self.uuid()).with_window(self.uuid()));
            v.vmti_mi_is_user_mi = self.chance(2);
        }
        let mut algorithms = Vec::new();
        for _ in 0..self.below(3) {
            let id = self.id(64);
            if !algorithms.contains(&id) {
                algorithms.push(id);
                let mut a = Algorithm::new(id, &self.text(20), &self.text(5));
                if self.chance(2) {
                    a.class = Some(self.text(10));
                }
                if self.chance(2) {
                    a.frames = Some(self.id(64));
                }
                v.algorithms.push(a);
            }
        }
        let mut ontologies = Vec::new();
        for _ in 0..self.below(3) {
            let id = self.id(64);
            if !ontologies.contains(&id) {
                ontologies.push(id);
                let mut o = Ontology::new(id, "http://purl.obolibrary.org/obo/envo.owl", &format!("urn:x:{id}"));
                if self.chance(2) {
                    o.label = Some(self.text(10));
                }
                if self.chance(3) {
                    o.version_iri = Some("http://purl.obolibrary.org/obo/envo/2021.owl".into());
                }
                v.ontologies.push(o);
            }
        }
        let mut ids = Vec::new();
        for _ in 0..self.below(6) {
            let id = self.id(63);
            if !ids.contains(&id) {
                ids.push(id);
                let t = self.target(id, w, v.frame_height.unwrap_or(4096), &algorithms, &ontologies);
                v.targets.push(t);
            }
        }
        if self.chance(3) {
            v.total_targets_detected = Some(ids.len() as u64 + self.below(3));
        }
        v
    }
}

#[test]
fn random_sets_round_trip() {
    let mut g = Gen { rng: Rng(0x5EED_0903), signals: false, lengths: false };
    let mut exact = 0;
    for round in 0..400 {
        g.signals = false;
        g.lengths = false;
        let v = g.vmti();
        let bytes = v.encode().unwrap_or_else(|e| panic!("round {round}: {e}: {v:?}"));
        let p = vmti_packet(&bytes);
        let set = vmti_of(&p);
        check_vmti(&v, set);
        // Re-encoding the decoded set gives the same bytes: from the
        // recorded bytes always, from the values alone unless a signal or
        // a non-nominal confidence length needs the recorded bytes.
        for cfg in [Config::default(), no_raw()] {
            let p = misb::decode_with(&encode_packet(&p, &EncodeOptions::default()).unwrap(), &cfg).unwrap();
            let mut b = vmti_parent();
            let r = b.set(Tag::VmtiLocalSet, Input::Value(Value::Set(Box::new(vmti_of(&p).clone())))).map(|_| ());
            if cfg.keep_raw || !(g.signals || g.lengths) {
                r.unwrap_or_else(|e| panic!("round {round}: {e}"));
                let again = misb::decode(&b.finish().unwrap()).unwrap();
                assert_eq!(again.item(Tag::VmtiLocalSet).unwrap().raw, bytes, "round {round}, keep_raw {}", cfg.keep_raw);
                exact += usize::from(!cfg.keep_raw);
            } else if let Err(e) = r {
                assert!(g.signals, "round {round}: {e}");
            }
        }
    }
    // Most sets take the values-only path.
    assert!(exact > 100, "{exact}");
}

/// The encoder never panics on any decoded value, and whatever it accepts
/// decodes cleanly: random edits of decoded sets.
#[test]
fn edited_decoded_sets_never_panic() {
    let leaves = [
        Value::Uint(0),
        Value::Uint(u64::MAX),
        Value::Int(-1),
        Value::Float(f64::NAN),
        Value::Float(1e300),
        Value::Float(-0.0),
        Value::Text(String::new()),
        Value::Text("\u{0}x ".into()),
        Value::Bytes(Vec::new()),
        Value::Bytes(vec![0xC1, 0, 0]),
        Value::Time(u64::MAX),
        Value::Enum { code: 300, label: None },
        Value::OutOfRange,
        Value::Unknown,
        Value::Invalid("x"),
        Value::List(Vec::new()),
        Value::Struct(Vec::new()),
    ];
    let base = full().encode().unwrap();
    let p = vmti_packet(&base);
    let base_set = vmti_of(&p).clone();
    let mut rng = Rng(0xBAD_5EED);
    for round in 0..3_000 {
        let mut set = base_set.clone();
        if round % 2 == 0 {
            for i in set.items.iter_mut() {
                i.raw.clear();
            }
        }
        // Pick a random node, then replace it.
        let item = rng.below(set.items.len());
        let mut path = Vec::new();
        let mut node = &set.items[item].value;
        loop {
            match node {
                Value::List(l) if !l.is_empty() && rng.below(3) != 0 => {
                    let i = rng.below(l.len());
                    path.push(i);
                    node = &l[i];
                }
                Value::Struct(f) if !f.is_empty() && rng.below(3) != 0 => {
                    let i = rng.below(f.len());
                    path.push(i);
                    node = &f[i].value;
                }
                _ => break,
            }
        }
        let mut node = &mut set.items[item].value;
        for i in path {
            node = match node {
                Value::List(l) => &mut l[i],
                Value::Struct(f) => &mut f[i].value,
                _ => unreachable!(),
            };
        }
        *node = leaves[rng.below(leaves.len())].clone();
        let mut b = vmti_parent();
        if b.set(Tag::VmtiLocalSet, Input::Value(Value::Set(Box::new(set)))).is_ok() {
            let p = misb::decode(&b.finish().unwrap()).unwrap();
            assert!(p.is_ok(), "round {round}: {p}");
        }
    }
}

/// encode(decode(b)) == b for every set the decoder reads without a
/// structural error: damaged copies of a valid set.
#[test]
fn damaged_sets_re_encode_from_their_bytes() {
    let base = full().encode().unwrap();
    let mut rng = Rng(0x0903_0601);
    let mut checked = 0;
    for _ in 0..3_000 {
        let mut v = base.clone();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(v.len());
            v[at] ^= 1 << rng.below(8);
        }
        let p = misb::decode(&packet(&[(74, &v)])).unwrap();
        let Some(set) = p.get(Tag::VmtiLocalSet).and_then(Value::as_set) else { continue };
        if set.error.is_some() || set.get(st0903::Tag::Checksum).is_some() {
            continue;
        }
        // Only minimally framed sets come back byte for byte: the decoder
        // accepts padded tags and lengths, the encoder writes the fewest
        // bytes (R-NESTED-ENCODE-012).
        let framed: Vec<u8> = set.items.iter().flat_map(|i| item(i.tag, &i.raw)).collect();
        if framed != v {
            continue;
        }
        let mut b = vmti_parent();
        b.set(Tag::VmtiLocalSet, Input::Value(Value::Set(Box::new(set.clone())))).unwrap();
        let again = misb::decode(&b.finish().unwrap()).unwrap();
        assert_eq!(again.item(Tag::VmtiLocalSet).unwrap().raw, v);
        checked += 1;
    }
    assert!(checked > 500, "{checked}");
}
