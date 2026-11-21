//! The live metadata state (MUXING_PLAN.md section 6.3): values checked when
//! set, snapshots that never mix two updates, staleness, the revision
//! counter, and nested sets. Time is passed in explicitly: nothing here
//! reads a clock.
#![cfg(feature = "encode")]
#![forbid(unsafe_code)]

use misb::encode::{
    Classification, EncodeOptions, ErrorKind, Input, Location, Policy, Security, St0601Builder, VTarget, Vmti,
};
use misb::state::{MetadataState, Snapshot, StalePolicy, Staleness};
use misb::st0601::Tag;
use misb::{MispTime, Value};
use std::time::Duration;

const T0: u64 = 1_700_000_000_000_000;

fn at(ms: u64) -> MispTime {
    MispTime::from_micros(T0 + ms * 1000)
}

fn decode(bytes: &[u8]) -> misb::Packet {
    let p = misb::decode(bytes).unwrap();
    assert!(p.is_ok(), "{p}");
    p
}

#[test]
fn snapshot_encodes_like_the_builder() {
    let mut s = MetadataState::new();
    s.set(Tag::MissionId, "MISSION01", at(0)).unwrap();
    s.set(Tag::SensorLatitude, 38.8895, at(0)).unwrap();
    s.set(Tag::SensorLongitude, -77.0353, at(1)).unwrap();
    s.unknown(Tag::SlantRange, at(2)).unwrap();
    s.set(Tag::IcingDetected, "Icing Detected", at(2)).unwrap();
    let snap = s.snapshot(at(3));
    assert_eq!(snap.len(), 5);
    assert_eq!(snap.time(), at(3));
    let tags: Vec<Tag> = snap.items().map(|(t, _)| t).collect();
    assert_eq!(tags, [Tag::MissionId, Tag::SensorLatitude, Tag::SensorLongitude, Tag::SlantRange, Tag::IcingDetected]);

    let mut b = St0601Builder::new(at(5));
    b.set(Tag::MissionId, "MISSION01").unwrap();
    b.set(Tag::SensorLatitude, 38.8895).unwrap();
    b.set(Tag::SensorLongitude, -77.0353).unwrap();
    b.unknown(Tag::SlantRange).unwrap();
    b.set(Tag::IcingDetected, Input::Code(2)).unwrap();
    let want = b.finish().unwrap();
    // Tag 2 is the time given to encode_at, not the snapshot's time.
    assert_eq!(snap.encode_at(at(5), &EncodeOptions::default()).unwrap(), want);
    let p = decode(&want);
    assert_eq!(p.get(Tag::SlantRange), Some(&Value::Unknown));

    // A reused builder gives the same bytes and keeps no earlier items.
    let mut reused = St0601Builder::new(at(0));
    reused.set(Tag::PlatformTailNumber, "OLD").unwrap().version(3);
    let mut out = Vec::new();
    snap.fill(at(5), &mut reused).unwrap().finish_into(&mut out).unwrap();
    assert_eq!(out, want);

    // The items, copied out, rebuild the same packet.
    let mut again = St0601Builder::new(at(5));
    for (tag, input) in snap.to_items() {
        match input {
            Input::Value(Value::Unknown) => again.unknown(tag).unwrap(),
            other => again.set(tag, other).unwrap(),
        };
    }
    assert_eq!(again.finish().unwrap(), want);
}

#[test]
fn bad_values_are_refused_at_once_and_change_nothing() {
    let mut s = MetadataState::new();
    s.set(Tag::SensorLatitude, 10.0, at(0)).unwrap();
    let rev = s.revision();
    for (tag, input, kind) in [
        (Tag::SensorLatitude, Input::Float(91.0), ErrorKind::OutOfRange),
        (Tag::SensorLatitude, Input::Float(f64::NAN), ErrorKind::NotFinite),
        (Tag::IcingDetected, Input::Code(9), ErrorKind::InvalidCode),
        (Tag::MissionId, Input::Float(1.0), ErrorKind::WrongType),
        (Tag::TargetId, Input::Text("x".repeat(33)), ErrorKind::TooLong),
        (Tag::PrecisionTimeStamp, Input::Uint(1), ErrorKind::NotAllowed),
        (Tag::Checksum, Input::Uint(1), ErrorKind::NotAllowed),
        (Tag::Deprecated, Input::Bytes(vec![1]), ErrorKind::NotAllowed),
        (Tag::MetadataSubstreamIdPack, Input::Uint(1), ErrorKind::NotAllowed),
        (Tag::WeaponLoad, Input::Uint(1), ErrorKind::NotAllowed),
        (Tag::UasDatalinkLsVersionNumber, Input::Uint(256), ErrorKind::OutOfRange),
    ] {
        let e = s.set(tag, input.clone(), at(1)).unwrap_err();
        assert_eq!(e.kind, kind, "{tag:?} {input:?}: {e}");
        assert_eq!(e.tag, Some(tag as u64));
    }
    assert!(s.unknown(Tag::ControlCommand, at(1)).is_err());
    assert!(s.unknown(Tag::UasDatalinkLsVersionNumber, at(1)).is_err());
    assert_eq!(s.revision(), rev);
    assert_eq!(s.get(Tag::SensorLatitude), Some(&Input::Float(10.0)));
    assert_eq!(s.len(), 1);
    // The error names the item.
    let e = s.set(Tag::SensorLatitude, 91.0, at(1)).unwrap_err();
    assert!(e.to_string().contains("tag 13 (Sensor Latitude)"), "{e}");
}

#[test]
fn clamp_policy_state() {
    let mut opts = EncodeOptions::default();
    opts.policy = Policy::Clamp;
    let mut s = MetadataState::with_options(opts.clone());
    s.set(Tag::SensorLatitude, 95.0, at(0)).unwrap();
    let b = s.snapshot(at(0)).to_builder(at(0), &opts).unwrap();
    assert_eq!(b.warnings().len(), 1);
    let p = decode(&b.finish().unwrap());
    assert!((p.get(Tag::SensorLatitude).unwrap().as_f64().unwrap() - 90.0).abs() < 1e-7);
}

#[test]
fn heights_75_and_104_are_exclusive() {
    let mut s = MetadataState::new();
    s.set(Tag::SensorEllipsoidHeight, 1000.0, at(0)).unwrap();
    let e = s.set(Tag::SensorEllipsoidHeightExtended, 1000.0, at(0)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotAllowed);
    assert!(s.unknown(Tag::SensorEllipsoidHeightExtended, at(0)).is_err());
    s.clear(Tag::SensorEllipsoidHeight);
    s.set(Tag::SensorEllipsoidHeightExtended, 1000.0, at(0)).unwrap();
}

#[test]
fn a_snapshot_never_sees_later_updates() {
    let mut s = MetadataState::new();
    s.set(Tag::SensorLatitude, 1.0, at(0)).unwrap();
    s.set(Tag::SensorLongitude, 2.0, at(0)).unwrap();
    let before = s.snapshot(at(0));
    let packet = before.encode_at(at(0), &EncodeOptions::default()).unwrap();
    s.set(Tag::SensorLatitude, 3.0, at(1)).unwrap();
    s.clear(Tag::SensorLongitude);
    s.set(Tag::MissionId, "NEW", at(1)).unwrap();
    // The old snapshot (and its clones, on any thread) still hold the
    // values of one moment.
    let copy = before.clone();
    let from_thread = std::thread::spawn(move || copy.encode_at(at(0), &EncodeOptions::default()).unwrap())
        .join()
        .unwrap();
    assert_eq!(from_thread, packet);
    assert_eq!(before.get(Tag::SensorLatitude), Some(&Input::Float(1.0)));
    assert_eq!(before.get(Tag::SensorLongitude), Some(&Input::Float(2.0)));
    assert!(before.get(Tag::MissionId).is_none());
    let after = s.snapshot(at(1));
    assert!(!after.same_items(&before));
    assert_eq!(after.get(Tag::SensorLatitude), Some(&Input::Float(3.0)));
    assert!(after.same_items(&s.snapshot(at(2))));
}

#[test]
fn revision_tells_whether_anything_changed() {
    let mut s = MetadataState::new();
    let r0 = s.revision();
    s.set(Tag::SensorLatitude, 1.0, at(0)).unwrap();
    let r1 = s.revision();
    assert!(r1 > r0);
    // Setting the same value again is still an update (its time moves).
    s.set(Tag::SensorLatitude, 1.0, at(5)).unwrap();
    assert!(s.revision() > r1);
    assert_eq!(s.set_at(Tag::SensorLatitude), Some(at(5)));
    let r2 = s.revision();
    let _ = s.snapshot(at(6));
    assert_eq!(s.revision(), r2, "snapshots do not count");
    assert!(!s.clear(Tag::MissionId));
    assert_eq!(s.revision(), r2, "clearing nothing is no change");
}

#[test]
fn version_override_and_clear_all() {
    let mut s = MetadataState::new();
    s.set(Tag::UasDatalinkLsVersionNumber, 17u8, at(0)).unwrap();
    assert_eq!(s.version(), Some(17));
    assert!(s.is_empty(), "the version is not an item");
    let p = decode(&s.snapshot(at(0)).encode_at(at(0), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(65u8), Some(&Value::Uint(17)));
    assert!(s.clear(Tag::UasDatalinkLsVersionNumber));
    assert_eq!(s.version(), None);
    s.set_version(Some(12));
    s.set(Tag::MissionId, "M", at(0)).unwrap();
    s.clear_all();
    assert!(s.is_empty());
    assert_eq!(s.version(), None);
    let p = decode(&s.snapshot(at(0)).encode_at(at(0), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(65u8), Some(&Value::Uint(19)));
    assert_eq!(p.items.len(), 3);
}

#[test]
fn stale_values_are_omitted_or_unknown() {
    let mut s = MetadataState::new();
    *s.staleness_mut() = Staleness::with_max_age(Duration::from_millis(500));
    s.staleness_mut().set_max_age(Tag::MissionId, None).set_max_age(Tag::SlantRange, Some(Duration::from_secs(2)));
    s.set(Tag::MissionId, "M", at(0)).unwrap();
    s.set(Tag::SensorLatitude, 1.0, at(0)).unwrap();
    s.set(Tag::SlantRange, 100.0, at(0)).unwrap();
    s.set(Tag::SensorLongitude, 2.0, at(400)).unwrap();

    let snap = s.snapshot(at(500));
    assert_eq!(snap.len(), 4, "exactly at the maximum age a value is still fresh");
    let snap = s.snapshot(at(501));
    let tags: Vec<Tag> = snap.items().map(|(t, _)| t).collect();
    assert_eq!(tags, [Tag::MissionId, Tag::SensorLongitude, Tag::SlantRange]);
    assert_eq!(s.next_expiry(at(0)), Some(at(500).checked_add_micros(1).unwrap()));
    assert_eq!(s.next_expiry(at(501)), Some(at(900).checked_add_micros(1).unwrap()));
    assert_eq!(s.next_expiry(at(2001)), None);
    let snap = s.snapshot(at(3000));
    assert_eq!(snap.len(), 1);

    s.staleness_mut().policy = StalePolicy::Unknown;
    let snap = s.snapshot(at(3000));
    assert_eq!(snap.len(), 4);
    assert_eq!(snap.get(Tag::SensorLatitude), Some(&Input::Value(Value::Unknown)));
    assert_eq!(snap.get(Tag::MissionId), Some(&Input::Text("M".into())));
    let p = decode(&snap.encode_at(at(3000), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(Tag::SensorLatitude), Some(&Value::Unknown));
    assert_eq!(p.get(Tag::SlantRange), Some(&Value::Unknown));
    // A fresh value replaces a stale one.
    s.set(Tag::SensorLatitude, 5.0, at(3000)).unwrap();
    assert_eq!(s.snapshot(at(3000)).get(Tag::SensorLatitude), Some(&Input::Float(5.0)));
    // The state holds stale values until they are cleared.
    assert!(s.get(Tag::SensorLongitude).is_some());
}

#[test]
fn nested_sets() {
    let mut s = MetadataState::new();
    let security = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
    s.set_security(&security, at(0)).unwrap();
    assert_eq!(s.get(Tag::SecurityLocalSet), Some(&Input::Set(security.encode().unwrap())));
    // A decoded set works too.
    let decoded = decode(&{
        let mut b = St0601Builder::new(at(0));
        b.set(Tag::SecurityLocalSet, Input::Set(security.encode().unwrap())).unwrap();
        b.finish().unwrap()
    });
    let set = decoded.get(Tag::SecurityLocalSet).unwrap().clone();
    s.set(Tag::SecurityLocalSet, set, at(1)).unwrap();
    // Malformed set bytes are refused.
    assert!(s.set(Tag::SecurityLocalSet, Input::Set(vec![1, 5, 1]), at(1)).is_err());
    let mut incomplete = Security::default();
    incomplete.classification = Some(Classification::Secret);
    assert!(s.set_security(&incomplete, at(1)).is_err());

    // VMTI needs the frame centre in the same packet (D-31): the state
    // takes the set, the packet without tags 23 and 24 is refused.
    let mut vmti = Vmti::new();
    let mut target = VTarget::new(1);
    target.location = Some(Location::new(38.0, -77.0, 100.0));
    vmti.targets.push(target);
    s.set_vmti(&vmti, at(1)).unwrap();
    let e = s.snapshot(at(1)).encode_at(at(1), &EncodeOptions::default()).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Missing);
    s.set(Tag::FrameCenterLatitude, 38.0, at(1)).unwrap();
    s.set(Tag::FrameCenterLongitude, -77.0, at(1)).unwrap();
    let p = decode(&s.snapshot(at(1)).encode_at(at(1), &EncodeOptions::default()).unwrap());
    assert!(matches!(p.get(Tag::VmtiLocalSet), Some(Value::Set(_))));
    assert!(matches!(p.get(Tag::SecurityLocalSet), Some(Value::Set(_))));
}

#[test]
fn snapshots_are_shareable() {
    fn shareable<T: Send + Sync + Clone>() {}
    shareable::<Snapshot>();
    shareable::<MetadataState>();
    let s = MetadataState::default();
    let snap = s.snapshot(at(0));
    assert!(snap.is_empty());
    assert_eq!(snap.version(), None);
    assert_eq!(decode(&snap.encode_at(at(0), &EncodeOptions::default()).unwrap()).items.len(), 3);
}

#[test]
fn iteration_and_queries() {
    let mut s = MetadataState::new();
    s.set(Tag::SlantRange, 5.0, at(2)).unwrap();
    s.set(Tag::MissionId, "M", at(1)).unwrap();
    let all: Vec<(Tag, MispTime)> = s.iter().map(|(t, _, when)| (t, when)).collect();
    assert_eq!(all, [(Tag::MissionId, at(1)), (Tag::SlantRange, at(2))]);
    assert!(s.contains(Tag::SlantRange));
    assert!(!s.contains(Tag::SensorLatitude));
    assert_eq!(s.staleness(), &Staleness::new());
    assert_eq!(s.options(), &EncodeOptions::default());
}
