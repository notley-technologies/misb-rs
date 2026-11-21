//! Keyframe tracks (MUXING_PLAN.md sections 2.1 and 6.3): interpolation
//! accuracy (linear midpoints, angles the short way, great circles), holds
//! for discrete items, never interpolating across unknown or special values,
//! gaps and staleness, hints, the streaming API, and sampled snapshots that
//! encode and decode back within the encoder's tolerance (half an LSB for
//! linear maps, [v - 1 LSB, v] for IMAPB). Time is passed in explicitly.
#![cfg(feature = "encode")]
#![forbid(unsafe_code)]

use misb::encode::{EncodeOptions, ErrorKind, Input};
use misb::st0601::Tag;
use misb::state::{Snapshot, StalePolicy, Staleness};
use misb::track::{default_interpolation, Interpolation, Keyframe, Track, TrackConfig, TrackError, GEODESIC_PAIRS};
use misb::{MispTime, Value};
use std::time::Duration;

const T0: u64 = 1_700_000_000_000_000;

fn at(ms: u64) -> MispTime {
    MispTime::from_micros(T0 + ms * 1000)
}

fn us(us: u64) -> MispTime {
    MispTime::from_micros(T0 + us)
}

fn kf(ms: u64) -> Keyframe {
    Keyframe::new(at(ms))
}

fn track(keyframes: Vec<Keyframe>) -> Track {
    Track::from_keyframes(TrackConfig::new(), keyframes).unwrap()
}

fn track_with(cfg: TrackConfig, keyframes: Vec<Keyframe>) -> Track {
    Track::from_keyframes(cfg, keyframes).unwrap()
}

fn num(s: &Snapshot, tag: Tag) -> f64 {
    s.get(tag).and_then(Input::as_f64).unwrap_or_else(|| panic!("{tag:?} is not a number in {s:?}"))
}

fn sample(t: &Track, ms: u64) -> Snapshot {
    t.sample(at(ms)).unwrap()
}

fn decode(bytes: &[u8]) -> misb::Packet {
    let p = misb::decode(bytes).unwrap();
    assert!(p.is_ok(), "{p}");
    p
}

/// Great-circle distance in radians (haversine), independent of the
/// track's spherical interpolation.
fn distance(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (p1, p2) = (a.0.to_radians(), b.0.to_radians());
    let dp = p2 - p1;
    let dl = (b.1 - a.1).to_radians();
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * h.sqrt().min(1.0).asin()
}

/// The difference between two angles in degrees, -180 to 180.
fn angle_diff(a: f64, b: f64) -> f64 {
    (a - b + 180.0).rem_euclid(360.0) - 180.0
}

#[test]
fn linear_midpoints_are_exact() {
    let t = track(vec![
        kf(0).set(Tag::SlantRange, 1000.0)
            .set(Tag::SensorTrueAltitude, 100.0)
            .set(Tag::SensorEllipsoidHeightExtended, 0.0)
            .set(Tag::PlatformTrueAirspeed, 10u8)
            .set(Tag::OffsetCornerLatitudePoint1, -0.05)
            .set(Tag::SensorHorizontalFieldOfView, 10.0)
            .set(Tag::OutsideAirTemperature, -10i8),
        kf(1000).set(Tag::SlantRange, 2000.0)
            .set(Tag::SensorTrueAltitude, 300.0)
            .set(Tag::SensorEllipsoidHeightExtended, 1000.0)
            .set(Tag::PlatformTrueAirspeed, 20u8)
            .set(Tag::OffsetCornerLatitudePoint1, 0.05)
            .set(Tag::SensorHorizontalFieldOfView, 20.0)
            .set(Tag::OutsideAirTemperature, 10i8),
    ]);
    let mid = sample(&t, 500);
    assert_eq!(num(&mid, Tag::SlantRange), 1500.0);
    assert_eq!(num(&mid, Tag::SensorTrueAltitude), 200.0);
    assert_eq!(num(&mid, Tag::SensorEllipsoidHeightExtended), 500.0);
    assert_eq!(num(&mid, Tag::PlatformTrueAirspeed), 15.0);
    assert_eq!(num(&mid, Tag::OffsetCornerLatitudePoint1), 0.0);
    assert_eq!(num(&mid, Tag::SensorHorizontalFieldOfView), 15.0);
    assert_eq!(num(&mid, Tag::OutsideAirTemperature), 0.0);
    let quarter = sample(&t, 250);
    assert_eq!(num(&quarter, Tag::SlantRange), 1250.0);
    assert_eq!(num(&quarter, Tag::PlatformTrueAirspeed), 12.5);
    // At a keyframe the value is the keyframe's, as given.
    assert_eq!(sample(&t, 0).get(Tag::PlatformTrueAirspeed), Some(&Input::Uint(10)));
    assert_eq!(sample(&t, 1000).get(Tag::SlantRange), Some(&Input::Float(2000.0)));
    // An integer item rounds (half away from zero) when encoded.
    let p = decode(&quarter.encode_at(at(250), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(Tag::PlatformTrueAirspeed), Some(&Value::Uint(13)));
}

#[test]
fn angles_go_the_short_way_around() {
    let t = track(vec![
        kf(0).set(Tag::PlatformHeadingAngle, 350.0)
            .set(Tag::PlatformSideslipAngleFull, -170.0)
            .set(Tag::PlatformCourseAngle, 350.0)
            .set(Tag::SensorRelativeElevationAngle, 170.0)
            .set(Tag::WindDirection, 10.0),
        kf(1000).set(Tag::PlatformHeadingAngle, 10.0)
            .set(Tag::PlatformSideslipAngleFull, 170.0)
            .set(Tag::PlatformCourseAngle, 10.0)
            .set(Tag::SensorRelativeElevationAngle, -170.0)
            .set(Tag::WindDirection, 350.0),
    ]);
    let mid = sample(&t, 500);
    assert_eq!(num(&mid, Tag::PlatformHeadingAngle), 0.0);
    assert_eq!(num(&mid, Tag::PlatformCourseAngle), 0.0);
    assert_eq!(num(&mid, Tag::WindDirection), 0.0);
    // -180 and 180 are the same direction; the range is -180 to 180.
    assert_eq!(num(&mid, Tag::PlatformSideslipAngleFull).abs(), 180.0);
    assert_eq!(num(&mid, Tag::SensorRelativeElevationAngle).abs(), 180.0);
    assert_eq!(num(&sample(&t, 250), Tag::PlatformHeadingAngle), 355.0);
    assert_eq!(num(&sample(&t, 750), Tag::PlatformHeadingAngle), 5.0);
    assert_eq!(num(&sample(&t, 250), Tag::PlatformSideslipAngleFull), -175.0);
    assert_eq!(num(&sample(&t, 750), Tag::PlatformSideslipAngleFull), 175.0);
    let p = decode(&mid.encode_at(at(500), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(Tag::PlatformHeadingAngle).and_then(Value::as_f64), Some(0.0));
    assert!((p.get(Tag::PlatformSideslipAngleFull).and_then(Value::as_f64).unwrap().abs() - 180.0).abs() < 1e-6);

    // Overridden to linear, the heading goes the long way.
    let mut cfg = TrackConfig::new();
    cfg.set_interpolation(Tag::PlatformHeadingAngle, Interpolation::Linear).unwrap();
    let t = track_with(
        cfg,
        vec![kf(0).set(Tag::PlatformHeadingAngle, 350.0), kf(1000).set(Tag::PlatformHeadingAngle, 10.0)],
    );
    assert_eq!(num(&sample(&t, 500), Tag::PlatformHeadingAngle), 180.0);
}

fn pair(lat: Tag, lon: Tag, a: (f64, f64), b: (f64, f64)) -> Track {
    track(vec![kf(0).set(lat, a.0).set(lon, a.1), kf(1000).set(lat, b.0).set(lon, b.1)])
}

fn position(s: &Snapshot, lat: Tag, lon: Tag) -> (f64, f64) {
    (num(s, lat), num(s, lon))
}

#[test]
fn great_circle_midpoints() {
    let (lat, lon) = (Tag::SensorLatitude, Tag::SensorLongitude);
    let close = |got: (f64, f64), want: (f64, f64)| {
        assert!((got.0 - want.0).abs() < 1e-9 && angle_diff(got.1, want.1).abs() < 1e-9, "{got:?} != {want:?}");
    };
    // Along the equator, the great circle is the equator.
    let t = pair(lat, lon, (0.0, 10.0), (0.0, 20.0));
    close(position(&sample(&t, 500), lat, lon), (0.0, 15.0));
    let t = pair(lat, lon, (0.0, 0.0), (0.0, 40.0));
    close(position(&sample(&t, 250), lat, lon), (0.0, 10.0));
    // Across the antimeridian, the short way.
    let t = pair(lat, lon, (0.0, 170.0), (0.0, -170.0));
    let mid = position(&sample(&t, 500), lat, lon);
    close(mid, (0.0, 180.0));
    assert!(mid.1.abs() <= 180.0);
    close(position(&sample(&t, 250), lat, lon), (0.0, 175.0));
    // Along a meridian.
    let t = pair(lat, lon, (0.0, 0.0), (60.0, 0.0));
    close(position(&sample(&t, 500), lat, lon), (30.0, 0.0));
    // Two points at 45 N, 90 degrees apart: the great circle rises to
    // atan(sqrt(2)) = 54.7356 N halfway, not 45 N as a rhumb line would.
    let t = pair(lat, lon, (45.0, 0.0), (45.0, 90.0));
    close(position(&sample(&t, 500), lat, lon), (2f64.sqrt().atan().to_degrees(), 45.0));
    // Every geodesic pair of the table behaves the same.
    for (lat, lon) in GEODESIC_PAIRS {
        assert_eq!(default_interpolation(lat), Interpolation::Geodesic);
        assert_eq!(default_interpolation(lon), Interpolation::Geodesic);
        let t = pair(lat, lon, (45.0, 0.0), (45.0, 90.0));
        close(position(&sample(&t, 500), lat, lon), (2f64.sqrt().atan().to_degrees(), 45.0));
    }
}

#[test]
fn great_circle_points_lie_on_the_circle() {
    // For many pairs and fractions, the sampled point is on the great circle
    // through both ends (the distances add up) at the right fraction of the
    // way, checked with the haversine distance.
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 11) as f64 / (1u64 << 53) as f64
    };
    for _ in 0..500 {
        let a = (next() * 170.0 - 85.0, next() * 360.0 - 180.0);
        let b = (next() * 170.0 - 85.0, next() * 360.0 - 180.0);
        let total = distance(a, b);
        if total > 3.1 || total < 1e-6 {
            continue; // near-antipodal pairs have no stable great circle
        }
        let t = pair(Tag::FrameCenterLatitude, Tag::FrameCenterLongitude, a, b);
        let ms = (next() * 999.0) as u64 + 1;
        let f = ms as f64 / 1000.0;
        let p = position(&sample(&t, ms), Tag::FrameCenterLatitude, Tag::FrameCenterLongitude);
        assert!((distance(a, p) - f * total).abs() < 1e-9, "{a:?} {b:?} {f}: {p:?}");
        assert!((distance(p, b) - (1.0 - f) * total).abs() < 1e-9, "{a:?} {b:?} {f}: {p:?}");
    }
}

#[test]
fn pairs_that_cannot_be_interpolated_hold() {
    let (lat, lon) = (Tag::SensorLatitude, Tag::SensorLongitude);
    // Antipodal points: no single great circle.
    let t = pair(lat, lon, (0.0, 0.0), (0.0, 180.0));
    assert_eq!(position(&sample(&t, 500), lat, lon), (0.0, 0.0));
    // The longitude's next keyframe is not the latitude's.
    let t = track(vec![
        kf(0).set(lat, 0.0).set(lon, 0.0),
        kf(1000).set(lat, 10.0),
        kf(2000).set(lat, 20.0).set(lon, 20.0),
    ]);
    assert_eq!(position(&sample(&t, 500), lat, lon), (0.0, 0.0));
    // Overridden together, each item interpolates on its own.
    let mut cfg = TrackConfig::new();
    cfg.set_interpolation(lat, Interpolation::Linear).unwrap().set_interpolation(lon, Interpolation::Angle).unwrap();
    let t = track_with(cfg, vec![kf(0).set(lat, 0.0).set(lon, 170.0), kf(1000).set(lat, 10.0).set(lon, -170.0)]);
    let p = position(&sample(&t, 500), lat, lon);
    assert_eq!(p.0, 5.0);
    assert_eq!(p.1.abs(), 180.0);
}

#[test]
fn discrete_items_hold() {
    let t = track(vec![
        kf(0).set(Tag::MissionId, "A")
            .set(Tag::IcingDetected, Input::Code(1))
            .set(Tag::NumberOfNavsatsInView, 5u8)
            .set(Tag::EventStartTime, at(0))
            .set(Tag::SensorFrameRatePack, Value::Struct(vec![misb::Field::new("Numerator", Value::Uint(30))])),
        kf(1000).set(Tag::MissionId, "B")
            .set(Tag::IcingDetected, Input::Code(2))
            .set(Tag::NumberOfNavsatsInView, 9u8)
            .set(Tag::EventStartTime, at(1000))
            .set(Tag::SensorFrameRatePack, Value::Struct(vec![misb::Field::new("Numerator", Value::Uint(60))])),
    ]);
    let s = sample(&t, 999);
    assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("A".into())));
    assert_eq!(s.get(Tag::IcingDetected), Some(&Input::Code(1)));
    assert_eq!(s.get(Tag::NumberOfNavsatsInView), Some(&Input::Uint(5)));
    assert_eq!(s.get(Tag::EventStartTime), Some(&Input::Time(at(0))));
    let s = sample(&t, 1000);
    assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("B".into())));
    assert_eq!(s.get(Tag::IcingDetected), Some(&Input::Code(2)));
    assert!(decode(&sample(&t, 500).encode_at(at(500), &EncodeOptions::default()).unwrap()).is_ok());
}

#[test]
fn never_across_unknown_or_special_values() {
    let t = track(vec![
        kf(0).set(Tag::SlantRange, 1000.0).set(Tag::FrameCenterLatitude, Input::OffEarth).set(Tag::FrameCenterLongitude, 20.0)
            .set(Tag::PlatformPitchAngle, Input::OutOfRange),
        kf(1000).unknown(Tag::SlantRange).set(Tag::FrameCenterLatitude, 10.0).set(Tag::FrameCenterLongitude, 30.0)
            .set(Tag::PlatformPitchAngle, 5.0),
        kf(2000).set(Tag::SlantRange, 2000.0),
    ]);
    let s = sample(&t, 500);
    assert_eq!(s.get(Tag::SlantRange), Some(&Input::Float(1000.0)), "the next value is unknown: hold");
    assert_eq!(s.get(Tag::FrameCenterLatitude), Some(&Input::OffEarth), "special: hold");
    assert_eq!(s.get(Tag::FrameCenterLongitude), Some(&Input::Float(20.0)), "its pair cannot move: hold");
    assert_eq!(s.get(Tag::PlatformPitchAngle), Some(&Input::OutOfRange));
    let s = sample(&t, 1500);
    assert_eq!(s.get(Tag::SlantRange), Some(&Input::Value(Value::Unknown)), "unknown holds until the next value");
    let p = decode(&s.encode_at(at(1500), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(Tag::SlantRange), Some(&Value::Unknown));
    assert_eq!(sample(&t, 2000).get(Tag::SlantRange), Some(&Input::Float(2000.0)));
}

#[test]
fn gaps_and_staleness() {
    let mut cfg = TrackConfig::new();
    cfg.max_gap = Some(Duration::from_secs(2));
    cfg.staleness = Staleness::with_max_age(Duration::from_secs(1));
    let keys = vec![
        kf(0).set(Tag::SlantRange, 0.0).set(Tag::MissionId, "M"),
        kf(2000).set(Tag::SlantRange, 2000.0),
        kf(7000).set(Tag::SlantRange, 7000.0),
    ];
    let t = track_with(cfg.clone(), keys.clone());
    // A 2 s gap is interpolated, and interpolated values are fresh even
    // past the maximum age.
    assert_eq!(num(&sample(&t, 1500), Tag::SlantRange), 1500.0);
    // A 5 s gap is not: the value holds, then goes stale.
    assert_eq!(num(&sample(&t, 3000), Tag::SlantRange), 2000.0);
    assert!(sample(&t, 3001).get(Tag::SlantRange).is_none());
    assert_eq!(num(&sample(&t, 7000), Tag::SlantRange), 7000.0);
    // After the last keyframe the value holds up to the maximum age.
    assert_eq!(num(&sample(&t, 8000), Tag::SlantRange), 7000.0);
    assert!(sample(&t, 8001).get(Tag::SlantRange).is_none());
    // MissionId was only in the first keyframe.
    assert!(sample(&t, 1000).get(Tag::MissionId).is_some());
    assert!(sample(&t, 1001).get(Tag::MissionId).is_none());

    // Stale values as unknown, and a per-item override.
    cfg.staleness.policy = StalePolicy::Unknown;
    cfg.staleness.set_max_age(Tag::MissionId, None);
    let t = track_with(cfg, keys);
    assert_eq!(sample(&t, 9000).get(Tag::SlantRange), Some(&Input::Value(Value::Unknown)));
    assert_eq!(sample(&t, 9000).get(Tag::MissionId), Some(&Input::Text("M".into())));
}

#[test]
fn before_the_first_keyframe() {
    let keys = vec![kf(5000).set(Tag::SlantRange, 1.0).with_version(17), kf(6000).set(Tag::MissionId, "M")];
    let t = track(keys.clone());
    assert!(sample(&t, 0).is_empty());
    assert_eq!(sample(&t, 0).version(), None);
    assert!(sample(&t, 5500).get(Tag::MissionId).is_none());
    let mut cfg = TrackConfig::new();
    cfg.hold_before_first = true;
    let t = track_with(cfg.clone(), keys.clone());
    let s = sample(&t, 0);
    assert_eq!(s.get(Tag::SlantRange), Some(&Input::Float(1.0)));
    assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("M".into())));
    assert_eq!(s.version(), Some(17));
    // Not further back than max_gap.
    cfg.max_gap = Some(Duration::from_secs(1));
    let t = track_with(cfg, keys);
    assert!(sample(&t, 3999).get(Tag::SlantRange).is_none());
    assert!(sample(&t, 4000).get(Tag::SlantRange).is_some());
    assert!(sample(&t, 4999).get(Tag::MissionId).is_none());
    assert!(sample(&t, 5000).get(Tag::MissionId).is_some());
}

#[test]
fn hints_override_the_configuration() {
    let mut cfg = TrackConfig::new();
    cfg.set_interpolation(Tag::SlantRange, Interpolation::Hold).unwrap();
    assert_eq!(cfg.interpolation(Tag::SlantRange), Interpolation::Hold);
    assert_eq!(cfg.interpolation(Tag::SensorTrueAltitude), Interpolation::Linear);
    let t = track_with(
        cfg,
        vec![
            kf(0).set(Tag::SlantRange, 0.0),
            kf(1000).set(Tag::SlantRange, 1000.0).with_interpolation(Tag::SlantRange, Interpolation::Linear),
            kf(2000).set(Tag::SlantRange, 2000.0),
            // A hint stays until changed, and applies from its keyframe on.
            kf(3000).set(Tag::SlantRange, 3000.0).with_interpolation(Tag::SlantRange, Interpolation::Hold),
            kf(4000).set(Tag::SlantRange, 4000.0),
        ],
    );
    assert_eq!(num(&sample(&t, 500), Tag::SlantRange), 0.0, "configured hold");
    assert_eq!(num(&sample(&t, 1500), Tag::SlantRange), 1500.0, "hinted linear");
    assert_eq!(num(&sample(&t, 2500), Tag::SlantRange), 2500.0, "still linear");
    assert_eq!(num(&sample(&t, 3500), Tag::SlantRange), 3000.0, "hinted hold");
}

#[test]
fn interpolations_that_cannot_apply_are_refused() {
    let mut cfg = TrackConfig::new();
    for (tag, how) in [
        (Tag::SlantRange, Interpolation::Geodesic),
        (Tag::SlantRange, Interpolation::Angle),
        (Tag::SensorLatitude, Interpolation::Angle),
        (Tag::MissionId, Interpolation::Linear),
        (Tag::IcingDetected, Interpolation::Linear),
        (Tag::EventStartTime, Interpolation::Linear),
    ] {
        let e = cfg.set_interpolation(tag, how).unwrap_err();
        assert!(matches!(e, TrackError::Interpolation { tag: t, interpolation: i, .. } if t == tag && i == how), "{e}");
    }
    let e = cfg.set_interpolation(Tag::SlantRange, Interpolation::Geodesic).unwrap_err();
    assert_eq!(
        e.to_string(),
        "ST 0601 tag 21 (Slant Range): geodesic: geodesic interpolation applies to latitude and longitude pairs"
    );
    let mut t = Track::new(TrackConfig::new());
    t.push(kf(0).set(Tag::SlantRange, 1.0)).unwrap();
    let held = t.values_held();
    let bad = kf(1000).set(Tag::SlantRange, 2.0).with_interpolation(Tag::MissionId, Interpolation::Geodesic);
    assert!(matches!(t.push(bad), Err(TrackError::Interpolation { .. })));
    assert_eq!(t.values_held(), held, "a refused keyframe changes nothing");
    assert_eq!(t.last_time(), Some(at(0)));
}

#[test]
fn push_rules() {
    let mut t = Track::new(TrackConfig::new());
    t.push(kf(1000).set(Tag::SlantRange, 1.0).set(Tag::MissionId, "A")).unwrap();
    assert_eq!(t.push(kf(999)), Err(TrackError::OutOfOrder { time: at(999), last: at(1000) }));
    // The same time merges: later values replace earlier ones.
    t.push(kf(1000).set(Tag::SlantRange, 2.0)).unwrap();
    let s = sample(&t, 1000);
    assert_eq!(s.get(Tag::SlantRange), Some(&Input::Float(2.0)));
    assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("A".into())));
    assert_eq!(t.values_held(), 2);
    // Values are checked like the builder checks them, before anything
    // changes.
    let e = t.push(kf(2000).set(Tag::SlantRange, 3.0).set(Tag::SensorLatitude, 91.0)).unwrap_err();
    assert!(matches!(e, TrackError::Encode(ref e) if e.kind == ErrorKind::OutOfRange && e.tag == Some(13)), "{e}");
    assert_eq!(t.last_time(), Some(at(1000)));
    let dup = t.push(kf(2000).set(Tag::SlantRange, 3.0).set(Tag::SlantRange, 4.0)).unwrap_err();
    assert!(matches!(dup, TrackError::Encode(ref e) if e.kind == ErrorKind::Duplicate), "{dup}");
    let both = t.push(kf(2000).set(Tag::SensorEllipsoidHeight, 1.0).set(Tag::SensorEllipsoidHeightExtended, 1.0));
    assert!(matches!(both, Err(TrackError::Encode(ref e)) if e.kind == ErrorKind::NotAllowed));
    assert!(t.push(kf(2000).set(Tag::PrecisionTimeStamp, 1u64)).is_err());
    // Tag 65 among the items is the version.
    t.push(kf(2000).set(Tag::UasDatalinkLsVersionNumber, 18u8)).unwrap();
    assert_eq!(sample(&t, 2500).version(), Some(18));
    assert!(t.push(kf(3000).with_version(1).set(Tag::UasDatalinkLsVersionNumber, 2u8)).is_err());
    assert_eq!(t.keyframes_pushed(), 3);
    t.finish();
    assert!(t.is_finished());
    assert_eq!(t.push(kf(4000)), Err(TrackError::Finished));
}

#[test]
fn ready_says_when_the_values_are_settled() {
    let mut t = Track::new(TrackConfig::new());
    assert!(!t.ready(at(0)));
    t.push(kf(0).set(Tag::SlantRange, 0.0).set(Tag::MissionId, "M")).unwrap();
    assert!(!t.ready(at(0)), "a keyframe at the same time could still merge");
    t.push(kf(1000).set(Tag::MissionId, "M")).unwrap();
    // The slant range could still be interpolated towards a later keyframe.
    assert!(!t.ready(at(500)));
    assert!(t.ready(at(0)), "exactly at a keyframe nothing later matters");
    t.push(kf(2000).set(Tag::SlantRange, 2000.0)).unwrap();
    assert!(t.ready(at(500)));
    assert_eq!(num(&sample(&t, 500), Tag::SlantRange), 500.0);
    assert!(!t.ready(at(2000)));
    t.finish();
    assert!(t.ready(at(1_000_000)));

    // Held and non-numeric items need no lookahead.
    let mut t = Track::new(TrackConfig::new());
    t.push(kf(0).set(Tag::MissionId, "M").set(Tag::SlantRange, Input::Value(Value::Unknown))).unwrap();
    t.push(kf(10)).unwrap();
    assert!(t.ready(at(5)));

    // With max_gap, a keyframe more than the gap ahead settles everything.
    let mut cfg = TrackConfig::new();
    cfg.max_gap = Some(Duration::from_millis(400));
    let mut t = Track::new(cfg.clone());
    t.push(kf(0).set(Tag::SlantRange, 0.0)).unwrap();
    t.push(kf(300)).unwrap();
    assert!(!t.ready(at(100)));
    t.push(kf(401)).unwrap();
    assert!(t.ready(at(100)), "the slant range's gap is already too long");

    // Holding first values back, any later item could matter.
    cfg.hold_before_first = true;
    let mut t = Track::new(cfg);
    t.push(kf(0).set(Tag::MissionId, "M")).unwrap();
    t.push(kf(300)).unwrap();
    assert!(!t.ready(at(100)));
    t.push(kf(501)).unwrap();
    assert!(t.ready(at(100)));
}

/// A long synthetic flight: a moving position crossing the antimeridian, a
/// turning heading, a changing range and an integer speed, keyframes every
/// 100 ms, the mission id only in the first one.
fn flight(n: u64) -> impl Iterator<Item = Keyframe> {
    (0..n).map(|i| {
        let s = i as f64 / 10.0;
        let mut k = kf(i * 100)
            .set(Tag::SensorLatitude, 30.0 + 10.0 * (s / 300.0).sin())
            .set(Tag::SensorLongitude, ((179.0 + s * 0.01 + 180.0) % 360.0) - 180.0)
            .set(Tag::PlatformHeadingAngle, (s * 7.3) % 360.0)
            .set(Tag::SlantRange, 5000.0 + 3000.0 * (s / 17.0).cos())
            .set(Tag::PlatformTrueAirspeed, (60 + (i % 40)) as u8)
            .set(Tag::SensorEllipsoidHeightExtended, 1500.0 + 100.0 * (s / 23.0).sin());
        if i == 0 {
            k = k.set(Tag::MissionId, "LONG").with_version(19);
        }
        k
    })
}

#[test]
fn streaming_matches_a_whole_track_with_bounded_memory() {
    let n = 20_000; // 2000 s of keyframes
    let mut cfg = TrackConfig::new();
    cfg.max_gap = Some(Duration::from_millis(500));
    let whole = Track::from_keyframes(cfg.clone(), flight(n)).unwrap();
    let mut streamed = Track::new(cfg);
    let mut source = flight(n).peekable();
    let mut most = 0;
    let mut frames = 0;
    // 29.97 frames per second.
    let mut t = 0u64;
    while t < (n - 1) * 100_000 {
        let time = us(t);
        while !streamed.ready(time) {
            match source.next() {
                Some(k) => streamed.push(k).unwrap(),
                None => streamed.finish(),
            }
        }
        let s = streamed.sample(time).unwrap();
        assert_eq!(s, whole.sample(time).unwrap(), "at {t} us");
        assert!(s.get(Tag::MissionId).is_some());
        streamed.prune(time);
        most = most.max(streamed.values_held());
        frames += 1;
        t += 33_367;
    }
    assert!(frames > 59_000);
    // One keyframe of lookahead plus the held values: never the whole file.
    assert!(most < 40, "{most} values held");
    assert!(whole.values_held() > 100_000);
    let last = us(t - 33_367);
    assert_eq!(streamed.earliest(), Some(last));
    assert!(matches!(streamed.sample(at(0)), Err(TrackError::Pruned { .. })));
}

/// The value LSB of the items `flight` uses, and whether the item is IMAPB.
fn lsb(tag: Tag) -> (f64, bool) {
    match tag {
        Tag::SensorLatitude => (180.0 / 4_294_967_294.0, false),
        Tag::SensorLongitude => (360.0 / 4_294_967_294.0, false),
        Tag::PlatformHeadingAngle => (360.0 / 65_535.0, false),
        Tag::SlantRange => (5_000_000.0 / 4_294_967_295.0, false),
        Tag::PlatformTrueAirspeed => (1.0, false),
        Tag::SensorEllipsoidHeightExtended => {
            let m = misb::imapb::Imapb::new(-900.0, 40_000.0, 3).unwrap();
            (m.int_to_real(1) - m.int_to_real(0), true)
        }
        other => panic!("no LSB for {other:?}"),
    }
}

#[test]
fn sampled_snapshots_encode_within_the_encoder_tolerance() {
    let t = Track::from_keyframes(TrackConfig::new(), flight(600)).unwrap();
    let opts = EncodeOptions::default();
    let mut checked = 0;
    let mut time = 0u64;
    while time < 59_900_000 {
        let s = t.sample(us(time)).unwrap();
        let p = decode(&s.encode_at(us(time), &opts).unwrap());
        assert_eq!(p.get(Tag::PrecisionTimeStamp), Some(&Value::Time(T0 + time)));
        for (tag, input) in s.items() {
            let Some(v) = input.as_f64() else { continue };
            let got = p.get(tag).and_then(Value::as_f64).unwrap_or_else(|| panic!("{tag:?} missing"));
            let (lsb, imapb) = lsb(tag);
            let slack = 1e-9 * v.abs().max(1.0);
            let d = if matches!(tag, Tag::PlatformHeadingAngle | Tag::SensorLongitude) { angle_diff(got, v) } else { got - v };
            if imapb {
                // ST 1201 truncates: [v - 1 LSB, v].
                assert!(d <= slack && d >= -lsb - slack, "{tag:?} at {time}: {v} -> {got}");
            } else {
                // Linear maps round to nearest: within half an LSB.
                assert!(d.abs() <= lsb / 2.0 + slack, "{tag:?} at {time}: {v} -> {got}");
            }
            checked += 1;
        }
        time += 33_367;
    }
    assert!(checked > 10_000);
}

#[test]
fn version_holds_and_snapshots_compare() {
    let t = track(vec![kf(0).with_version(17).set(Tag::SlantRange, 1.0), kf(1000).set(Tag::SlantRange, 1.0)]);
    let a = sample(&t, 200);
    let b = sample(&t, 800);
    assert_eq!(a.version(), Some(17));
    assert!(a.same_items(&b), "equal values at different times");
    assert_ne!(a, b);
    let p = decode(&a.encode_at(at(200), &EncodeOptions::default()).unwrap());
    assert_eq!(p.get(65u8), Some(&Value::Uint(17)));
    assert!(t.config().max_gap.is_none());
}
