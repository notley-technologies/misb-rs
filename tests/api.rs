//! Behaviour of the public API: values and their accessors, tag lookups,
//! packet health, configuration, the entry points, the stream decoder's
//! extras, access unit cells and zero-length items.
mod common;

use common::*;
use misb::{
    st0102, st0601, st0806, st0903, Checksum, Config, Decoder, Error, Field, Item, Packet, Standard, TagKey, Value,
};

// ---------------------------------------------------------------- values

#[test]
fn accessors() {
    assert_eq!(Value::Float(1.5).as_f64(), Some(1.5));
    assert_eq!(Value::Uint(7).as_f64(), Some(7.0));
    assert_eq!(Value::Int(-7).as_f64(), Some(-7.0));
    assert_eq!(Value::Text("7".into()).as_f64(), None);
    assert_eq!(Value::Uint(u64::MAX).as_u64(), Some(u64::MAX));
    assert_eq!(Value::Int(5).as_u64(), Some(5));
    assert_eq!(Value::Int(-5).as_u64(), None);
    assert_eq!(Value::Enum { code: 4, label: None }.as_u64(), Some(4));
    assert_eq!(Value::Float(4.0).as_u64(), None);
    assert_eq!(Value::Uint(1 << 63).as_i64(), None);
    assert_eq!(Value::Uint(12).as_i64(), Some(12));
    assert_eq!(Value::Bytes(vec![1]).as_bytes(), Some(&[1u8][..]));
    assert_eq!(Value::Text("x".into()).as_bytes(), None);
    assert_eq!(Value::Time(9).as_time(), Some(9));
    assert_eq!(Value::Uint(9).as_time(), None);
    let set = Value::Set(Box::new(Packet::new(Standard::St0102)));
    assert_eq!(set.as_set().map(|p| p.standard), Some(Standard::St0102));
    assert!(Value::List(vec![]).as_list().is_some_and(<[Value]>::is_empty));
    let pack = Value::Struct(vec![Field::new("A", Value::Uint(1)), Field::new("A", Value::Uint(2))]);
    assert_eq!(pack.field("A"), Some(&Value::Uint(1)), "the first field of that name");
    assert_eq!(pack.as_fields().map(<[Field]>::len), Some(2));
    assert_eq!(Value::Uint(1).field("A"), None);
    for v in [Value::Unknown, Value::OutOfRange, Value::Invalid("x")] {
        assert_eq!((v.as_f64(), v.as_u64(), v.as_i64(), v.as_time()), (None, None, None, None));
        assert_eq!((v.as_str(), v.as_bytes(), v.as_set().is_none(), v.as_list().is_none()), (None, None, true, true));
    }
    assert!(Value::Unknown.is_valid());
    assert!(!Value::OutOfRange.is_valid());
    assert!(!Value::Invalid("x").is_valid());
    assert!(Value::Set(Box::new(Packet::new(Standard::St0601))).is_valid());
}

#[test]
fn equality_treats_nan_as_equal() {
    assert_eq!(Value::Float(f64::NAN), Value::Float(f64::NAN));
    assert_eq!(Value::Float(0.0), Value::Float(-0.0));
    assert_ne!(Value::Float(1.0), Value::Uint(1));
    assert_ne!(Value::Unknown, Value::OutOfRange);
    assert_ne!(Value::Invalid("a"), Value::Invalid("b"));
    // A packet holding a NaN equals its copy.
    let mut p = Packet::new(Standard::St0601);
    p.items.push(Item::new(117, "Sensor Azimuth Rate", "deg/s", Value::Float(f64::NAN), vec![0xD0, 0]));
    assert_eq!(p.clone(), p);
}

#[test]
fn display() {
    assert_eq!(Value::Uint(3).to_string(), "3");
    assert_eq!(Value::Int(-3).to_string(), "-3");
    assert_eq!(Value::Float(1.25).to_string(), "1.25");
    assert_eq!(Value::Bytes(vec![0x0A, 0xFF]).to_string(), "0A FF");
    assert_eq!(Value::Time(0).to_string(), "1970-01-01T00:00:00.000000 MISP");
    assert_eq!(Value::Time(951_782_400_000_001).to_string(), "2000-02-29T00:00:00.000001 MISP");
    assert_eq!(Value::Time(u64::MAX).to_string(), "586524-01-19T08:01:49.551615 MISP");
    assert_eq!(Value::Enum { code: 2, label: Some("Hostile") }.to_string(), "Hostile (2)");
    assert_eq!(Value::Enum { code: 99, label: None }.to_string(), "99");
    assert_eq!(Value::OutOfRange.to_string(), "out of range");
    assert_eq!(Value::Unknown.to_string(), "unknown");
    assert_eq!(Value::Invalid("wrong length for this tag").to_string(), "invalid (wrong length for this tag)");
    assert_eq!(Value::List(vec![Value::Uint(1), Value::Uint(2)]).to_string(), "[1, 2]");
    assert_eq!(Value::Struct(vec![Field::new("A", Value::Uint(1))]).to_string(), "{ A: 1 }");
    // Hostile text cannot start a new line or send escape sequences.
    let v = Value::Text("a\nb\u{1b}[2J\u{202e}c".into());
    assert_eq!(v.to_string(), "a\\nb\\u{1b}[2J\\u{202e}c");
    assert_eq!(v.as_str(), Some("a\nb\u{1b}[2J\u{202e}c"));
    // A nested set shows its items and its error.
    let mut s = Packet::new(Standard::St0102);
    s.items.push(Item::new(3, "Classifying Country", "", Value::Text("//USA".into()), vec![]));
    s.error = Some(Error::TooDeep);
    assert_eq!(Value::Set(Box::new(s)).to_string(), "ST 0102 { Classifying Country: //USA, error: sets nested too deeply }");
    let item = Item::new(15, "Sensor True Altitude", "m", Value::Float(100.5), vec![]);
    assert_eq!(item.to_string(), " 15 Sensor True Altitude: 100.5 m");
    // No units after values that are not numbers.
    let item = Item::new(15, "Sensor True Altitude", "m", Value::Unknown, vec![]);
    assert_eq!(item.to_string(), " 15 Sensor True Altitude: unknown");
    // A packet prints its standard, checksum, items and error.
    let p = misb::decode(&St0601::new().time(0).build()).unwrap();
    assert_eq!(
        p.to_string(),
        "ST 0601 UAS Datalink Local Set checksum ok\n    2 Precision Time Stamp: 1970-01-01T00:00:00.000000 MISP\n    1 Checksum: "
            .to_string()
            + &p.items[1].value.to_string()
    );
    let mut bad = St0601::new().time(0).build();
    corrupt_checksum(&mut bad);
    assert!(misb::decode(&bad).unwrap().to_string().contains("checksum MISMATCH"));
    let missing = St0601::new().time(0).no_checksum().build();
    assert!(misb::decode(&missing).unwrap().to_string().starts_with("ST 0601 UAS Datalink Local Set checksum missing"));
}

#[test]
fn standards() {
    let all = [Standard::St0601, Standard::St0102, Standard::St0806, Standard::St0903];
    let names: Vec<&str> = all.iter().map(|s| s.name()).collect();
    assert_eq!(names, ["ST 0601", "ST 0102", "ST 0806", "ST 0903"]);
    for s in all {
        assert_eq!(s.to_string(), s.name());
        assert!(s.revision().starts_with(s.name()));
        assert!(!s.title().is_empty());
    }
    assert_eq!(Standard::St0903.title(), "Video Moving Target Indicator Local Set");
    assert!(!misb::VERSION.is_empty());
}

// ---------------------------------------------------------------- tags

#[test]
fn tag_enums() {
    for n in 1..=143u64 {
        let t = st0601::Tag::from_u64(n).unwrap_or_else(|| panic!("ST 0601 tag {n}"));
        assert_eq!(u64::from(t), n);
        assert_eq!(t.number(), n);
        assert_eq!(t.standard(), Some(Standard::St0601));
        assert!(!t.name().is_empty());
    }
    assert_eq!(st0601::Tag::from_u64(0), None);
    assert_eq!(st0601::Tag::from_u64(144), None);
    assert_eq!(st0601::Tag::from_u64(u64::MAX), None);
    assert_eq!(st0601::Tag::SensorLatitude.units(), "deg");
    for n in 1..=24u64 {
        assert_eq!(st0102::Tag::from_u64(n).map(u64::from), Some(n));
    }
    assert_eq!(st0102::Tag::from_u64(25), None);
    for n in 1..=21u64 {
        assert_eq!(st0806::Tag::from_u64(n).map(u64::from), Some(n));
    }
    assert_eq!(st0806::Tag::from_u64(22), None);
    for n in (1..=13u64).chain(101..=103) {
        assert_eq!(st0903::Tag::from_u64(n).map(u64::from), Some(n));
    }
    assert_eq!(st0903::Tag::from_u64(14), None);
    assert_eq!(st0903::Tag::from_u64(100), None);
    assert_eq!(7u8.number(), 7);
    assert_eq!(7u16.standard(), None);
    assert_eq!(u32::MAX.number(), u64::from(u32::MAX));
}

#[test]
fn lookups_across_standards() {
    let p = misb::decode(&rich(0)).unwrap();
    assert!(p.is_ok(), "{p}");
    // A bare number looks in the packet's own standard.
    assert_eq!(p.get(3u8), p.get(st0601::Tag::MissionId));
    assert_eq!(p.get(3u16), p.get(3u64));
    assert_eq!(p.item(3u32).map(|i| i.name), Some("Mission ID"));
    // Another standard's tag finds nothing at this level, even when the
    // number exists: ST 0102 tag 3 is not ST 0601 tag 3.
    assert_eq!(p.get(st0102::Tag::ClassifyingCountry), None);
    assert_eq!(p.get(st0903::Tag::VmtiSystemName), None);
    assert_eq!(p.get_all(st0806::Tag::PlatformTrueAirspeed).count(), 0);
    let security = p.get(st0601::Tag::SecurityLocalSet).and_then(Value::as_set).unwrap();
    assert_eq!(security.get(st0102::Tag::ClassifyingCountry).and_then(Value::as_str), Some("//USA"));
    assert_eq!(security.get(3u8).and_then(Value::as_str), Some("//USA"));
    assert_eq!(security.get(st0601::Tag::MissionId), None);
    let rvt = p.get(st0601::Tag::RvtLocalSet).and_then(Value::as_set).unwrap();
    assert_eq!(rvt.standard, Standard::St0806);
    assert_eq!(rvt.get(st0806::Tag::PlatformTrueAirspeed), Some(&Value::Uint(147)));
    let vmti = p.get(st0601::Tag::VmtiLocalSet).and_then(Value::as_set).unwrap();
    assert_eq!(vmti.get(st0903::Tag::VmtiSystemName).and_then(Value::as_str), Some("DSTO_ADSS_VMTI"));
    // Segment and Amend sets are ST 0601 sets: ST 0601 tags apply.
    let segment = p.get(st0601::Tag::SegmentLocalSet).and_then(Value::as_set).unwrap();
    assert_eq!(segment.standard, Standard::St0601);
    assert!(segment.get(st0601::Tag::SensorLatitude).is_some());
    // Nothing for a tag that is not there.
    assert_eq!(p.get(st0601::Tag::WeaponsStores), None);
    assert_eq!(p.get(9999u64), None);
}

#[test]
fn get_all_and_iteration() {
    let bytes = St0601::new()
        .time(1)
        .set(100, Set::new().item(3, b"one"))
        .item(3, b"mission")
        .set(100, Set::new().item(3, b"two"))
        .item(102, &sdcc())
        .item(102, &sdcc())
        .build();
    let p = misb::decode(&bytes).unwrap();
    assert!(p.is_ok());
    let segments: Vec<&str> = p
        .get_all(st0601::Tag::SegmentLocalSet)
        .map(|i| i.value.as_set().unwrap().get(3u8).and_then(Value::as_str).unwrap())
        .collect();
    assert_eq!(segments, ["one", "two"]);
    assert_eq!(p.get_all(102u8).count(), 2);
    assert_eq!(p.get(st0601::Tag::SegmentLocalSet), Some(&p.items[1].value), "get is the first");
    assert_eq!(p.len(), p.items.len());
    assert!(!p.is_empty());
    assert_eq!(p.iter().count(), p.len());
    assert_eq!((&p).into_iter().map(|i| i.tag).collect::<Vec<_>>(), [2, 100, 3, 100, 102, 102, 1]);
    assert!(Packet::new(Standard::St0601).is_empty());
}

// ---------------------------------------------------------------- packet health

#[test]
fn is_ok_semantics() {
    let good = misb::decode(&sample(0)).unwrap();
    assert!(good.is_ok());
    assert_eq!(good.checksum, Checksum::Valid);

    // A missing checksum is a failure for a top-level ST 0601 packet...
    let p = misb::decode(&St0601::new().time(1).no_checksum().build()).unwrap();
    assert_eq!(p.checksum, Checksum::Missing);
    assert_eq!(p.error, None);
    assert!(!p.is_ok());
    // ...whether tag 1 is absent, not last, or the wrong length.
    let not_last = St0601::new().time(1).item(1, &[0, 0]).item(3, b"x").no_checksum().build();
    assert_eq!(misb::decode(&not_last).unwrap().checksum, Checksum::Missing);
    let short = St0601::new().time(1).item(1, &[0]).no_checksum().build();
    assert_eq!(misb::decode(&short).unwrap().checksum, Checksum::Missing);
    // ...but not checked at all with verify_checksum off.
    let mut off = Config::default();
    off.verify_checksum = false;
    let p = misb::decode_with(&St0601::new().time(1).no_checksum().build(), &off).unwrap();
    assert_eq!(p.checksum, Checksum::NotApplicable);
    assert!(p.is_ok());

    // A mismatch.
    let mut bad = sample(0);
    corrupt_checksum(&mut bad);
    let p = misb::decode(&bad).unwrap();
    assert!(matches!(p.checksum, Checksum::Mismatch { .. }));
    assert!(!p.is_ok());

    // A malformed item stops the top level.
    let p = misb::decode(&St0601::new().time(1).raw(&[3, 0x7F, b'x']).build()).unwrap();
    assert!(matches!(p.error, Some(Error::Truncated { .. })));
    assert_eq!(p.items.len(), 1, "items before the problem are kept");
    assert!(!p.is_ok());

    // A nested set that stopped with an error, at any depth.
    let deep = nest(3, &[100], Set::new().raw(&[3, 9, b'x']));
    let p = misb::decode(&St0601::new().time(1).set(101, deep).build()).unwrap();
    assert_eq!(p.error, None);
    assert_eq!(p.checksum, Checksum::Valid);
    assert!(!p.is_ok(), "nested error must make the packet not ok");
    let amend = p.get(st0601::Tag::AmendLocalSet).unwrap();
    assert!(amend.is_valid(), "a set is a valid value even when it stopped early");

    // Invalid, out-of-range and unknown values do not change it.
    let p = misb::decode(&St0601::new().time(1).item(6, &[0x80, 0]).item(5, &[1]).item(13, &[]).build()).unwrap();
    assert_eq!(p.get(6u8), Some(&Value::OutOfRange));
    assert!(!p.get(5u8).unwrap().is_valid());
    assert_eq!(p.get(13u8), Some(&Value::Unknown));
    assert!(p.is_ok());

    // A nested set never carries a checksum, so Missing does not apply.
    let mut nested = Packet::new(Standard::St0102);
    nested.checksum = Checksum::Missing;
    assert!(nested.is_ok());
}

// ---------------------------------------------------------------- config

#[test]
fn config_validate_rules() {
    assert_eq!(Config::default().validate(), Ok(()));
    let rules: [(fn(&mut Config), &str); 6] = [
        (|c| c.max_packet_bytes = 0, "max_packet_bytes"),
        (|c| c.max_buffer_bytes = 0, "max_buffer_bytes"),
        (|c| c.max_skip_bytes = 0, "max_skip_bytes"),
        (|c| c.max_items = 0, "max_items"),
        (|c| c.max_total_items = 0, "max_total_items"),
        (|c| c.max_depth = Config::MAX_DEPTH_LIMIT + 1, "max_depth"),
    ];
    for (break_it, field) in rules {
        let mut c = Config::default();
        break_it(&mut c);
        match c.validate() {
            Err(Error::InvalidConfig(why)) => assert!(why.contains(field), "{why}"),
            other => panic!("{field}: {other:?}"),
        }
        let e = c.validate().unwrap_err();
        assert_eq!(e.kind(), "invalid_config");
        assert!(e.to_string().starts_with("invalid config: "));
        // Every function that takes a config refuses it, before reading.
        assert_eq!(misb::decode_with(&sample(0), &c).err(), Some(e.clone()));
        assert_eq!(misb::decode_with(&[], &c).err(), Some(e.clone()));
        assert_eq!(misb::decode_prefix(&sample(0), &c).err(), Some(e.clone()));
        assert_eq!(misb::decode_all_with(&sample(0), &c).err(), Some(e.clone()));
        assert_eq!(misb::decode_iter_with(&sample(0), &c).err(), Some(e.clone()));
        assert_eq!(Decoder::with_config(c).err(), Some(e));
    }
    // Huge values mean "no limit of their own"; the edges are accepted.
    let mut c = Config::default();
    c.max_packet_bytes = usize::MAX;
    c.max_buffer_bytes = usize::MAX;
    c.max_skip_bytes = usize::MAX;
    c.max_items = usize::MAX;
    c.max_total_items = usize::MAX;
    c.max_depth = Config::MAX_DEPTH_LIMIT;
    assert_eq!(c.validate(), Ok(()));
    // Without the limits a declared length of gigabytes would be waited
    // for, so compare on a stream without one.
    let mut s = rich(0).repeat(3);
    s.extend(other_key(b"x"));
    s.extend(spec_packet_a());
    let all = misb::decode_all_with(&s, &c).unwrap().0;
    assert_eq!(all, misb::decode_all(&s));
    assert_eq!(all.len(), 4);
    c.max_depth = 0;
    c.max_buffer_bytes = 1;
    c.max_items = 1;
    assert_eq!(c.validate(), Ok(()));
    let d = Decoder::with_config(c.clone()).unwrap();
    assert_eq!(d.config(), &c);
    assert_eq!(Decoder::new().config(), &Config::default());
    assert_eq!(Decoder::default().config(), &Config::default());
}

#[test]
fn config_limits_apply() {
    // max_packet_bytes: rejected by decode_with as soon as the length is read.
    let big = St0601::new().time(1).item(3, &[b'x'; 300]).build();
    let mut c = Config::default();
    c.max_packet_bytes = 100;
    match misb::decode_with(&big, &c) {
        Err(Error::TooLarge { size, limit, .. }) => assert_eq!((size, limit), (big.len() - 19, 100)),
        other => panic!("{other:?}"),
    }
    // max_depth: a set one level deeper than the limit is empty with TooDeep.
    c = Config::default();
    c.max_depth = 2;
    let p = misb::decode_with(&St0601::new().set(100, nest(3, &[101], Set::new().item(3, b"in"))).build(), &c).unwrap();
    let mut level = &p;
    let mut depth = 0;
    while let Some(next) = level.items.iter().find_map(|i| i.value.as_set()) {
        level = next;
        depth += 1;
    }
    assert_eq!(depth, 3);
    assert_eq!(level.error, Some(Error::TooDeep));
    assert!(level.items.is_empty());
    assert!(!p.is_ok());
    // max_items per set and max_total_items per packet.
    let mut b = St0601::new();
    for i in 0..50u8 {
        b = b.item(3, &[i]);
    }
    c = Config::default();
    c.max_items = 10;
    let p = misb::decode_with(&b.build(), &c).unwrap();
    assert_eq!(p.items.len(), 10);
    match p.error {
        Some(Error::TooManyItems { count, limit, .. }) => assert_eq!((count, limit), (11, 10)),
        ref other => panic!("{other:?}"),
    }
    let mut b = St0601::new();
    for _ in 0..10 {
        b = b.set(100, Set::new().item(3, b"a").item(3, b"b").item(3, b"c"));
    }
    c = Config::default();
    c.max_total_items = 20;
    let p = misb::decode_with(&b.build(), &c).unwrap();
    check_packet(&p, &c, 1000);
    assert!(!p.is_ok());
    assert!(matches!(p.error, Some(Error::TooManyItems { .. })) || p.items.iter().any(|i| i.value.as_set().is_some_and(|s| s.error.is_some())));
    // keep_raw off: valid values drop their bytes, invalid ones keep them.
    c = Config::default();
    c.keep_raw = false;
    let p = misb::decode_with(&St0601::new().time(1).item(5, &[1]).item(6, &[0x80, 0]).build(), &c).unwrap();
    assert!(p.items[0].raw.is_empty());
    assert_eq!(p.items[1].raw, [1], "invalid value keeps its bytes");
    assert_eq!(p.items[2].raw, [0x80, 0], "out of range value keeps its bytes");
    check_packet(&p, &c, 100);
}

// ---------------------------------------------------------------- entry points

#[test]
fn decode_prefix_and_decode_with() {
    let cfg = Config::default();
    let mut buf = sample(0);
    let len = buf.len();
    buf.extend(sample(1));
    buf.extend([0xEE; 5]);
    let (first, used) = misb::decode_prefix(&buf, &cfg).unwrap();
    assert_eq!(used, len);
    assert_eq!(first, misb::decode(&sample(0)).unwrap());
    let (second, used2) = misb::decode_prefix(&buf[used..], &cfg).unwrap();
    assert_eq!(second, misb::decode(&sample(1)).unwrap());
    assert_eq!(misb::decode_prefix(&buf[used + used2..], &cfg), Err(Error::NotSt0601));
    assert_eq!(misb::decode_with(&buf, &cfg).unwrap(), first);

    // Errors.
    assert!(matches!(misb::decode(&[]), Err(Error::Truncated { .. })));
    assert_eq!(misb::decode(&other_key(b"abc")), Err(Error::NotSt0601));
    assert_eq!(misb::decode(&other_key(b"abc")[..10]), Err(Error::NotSt0601), "key checked before length");
    assert_eq!(misb::decode(&[0x06, 0x0E, 0x2B, 0x35]), Err(Error::NotSt0601));
    let pkt = sample(0);
    for cut in [1, 10, 16, 17, pkt.len() - 1] {
        match misb::decode(&pkt[..cut]) {
            Err(Error::Truncated { needed, available, .. }) => {
                assert_eq!(available, cut);
                assert!(needed > cut && needed <= pkt.len(), "needed {needed} at {cut}");
            }
            other => panic!("cut {cut}: {other:?}"),
        }
    }
    let mut bad_len = KEY.to_vec();
    bad_len.push(0x80);
    assert_eq!(misb::decode(&bad_len), Err(Error::BadLength), "indefinite length");
    bad_len[16] = 0xFF;
    assert_eq!(misb::decode(&bad_len), Err(Error::BadLength), "reserved length");
    // A huge declared length is TooLarge before any value byte is needed.
    let mut huge = KEY.to_vec();
    huge.extend([0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(matches!(misb::decode(&huge), Err(Error::TooLarge { .. })));
    // The version byte is ignored and long-form lengths work.
    let p = misb::decode(&St0601::new().time(1).version_byte(0x0A).long_length(4).build()).unwrap();
    assert!(p.is_ok());
}

#[test]
fn decode_all_iter_and_stats() {
    let s = mixed_stream();
    let cfg = Config::default();
    let (all, stats) = misb::decode_all_with(&s, &cfg).unwrap();
    assert_eq!(all, misb::decode_all(&s));
    let mut it = misb::decode_iter_with(&s, &cfg).unwrap();
    let lazy: Vec<Packet> = it.by_ref().collect();
    assert_eq!(lazy, all);
    assert_eq!(it.next(), None, "fused");
    assert_eq!(it.stats(), &stats);
    assert_eq!(misb::decode_iter(&s).count(), all.len());
    assert_eq!(stats.packets, all.len() as u64);
    assert_eq!(stats.bytes, s.len() as u64);
    assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
    assert_eq!(stats.skipped_keys, 1);
    assert_eq!(stats.checksum_errors, 1);
    // The packet without tag 1, and the one whose damaged item swallowed
    // its checksum item (the bytes still sum correctly, which proves
    // nothing: Missing, not Valid).
    assert_eq!(stats.checksum_missing, 2);
    assert_eq!(stats.truncated_at_finish, 1);
    assert!(stats.bad_lengths >= 1);
    assert_eq!(stats.malformed, all.iter().filter(|p| p.error.is_some()).count() as u64);
    assert!(misb::decode_all(&[]).is_empty());
    // A buffer far larger than the queue loses nothing.
    let many = sample(9).repeat(60_000);
    let mut small = Config::default();
    small.max_buffer_bytes = 4096;
    small.max_packet_bytes = 1024;
    let (all, stats) = misb::decode_all_with(&many, &small).unwrap();
    assert_eq!((all.len(), stats.dropped), (60_000, 0));
}

/// Regression (found by the stream fuzzer): with a queue limit smaller than
/// what one slice can complete, `decode_all_with` and `decode_iter_with`
/// dropped packets, which their documentation rules out whatever
/// `max_buffer_bytes` is. A long-form length that awaits 126 length bytes
/// holds back eight small packets until it proves malformed; then all
/// eight complete in one push.
#[test]
fn whole_buffer_decoding_never_drops_with_a_tiny_queue() {
    let mut s = KEY.to_vec();
    s.push(0xFE);
    let tiny = St0601::new().no_checksum().build();
    assert_eq!(tiny.len(), 17);
    for _ in 0..8 {
        s.extend(&tiny);
    }
    s.extend(sample(1));
    for queue in [1, 17, 87, 200, 1000] {
        let mut cfg = Config::default();
        cfg.max_buffer_bytes = queue;
        cfg.max_packet_bytes = 3739;
        let (all, stats) = misb::decode_all_with(&s, &cfg).unwrap();
        assert_eq!((all.len(), stats.dropped), (9, 0), "queue {queue}");
        assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
        let mut it = misb::decode_iter_with(&s, &cfg).unwrap();
        assert!(it.by_ref().eq(all.iter().cloned()), "queue {queue}");
        assert_eq!(it.stats(), &stats);
    }
}

// ---------------------------------------------------------------- decoder

#[test]
fn push_with_delivers_queued_packets_first() {
    let mut d = Decoder::new();
    d.push(&sample(0));
    d.push(&sample(1)[..10]);
    let mut got = Vec::new();
    let mut rest = sample(1)[10..].to_vec();
    rest.extend(sample(2));
    d.push_with(&rest, |p| got.push(p));
    let want: Vec<Packet> = (0..3).map(|i| misb::decode(&sample(i)).unwrap()).collect();
    assert_eq!(got, want);
    assert_eq!(d.next_packet(), None);
    assert_eq!(d.stats().packets, 3);
    // Big input with a small queue: nothing dropped.
    let mut cfg = Config::default();
    cfg.max_buffer_bytes = 64 * 1024;
    cfg.max_packet_bytes = 1024;
    let mut d = Decoder::with_config(cfg).unwrap();
    let big = rich(0).repeat(5000);
    let mut n = 0;
    d.push_with(&big, |_| n += 1);
    assert_eq!((n, d.stats().dropped), (5000, 0));
}

#[test]
fn next_received_gives_bytes_and_offsets() {
    let mut s = vec![0xAA; 7];
    let a = St0601::new().time(1).version_byte(0x0A).build();
    s.extend(&a);
    s.extend(other_key(b"x"));
    let b = rich(2);
    let b_at = s.len();
    s.extend(&b);
    let mut d = Decoder::new();
    for c in s.chunks(5) {
        d.push(c);
    }
    let r = d.next_received().unwrap();
    assert_eq!((r.offset, &r.bytes), (7, &a));
    assert_eq!(r.key()[7], 0x0A, "the key as received, version byte included");
    assert_eq!(r.packet, misb::decode(&a).unwrap());
    let r = d.next_received().unwrap();
    assert_eq!((r.offset, r.bytes.len()), (b_at as u64, b.len()));
    assert_eq!(r.key(), KEY);
    assert_eq!(&s[b_at..b_at + b.len()], &r.bytes[..]);
    assert!(d.next_received().is_none());
    assert_eq!(d.stats().packets, 2);
    assert_eq!(d.stats().packet_bytes, (a.len() + b.len()) as u64);
}

#[test]
fn reject_bad_checksum_drops_and_counts() {
    let mut cfg = Config::default();
    cfg.reject_bad_checksum = true;
    cfg.verify_checksum = false; // rejecting implies checking
    let mut s = sample(0);
    let mut bad = sample(1);
    corrupt_checksum(&mut bad);
    s.extend(&bad);
    let missing = St0601::new().time(1).no_checksum().build();
    s.extend(&missing);
    s.extend(sample(2));
    let (all, stats) = misb::decode_all_with(&s, &cfg).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|p| p.checksum == Checksum::Valid));
    assert_eq!((stats.checksum_errors, stats.checksum_missing), (1, 1));
    assert_eq!(stats.bytes_skipped, (bad.len() + missing.len()) as u64);
    assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
    // decode_with does not drop: it reports.
    assert!(matches!(misb::decode_with(&bad, &cfg).unwrap().checksum, Checksum::Mismatch { .. }));
}

#[test]
fn stats_count_nested_errors_and_malformed() {
    let mut s = St0601::new().time(1).set(100, Set::new().raw(&[3, 9])).build();
    s.extend(St0601::new().time(2).raw(&[3, 9]).build());
    s.extend(sample(3));
    let (all, stats) = misb::decode_all_with(&s, &Config::default()).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!((stats.nested_errors, stats.malformed), (1, 1));
}

// ---------------------------------------------------------------- AU cells

#[test]
fn au_cells_complete_and_fragmented() {
    let a = sample(0);
    let b = rich(1);
    // One complete access unit of two packets, then one packet in three
    // fragments (first, middle, last).
    let mut pes = au_cell(0, 0, 3, &[a.clone(), b.clone()].concat());
    let third = b.len() / 3;
    pes.extend(au_cell(0, 1, 2, &b[..third]));
    pes.extend(au_cell(0, 2, 0, &b[third..2 * third]));
    pes.extend(au_cell(0, 3, 1, &b[2 * third..]));
    let cells: Vec<misb::AuCell<'_>> = misb::au_cells(&pes).collect::<Result<_, _>>().unwrap();
    assert_eq!(cells.len(), 4);
    assert_eq!(cells.iter().map(|c| c.fragment).collect::<Vec<_>>(), [3, 2, 0, 1]);
    assert_eq!(cells.iter().map(|c| c.sequence_number).collect::<Vec<_>>(), [0, 1, 2, 3]);
    assert!(cells.iter().all(|c| c.random_access && !c.decoder_config && c.service_id == 0));
    // A complete cell holds whole packets.
    assert_eq!(misb::decode_all(cells[0].data).len(), 2);
    // Fragments join when pushed in order into one decoder.
    let mut d = Decoder::new();
    for c in &cells {
        d.push(c.data);
    }
    let got: Vec<Packet> = d.packets().collect();
    let want = [misb::decode(&a).unwrap(), misb::decode(&b).unwrap(), misb::decode(&b).unwrap()];
    assert_eq!(got, want);

    // A cut-short cell yields one error, then nothing.
    let mut cut = au_cell(1, 9, 3, &a);
    cut.truncate(cut.len() - 1);
    let mut it = misb::au_cells(&cut);
    assert!(matches!(it.next(), Some(Err(Error::Truncated { .. }))));
    assert!(it.next().is_none());
    assert!(it.next().is_none());
    assert!(matches!(misb::au_cells(&[0, 1, 2]).next(), Some(Err(Error::Truncated { .. }))));
    assert!(misb::au_cells(&[]).next().is_none());
    // An empty cell is fine.
    let empty = au_cell(5, 6, 3, &[]);
    let c = misb::au_cells(&empty).next().unwrap().unwrap();
    assert_eq!((c.service_id, c.sequence_number, c.data.len()), (5, 6, 0));
    // Flags: decoder_config is bit 5 of the flags byte.
    let flags = [0, 0, 0xE0, 0, 0];
    let c = misb::au_cells(&flags).next().unwrap().unwrap();
    assert!(c.decoder_config && !c.random_access && c.fragment == 3);
}

// ---------------------------------------------------------------- zero-length items

#[test]
fn zero_length_items_st0601() {
    // ST 0601.19 section 6.5: forbidden for the mandatory items (1, 2, 65)
    // and those that may repeat (100, 101, 102, 115).
    let forbidden = [1u64, 2, 65, 100, 101, 102, 115];
    for tag in 1..=143u64 {
        let p = misb::decode(&St0601::new().item(tag, &[]).build()).unwrap();
        let item = p.items.first().unwrap();
        assert_eq!(item.tag, tag);
        assert!(item.raw.is_empty());
        if forbidden.contains(&tag) {
            assert!(matches!(item.value, Value::Invalid(_)), "tag {tag}: {:?}", item.value);
        } else {
            assert_eq!(item.value, Value::Unknown, "tag {tag}");
        }
        assert!(p.is_ok(), "a zero-length item is not a parse error");
    }
    // An undefined tag stays empty bytes.
    let p = misb::decode(&St0601::new().item(200, &[]).build()).unwrap();
    assert_eq!(p.items[0].value, Value::Bytes(vec![]));
    assert_eq!(p.items[0].name, "Unknown");
}

#[test]
fn zero_length_items_nested_standards() {
    let inner = |tag: u64, set: Set| -> Packet {
        let p = misb::decode(&St0601::new().time(1).set(tag, set).build()).unwrap();
        p.get(tag).and_then(Value::as_set).unwrap().clone()
    };
    // ST 0102: the Required items 1, 2, 3, 12, 13 and 22.
    for tag in 1..=24u64 {
        let s = inner(48, Set::new().item(tag, &[]));
        let required = [1, 2, 3, 12, 13, 22].contains(&tag);
        assert_eq!(matches!(s.items[0].value, Value::Invalid(_)), required, "ST 0102 tag {tag}");
        assert_eq!(s.items[0].value == Value::Unknown, !required, "ST 0102 tag {tag}");
    }
    // ST 0806: the CRC and the repeatable subordinate sets 11 to 13.
    for tag in 1..=21u64 {
        let s = inner(73, Set::new().item(tag, &[]));
        let forbidden = [1, 11, 12, 13].contains(&tag);
        assert_eq!(matches!(s.items[0].value, Value::Invalid(_)), forbidden, "ST 0806 tag {tag}");
    }
    // ...and the items each subordinate set must contain.
    let sub = |tag: u64, field: u64| {
        let s = inner(73, Set::new().set(tag, Set::new().item(field, &[])));
        s.items[0].value.as_fields().unwrap()[0].value.clone()
    };
    for f in 1..=10 {
        assert_eq!(matches!(sub(12, f), Value::Invalid(_)), f <= 3, "POI {f}");
        assert_eq!(matches!(sub(13, f), Value::Invalid(_)), f <= 6, "AOI {f}");
    }
    assert!(matches!(sub(11, 1), Value::Invalid(_)));
    assert!(matches!(sub(11, 2), Value::Invalid(_)));
    assert_eq!(sub(12, 4), Value::Unknown);
    // ST 0903: VMTI tags 1 and 4.
    for tag in (1..=13u64).chain(101..=103) {
        let s = inner(74, Set::new().item(tag, &[]));
        let forbidden = [1, 4].contains(&tag);
        assert_eq!(matches!(s.items[0].value, Value::Invalid(_)), forbidden, "VMTI tag {tag}");
        assert_eq!(s.items[0].value == Value::Unknown, !forbidden, "VMTI tag {tag}");
    }
    // VChip tag 1, Algorithm tags 1 to 3, Ontology tags 1, 3 and 4.
    let in_series = |vmti_tag: u64, field: u64| {
        let s = inner(74, Set::new().item(vmti_tag, &series(&[Set::new().item(field, &[]).0])));
        s.items[0].value.as_list().unwrap()[0].as_fields().unwrap()[0].value.clone()
    };
    for f in 1..=5 {
        assert_eq!(matches!(in_series(102, f), Value::Invalid(_)), f <= 3, "Algorithm {f}");
    }
    for f in 1..=6 {
        assert_eq!(matches!(in_series(103, f), Value::Invalid(_)), [1, 3, 4].contains(&f), "Ontology {f}");
    }
    let chip = |field: u64| {
        let target = vtarget(1, Set::new().set(105, Set::new().item(field, &[])));
        let s = inner(74, Set::new().item(101, &series(&[target])));
        let t = &s.items[0].value.as_list().unwrap()[0];
        t.field("VChip").unwrap().as_fields().unwrap()[0].value.clone()
    };
    assert!(matches!(chip(1), Value::Invalid(_)));
    assert_eq!(chip(2), Value::Unknown);
    // Packs: a zero-length country code is unknown.
    let p = misb::decode(&St0601::new().item(122, &hex("010E 00 03 465241")).build()).unwrap();
    assert_eq!(p.get(122u8).and_then(|v| v.field("Overflight Country")), Some(&Value::Unknown));
}

// ---------------------------------------------------------------- errors

#[test]
fn errors() {
    let all = [
        (Error::BadLength, "bad_length"),
        (Error::BadTag, "bad_tag"),
        (Error::NotSt0601, "not_st0601"),
        (Error::TooDeep, "too_deep"),
        (Error::InvalidConfig("x"), "invalid_config"),
    ];
    for (e, kind) in all {
        assert_eq!(e.kind(), kind);
        assert!(!e.to_string().is_empty());
        let _: &dyn std::error::Error = &e;
    }
    assert_eq!(misb::decode(&[]).unwrap_err().kind(), "truncated");
    let mut c = Config::default();
    c.max_packet_bytes = 1;
    assert_eq!(misb::decode_with(&sample(0), &c).unwrap_err().kind(), "too_large");
}

#[cfg(feature = "serde")]
#[test]
fn json_round_trip_of_decoded_packets() {
    for bytes in [spec_packet_a(), rich(0), sample(1)] {
        let p = misb::decode(&bytes).unwrap();
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["standard"], "st0601");
        assert_eq!(json["checksum"]["type"], "valid");
        assert_eq!(json["items"].as_array().unwrap().len(), p.items.len());
        let line = serde_json::to_string(&p).unwrap();
        assert!(!line.contains('\n'));
    }
    let p = misb::decode(&rich(0)).unwrap();
    let json = serde_json::to_value(&p).unwrap();
    let security = json["items"].as_array().unwrap().iter().find(|i| i["tag"] == 48).unwrap();
    assert_eq!(security["value"]["type"], "set");
    assert_eq!(security["value"]["value"]["standard"], "st0102");
    let c: Config = serde_json::from_str(r#"{"max_depth": 3}"#).unwrap();
    assert_eq!(c.max_depth, 3);
}
