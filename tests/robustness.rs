//! Hostile input: nothing panics, and every decoded packet stays within
//! the `Config` limits. Covers nesting to and beyond the depth limit,
//! declared lengths far beyond the input, item limits, and every tag of
//! every standard with values of every short length.
mod common;

use common::*;
use misb::{Config, Decoder, Error, Packet, Standard, Value};

/// Decode `bytes` (one ST 0601 packet) every way, check the limits, and
/// return the packet.
fn decode_checked(bytes: &[u8], cfg: &Config) -> Packet {
    let (p, used) = misb::decode_prefix(bytes, cfg).expect("outer packet decodes");
    assert_eq!(used, bytes.len());
    check_packet(&p, cfg, bytes.len());
    let mut d = Decoder::with_config(cfg.clone()).unwrap();
    for c in bytes.chunks(37) {
        d.push(c);
    }
    d.finish();
    assert_eq!(d.next_packet().as_ref(), Some(&p), "stream and buffer decode differ");
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_string(&p).unwrap();
        // serde_json refuses to parse more than 128 levels, which the
        // deepest nesting Config allows reaches.
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&json) {
            assert!(e.to_string().contains("recursion limit"), "JSON output does not parse: {e}");
        }
    }
    p
}

/// The deepest chain of nested `Value::Set`s.
fn set_depth(p: &Packet) -> usize {
    p.items.iter().filter_map(|i| i.value.as_set()).map(|s| 1 + set_depth(s)).max().unwrap_or(0)
}

#[test]
fn nesting_to_the_limit_and_beyond() {
    // Segment and Amend sets (tags 100, 101) nest ST 0601 inside ST 0601,
    // the only unbounded recursion the standards allow; the innermost level
    // holds ST 0102, ST 0806 and ST 0903 sets, which nest further.
    let innermost = Set::new().set(48, security_set()).set(73, rvt_set()).set(74, vmti_set());
    for depth_limit in [0, 1, 2, 4, 8, 16, Config::MAX_DEPTH_LIMIT] {
        let mut cfg = Config::default();
        cfg.max_depth = depth_limit;
        for levels in [0, 1, depth_limit.saturating_sub(1), depth_limit, depth_limit + 1, depth_limit + 5, 100] {
            let bytes = St0601::new().time(1).set(100, nest(levels, &[100, 101], innermost.clone())).build();
            let p = decode_checked(&bytes, &cfg);
            // levels + 1 sets of ST 0601, then the innermost level's sets.
            let wanted = levels + 2;
            let depth = set_depth(&p);
            assert!(depth <= depth_limit + 1, "depth {depth} with max_depth {depth_limit}");
            assert_eq!(depth, wanted.min(depth_limit + 1), "levels {levels}, limit {depth_limit}");
            assert_eq!(p.is_ok(), wanted <= depth_limit, "levels {levels}, limit {depth_limit}");
        }
    }
    // A config over the ceiling is refused; one that skipped validation
    // (impossible through the public API) is covered by the unit tests.
    let mut cfg = Config::default();
    cfg.max_depth = usize::MAX;
    assert!(cfg.validate().is_err());
}

#[test]
fn deep_vmti_structures_obey_the_limit() {
    // ST 0601 > ST 0903 > VTarget > VObject > VFeature: four levels below
    // the packet. Every limit below that cuts the structure off.
    let feature = Set::new().item(3, &[2]).item(4, &[0x40, 0]);
    let object = Set::new().item(3, &[1]).item(5, &series(&[feature.0]));
    let target = vtarget(1, Set::new().item(4, &[1]).item(107, &series(&[object.0])));
    let bytes = St0601::new().time(1).set(74, Set::new().item(4, &[6]).item(101, &series(&[target]))).build();
    for limit in 0..=5 {
        let mut cfg = Config::default();
        cfg.max_depth = limit;
        let p = decode_checked(&bytes, &cfg);
        let vmti = p.get(74u8).and_then(Value::as_set).unwrap();
        if limit == 0 {
            assert_eq!(vmti.error, Some(Error::TooDeep));
            continue;
        }
        let series = vmti.get(101u8).unwrap();
        let text = format!("{series:?}");
        let complete = limit >= 4;
        assert_eq!(!text.contains("Invalid"), complete, "limit {limit}: {text}");
    }
}

#[test]
fn huge_declared_lengths() {
    let cfg = Config::default();
    // An item claiming far more than the set holds, in every length form.
    for len in [&[0x84, 0xFF, 0xFF, 0xFF, 0xFF][..], &[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &[0x7F], &[0x82, 0x10, 0x00]] {
        let mut raw = vec![3];
        raw.extend_from_slice(len);
        raw.extend(b"abc");
        let bytes = St0601::new().time(1).raw(&raw).build();
        let p = decode_checked(&bytes, &cfg);
        assert!(matches!(p.error, Some(Error::Truncated { .. }) | Some(Error::BadLength)), "{:?}", p.error);
        assert_eq!(p.items.len(), 1);
        // The same inside nested sets and packs.
        for tag in [48u64, 73, 74, 100, 101, 102, 122, 128, 138, 140, 141] {
            let bytes = St0601::new().time(1).item(tag, &raw).build();
            let p = decode_checked(&bytes, &cfg);
            assert_eq!(p.error, None, "tag {tag}: the outer set is intact");
        }
    }
    // A long-form length with 127 length bytes, and lengths of length 0.
    let mut raw = vec![3, 0xFF];
    raw.extend([0xFF; 126]);
    decode_checked(&St0601::new().time(1).raw(&raw).build(), &cfg);
    decode_checked(&St0601::new().time(1).raw(&[3, 0x80]).build(), &cfg);
    let mut many = vec![3, 0xFE];
    many.extend([0; 126]);
    decode_checked(&St0601::new().time(1).raw(&many).build(), &cfg);

    // Packets declaring gigabytes: never buffered, and the next packet is
    // found.
    for len in [
        &[0x84, 0x7F, 0xFF, 0xFF, 0xFF][..],
        &[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let mut s = KEY.to_vec();
        s.extend_from_slice(len);
        s.extend([0u8; 300]);
        s.extend(sample(1));
        let (all, stats) = misb::decode_all_with(&s, &cfg).unwrap();
        assert_eq!(all, [misb::decode(&sample(1)).unwrap()], "{len:02X?}");
        assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
        assert!(misb::decode(&s).is_err());
    }
}

#[test]
fn item_limits() {
    // 2000 items in one set.
    let mut b = St0601::new();
    for i in 0..2000u32 {
        b = b.item(3, &i.to_be_bytes());
    }
    let bytes = b.build();
    for max_items in [1, 2, 10, 1999, 2000, 2001, usize::MAX] {
        let mut cfg = Config::default();
        cfg.max_items = max_items;
        let p = decode_checked(&bytes, &cfg);
        assert_eq!(p.items.len(), 2001.min(max_items));
        assert_eq!(p.error.is_some(), max_items < 2001);
    }
    // Many nested sets of many items: max_total_items bounds the packet.
    let inner = (0..100u8).fold(Set::new(), |s, i| s.item(3, &[i]));
    let mut b = St0601::new().time(1);
    for _ in 0..50 {
        b = b.set(100, inner.clone()).set(101, nest(3, &[100], inner.clone()));
    }
    let bytes = b.build();
    for total in [1, 10, 100, 1000, 5000, 65_536] {
        let mut cfg = Config::default();
        cfg.max_total_items = total;
        let p = decode_checked(&bytes, &cfg);
        assert_eq!(p.is_ok(), total >= 50 * (100 + 4 * 100 + 6) + 2, "total {total}");
    }
    // Lists inside packs are bounded by max_items too.
    let ids: Vec<u8> = (1..=120).collect();
    let bytes = St0601::new().item(116, &ids).item(121, &[1; 50]).item(139, &[0xFF; 20]).build();
    for max_items in [1, 5, 49, 50, 1000] {
        let mut cfg = Config::default();
        cfg.max_items = max_items;
        decode_checked(&bytes, &cfg);
    }
    // ST 1010 matrices: N far larger than the bytes, or than max_items.
    for pack in [vec![0x84, 0xFF, 0xFF, 0x7F, 0x93, 0x04], vec![0x7F, 0x93, 0x04], vec![0x40, 0x40]] {
        let mut padded = pack.clone();
        padded.extend([0x3F; 64]);
        let mut cfg = Config::default();
        cfg.max_items = 8;
        decode_checked(&St0601::new().item(102, &padded).build(), &cfg);
        assert!(!misb::st1010::decode(&pack).is_valid());
    }
}

/// Every place a tag of each standard can appear, as a function wrapping
/// one item (`tag`, `value`) into an ST 0601 packet.
fn contexts() -> Vec<(&'static str, Vec<u64>, fn(u64, &[u8]) -> Vec<u8>)> {
    fn in_vtarget(set: Set) -> Vec<u8> {
        St0601::new().time(1).set(74, Set::new().item(4, &[6]).item(101, &series(&[vtarget(7, set)]))).build()
    }
    fn in_vmti_series(vmti_tag: u64, set: Set) -> Vec<u8> {
        St0601::new().time(1).set(74, Set::new().item(4, &[6]).item(vmti_tag, &series(&[set.0]))).build()
    }
    let vtarget_tags: Vec<u64> = (1..=23).chain(101..=107).chain([24, 100, 108, 200]).collect();
    vec![
        ("ST 0601", (1..=143).chain([144, 200, 1000, 70_000]).collect(), |t, v| St0601::new().time(1).item(t, v).build()),
        ("ST 0601 Segment", (1..=143).collect(), |t, v| St0601::new().time(1).set(100, Set::new().item(t, v)).build()),
        ("ST 0102", (1..=26).collect(), |t, v| St0601::new().time(1).set(48, Set::new().item(t, v)).build()),
        ("ST 0806", (1..=23).collect(), |t, v| St0601::new().time(1).set(73, Set::new().item(t, v)).build()),
        ("ST 0806 User Defined", (1..=3).collect(), |t, v| {
            St0601::new().time(1).set(73, Set::new().set(11, Set::new().item(1, &[0x85]).item(t, v))).build()
        }),
        ("ST 0806 POI", (1..=11).collect(), |t, v| St0601::new().time(1).set(73, Set::new().set(12, Set::new().item(t, v))).build()),
        ("ST 0806 AOI", (1..=11).collect(), |t, v| St0601::new().time(1).set(73, Set::new().set(13, Set::new().item(t, v))).build()),
        ("ST 0903", (1..=14).chain(100..=104).chain([200]).collect(), |t, v| {
            St0601::new().time(1).set(74, Set::new().item(4, &[6]).item(t, v)).build()
        }),
        ("VTarget", vtarget_tags, |t, v| in_vtarget(Set::new().item(t, v))),
        ("VMask", (1..=3).collect(), |t, v| in_vtarget(Set::new().set(101, Set::new().item(t, v)))),
        ("VObject", (1..=6).collect(), |t, v| in_vtarget(Set::new().set(102, Set::new().item(t, v)))),
        ("VFeature", (1..=5).collect(), |t, v| in_vtarget(Set::new().set(103, Set::new().item(t, v)))),
        ("VTracker", (1..=13).collect(), |t, v| in_vtarget(Set::new().set(104, Set::new().item(t, v)))),
        ("VChip", (1..=4).collect(), |t, v| in_vtarget(Set::new().set(105, Set::new().item(t, v)))),
        ("VChip Series", (1..=4).collect(), |t, v| in_vtarget(Set::new().item(106, &series(&[Set::new().item(t, v).0])))),
        ("VObject Series", (1..=6).collect(), |t, v| in_vtarget(Set::new().item(107, &series(&[Set::new().item(t, v).0])))),
        ("VFeature Series", (1..=5).collect(), |t, v| {
            in_vtarget(Set::new().set(102, Set::new().item(5, &series(&[Set::new().item(t, v).0]))))
        }),
        ("Algorithm", (1..=6).collect(), |t, v| in_vmti_series(102, Set::new().item(t, v))),
        ("Ontology", (1..=7).collect(), |t, v| in_vmti_series(103, Set::new().item(t, v))),
    ]
}

/// Values of every length from 0 to 20: random, all 0x00, all 0xFF, and a
/// few longer ones.
fn values(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for len in 0..=20 {
        out.push(rng.bytes(len));
        out.push(rng.bytes(len));
        out.push(vec![0x00; len]);
        out.push(vec![0xFF; len]);
        out.push(vec![0x80; len]);
    }
    for len in [32, 50, 64, 127, 128, 255, 300] {
        out.push(rng.bytes(len));
        out.push(vec![0xFF; len]);
    }
    out
}

#[test]
fn every_tag_of_every_standard_with_hostile_values() {
    let mut rng = Rng(0x0601_0102_0806_0903);
    let mut tight = Config::default();
    tight.max_items = 3;
    tight.max_depth = 2;
    tight.keep_raw = false;
    let mut decoded = 0;
    for (name, tags, wrap) in contexts() {
        for tag in tags {
            for v in values(&mut rng) {
                let bytes = wrap(tag, &v);
                let p = decode_checked(&bytes, &Config::default());
                // The outer structure is intact whatever the value.
                assert_eq!(p.error, None, "{name} tag {tag} {v:02X?}");
                assert_eq!(p.checksum, misb::Checksum::Valid, "{name} tag {tag}");
                decode_checked(&bytes, &tight);
                decoded += 1;
            }
        }
    }
    assert!(decoded > 30_000, "{decoded}");
}

#[test]
fn top_level_items_keep_their_tag_and_bytes() {
    let mut rng = Rng(42);
    for tag in 1..=143u64 {
        for v in values(&mut rng) {
            let p = decode_checked(&St0601::new().item(tag, &v).build(), &Config::default());
            let item = &p.items[0];
            assert_eq!(item.tag, tag);
            assert_eq!(item.name, misb::st0601::Tag::from_u64(tag).unwrap().name());
            if !matches!(item.value, Value::Unknown) {
                assert_eq!(item.raw, v, "tag {tag}");
            }
            if v.is_empty() {
                assert!(matches!(item.value, Value::Unknown | Value::Invalid(_)), "tag {tag}: {:?}", item.value);
            }
            if let Value::Set(s) = &item.value {
                assert!(matches!(s.standard, Standard::St0102 | Standard::St0806 | Standard::St0903 | Standard::St0601));
            }
        }
    }
}

#[test]
fn random_bytes_and_bit_flips_never_panic() {
    let mut rng = Rng(7);
    let cfgs = {
        let mut tight = Config::default();
        tight.max_packet_bytes = 300;
        tight.max_buffer_bytes = 2048;
        tight.max_skip_bytes = 600;
        tight.max_items = 4;
        tight.max_total_items = 9;
        tight.max_depth = 1;
        tight.reject_bad_checksum = true;
        [Config::default(), tight]
    };
    let base = mixed_stream();
    for round in 0..300 {
        let mut s = base.clone();
        for _ in 0..1 + rng.below(20) {
            let at = rng.below(s.len());
            flip(&mut s, at, rng.next() as u8);
        }
        if round % 3 == 0 {
            let n = rng.below(400);
            s = rng.bytes(n);
        }
        for cfg in &cfgs {
            let (all, stats) = misb::decode_all_with(&s, cfg).unwrap();
            assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
            for p in &all {
                check_packet(p, cfg, s.len());
            }
            let _ = misb::decode_prefix(&s, cfg);
            for at in [0, 1, 16, s.len() / 2] {
                if let Ok((p, used)) = misb::decode_prefix(&s[at.min(s.len())..], cfg) {
                    assert!(used <= s.len());
                    check_packet(&p, cfg, s.len());
                }
            }
            for cell in misb::au_cells(&s).flatten() {
                assert!(cell.data.len() <= s.len());
            }
        }
    }
}

#[test]
fn text_with_control_and_invalid_utf8() {
    let hostile = b"\x1b[31mred\x1b[0m\nnext line\r\x00\xFF\xFE\xC3\x28 \xE2\x80\xAE";
    let bytes = St0601::new().item(3, hostile).set(48, Set::new().item(13, hostile).item(3, hostile)).build();
    let p = decode_checked(&bytes, &Config::default());
    let shown = p.to_string();
    assert!(!shown.contains('\u{1b}'), "escape sequences printed");
    assert!(!shown.contains('\u{202e}'), "bidirectional override printed");
    assert_eq!(shown.lines().count(), p.items.len() + 1, "a value started a new line");
    assert!(p.get(3u8).and_then(Value::as_str).unwrap().contains('\u{FFFD}'));
}
