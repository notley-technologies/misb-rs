//! MISB ST 0604.6 timestamps in video: the worked messages of
//! st1402-time.md section 3.9 (the Motion Imagery Handbook's reference time
//! as H.264, H.265 microseconds and H.265 nanoseconds), the ST 0603.5
//! rounding vectors, what the decoder tolerates (DECISIONS D-14) and round
//! trips for every identifier and valid status. ST 0604.6 itself publishes
//! no byte examples.
#![forbid(unsafe_code)]

use misb::st0604::{
    self, Identifier, Jump, St0604Error, TimeStatus, Timestamp, HEVC_MICROSECONDS_UUID, HEVC_NANOSECONDS_UUID,
    MISP_MICROSECTIME, PAYLOAD_LEN, TIMESTAMP_LEN,
};
use misb::MispTime;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

/// 2022-07-12T09:05:32.000618 MISP (R-ST1402TIME-61).
const HANDBOOK_US: u64 = 1_657_616_732_000_618;

/// The SEI payloads of st1402-time.md section 3.9: the NAL units without
/// start code, NAL header, payloadType, payloadSize and trailing bits.
fn h264() -> Vec<u8> {
    hex("4D 49 53 50 6D 69 63 72 6F 73 65 63 74 69 6D 65 9F 00 05 FF E3 97 FF F8 7C FF 11 6A")
}

fn h265_micro() -> Vec<u8> {
    hex("A8 68 7D D4 D7 59 37 58 A5 CE F0 33 8B 65 45 F1 9F 00 05 FF E3 97 FF F8 7C FF 11 6A")
}

fn h265_nano() -> Vec<u8> {
    hex("CF 84 82 78 EE 23 30 6C 92 65 E8 FE F2 2F B8 B8 9F 17 01 FF 09 A2 FF A4 A4 FF 06 10")
}

#[test]
fn identifiers_are_the_published_bytes() {
    // R-ST1402TIME-69, -70.
    assert_eq!(MISP_MICROSECTIME.to_vec(), hex("4D 49 53 50 6D 69 63 72 6F 73 65 63 74 69 6D 65"));
    assert_eq!(HEVC_MICROSECONDS_UUID.to_vec(), hex("A8 68 7D D4 D7 59 37 58 A5 CE F0 33 8B 65 45 F1"));
    assert_eq!(HEVC_NANOSECONDS_UUID.to_vec(), hex("CF 84 82 78 EE 23 30 6C 92 65 E8 FE F2 2F B8 B8"));
    assert_eq!((TIMESTAMP_LEN, PAYLOAD_LEN), (28, 12));
}

#[test]
fn worked_messages_decode() {
    for (bytes, id, value) in [
        (h264(), Identifier::MispMicrosectime, HANDBOOK_US),
        (h265_micro(), Identifier::HevcMicroseconds, HANDBOOK_US),
        (h265_nano(), Identifier::HevcNanoseconds, HANDBOOK_US * 1000),
    ] {
        let d = st0604::decode(&bytes).unwrap();
        assert_eq!(d.timestamp, Timestamp::new(id, TimeStatus::LOCK_UNKNOWN, value));
        assert_eq!(d.timestamp.misp_time(), MispTime::from_micros(HANDBOOK_US));
        assert!(d.warnings.is_empty(), "{id}: {:?}", d.warnings);
        assert!(!d.timestamp.status.is_locked());
        assert_eq!(d.timestamp.status.jump(), None);
        // The payload alone, with the identifier already recognised.
        assert_eq!(st0604::decode_payload(id, &bytes[16..]), Ok(d));
    }
}

#[cfg(feature = "encode")]
#[test]
fn worked_messages_encode_byte_for_byte() {
    let t = MispTime::from_micros(HANDBOOK_US);
    for (bytes, id) in [
        (h264(), Identifier::MispMicrosectime),
        (h265_micro(), Identifier::HevcMicroseconds),
        (h265_nano(), Identifier::HevcNanoseconds),
    ] {
        let ts = Timestamp::from_misp(id, TimeStatus::default(), t).unwrap();
        assert_eq!(ts.to_bytes().unwrap().to_vec(), bytes, "{id}");
        assert_eq!(ts.payload().unwrap().to_vec(), bytes[16..], "{id}");
    }
}

#[test]
fn any_identifier_in_any_codec() {
    // R-ST1402TIME-88: the identifier, not the codec, decides the unit, so
    // an H.265 UUID inside H.264 video (or the ASCII identifier in H.265)
    // reads the same.
    let payload = &h264()[16..];
    for id in Identifier::ALL {
        let mut b = id.bytes().to_vec();
        b.extend_from_slice(payload);
        let d = st0604::decode(&b).unwrap();
        assert_eq!(d.timestamp.identifier, id);
        assert_eq!(d.timestamp.value, HANDBOOK_US);
    }
}

#[test]
fn nano_to_micro_rounds_half_up() {
    // ST 0603.5 Tables 1 and 2 (R-ST1402TIME-56), DECISIONS D-11.
    for (ns, us) in [(31_276u64, 31u64), (9_572_831, 9573), (9_572_632, 9573), (1_499, 1), (1_500, 2)] {
        let t = Timestamp::new(Identifier::HevcNanoseconds, TimeStatus::LOCKED, ns);
        assert_eq!(t.misp_time(), MispTime::from_micros(us), "{ns} ns");
    }
    for (us, ns) in [(31u64, 31_000u64), (9573, 9_573_000)] {
        let t = Timestamp::from_misp(Identifier::HevcNanoseconds, TimeStatus::LOCKED, MispTime::from_micros(us)).unwrap();
        assert_eq!(t.value, ns);
        let micro = Timestamp::from_misp(Identifier::MispMicrosectime, TimeStatus::LOCKED, MispTime::from_micros(us)).unwrap();
        assert_eq!((micro.value, micro.nanos()), (us, Some(ns)));
    }
}

#[test]
fn damage_is_tolerated_with_warnings() {
    // DECISIONS D-14: separators that are not FF, reserved status bits not
    // all 1, bit 5 without bit 6, and a longer payload are read anyway.
    let mut b = h264();
    b[19] = 0x00;
    b[25] = 0x7F;
    b[16] = 0x20; // locked, reverse without discontinuity, reserved bits 0
    b.extend([0xAA, 0xBB]);
    let d = st0604::decode(&b).unwrap();
    assert_eq!(d.timestamp.value, HANDBOOK_US, "separator values are ignored");
    assert_eq!(d.timestamp.status.byte(), 0x20);
    assert!(d.timestamp.status.is_locked());
    assert_eq!(d.warnings.bad_separators, 2);
    assert!(d.warnings.reserved_bits);
    assert!(d.warnings.reverse_without_discontinuity);
    assert_eq!(d.warnings.trailing_bytes, 2);
    assert!(!d.warnings.is_empty());
    // Each warning on its own.
    let mut only_reserved = h264();
    only_reserved[16] = 0x80;
    let w = st0604::decode(&only_reserved).unwrap().warnings;
    assert!(w.reserved_bits && !w.reverse_without_discontinuity && w.bad_separators == 0 && w.trailing_bytes == 0);
}

#[test]
fn errors() {
    let b = h264();
    for n in 0..TIMESTAMP_LEN {
        assert_eq!(st0604::decode(&b[..n]), Err(St0604Error::Truncated { needed: 28, available: n }), "{n} bytes");
    }
    let mut other = b.clone();
    other[0] = b'm';
    assert_eq!(st0604::decode(&other), Err(St0604Error::UnknownIdentifier));
    assert_eq!(st0604::decode_payload(Identifier::HevcNanoseconds, &b[16..27]).unwrap_err().to_string(),
        "ST 0604 timestamp truncated: needed 28 bytes, 27 available");
    assert_eq!(St0604Error::UnknownIdentifier.to_string(), "not an ST 0604 identifier");
}

#[test]
fn status_byte_meanings() {
    // ST 0603.5 Table 3 (R-ST1402TIME-57).
    let cases = [
        (TimeStatus::LOCKED, true, None),
        (TimeStatus::LOCK_UNKNOWN, false, None),
        (TimeStatus::LOCKED_FORWARD_JUMP, true, Some(Jump::Forward)),
        (TimeStatus::LOCKED_BACKWARD_JUMP, true, Some(Jump::Backward)),
        (TimeStatus::LOCK_UNKNOWN_FORWARD_JUMP, false, Some(Jump::Forward)),
        (TimeStatus::LOCK_UNKNOWN_BACKWARD_JUMP, false, Some(Jump::Backward)),
    ];
    for (s, locked, jump) in cases {
        assert!(s.is_valid());
        assert_eq!(s.is_locked(), locked);
        assert_eq!(s.jump(), jump);
        assert_eq!(s.is_discontinuity(), jump.is_some());
        assert_eq!(TimeStatus::new(locked, jump), s);
        assert_eq!(TimeStatus::from(u8::from(s)), s);
    }
    assert_eq!(TimeStatus::default(), TimeStatus::LOCK_UNKNOWN);
}

#[cfg(feature = "encode")]
#[test]
fn round_trips_and_hand_computed_bytes() {
    let statuses = [
        TimeStatus::LOCKED,
        TimeStatus::LOCK_UNKNOWN,
        TimeStatus::LOCKED_FORWARD_JUMP,
        TimeStatus::LOCKED_BACKWARD_JUMP,
        TimeStatus::LOCK_UNKNOWN_FORWARD_JUMP,
        TimeStatus::LOCK_UNKNOWN_BACKWARD_JUMP,
    ];
    let mut x = 0x1234_5678_9ABC_DEF0u64;
    for i in 0..3000u32 {
        // xorshift64: a spread of 64-bit values, including the extremes.
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let value = match i {
            0 => 0,
            1 => u64::MAX,
            _ => x,
        };
        for id in Identifier::ALL {
            let ts = Timestamp::new(id, statuses[i as usize % statuses.len()], value);
            let bytes = ts.to_bytes().unwrap();
            assert_eq!([bytes[19], bytes[22], bytes[25]], [0xFF; 3]);
            let d = st0604::decode(&bytes).unwrap();
            assert_eq!(d.timestamp, ts);
            assert!(d.warnings.is_empty());
        }
    }
    // Hand computed: time 0x0102030405060708, locked.
    let ts = Timestamp::new(Identifier::HevcMicroseconds, TimeStatus::LOCKED, 0x0102_0304_0506_0708);
    assert_eq!(ts.payload().unwrap().to_vec(), hex("1F 01 02 FF 03 04 FF 05 06 FF 07 08"));
    let zero = Timestamp::new(Identifier::MispMicrosectime, TimeStatus::LOCK_UNKNOWN, 0);
    assert_eq!(zero.payload().unwrap().to_vec(), hex("9F 00 00 FF 00 00 FF 00 00 FF 00 00"));
    // Only the six valid status values are written.
    for b in 0..=255u8 {
        let ts = Timestamp::new(Identifier::MispMicrosectime, TimeStatus::from_byte(b), 1);
        assert_eq!(ts.to_bytes().is_ok(), TimeStatus::from_byte(b).is_valid(), "{b:02X}");
        if !TimeStatus::from_byte(b).is_valid() {
            assert_eq!(ts.payload(), Err(St0604Error::InvalidStatus(b)));
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for len in 0..64usize {
        for _ in 0..200 {
            let mut b = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b.push(x as u8);
            }
            // Half the time with a real identifier in front.
            if len >= 16 && x & 1 == 0 {
                b[..16].copy_from_slice(&Identifier::ALL[(x % 3) as usize].bytes());
            }
            match st0604::decode(&b) {
                Ok(d) => assert_eq!(d.warnings.trailing_bytes, len - 28),
                Err(St0604Error::Truncated { available, .. }) => assert_eq!(available, len),
                Err(e) => assert_eq!(e, St0604Error::UnknownIdentifier),
            }
        }
    }
}
