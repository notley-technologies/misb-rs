//! MISB ST 0604.6 timestamps carried in compressed video.
//!
//! ST 0604 puts a MISP time (MISB ST 0603, [`MispTime`]) into the frames of
//! H.262/MPEG-2, H.264 and H.265 video, so that frames and ST 0601 packets
//! (tag 2) can be correlated through one clock (R-ST1402TIME-66). The
//! timestamp information is 28 bytes (R-ST1402TIME-68, `st1402-time.md`
//! section 3.8):
//!
//! | bytes | content |
//! |---|---|
//! | 1-16 | identifier: [`MISP_MICROSECTIME`], [`HEVC_MICROSECONDS_UUID`] or [`HEVC_NANOSECONDS_UUID`] |
//! | 17 | Time Status ([`TimeStatus`], ST 0603.5 Table 3) |
//! | 18-28 | modified timestamp: the 8-byte value, most significant byte first, with `FF` after every two bytes |
//!
//! The identifier alone says whether the value counts microseconds (a
//! Precision Time Stamp) or nanoseconds (a Nano Precision Time Stamp, H.265
//! only; R-ST1402TIME-70). In H.264 and H.265 the 28 bytes are a
//! user_data_unregistered SEI message (payloadType 5): uuid_iso_iec_11578
//! is the identifier and user_data_payload_byte the other 12 bytes
//! (R-ST1402TIME-73, -74). In MPEG-2 video they follow a user_data start
//! code `00 00 01 B2` after the picture header (R-ST1402TIME-75). Finding
//! those messages in a bitstream (start codes, emulation prevention bytes,
//! SEI message framing) is the job of a video parser, such as the one in
//! the `mpegts` crate; this module reads and writes the 28 bytes.
//!
//! [`decode`] is in every build. It accepts any of the three identifiers
//! whatever the codec (R-ST1402TIME-88), and reports separator bytes that
//! are not `FF` and a Time Status with unexpected bits as [`Warnings`]
//! rather than errors (DECISIONS D-14). Writing needs the `encode`
//! feature: `Timestamp::to_bytes` gives the 28 bytes and
//! `Timestamp::payload` the 12 bytes of user_data_payload_byte.
//!
//! ```
//! use misb::st0604::{self, Identifier, TimeStatus};
//! use misb::MispTime;
//!
//! // The H.264 message for the Motion Imagery Handbook's reference time
//! // (st1402-time.md section 3.9).
//! let user_data = [
//!     0x4D, 0x49, 0x53, 0x50, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x65, 0x63, 0x74, 0x69, 0x6D, 0x65, // "MISPmicrosectime"
//!     0x9F, // lock unknown
//!     0x00, 0x05, 0xFF, 0xE3, 0x97, 0xFF, 0xF8, 0x7C, 0xFF, 0x11, 0x6A,
//! ];
//! let d = st0604::decode(&user_data).unwrap();
//! assert_eq!(d.timestamp.identifier, Identifier::MispMicrosectime);
//! assert_eq!(d.timestamp.status, TimeStatus::LOCK_UNKNOWN);
//! assert_eq!(d.timestamp.misp_time(), MispTime::from_micros(1_657_616_732_000_618));
//! assert!(d.warnings.is_empty());
//! ```

use crate::MispTime;
use std::fmt;

/// The identifier for H.262/MPEG-2 and H.264: the ASCII string
/// "MISPmicrosectime" (ST 0604.6 Table 1, R-ST1402TIME-69). The value is a
/// Precision Time Stamp in microseconds.
pub const MISP_MICROSECTIME: [u8; 16] = *b"MISPmicrosectime";

/// The H.265 identifier of a Precision Time Stamp in microseconds, the UUID
/// a8687dd4-d759-3758-a5ce-f0338b6545f1 (ST 0604.6 section 7.2,
/// R-ST1402TIME-70).
pub const HEVC_MICROSECONDS_UUID: [u8; 16] =
    [0xA8, 0x68, 0x7D, 0xD4, 0xD7, 0x59, 0x37, 0x58, 0xA5, 0xCE, 0xF0, 0x33, 0x8B, 0x65, 0x45, 0xF1];

/// The H.265 identifier of a Nano Precision Time Stamp in nanoseconds, the
/// UUID cf848278-ee23-306c-9265-e8fef22fb8b8 (ST 0604.6 section 8.1,
/// R-ST1402TIME-70).
pub const HEVC_NANOSECONDS_UUID: [u8; 16] =
    [0xCF, 0x84, 0x82, 0x78, 0xEE, 0x23, 0x30, 0x6C, 0x92, 0x65, 0xE8, 0xFE, 0xF2, 0x2F, 0xB8, 0xB8];

/// Length of the timestamp information: identifier, Time Status and
/// modified timestamp (R-ST1402TIME-68).
pub const TIMESTAMP_LEN: usize = 28;

/// Length of what follows the identifier: the Time Status and the 11-byte
/// modified timestamp (user_data_payload_byte, R-ST1402TIME-73).
pub const PAYLOAD_LEN: usize = 12;

/// Payload bytes (0-based, after the identifier) that ST 0604 fills with
/// `FF` (ST 0604.6 Table 2: bytes 20, 23 and 26 of the 28).
const SEPARATORS: [usize; 3] = [3, 6, 9];

/// Which of the three ST 0604 identifiers a message carries, and so which
/// resolution its value has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Identifier {
    /// [`MISP_MICROSECTIME`]: microseconds; the identifier written in
    /// H.262/MPEG-2 and H.264 (R-ST1402TIME-69).
    MispMicrosectime,
    /// [`HEVC_MICROSECONDS_UUID`]: microseconds; written in H.265 unless
    /// nanoseconds are chosen (DECISIONS D-12).
    HevcMicroseconds,
    /// [`HEVC_NANOSECONDS_UUID`]: nanoseconds; H.265 only.
    HevcNanoseconds,
}

impl Identifier {
    /// The three identifiers.
    pub const ALL: [Identifier; 3] = [Identifier::MispMicrosectime, Identifier::HevcMicroseconds, Identifier::HevcNanoseconds];

    /// The 16 identifier bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        match self {
            Identifier::MispMicrosectime => MISP_MICROSECTIME,
            Identifier::HevcMicroseconds => HEVC_MICROSECONDS_UUID,
            Identifier::HevcNanoseconds => HEVC_NANOSECONDS_UUID,
        }
    }

    /// The identifier these 16 bytes are, if any (a slice of another
    /// length is none).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Identifier> {
        Identifier::ALL.into_iter().find(|id| id.bytes()[..] == *bytes)
    }

    /// Whether the value counts nanoseconds (a Nano Precision Time Stamp)
    /// rather than microseconds.
    #[must_use]
    pub const fn is_nanoseconds(self) -> bool {
        matches!(self, Identifier::HevcNanoseconds)
    }

    /// A short description, e.g. "H.265 nanoseconds UUID".
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Identifier::MispMicrosectime => "MISPmicrosectime",
            Identifier::HevcMicroseconds => "H.265 microseconds UUID",
            Identifier::HevcNanoseconds => "H.265 nanoseconds UUID",
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The direction of a time discontinuity (Time Status bit 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Jump {
    /// Time jumped forward (bit 5 = 0).
    Forward,
    /// Time jumped backward (bit 5 = 1).
    Backward,
}

/// The MISB ST 0603.5 Time Status byte that precedes the timestamp
/// (R-ST1402TIME-57, -71; `st1402-time.md` section 3.7).
///
/// | bit | meaning |
/// |---|---|
/// | 7 | 0 locked to an absolute time reference, 1 lock unknown |
/// | 6 | 0 normal, 1 discontinuity (time did not move forward linearly) |
/// | 5 | with bit 6: 0 jumped forward, 1 jumped backward; 0 without bit 6 |
/// | 4-0 | reserved, `11111` |
///
/// The six values an encoder writes are the associated constants;
/// [`TimeStatus::default`] is [`TimeStatus::LOCK_UNKNOWN`] (`9F`), which an
/// injector that computes times from an anchor writes because it cannot
/// assert lock (DECISIONS D-12). A decoded byte keeps every bit as
/// received, so a status with reserved bits cleared can be inspected;
/// [`TimeStatus::is_valid`] says whether the encoder would write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TimeStatus(u8);

impl TimeStatus {
    /// `1F`: locked, normal.
    pub const LOCKED: TimeStatus = TimeStatus(0x1F);
    /// `9F`: lock unknown, normal (the default).
    pub const LOCK_UNKNOWN: TimeStatus = TimeStatus(0x9F);
    /// `5F`: locked, discontinuity, jumped forward.
    pub const LOCKED_FORWARD_JUMP: TimeStatus = TimeStatus(0x5F);
    /// `7F`: locked, discontinuity, jumped backward.
    pub const LOCKED_BACKWARD_JUMP: TimeStatus = TimeStatus(0x7F);
    /// `DF`: lock unknown, discontinuity, jumped forward.
    pub const LOCK_UNKNOWN_FORWARD_JUMP: TimeStatus = TimeStatus(0xDF);
    /// `FF`: lock unknown, discontinuity, jumped backward.
    pub const LOCK_UNKNOWN_BACKWARD_JUMP: TimeStatus = TimeStatus(0xFF);

    /// Bit 7: set when the clock's lock to an absolute reference is unknown.
    pub const LOCK_UNKNOWN_BIT: u8 = 0x80;
    /// Bit 6: set at a discontinuity.
    pub const DISCONTINUITY_BIT: u8 = 0x40;
    /// Bit 5: with bit 6, set when time jumped backward.
    pub const REVERSE_BIT: u8 = 0x20;
    /// Bits 4 to 0: reserved, written as `11111`.
    pub const RESERVED_BITS: u8 = 0x1F;

    /// A valid status: locked or not, and the discontinuity if any.
    #[must_use]
    pub const fn new(locked: bool, jump: Option<Jump>) -> TimeStatus {
        let lock = if locked { 0 } else { TimeStatus::LOCK_UNKNOWN_BIT };
        let jump = match jump {
            None => 0,
            Some(Jump::Forward) => TimeStatus::DISCONTINUITY_BIT,
            Some(Jump::Backward) => TimeStatus::DISCONTINUITY_BIT | TimeStatus::REVERSE_BIT,
        };
        TimeStatus(lock | jump | TimeStatus::RESERVED_BITS)
    }

    /// A status byte as received, every bit kept.
    #[must_use]
    pub const fn from_byte(byte: u8) -> TimeStatus {
        TimeStatus(byte)
    }

    /// The byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.0
    }

    /// Bit 7 is 0: the clock is locked to an absolute time reference.
    #[must_use]
    pub const fn is_locked(self) -> bool {
        self.0 & TimeStatus::LOCK_UNKNOWN_BIT == 0
    }

    /// Bit 6 is 1: time did not move forward linearly.
    #[must_use]
    pub const fn is_discontinuity(self) -> bool {
        self.0 & TimeStatus::DISCONTINUITY_BIT != 0
    }

    /// The discontinuity and its direction, `None` when bit 6 is 0 (bit 5
    /// means nothing then).
    #[must_use]
    pub const fn jump(self) -> Option<Jump> {
        if !self.is_discontinuity() {
            None
        } else if self.0 & TimeStatus::REVERSE_BIT != 0 {
            Some(Jump::Backward)
        } else {
            Some(Jump::Forward)
        }
    }

    /// Whether the reserved bits 4 to 0 are all 1, as ST 0603.5 Table 3
    /// requires.
    #[must_use]
    pub const fn reserved_bits_set(self) -> bool {
        self.0 & TimeStatus::RESERVED_BITS == TimeStatus::RESERVED_BITS
    }

    /// Whether this is one of the six values an encoder writes: reserved
    /// bits all 1, and bit 5 only with bit 6.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.reserved_bits_set() && (self.is_discontinuity() || self.0 & TimeStatus::REVERSE_BIT == 0)
    }

    /// This status with bit 7 set from `locked`, the other bits unchanged
    /// (DECISIONS D-12 copies bit 7 from the input's messages).
    #[must_use]
    pub const fn with_locked(self, locked: bool) -> TimeStatus {
        let rest = self.0 & !TimeStatus::LOCK_UNKNOWN_BIT;
        TimeStatus(if locked { rest } else { rest | TimeStatus::LOCK_UNKNOWN_BIT })
    }

    /// This status with bits 6 and 5 set from `jump`, the other bits
    /// unchanged (DECISIONS D-12 sets them on the first access unit after a
    /// discontinuity).
    #[must_use]
    pub const fn with_jump(self, jump: Option<Jump>) -> TimeStatus {
        let rest = self.0 & !(TimeStatus::DISCONTINUITY_BIT | TimeStatus::REVERSE_BIT);
        TimeStatus(
            rest | match jump {
                None => 0,
                Some(Jump::Forward) => TimeStatus::DISCONTINUITY_BIT,
                Some(Jump::Backward) => TimeStatus::DISCONTINUITY_BIT | TimeStatus::REVERSE_BIT,
            },
        )
    }
}

impl Default for TimeStatus {
    /// [`TimeStatus::LOCK_UNKNOWN`] (`9F`).
    fn default() -> Self {
        TimeStatus::LOCK_UNKNOWN
    }
}

impl From<u8> for TimeStatus {
    fn from(byte: u8) -> TimeStatus {
        TimeStatus(byte)
    }
}

impl From<TimeStatus> for u8 {
    fn from(s: TimeStatus) -> u8 {
        s.0
    }
}

/// One ST 0604 timestamp: which identifier, the Time Status and the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Timestamp {
    /// The identifier, which fixes the unit of [`value`](Timestamp::value).
    pub identifier: Identifier,
    /// The Time Status byte.
    pub status: TimeStatus,
    /// MISP time in microseconds, or in nanoseconds for
    /// [`Identifier::HevcNanoseconds`].
    pub value: u64,
}

impl Timestamp {
    /// A timestamp from its parts; `value` is in the identifier's unit.
    #[must_use]
    pub const fn new(identifier: Identifier, status: TimeStatus, value: u64) -> Timestamp {
        Timestamp { identifier, status, value }
    }

    /// The timestamp of MISP time `time` under `identifier`: the
    /// microsecond count, or for nanoseconds that count times 1000
    /// (ST 0603.5 section 7.3). `None` only for nanoseconds past
    /// 2554-07-21, which do not fit 64 bits.
    #[must_use]
    pub fn from_misp(identifier: Identifier, status: TimeStatus, time: MispTime) -> Option<Timestamp> {
        let value = if identifier.is_nanoseconds() { time.as_micros().checked_mul(1000)? } else { time.as_micros() };
        Some(Timestamp { identifier, status, value })
    }

    /// The MISP time in microseconds. A nanosecond value is rounded half up
    /// to the microsecond, `(ns + 500) / 1000` (ST 0603.5 section 7.3,
    /// DECISIONS D-11).
    #[must_use]
    pub const fn misp_time(&self) -> MispTime {
        if self.identifier.is_nanoseconds() {
            // (ns + 500) / 1000 without overflowing near u64::MAX.
            let rounded = self.value / 1000 + (self.value % 1000 >= 500) as u64;
            MispTime::from_micros(rounded)
        } else {
            MispTime::from_micros(self.value)
        }
    }

    /// The value in nanoseconds: as carried, or the microsecond count times
    /// 1000; `None` if that does not fit 64 bits.
    #[must_use]
    pub const fn nanos(&self) -> Option<u64> {
        if self.identifier.is_nanoseconds() {
            Some(self.value)
        } else {
            self.value.checked_mul(1000)
        }
    }

    /// The 28 bytes of timestamp information: identifier, Time Status,
    /// modified timestamp (R-ST1402TIME-68, -72). Fails with
    /// [`St0604Error::InvalidStatus`] for a status that is not one of the
    /// six valid values ([`TimeStatus::is_valid`]).
    #[cfg(feature = "encode")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
    pub fn to_bytes(&self) -> Result<[u8; TIMESTAMP_LEN], St0604Error> {
        let payload = self.payload()?;
        let mut out = [0u8; TIMESTAMP_LEN];
        out[..16].copy_from_slice(&self.identifier.bytes());
        out[16..].copy_from_slice(&payload);
        Ok(out)
    }

    /// The 12 bytes that follow the identifier, the user_data_payload_byte
    /// of the SEI message: Time Status, then the 8-byte value most
    /// significant byte first with `FF` after every two bytes
    /// (R-ST1402TIME-71 to -73). Fails like [`Timestamp::to_bytes`].
    ///
    /// The `FF` bytes are MISB's own start code emulation prevention; an
    /// SEI NAL unit still needs H.264/H.265 emulation prevention
    /// (R-ST1402TIME-78, -81).
    #[cfg(feature = "encode")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
    pub fn payload(&self) -> Result<[u8; PAYLOAD_LEN], St0604Error> {
        if !self.status.is_valid() {
            return Err(St0604Error::InvalidStatus(self.status.byte()));
        }
        let v = self.value.to_be_bytes();
        Ok([self.status.byte(), v[0], v[1], 0xFF, v[2], v[3], 0xFF, v[4], v[5], 0xFF, v[6], v[7]])
    }
}

/// Departures from ST 0604 that [`decode`] tolerated (DECISIONS D-14).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Warnings {
    /// How many of the three separator bytes (bytes 20, 23 and 26) are not
    /// `FF`, 0 to 3. Their values are ignored.
    pub bad_separators: u8,
    /// The Time Status reserved bits 4 to 0 are not all 1.
    pub reserved_bits: bool,
    /// The Time Status has bit 5 (backward) set without bit 6
    /// (discontinuity).
    pub reverse_without_discontinuity: bool,
    /// Bytes after the 28 bytes of timestamp information (an SEI payload
    /// longer than ST 0604 defines); they are ignored.
    pub trailing_bytes: usize,
}

impl Warnings {
    /// No warning.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Warnings::default()
    }
}

/// A decoded timestamp and what was tolerated to read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Decoded {
    /// The timestamp, its status byte as received.
    pub timestamp: Timestamp,
    /// What did not follow ST 0604 exactly.
    pub warnings: Warnings,
}

/// Why ST 0604 bytes could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum St0604Error {
    /// Fewer bytes than the timestamp information needs.
    Truncated {
        /// Bytes needed.
        needed: usize,
        /// Bytes given.
        available: usize,
    },
    /// The first 16 bytes are none of the three identifiers: not an ST 0604
    /// message.
    UnknownIdentifier,
    /// A Time Status byte the encoder does not write: reserved bits not all
    /// 1, or bit 5 without bit 6 ([`TimeStatus::is_valid`]).
    InvalidStatus(u8),
}

impl fmt::Display for St0604Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            St0604Error::Truncated { needed, available } => {
                write!(f, "ST 0604 timestamp truncated: needed {needed} bytes, {available} available")
            }
            St0604Error::UnknownIdentifier => f.write_str("not an ST 0604 identifier"),
            St0604Error::InvalidStatus(b) => write!(f, "Time Status {b:02X} is not a valid ST 0603 value"),
        }
    }
}

impl std::error::Error for St0604Error {}

/// Read ST 0604 timestamp information: a 16-byte identifier followed by at
/// least 12 bytes (for H.264 and H.265 the whole user_data_unregistered
/// payload, uuid_iso_iec_11578 included; for MPEG-2 the bytes after the
/// user_data start code).
///
/// Any of the three identifiers is accepted in any codec
/// (R-ST1402TIME-88). Separator bytes that are not `FF`, a Time Status with
/// reserved bits not all 1 or bit 5 without bit 6, and bytes after the 28
/// are reported in [`Decoded::warnings`] (DECISIONS D-14). Fails with
/// [`St0604Error::UnknownIdentifier`] when the first 16 bytes are no
/// identifier, and [`St0604Error::Truncated`] for fewer than 28 bytes.
pub fn decode(user_data: &[u8]) -> Result<Decoded, St0604Error> {
    if user_data.len() >= 16 {
        let identifier = Identifier::from_bytes(&user_data[..16]).ok_or(St0604Error::UnknownIdentifier)?;
        return decode_payload(identifier, &user_data[16..]);
    }
    Err(St0604Error::Truncated { needed: TIMESTAMP_LEN, available: user_data.len() })
}

/// Read the 12 bytes that follow an identifier already recognised (for
/// example by an SEI parser that splits uuid_iso_iec_11578 from the payload
/// bytes), with the tolerance of [`decode`]. Fails with
/// [`St0604Error::Truncated`] for fewer than 12 bytes.
pub fn decode_payload(identifier: Identifier, payload: &[u8]) -> Result<Decoded, St0604Error> {
    if payload.len() < PAYLOAD_LEN {
        return Err(St0604Error::Truncated { needed: TIMESTAMP_LEN, available: payload.len() + 16 });
    }
    let p = &payload[..PAYLOAD_LEN];
    let status = TimeStatus::from_byte(p[0]);
    let v = [p[1], p[2], p[4], p[5], p[7], p[8], p[10], p[11]];
    let warnings = Warnings {
        bad_separators: SEPARATORS.iter().filter(|&&i| p[i] != 0xFF).count() as u8,
        reserved_bits: !status.reserved_bits_set(),
        reverse_without_discontinuity: !status.is_discontinuity() && status.byte() & TimeStatus::REVERSE_BIT != 0,
        trailing_bytes: payload.len() - PAYLOAD_LEN,
    };
    Ok(Decoded { timestamp: Timestamp { identifier, status, value: u64::from_be_bytes(v) }, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert_eq!(&MISP_MICROSECTIME, b"MISPmicrosectime");
        for id in Identifier::ALL {
            assert_eq!(Identifier::from_bytes(&id.bytes()), Some(id));
        }
        assert_eq!(Identifier::from_bytes(&MISP_MICROSECTIME[..15]), None);
        assert_eq!(Identifier::from_bytes(&[0; 16]), None);
        assert!(Identifier::HevcNanoseconds.is_nanoseconds());
        assert!(!Identifier::HevcMicroseconds.is_nanoseconds());
    }

    #[test]
    fn status_bits() {
        let valid = [0x1F, 0x9F, 0x5F, 0x7F, 0xDF, 0xFF];
        for b in 0..=255u8 {
            assert_eq!(TimeStatus::from_byte(b).is_valid(), valid.contains(&b), "{b:02X}");
        }
        assert_eq!(TimeStatus::new(true, None), TimeStatus::LOCKED);
        assert_eq!(TimeStatus::new(false, None), TimeStatus::LOCK_UNKNOWN);
        assert_eq!(TimeStatus::new(true, Some(Jump::Forward)), TimeStatus::LOCKED_FORWARD_JUMP);
        assert_eq!(TimeStatus::new(true, Some(Jump::Backward)), TimeStatus::LOCKED_BACKWARD_JUMP);
        assert_eq!(TimeStatus::new(false, Some(Jump::Forward)), TimeStatus::LOCK_UNKNOWN_FORWARD_JUMP);
        assert_eq!(TimeStatus::new(false, Some(Jump::Backward)), TimeStatus::LOCK_UNKNOWN_BACKWARD_JUMP);
        assert_eq!(TimeStatus::default().byte(), 0x9F);
        let s = TimeStatus::LOCK_UNKNOWN.with_locked(true).with_jump(Some(Jump::Backward));
        assert_eq!(s, TimeStatus::LOCKED_BACKWARD_JUMP);
        assert_eq!(s.with_jump(None).with_locked(false), TimeStatus::LOCK_UNKNOWN);
        assert_eq!(TimeStatus::from_byte(0x20).jump(), None);
        assert!(!TimeStatus::from_byte(0x80).is_locked());
    }

    #[test]
    fn nanoseconds_round_half_up() {
        // ST 0603.5 Table 1 (R-ST1402TIME-56).
        for (ns, us) in [(31_276u64, 31u64), (9_572_831, 9573), (9_572_632, 9573), (499, 0), (500, 1), (u64::MAX, 18_446_744_073_709_552)] {
            let t = Timestamp::new(Identifier::HevcNanoseconds, TimeStatus::LOCKED, ns);
            assert_eq!(t.misp_time().as_micros(), us, "{ns}");
        }
        let t = Timestamp::from_misp(Identifier::HevcNanoseconds, TimeStatus::LOCKED, MispTime::from_micros(9573)).unwrap();
        assert_eq!(t.value, 9_573_000);
        assert!(Timestamp::from_misp(Identifier::HevcNanoseconds, TimeStatus::LOCKED, MispTime::from_micros(u64::MAX)).is_none());
        assert_eq!(Timestamp::new(Identifier::MispMicrosectime, TimeStatus::LOCKED, u64::MAX).nanos(), None);
    }

    #[test]
    fn short_input() {
        assert_eq!(decode(&[]), Err(St0604Error::Truncated { needed: 28, available: 0 }));
        assert_eq!(decode(&MISP_MICROSECTIME[..10]), Err(St0604Error::Truncated { needed: 28, available: 10 }));
        let mut b = MISP_MICROSECTIME.to_vec();
        b.extend([0x9F; 11]);
        assert_eq!(decode(&b), Err(St0604Error::Truncated { needed: 28, available: 27 }));
        let mut other = [0u8; 28];
        other[0] = 1;
        assert_eq!(decode(&other), Err(St0604Error::UnknownIdentifier));
    }
}
