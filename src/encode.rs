//! Encoding MISB ST 0601 packets (feature `encode`).
//!
//! The encoder is the inverse of the decoder and is driven by the same tag
//! tables, so a mapping can never differ between the two. It follows the
//! phase 0 rules in `docs/standards/` (`st0601-encode.md` for ST 0601,
//! `nested-encode.md` for the nested sets; rule ids such as
//! R-ST0601-ENCODE-33 are cited in the code) and writes only conformant
//! values: an input it cannot write as the standard requires is an error,
//! never silently changed.
//!
//! - [`St0601Builder`] builds one packet from engineering values: tag 2
//!   first, tag 65 (19 unless overridden), tag 1 (the checksum) last, the
//!   other items in ascending tag order by default (D-01), with minimal BER
//!   lengths and tags.
//! - [`encode_packet`] re-encodes a decoded [`Packet`]: items whose value is
//!   unchanged are written from their original bytes ([`crate::Item::raw`]),
//!   so decoding then encoding a valid packet gives back the same bytes.
//! - [`Security`] builds the MISB ST 0102 Security Local Set of tag 48.
//!
//! ```
//! use misb::encode::{Classification, Input, Security, St0601Builder};
//! use misb::{st0601::Tag, MispTime};
//!
//! let security = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
//! let mut b = St0601Builder::new(MispTime::from_micros(1_657_616_732_000_618));
//! b.set(Tag::MissionId, "MISSION01")?
//!     .set(Tag::PlatformHeadingAngle, 159.9744)?
//!     .set(Tag::SensorLatitude, 60.176_822_966_978_335)?
//!     .unknown(Tag::SlantRange)?
//!     .set(Tag::SecurityLocalSet, Input::Set(security.encode()?))?;
//! let bytes = b.finish()?;
//! let packet = misb::decode(&bytes).unwrap();
//! assert!(packet.is_ok());
//! # Ok::<(), misb::encode::EncodeError>(())
//! ```
//!
//! # Values
//!
//! [`Input`] carries a value in engineering units: `f64` for mapped and
//! IMAPB items (degrees, metres, ...), integers, text, [`MispTime`], an
//! enumeration code, the special states some items define
//! ([`Input::OffEarth`], [`Input::OutOfRange`], [`Input::BelowMinimum`],
//! [`Input::AboveMaximum`]), an already encoded nested set, or any decoded
//! [`Value`] (packs and lists use the field names the decoder produces,
//! listed in each [`crate::st0601::Tag`]'s documentation).
//!
//! # Range policy
//!
//! [`EncodeOptions::policy`] says what happens to a value outside its
//! item's range (DECISIONS D-07): [`Policy::Strict`] (the default) rejects
//! it, except where the item defines an "Out of Range" indicator (written,
//! with a warning) or is a full-circle angle (reduced modulo 360);
//! [`Policy::Clamp`] clamps it to the nearest end and records a
//! [`Warning`]. NaN and infinity, invalid enumeration codes and reserved
//! codes are always errors.

use crate::{st0601, Field, MispTime, Packet, Standard, Value};
use smpte_klv::ber::{self, BerForm};
use std::fmt;

pub use crate::st0102::encode::{Classification, Security};
pub use crate::st0903::encode::{
    Algorithm, DetectionStatus, ImageType, Imap, Location, Motion, Ontology, PixelRun, VChip, VFeature, VMask, VObject,
    VTarget, VTracker, Vmti,
};
pub use crate::st1204::encode::{CoreIdentifier, IdType};

/// Default largest packet, key and length included (DECISIONS D-18), so the
/// checksummed range fits the 16-bit length of the reference checksum code
/// some receivers implement literally.
pub const DEFAULT_MAX_PACKET_BYTES: usize = 65_535;
/// Largest value accepted for [`EncodeOptions::max_packet_bytes`] (the
/// decoder's default packet limit).
pub const MAX_PACKET_BYTES_LIMIT: usize = 1 << 20;

/// What to do with a value outside its item's range (DECISIONS D-07).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Policy {
    /// Reject it (default). Items with an "Out of Range" indicator write
    /// the indicator, IMAPB items write the below-minimum or above-maximum
    /// flag, each with a warning.
    #[default]
    Strict,
    /// Clamp it to the nearest end of the range, with a warning. Items with
    /// an "Out of Range" indicator still write the indicator.
    Clamp,
}

/// Order of the items between tag 2 and tag 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ItemOrder {
    /// Ascending tag number, tag 65 in its place (default, DECISIONS D-01;
    /// reproduces the ST 0902.8 Annex C packets byte for byte).
    #[default]
    Ascending,
    /// The order the items were set in. Needed for an SDCC-FLP (tag 102),
    /// which must follow the items it describes (R-ST0601-ENCODE-15).
    Caller,
}

/// Encoder settings. Start from [`EncodeOptions::default`] and change the
/// fields you need.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct EncodeOptions {
    /// Out-of-range handling (default [`Policy::Strict`]).
    pub policy: Policy,
    /// Item order (default [`ItemOrder::Ascending`]).
    pub order: ItemOrder,
    /// Largest packet, key and length included (default
    /// [`DEFAULT_MAX_PACKET_BYTES`], at most [`MAX_PACKET_BYTES_LIMIT`]).
    pub max_packet_bytes: usize,
    /// Allow the replaced items 60 and 61 (DECISIONS D-14; tag 140 replaces
    /// them). Default off.
    pub allow_legacy: bool,
    /// Reject text that is not ASCII (DECISIONS D-10: ST 0902 types some
    /// strings as ISO 646). Default off: text is UTF-8 as ST 0601.19 says.
    pub ascii_only: bool,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        EncodeOptions {
            policy: Policy::Strict,
            order: ItemOrder::Ascending,
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
            allow_legacy: false,
            ascii_only: false,
        }
    }
}

impl EncodeOptions {
    /// Check every field is in range.
    pub fn validate(&self) -> Result<(), EncodeError> {
        // Key, a 1-byte length, tags 2, 65 and 1: the smallest packet.
        if !(34..=MAX_PACKET_BYTES_LIMIT).contains(&self.max_packet_bytes) {
            return Err(EncodeError::new(
                Standard::St0601,
                None,
                ErrorKind::InvalidOptions,
                "max_packet_bytes must be 34 to 1 MiB",
            ));
        }
        Ok(())
    }
}

/// A value to encode, in engineering units.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Input {
    /// A real value: degrees, metres, ... (mapped and IMAPB items).
    Float(f64),
    /// An unsigned integer.
    Uint(u64),
    /// A signed integer.
    Int(i64),
    /// Text. Empty text is written as the single byte `00`
    /// (R-ST0601-ENCODE-44); use the builder's `unknown` for a value that
    /// is not known.
    Text(String),
    /// A MISP time (tags 2, 72, 131 and pack time fields).
    Time(MispTime),
    /// Bytes written as they are (sets kept as bytes, tag 94, raw values).
    Bytes(Vec<u8>),
    /// An enumeration code.
    Code(u64),
    /// "N/A (Off-Earth)" for the latitude and longitude items that define
    /// it (R-ST0601-ENCODE-38).
    OffEarth,
    /// The "Out of Range" indicator of the items that define one
    /// (R-ST0601-ENCODE-37).
    OutOfRange,
    /// ST 1201 IMAP_BELOW_MINIMUM for an IMAPB item (R-ST0601-ENCODE-35).
    BelowMinimum,
    /// ST 1201 IMAP_ABOVE_MAXIMUM for an IMAPB item.
    AboveMaximum,
    /// A decoded value: scalars, packs and lists ([`Value::Struct`],
    /// [`Value::List`] with the decoder's field names) and nested sets
    /// ([`Value::Set`]).
    Value(Value),
    /// The items of an already encoded nested set (for tag 48 the output of
    /// [`Security::encode`]): written as they are.
    Set(Vec<u8>),
}

macro_rules! input_from {
    ($($t:ty => $v:ident as $c:ty),* $(,)?) => {
        $(impl From<$t> for Input {
            fn from(x: $t) -> Input {
                Input::$v(<$c>::from(x))
            }
        })*
    };
}

input_from! {
    f64 => Float as f64, f32 => Float as f64,
    u8 => Uint as u64, u16 => Uint as u64, u32 => Uint as u64, u64 => Uint as u64,
    i8 => Int as i64, i16 => Int as i64, i32 => Int as i64, i64 => Int as i64,
    String => Text as String, MispTime => Time as MispTime, Value => Value as Value,
}

impl From<&str> for Input {
    fn from(s: &str) -> Input {
        Input::Text(s.to_string())
    }
}

impl From<&Value> for Input {
    fn from(v: &Value) -> Input {
        Input::Value(v.clone())
    }
}

impl Input {
    /// The value as a real number when it is a plain number
    /// ([`Input::Float`], [`Input::Uint`], [`Input::Int`], or the same in a
    /// [`Value`]); `None` for text, codes, times, special states and sets.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Input::Float(x) | Input::Value(Value::Float(x)) => Some(*x),
            Input::Uint(x) | Input::Value(Value::Uint(x)) => Some(*x as f64),
            Input::Int(x) | Input::Value(Value::Int(x)) => Some(*x as f64),
            _ => None,
        }
    }

    /// Whether this is `Input::Value(Value::Unknown)`, which writes a
    /// zero-length item (the value is unknown).
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self, Input::Value(Value::Unknown))
    }
}

/// What kind of problem stopped encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The tag is not defined by the standard (use `set_raw` to pass
    /// recorded bytes through).
    UnknownTag,
    /// The item may not be written here (deprecated, root-level 143, a
    /// zero-length item of a mandatory item, legacy items without
    /// [`EncodeOptions::allow_legacy`], ...).
    NotAllowed,
    /// The input's type does not fit the item.
    WrongType,
    /// The value is outside the item's range.
    OutOfRange,
    /// NaN or infinity.
    NotFinite,
    /// An enumeration code the standard does not define, or marks Reserved.
    InvalidCode,
    /// Text or bytes longer than the item allows.
    TooLong,
    /// A single-use item was set twice.
    Duplicate,
    /// A required item or field is missing.
    Missing,
    /// The packet would exceed [`EncodeOptions::max_packet_bytes`].
    TooLarge,
    /// [`EncodeOptions`] out of range.
    InvalidOptions,
    /// Not supported by this encoder yet (write the bytes with `set_raw`).
    Unsupported,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::UnknownTag => "unknown tag",
            ErrorKind::NotAllowed => "not allowed",
            ErrorKind::WrongType => "wrong type",
            ErrorKind::OutOfRange => "out of range",
            ErrorKind::NotFinite => "not finite",
            ErrorKind::InvalidCode => "invalid code",
            ErrorKind::TooLong => "too long",
            ErrorKind::Duplicate => "duplicate",
            ErrorKind::Missing => "missing",
            ErrorKind::TooLarge => "too large",
            ErrorKind::InvalidOptions => "invalid options",
            ErrorKind::Unsupported => "unsupported",
        }
    }
}

/// Why a value or packet could not be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeError {
    /// The standard of the set the item belongs to.
    pub standard: Standard,
    /// The item's tag, when the error concerns one.
    pub tag: Option<u64>,
    /// The kind of problem.
    pub kind: ErrorKind,
    /// What exactly is wrong.
    pub reason: &'static str,
}

impl EncodeError {
    pub(crate) fn new(standard: Standard, tag: Option<u64>, kind: ErrorKind, reason: &'static str) -> Self {
        EncodeError { standard, tag, kind, reason }
    }
}

/// "ST 0601 tag 13 (Sensor Latitude)", or "ST 0601" without a tag.
fn location(f: &mut fmt::Formatter<'_>, standard: Standard, tag: Option<u64>) -> fmt::Result {
    let Some(tag) = tag else { return f.write_str(standard.name()) };
    let name = match standard {
        Standard::St0601 => st0601::Tag::from_u64(tag).map(st0601::Tag::name),
        Standard::St0102 => crate::st0102::Tag::from_u64(tag).map(crate::st0102::Tag::name),
        Standard::St0806 => crate::st0806::Tag::from_u64(tag).map(crate::st0806::Tag::name),
        Standard::St0903 => crate::st0903::Tag::from_u64(tag).map(crate::st0903::Tag::name),
    };
    match name {
        Some(name) => write!(f, "{} tag {tag} ({name})", standard.name()),
        None => write!(f, "{} tag {tag}", standard.name()),
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        location(f, self.standard, self.tag)?;
        write!(f, ": {}: {}", self.kind.as_str(), self.reason)
    }
}

impl std::error::Error for EncodeError {}

/// Something the encoder did that the caller should know about: a value it
/// clamped, the out-of-range indicator it wrote, text it cleaned.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// The standard of the set the item belongs to.
    pub standard: Standard,
    /// The item's tag.
    pub tag: Option<u64>,
    /// What happened.
    pub reason: &'static str,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        location(f, self.standard, self.tag)?;
        write!(f, ": {}", self.reason)
    }
}

// ----------------------------------------------------------------- context

/// Options, warnings and the item being encoded, for error messages.
pub(crate) struct Ctx<'a> {
    pub(crate) opts: &'a EncodeOptions,
    pub(crate) warnings: &'a mut Vec<Warning>,
    pub(crate) standard: Standard,
    pub(crate) tag: Option<u64>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(opts: &'a EncodeOptions, warnings: &'a mut Vec<Warning>, standard: Standard) -> Self {
        Ctx { opts, warnings, standard, tag: None }
    }

    /// Run `f` for item `tag` of `standard`, then restore the context (for
    /// nested sets and packs).
    pub(crate) fn within<R>(&mut self, standard: Standard, tag: u64, f: impl FnOnce(&mut Ctx<'_>) -> R) -> R {
        let saved = (self.standard, self.tag);
        self.standard = standard;
        self.tag = Some(tag);
        let r = f(self);
        (self.standard, self.tag) = saved;
        r
    }

    pub(crate) fn err(&self, kind: ErrorKind, reason: &'static str) -> EncodeError {
        EncodeError::new(self.standard, self.tag, kind, reason)
    }

    pub(crate) fn warn(&mut self, reason: &'static str) {
        self.warnings.push(Warning { standard: self.standard, tag: self.tag, reason });
    }

    pub(crate) fn strict(&self) -> bool {
        self.opts.policy == Policy::Strict
    }

    /// A finite real from a numeric input.
    pub(crate) fn real(&self, v: View<'_>) -> Result<f64, EncodeError> {
        let x = match v {
            View::Float(x) => x,
            View::Uint(x) => x as f64,
            View::Int(x) => x as f64,
            _ => return Err(self.err(ErrorKind::WrongType, "expected a number")),
        };
        if !x.is_finite() {
            return Err(self.err(ErrorKind::NotFinite, "NaN and infinity cannot be encoded here"));
        }
        // R-ST0601-ENCODE-36: negative zero is sent as positive zero.
        Ok(if x == 0.0 { 0.0 } else { x })
    }

    /// `x` checked against `[lo, hi]` under the range policy.
    pub(crate) fn in_range(&mut self, x: f64, lo: f64, hi: f64) -> Result<f64, EncodeError> {
        if (lo..=hi).contains(&x) {
            return Ok(x);
        }
        if self.strict() {
            return Err(self.err(ErrorKind::OutOfRange, "value outside the item's range"));
        }
        self.warn("value clamped to the item's range");
        Ok(x.clamp(lo, hi))
    }

    /// A non-negative integer: integers, codes, times, and integral floats.
    pub(crate) fn integer(&self, v: View<'_>) -> Result<u64, EncodeError> {
        match v {
            View::Uint(x) | View::Code(x) | View::Time(x) => Ok(x),
            View::Int(x) => u64::try_from(x).map_err(|_| self.err(ErrorKind::OutOfRange, "negative value")),
            View::Float(x) if x.is_finite() && x.fract() == 0.0 && (0.0..=u64::MAX as f64).contains(&x) => Ok(x as u64),
            View::Float(x) if !x.is_finite() => Err(self.err(ErrorKind::NotFinite, "NaN and infinity cannot be encoded")),
            _ => Err(self.err(ErrorKind::WrongType, "expected an integer")),
        }
    }

    /// A signed integer: integers and integral floats.
    pub(crate) fn signed_integer(&self, v: View<'_>) -> Result<i64, EncodeError> {
        match v {
            View::Int(x) => Ok(x),
            View::Uint(x) | View::Code(x) => {
                i64::try_from(x).map_err(|_| self.err(ErrorKind::OutOfRange, "value too large"))
            }
            View::Float(x) if x.is_finite() && x.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&x) => {
                Ok(x as i64)
            }
            View::Float(x) if !x.is_finite() => Err(self.err(ErrorKind::NotFinite, "NaN and infinity cannot be encoded")),
            _ => Err(self.err(ErrorKind::WrongType, "expected an integer")),
        }
    }

    /// A rounded integer in `[lo, hi]` from a number (ST 0601 items given
    /// as "uint8 round(x)" and the like), under the range policy.
    pub(crate) fn rounded(&mut self, v: View<'_>, lo: f64, hi: f64) -> Result<i64, EncodeError> {
        let x = self.real(v)?;
        let x = self.in_range(x, lo, hi)?;
        Ok(x.round() as i64)
    }

    /// UTF-8 text per MISB ST 0107.4 section 6.3.3 (R-ST0601-ENCODE-43 to
    /// -46, R-NESTED-ENCODE-019 to -021): control characters removed,
    /// leading and trailing blanks trimmed, `""` written as `00`, at most
    /// `max` bytes.
    pub(crate) fn text(&mut self, v: View<'_>, max: usize, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let View::Text(s) = v else {
            return Err(self.err(ErrorKind::WrongType, "expected text"));
        };
        if s.is_empty() {
            out.push(0);
            return Ok(());
        }
        let removed = |c: char| matches!(c, '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}');
        let trimmed = |c: char| matches!(c, '\u{0}' | '\t' | '\n' | '\r' | ' ');
        let cleaned: String = s.chars().filter(|&c| !removed(c)).collect();
        let cleaned = cleaned.trim_matches(trimmed);
        if cleaned.len() != s.len() {
            self.warn("control characters or surrounding blanks removed from text");
        }
        if self.opts.ascii_only && !cleaned.is_ascii() {
            return Err(self.err(ErrorKind::WrongType, "text is not ASCII and ascii_only is set"));
        }
        if cleaned.is_empty() {
            out.push(0);
            return Ok(());
        }
        let bytes = if cleaned.len() <= max {
            cleaned
        } else if self.strict() {
            return Err(self.err(ErrorKind::TooLong, "text longer than the item allows"));
        } else {
            self.warn("text cut to the item's maximum length");
            let mut end = max;
            while !cleaned.is_char_boundary(end) {
                end -= 1;
            }
            &cleaned[..end]
        };
        out.extend_from_slice(bytes.as_bytes());
        Ok(())
    }

    /// ST 1201 IMAPB(`min`, `max`) in `len` bytes (R-ST0601-ENCODE-34,
    /// -35): truncating forward mapping; below the range the
    /// IMAP_BELOW_MINIMUM flag `E0 00..`, above it IMAP_ABOVE_MAXIMUM `E1
    /// 00..` (with a warning) unless the policy clamps. `wrap` reduces
    /// full-circle angles modulo 360 first (D-07).
    pub(crate) fn imapb(
        &mut self,
        v: View<'_>,
        min: f64,
        max: f64,
        len: usize,
        wrap: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let flag = |out: &mut Vec<u8>, first: u8| {
            out.push(first);
            out.extend(std::iter::repeat(0).take(len - 1));
        };
        match v {
            View::Below => {
                flag(out, 0xE0);
                return Ok(());
            }
            View::Above => {
                flag(out, 0xE1);
                return Ok(());
            }
            _ => {}
        }
        let map = crate::imapb::Imapb::new(min, max, len)
            .ok_or_else(|| self.err(ErrorKind::OutOfRange, "IMAPB length outside the item's limits"))?;
        let mut x = self.real(v)?;
        if wrap {
            x = wrap_angle(x, min, max);
        }
        if x < min || x > max {
            match self.opts.policy {
                Policy::Strict => {
                    self.warn("IMAPB value outside the range written as the below/above flag");
                    flag(out, if x < min { 0xE0 } else { 0xE1 });
                    return Ok(());
                }
                Policy::Clamp => {
                    self.warn("value clamped to the item's range");
                    x = x.clamp(min, max);
                }
            }
        }
        let y = map.real_to_int(x).ok_or_else(|| self.err(ErrorKind::OutOfRange, "IMAPB value cannot be mapped"))?;
        out.extend_from_slice(&y.to_be_bytes()[8 - len..]);
        Ok(())
    }
}

/// A full-circle angle reduced into `[lo, hi]` (a 360-degree span) when
/// outside it; values inside, both ends included, are unchanged (D-07).
pub(crate) fn wrap_angle(x: f64, lo: f64, hi: f64) -> f64 {
    if (lo..=hi).contains(&x) || !x.is_finite() {
        x
    } else {
        lo + (x - lo).rem_euclid(360.0)
    }
}

/// A uniform read-only view of an [`Input`] or a decoded [`Value`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum View<'a> {
    Float(f64),
    Uint(u64),
    Int(i64),
    Text(&'a str),
    Time(u64),
    Bytes(&'a [u8]),
    /// A code (an enumeration value).
    Code(u64),
    OffEarth,
    OutOfRange,
    Below,
    Above,
    /// Encoded nested set items.
    Set(&'a [u8]),
    Packet(&'a Packet),
    Struct(&'a [Field]),
    List(&'a [Value]),
    Unknown,
    Invalid,
}

impl<'a> View<'a> {
    pub(crate) fn of(input: &'a Input) -> View<'a> {
        match input {
            Input::Float(x) => View::Float(*x),
            Input::Uint(x) => View::Uint(*x),
            Input::Int(x) => View::Int(*x),
            Input::Text(s) => View::Text(s),
            Input::Time(t) => View::Time(t.as_micros()),
            Input::Bytes(b) => View::Bytes(b),
            Input::Code(c) => View::Code(*c),
            Input::OffEarth => View::OffEarth,
            Input::OutOfRange => View::OutOfRange,
            Input::BelowMinimum => View::Below,
            Input::AboveMaximum => View::Above,
            Input::Value(v) => View::value(v),
            Input::Set(b) => View::Set(b),
        }
    }

    pub(crate) fn value(v: &'a Value) -> View<'a> {
        match v {
            Value::Float(x) => View::Float(*x),
            Value::Uint(x) => View::Uint(*x),
            Value::Int(x) => View::Int(*x),
            Value::Text(s) => View::Text(s),
            Value::Bytes(b) => View::Bytes(b),
            Value::Time(t) => View::Time(*t),
            Value::Enum { label: Some("N/A (Off-Earth)"), .. } => View::OffEarth,
            Value::Enum { code, .. } => View::Code(*code),
            Value::OutOfRange => View::OutOfRange,
            Value::Unknown => View::Unknown,
            Value::Set(p) => View::Packet(p),
            Value::List(l) => View::List(l),
            Value::Struct(f) => View::Struct(f),
            Value::Invalid(_) => View::Invalid,
        }
    }
}

/// The field `name` of a pack, if present.
pub(crate) fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Value> {
    fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

// ----------------------------------------------------------------- writers

/// Minimal BER-OID (R-ST0601-ENCODE-08, -31).
pub(crate) fn put_oid(out: &mut Vec<u8>, v: u64) {
    // Writing to a Vec cannot fail.
    let _ = ber::encode_oid(v, out);
}

/// Minimal BER length (R-ST0601-ENCODE-06, -07).
pub(crate) fn put_len(out: &mut Vec<u8>, n: usize) {
    let _ = ber::encode_length(n as u64, BerForm::Minimal, out);
}

/// BER length then the bytes.
pub(crate) fn put_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// One local set item: BER-OID tag, BER length, value.
pub(crate) fn put_item(out: &mut Vec<u8>, tag: u64, value: &[u8]) {
    put_oid(out, tag);
    put_prefixed(out, value);
}

/// Encoded size of an item with a `len`-byte value.
pub(crate) fn item_size(tag: u64, len: usize) -> usize {
    ber::oid_size(tag) + ber::length_size(len as u64, BerForm::Minimal).unwrap_or(9) + len
}

/// Fewest big-endian bytes of an unsigned value, at least one
/// (R-ST0601-ENCODE-29: `0` is `00`, never a zero-length item).
pub(crate) fn put_uint_min(out: &mut Vec<u8>, v: u64) {
    let n = (8 - (v.leading_zeros() / 8) as usize).max(1);
    out.extend_from_slice(&v.to_be_bytes()[8 - n..]);
}

/// Fewest two's complement bytes of a signed value (no redundant sign
/// extension, R-ST0601-ENCODE-29).
pub(crate) fn put_int_min(out: &mut Vec<u8>, v: i64) {
    let bytes = v.to_be_bytes();
    let mut i = 0;
    while i < 7 {
        let redundant = (bytes[i] == 0x00 && bytes[i + 1] & 0x80 == 0) || (bytes[i] == 0xFF && bytes[i + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        i += 1;
    }
    out.extend_from_slice(&bytes[i..]);
}

/// `v` as exactly `n` big-endian bytes.
pub(crate) fn put_uint_n(out: &mut Vec<u8>, v: u64, n: usize) {
    out.extend_from_slice(&v.to_be_bytes()[8 - n..]);
}

// ----------------------------------------------------------------- builder

/// One item in the builder: its tag and where its value sits in the arena.
#[derive(Clone, Debug)]
struct Entry {
    tag: u64,
    start: usize,
    end: usize,
}

/// Builds one ST 0601 packet.
///
/// Values are encoded and checked as they are set, so an error points at
/// the item that caused it. [`finish`](St0601Builder::finish) adds the key,
/// the length, tag 65 when not set, and the checksum. After
/// [`clear`](St0601Builder::clear) the builder can be reused for the next
/// packet without allocating once its buffers have grown.
#[derive(Clone, Debug)]
pub struct St0601Builder {
    opts: EncodeOptions,
    time: MispTime,
    version: u8,
    version_set: bool,
    entries: Vec<Entry>,
    arena: Vec<u8>,
    /// Single-use tags 1..=143 already present, one bit each.
    seen: [u64; 3],
    warnings: Vec<Warning>,
    /// Apply the rules between items that a recorded packet may break
    /// (D-31); off when re-encoding with `encode_packet`.
    authoring: bool,
}

impl St0601Builder {
    /// A packet stamped `time` (tag 2), with default options.
    #[must_use]
    pub fn new(time: MispTime) -> Self {
        St0601Builder::with_options(time, EncodeOptions::default())
    }

    /// A packet stamped `time` with these options. Invalid options are
    /// reported by [`finish`](St0601Builder::finish).
    #[must_use]
    pub fn with_options(time: MispTime, opts: EncodeOptions) -> Self {
        St0601Builder {
            opts,
            time,
            version: crate::encode::ST0601_VERSION,
            version_set: false,
            entries: Vec::new(),
            arena: Vec::new(),
            seen: [0; 3],
            warnings: Vec::new(),
            authoring: true,
        }
    }

    /// The options.
    #[must_use]
    pub fn options(&self) -> &EncodeOptions {
        &self.opts
    }

    /// Change tag 2, the time of birth of every item in the packet.
    pub fn time(&mut self, time: MispTime) -> &mut Self {
        self.time = time;
        self
    }

    /// Override tag 65 (DECISIONS D-05: only for re-encoding recorded
    /// packets or reproducing published vectors; the default is 19).
    pub fn version(&mut self, version: u8) -> &mut Self {
        self.version = version;
        self
    }

    /// Warnings collected so far.
    #[must_use]
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Forget every item and warning (keeps the time, version and
    /// options, and the buffers' capacity).
    pub fn clear(&mut self) -> &mut Self {
        self.entries.clear();
        self.arena.clear();
        self.seen = [0; 3];
        self.warnings.clear();
        self.version_set = false;
        self
    }

    fn mark(&mut self, tag: u64) -> Result<(), EncodeError> {
        // R-ST0601-ENCODE-16 / D-12: 100, 101, 102 and 115 may repeat.
        if matches!(tag, 100 | 101 | 102 | 115) || !(1..=143).contains(&tag) {
            return Ok(());
        }
        let (word, bit) = ((tag / 64) as usize, tag % 64);
        if self.seen[word] & (1 << bit) != 0 {
            return Err(EncodeError::new(Standard::St0601, Some(tag), ErrorKind::Duplicate, "item already set"));
        }
        self.seen[word] |= 1 << bit;
        Ok(())
    }

    fn has(&self, tag: u64) -> bool {
        tag < 192 && self.seen[(tag / 64) as usize] & (1 << (tag % 64)) != 0
    }

    /// Checks shared by `set`, `unknown` and `set_raw` for a defined tag.
    /// `raw` (pass-through of recorded bytes) skips the legacy-item check.
    fn admit(&mut self, tag: u64, raw: bool) -> Result<(), EncodeError> {
        let e = |kind, reason| Err(EncodeError::new(Standard::St0601, Some(tag), kind, reason));
        match tag {
            1 => return e(ErrorKind::NotAllowed, "the checksum is computed by finish"),
            2 => return e(ErrorKind::NotAllowed, "set tag 2 with time()"),
            65 => return e(ErrorKind::NotAllowed, "set tag 65 with version()"),
            // R-ST0601-ENCODE-70.
            66 => return e(ErrorKind::NotAllowed, "item 66 is deprecated"),
            // R-ST0601-ENCODE-65.
            143 => return e(ErrorKind::NotAllowed, "item 143 is only allowed inside items 100 and 101"),
            // R-ST0601-ENCODE-71, D-14.
            60 | 61 if !raw && !self.opts.allow_legacy => {
                return e(ErrorKind::NotAllowed, "items 60 and 61 are replaced by 140; set allow_legacy")
            }
            // R-ST0601-ENCODE-83: 75 and 104 are exclusive.
            75 if self.has(104) => return e(ErrorKind::NotAllowed, "items 75 and 104 are exclusive"),
            104 if self.has(75) => return e(ErrorKind::NotAllowed, "items 75 and 104 are exclusive"),
            102 if self.opts.order == ItemOrder::Ascending => {
                return e(ErrorKind::NotAllowed, "an SDCC-FLP must follow its items: use ItemOrder::Caller")
            }
            _ => {}
        }
        self.mark(tag)?;
        // R-ST0601-ENCODE-73: one of 110 and 131, not both (a suggestion).
        if (tag == 110 && self.has(131)) || (tag == 131 && self.has(110)) {
            self.warnings.push(Warning {
                standard: Standard::St0601,
                tag: Some(tag),
                reason: "items 110 and 131 carry the same information; send one",
            });
        }
        Ok(())
    }

    fn push(&mut self, tag: u64, start: usize) {
        let entry = Entry { tag, start, end: self.arena.len() };
        match self.opts.order {
            ItemOrder::Caller => self.entries.push(entry),
            ItemOrder::Ascending => {
                // Stable: after any earlier item with the same tag.
                let at = self.entries.partition_point(|e| e.tag <= tag);
                self.entries.insert(at, entry);
            }
        }
    }

    /// Set an item from an engineering value. Tag 65 sets the version (as
    /// [`version`](St0601Builder::version)); tags 1 and 2 are not set here.
    pub fn set(&mut self, tag: st0601::Tag, value: impl Into<Input>) -> Result<&mut Self, EncodeError> {
        self.set_input(tag, &value.into(), None)
    }

    /// Set an IMAPB item with an explicit length of `len` bytes (1 to the
    /// item's maximum; DECISIONS D-08 lists the defaults).
    pub fn set_imapb(&mut self, tag: st0601::Tag, value: impl Into<Input>, len: usize) -> Result<&mut Self, EncodeError> {
        self.set_input(tag, &value.into(), Some(len))
    }

    /// [`set`](St0601Builder::set) from a borrowed value (live state
    /// snapshots and tracks keep their values).
    pub(crate) fn set_ref(&mut self, tag: st0601::Tag, input: &Input) -> Result<&mut Self, EncodeError> {
        self.set_input(tag, input, None)
    }

    /// Whether the version (tag 65) was set as an item since the last
    /// [`clear`](St0601Builder::clear), and its value.
    pub(crate) fn version_override(&self) -> Option<u8> {
        self.version_set.then_some(self.version)
    }

    fn set_input(&mut self, tag: st0601::Tag, input: &Input, len: Option<usize>) -> Result<&mut Self, EncodeError> {
        let n = u64::from(tag);
        if tag == st0601::Tag::UasDatalinkLsVersionNumber {
            let mut ctx = Ctx::new(&self.opts, &mut self.warnings, Standard::St0601);
            ctx.tag = Some(65);
            let v = ctx.integer(View::of(input))?;
            self.version = u8::try_from(v).map_err(|_| ctx.err(ErrorKind::OutOfRange, "version is 0 to 255"))?;
            if self.version_set {
                return Err(EncodeError::new(Standard::St0601, Some(65), ErrorKind::Duplicate, "item already set"));
            }
            self.version_set = true;
            if self.opts.order == ItemOrder::Caller {
                let start = self.arena.len();
                self.push(65, start);
            }
            return Ok(self);
        }
        if matches!(View::of(input), View::Unknown) {
            return self.unknown(tag);
        }
        self.admit(n, false)?;
        let start = self.arena.len();
        let mut ctx = Ctx::new(&self.opts, &mut self.warnings, Standard::St0601);
        ctx.tag = Some(n);
        if let Err(e) = st0601::encode::encode_value(tag, View::of(input), len, &mut ctx, &mut self.arena) {
            self.arena.truncate(start);
            self.unmark(n);
            return Err(e);
        }
        self.push(n, start);
        Ok(self)
    }

    fn unmark(&mut self, tag: u64) {
        if (1..=143).contains(&tag) && !matches!(tag, 100 | 101 | 102 | 115) {
            self.seen[(tag / 64) as usize] &= !(1 << (tag % 64));
        }
    }

    /// Write a zero-length item: the value is now unknown (ST 0601.19
    /// section 6.5). Not allowed for items 1, 2, 65, 66, 100, 101, 102,
    /// 115, 143 (R-ST0601-ENCODE-48, -49, D-11).
    pub fn unknown(&mut self, tag: st0601::Tag) -> Result<&mut Self, EncodeError> {
        let n = u64::from(tag);
        if matches!(n, 65 | 100 | 101 | 102 | 115) {
            return Err(EncodeError::new(
                Standard::St0601,
                Some(n),
                ErrorKind::NotAllowed,
                "this item may not be a zero-length item",
            ));
        }
        self.admit(n, false)?;
        let start = self.arena.len();
        self.push(n, start);
        Ok(self)
    }

    /// Write a value exactly as given, unchecked: for passing recorded
    /// bytes through, including tags this encoder does not model or that
    /// the standard does not define (R-ST0601-ENCODE-86). Tags 1, 2, 65,
    /// 66 and 143 are not set here; single-use tags still appear only once.
    pub fn set_raw(&mut self, tag: u64, value: &[u8]) -> Result<&mut Self, EncodeError> {
        if tag == 0 {
            return Err(EncodeError::new(Standard::St0601, Some(0), ErrorKind::UnknownTag, "tag 0 is not a tag"));
        }
        if (1..=143).contains(&tag) {
            self.admit(tag, true)?;
        }
        let start = self.arena.len();
        self.arena.extend_from_slice(value);
        self.push(tag, start);
        Ok(self)
    }

    /// R-NESTED-ENCODE-008, DECISIONS D-31: a packet carrying VMTI (tag 74)
    /// carries the frame centre (tags 23 and 24) its offsets refer to:
    /// always under the strict policy (ST 0903.6 Table 6 marks them
    /// Required), and under the clamp policy whenever a VTarget uses an
    /// offset item.
    fn check_vmti_parent(&self) -> Result<(), EncodeError> {
        if !self.authoring || !self.has(74) || (self.has(23) && self.has(24)) {
            return Ok(());
        }
        let needed = self.opts.policy == Policy::Strict
            || self.entries.iter().filter(|e| e.tag == 74).any(|e| vmti_uses_offsets(&self.arena[e.start..e.end]));
        if needed {
            return Err(EncodeError::new(
                Standard::St0601,
                Some(74),
                ErrorKind::Missing,
                "a packet with VMTI needs Frame Center Latitude and Longitude (tags 23 and 24)",
            ));
        }
        Ok(())
    }

    /// The finished packet.
    pub fn finish(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        self.finish_into(&mut out)?;
        Ok(out)
    }

    /// Write the finished packet into `out`, replacing its contents, and
    /// return its length. Reusing `out` avoids allocating per packet.
    pub fn finish_into(&self, out: &mut Vec<u8>) -> Result<usize, EncodeError> {
        self.opts.validate()?;
        self.check_vmti_parent()?;
        // In caller order an explicitly set tag 65 has a marker entry where
        // it was set; otherwise it goes in its numeric place (ascending,
        // D-01) or just before the checksum (caller order).
        let marker = self.opts.order == ItemOrder::Caller && self.version_set;
        // Value: tag 2 (10 bytes), the items, tag 65 (3), tag 1 (4).
        let mut value_len = 10 + 3 + 4;
        for e in self.entries.iter().filter(|e| !(marker && e.tag == 65)) {
            value_len += item_size(e.tag, e.end - e.start);
        }
        let total = 16 + ber::length_size(value_len as u64, BerForm::Minimal).unwrap_or(9) + value_len;
        if total > self.opts.max_packet_bytes {
            return Err(EncodeError::new(
                Standard::St0601,
                None,
                ErrorKind::TooLarge,
                "packet larger than max_packet_bytes (split the content over packets)",
            ));
        }
        out.clear();
        out.reserve(total);
        // R-ST0601-ENCODE-01, -05, -06.
        out.extend_from_slice(&st0601::KEY);
        put_len(out, value_len);
        // R-ST0601-ENCODE-11, -25: tag 2 first.
        out.extend_from_slice(&[0x02, 0x08]);
        out.extend_from_slice(&self.time.as_micros().to_be_bytes());
        // R-ST0601-ENCODE-13, -24: tag 65 in every packet.
        let version = [0x41, 0x01, self.version];
        let mut version_written = false;
        for e in &self.entries {
            if marker && e.tag == 65 {
                out.extend_from_slice(&version);
                version_written = true;
                continue;
            }
            if !version_written && self.opts.order == ItemOrder::Ascending && e.tag > 65 {
                out.extend_from_slice(&version);
                version_written = true;
            }
            put_item(out, e.tag, &self.arena[e.start..e.end]);
        }
        if !version_written {
            out.extend_from_slice(&version);
        }
        // R-ST0601-ENCODE-12, -20 to -22: checksum last, over everything
        // up to and including its own tag and length.
        out.extend_from_slice(&[0x01, 0x02]);
        let sum = crate::checksum::st0601_checksum(out);
        out.extend_from_slice(&sum.to_be_bytes());
        debug_assert_eq!(out.len(), total);
        Ok(out.len())
    }
}

/// Whether encoded VMTI items have a VTarget with an offset item (VTarget
/// tags 10, 11 and 13 to 16, relative to the parent's frame centre).
fn vmti_uses_offsets(items: &[u8]) -> bool {
    const OFFSETS: [&str; 6] = [
        "Target Location Latitude Offset",
        "Target Location Longitude Offset",
        "Bounding Box Top Left Latitude Offset",
        "Bounding Box Top Left Longitude Offset",
        "Bounding Box Bottom Right Latitude Offset",
        "Bounding Box Bottom Right Longitude Offset",
    ];
    let item = crate::registry::decode_item_of(Standard::St0601, 74, items, 0, &crate::Config::default());
    let Value::Set(vmti) = item.value else { return false };
    let Some(Value::List(targets)) = vmti.get(crate::st0903::Tag::VTargetSeries) else { return false };
    targets.iter().any(|t| match t {
        Value::Struct(fields) => fields.iter().any(|f| OFFSETS.contains(&f.name)),
        _ => false,
    })
}

/// UAS Datalink LS version this encoder implements (tag 65,
/// R-ST0601-ENCODE-24).
pub const ST0601_VERSION: u8 = 19;

/// Re-encode a decoded ST 0601 packet.
///
/// Items are written in the packet's order, tag 1 recomputed. An item whose
/// [`crate::Item::raw`] bytes still decode to its value is written from
/// those bytes, so a packet decoded from valid, minimally encoded bytes
/// encodes back to the same bytes, including values the decoded model
/// cannot tell apart, such as IMAPB below-minimum and above-maximum flags
/// (DECISIONS D-23, P-2). Other items are encoded from their value under
/// `opts`. Tag 65 keeps the packet's version (D-05). Rules between items
/// that only an author can satisfy, such as the frame centre a VMTI set
/// needs (D-31), are not checked.
pub fn encode_packet(packet: &Packet, opts: &EncodeOptions) -> Result<Vec<u8>, EncodeError> {
    let err = |tag, kind, reason| EncodeError::new(Standard::St0601, tag, kind, reason);
    if packet.standard != Standard::St0601 {
        return Err(err(None, ErrorKind::WrongType, "not an ST 0601 packet"));
    }
    let time = match packet.get(st0601::Tag::PrecisionTimeStamp) {
        Some(Value::Time(t)) => MispTime::from_micros(*t),
        _ => return Err(err(Some(2), ErrorKind::Missing, "the packet has no valid tag 2")),
    };
    let mut opts = opts.clone();
    opts.order = ItemOrder::Caller;
    let mut b = St0601Builder::with_options(time, opts);
    // Re-encoding reproduces what the decoder accepted, so rules between
    // items (D-31) are the author's, not checked here.
    b.authoring = false;
    let cfg = crate::Config::default();
    let mut version_seen = false;
    for item in &packet.items {
        match item.tag {
            1 | 2 => continue,
            65 if !version_seen => {
                version_seen = true;
                b.set(st0601::Tag::UasDatalinkLsVersionNumber, &item.value)?;
                continue;
            }
            _ => {}
        }
        let raw_still_valid = !item.raw.is_empty()
            && same_value(&crate::registry::decode_item_of(Standard::St0601, item.tag, &item.raw, 0, &cfg).value, &item.value);
        let defined = st0601::Tag::from_u64(item.tag);
        match (defined, raw_still_valid) {
            (_, true) | (None, _) => {
                let bytes = if raw_still_valid { &item.raw[..] } else { value_bytes(&item.value) };
                b.set_raw(item.tag, bytes)?;
            }
            (Some(tag), false) if matches!(item.value, Value::Unknown) => {
                b.unknown(tag)?;
            }
            (Some(tag), false) => {
                b.set(tag, &item.value)?;
            }
        }
    }
    if !version_seen {
        return Err(err(Some(65), ErrorKind::Missing, "the packet has no tag 65"));
    }
    b.finish()
}

/// Whether recorded bytes that decode to `a` still stand for `b`: NaN
/// equals NaN, enumerations compare by code (labels follow from the code,
/// and JSON input may leave them out), invalid matches invalid (the bytes
/// are the only truth there), recursing into packs, lists and nested sets.
pub(crate) fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Value::Enum { code: x, .. }, Value::Enum { code: y, .. }) => x == y,
        (Value::Invalid(_), Value::Invalid(_)) => true,
        (Value::List(x), Value::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same_value(a, b)),
        (Value::Struct(x), Value::Struct(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| a.name == b.name && same_value(&a.value, &b.value))
        }
        (Value::Set(x), Value::Set(y)) => {
            x.standard == y.standard
                && x.items.len() == y.items.len()
                && x.items.iter().zip(&y.items).all(|(a, b)| a.tag == b.tag && same_value(&a.value, &b.value))
        }
        _ => a == b,
    }
}

/// The bytes of a value kept as bytes (unknown tags).
fn value_bytes(v: &Value) -> &[u8] {
    match v {
        Value::Bytes(b) => b,
        _ => &[],
    }
}
