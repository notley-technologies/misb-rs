//! Decoded values, items and packets.

use crate::Error;
use std::fmt;

/// A decoded value.
///
/// Mapped integers are converted to engineering units with the formula the
/// standard gives for the tag, so most numeric items arrive as
/// [`Value::Float`].
///
/// Equality follows IEEE 754 for floats except that every NaN equals every
/// other NaN, so a packet holding an ST 1201 IMAPB "not a number" value
/// still equals a copy of itself (and `0.0 == -0.0`).
///
/// [`Display`](fmt::Display) is for people: text values are printed with
/// control and bidirectional formatting characters escaped, so that hostile
/// metadata cannot forge lines in a log or send escape sequences to a
/// terminal; [`Value::as_str`] gives the text unchanged.
///
/// # JSON
///
/// With the `serde` feature every value serializes as an object with a
/// snake_case `"type"` and, for variants that carry data, a `"value"`:
/// `{"type":"float","value":1.5}`, `{"type":"enum","value":{"code":1,
/// "label":"On"}}`, `{"type":"out_of_range"}`, `{"type":"unknown"}`. A
/// non-finite `Float` is the string `"NaN"`, `"Infinity"` or
/// `"-Infinity"` (JSON has no such numbers), and byte strings
/// ([`Value::Bytes`], [`Item::raw`]) are lowercase hex strings.
/// [`Checksum`] follows the same shape, and [`Error`] serializes as
/// `{"kind": .., "message": ..}` with the message of its
/// [`Display`](fmt::Display).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "value", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Value {
    /// Unsigned integer.
    Uint(u64),
    /// Signed integer.
    Int(i64),
    /// Engineering value after the standard's mapping (degrees, metres, ...).
    Float(#[cfg_attr(feature = "serde", serde(serialize_with = "ser::float"))] f64),
    /// Text: lossy UTF-8 of ISO 646 / UTF-8 strings.
    Text(String),
    /// Opaque bytes.
    Bytes(#[cfg_attr(feature = "serde", serde(serialize_with = "ser::hex"))] Vec<u8>),
    /// Microseconds since the MISP epoch (1970-01-01), on the continuous
    /// time scale defined by ST 0603.5 section 6. Display labels the calendar
    /// reading `MISP`. Converting it to UTC requires the offset for that date.
    Time(u64),
    /// Enumerated code with the standard's label when known.
    Enum {
        /// The code as received.
        code: u64,
        /// The standard's name for the code, if it defines one.
        label: Option<&'static str>,
    },
    /// A standard's reserved "out of range"/error indicator encoding (e.g.
    /// 0x8000 for a mapped int16).
    OutOfRange,
    /// Zero-length item: the value is not known. MISB ST 0601.19 section
    /// 6.5 and MISB ST 0107 let a producer send an item with length 0 to
    /// say that a value it reported before is now unknown. Only items a
    /// standard allows to be unknown decode to this; a zero-length item
    /// the standard forbids (a mandatory item, or one that may repeat) is
    /// [`Value::Invalid`]. Not an error: [`Value::is_valid`] is true, and
    /// the accessors return `None`.
    Unknown,
    /// Nested local set (ST 0102 inside 0601 tag 48, ST 0903 in tag 74, ...),
    /// already decoded.
    Set(Box<Packet>),
    /// Ordered list (series / variable-length lists).
    List(Vec<Value>),
    /// Fixed or defined-length pack with named fields.
    Struct(Vec<Field>),
    /// Value could not be decoded; [`Item::raw`] keeps the bytes. The text
    /// says why.
    Invalid(&'static str),
}

/// Serializers for values JSON cannot carry directly.
#[cfg(feature = "serde")]
pub(crate) mod ser {
    use serde::Serializer;

    /// A finite float as a number; NaN and the infinities as strings.
    pub(crate) fn float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        match *v {
            v if v.is_finite() => s.serialize_f64(v),
            v if v.is_nan() => s.serialize_str("NaN"),
            v if v > 0.0 => s.serialize_str("Infinity"),
            _ => s.serialize_str("-Infinity"),
        }
    }

    /// Bytes as a lowercase hex string.
    pub(crate) fn hex<T: AsRef<[u8]>, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(v.as_ref().len() * 2);
        for &b in v.as_ref() {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
        }
        s.serialize_str(&out)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (Uint(a), Uint(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Float(a), Float(b)) => a == b || (a.is_nan() && b.is_nan()),
            (Text(a), Text(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Time(a), Time(b)) => a == b,
            (Enum { code: a, label: la }, Enum { code: b, label: lb }) => a == b && la == lb,
            (OutOfRange, OutOfRange) | (Unknown, Unknown) => true,
            (Set(a), Set(b)) => a == b,
            (List(a), List(b)) => a == b,
            (Struct(a), Struct(b)) => a == b,
            (Invalid(a), Invalid(b)) => a == b,
            _ => false,
        }
    }
}

/// One named field of a [`Value::Struct`].
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Field {
    /// Field name from the standard.
    pub name: &'static str,
    /// Field value.
    pub value: Value,
}

impl Field {
    /// A field, for building values in tests and tools.
    #[must_use]
    pub fn new(name: &'static str, value: Value) -> Field {
        Field { name, value }
    }
}

impl Value {
    /// Numeric value as `f64`: `Float`, `Uint` or `Int`.
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Float(1.5).as_f64(), Some(1.5));
    /// assert_eq!(Value::Uint(3).as_f64(), Some(3.0));
    /// assert_eq!(Value::Unknown.as_f64(), None);
    /// ```
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            Value::Float(f) => Some(f),
            Value::Uint(u) => Some(u as f64),
            Value::Int(i) => Some(i as f64),
            _ => None,
        }
    }

    /// `Uint`, a non-negative `Int`, or an `Enum` code.
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Enum { code: 2, label: Some("Hostile") }.as_u64(), Some(2));
    /// assert_eq!(Value::Int(-1).as_u64(), None);
    /// ```
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Uint(u) | Value::Enum { code: u, .. } => Some(u),
            Value::Int(i) => u64::try_from(i).ok(),
            _ => None,
        }
    }

    /// `Int`, or a `Uint` that fits `i64`.
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Int(-128).as_i64(), Some(-128));
    /// assert_eq!(Value::Uint(u64::MAX).as_i64(), None);
    /// ```
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Int(i) => Some(i),
            Value::Uint(u) => i64::try_from(u).ok(),
            _ => None,
        }
    }

    /// Text content, unescaped (unlike [`Display`](fmt::Display)).
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Text("MISSION01".into()).as_str(), Some("MISSION01"));
    /// assert_eq!(Value::Unknown.as_str(), None);
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Opaque byte content.
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Bytes(vec![1, 2]).as_bytes(), Some(&[1u8, 2][..]));
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The raw MISP time count: microseconds since 1970-01-01T00:00:00 on a
    /// time scale without leap seconds, so not UTC (see [`Value::Time`]).
    ///
    /// ```
    /// use misb::Value;
    /// assert_eq!(Value::Time(1_224_807_209_913_000).as_time(), Some(1_224_807_209_913_000));
    /// assert_eq!(Value::Uint(1).as_time(), None);
    /// ```
    #[must_use]
    pub fn as_time(&self) -> Option<u64> {
        match *self {
            Value::Time(t) => Some(t),
            _ => None,
        }
    }

    /// Nested set.
    ///
    /// ```
    /// use misb::{Packet, Standard, Value};
    /// let v = Value::Set(Box::new(Packet::new(Standard::St0102)));
    /// assert_eq!(v.as_set().map(|p| p.standard), Some(Standard::St0102));
    /// ```
    #[must_use]
    pub fn as_set(&self) -> Option<&Packet> {
        match self {
            Value::Set(p) => Some(p),
            _ => None,
        }
    }

    /// List elements.
    ///
    /// ```
    /// use misb::Value;
    /// let v = Value::List(vec![Value::Uint(3), Value::Uint(7)]);
    /// assert_eq!(v.as_list().map(|l| l.len()), Some(2));
    /// ```
    #[must_use]
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    /// Struct fields.
    ///
    /// ```
    /// use misb::{Field, Value};
    /// let v = Value::Struct(vec![Field::new("Numerator", Value::Uint(60))]);
    /// assert_eq!(v.as_fields().map(|f| f[0].name), Some("Numerator"));
    /// ```
    #[must_use]
    pub fn as_fields(&self) -> Option<&[Field]> {
        match self {
            Value::Struct(f) => Some(f),
            _ => None,
        }
    }

    /// The first struct field with this name.
    ///
    /// ```
    /// use misb::{Field, Value};
    /// let v = Value::Struct(vec![Field::new("Denominator", Value::Uint(1001))]);
    /// assert_eq!(v.field("Denominator"), Some(&Value::Uint(1001)));
    /// assert_eq!(v.field("Numerator"), None);
    /// ```
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.as_fields()?.iter().find(|f| f.name == name).map(|f| &f.value)
    }

    /// False for [`Value::OutOfRange`] and [`Value::Invalid`]. True for
    /// [`Value::Unknown`]: a zero-length item the standard allows is not an
    /// error, though it carries no value.
    ///
    /// ```
    /// use misb::Value;
    /// assert!(Value::Unknown.is_valid());
    /// assert!(!Value::Invalid("wrong length for this tag").is_valid());
    /// ```
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !matches!(self, Value::OutOfRange | Value::Invalid(_))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Uint(v) => write!(f, "{v}"),
            Value::Int(v) => write!(f, "{v}"),
            Value::Float(v) => write!(f, "{v}"),
            Value::Text(s) => write_escaped(f, s),
            Value::Bytes(b) => {
                for (i, x) in b.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" ")?;
                    }
                    write!(f, "{x:02X}")?;
                }
                Ok(())
            }
            Value::Time(us) => write_time(f, *us),
            Value::Enum { code, label: Some(l) } => write!(f, "{l} ({code})"),
            Value::Enum { code, label: None } => write!(f, "{code}"),
            Value::OutOfRange => f.write_str("out of range"),
            Value::Unknown => f.write_str("unknown"),
            Value::Set(p) => {
                write!(f, "{} {{", p.standard.name())?;
                for (i, item) in p.items.iter().enumerate() {
                    f.write_str(if i > 0 { ", " } else { " " })?;
                    write!(f, "{}: {}", item.name, item.value)?;
                }
                if let Some(e) = &p.error {
                    f.write_str(if p.items.is_empty() { " " } else { ", " })?;
                    write!(f, "error: {e}")?;
                }
                f.write_str(" }")
            }
            Value::List(l) => {
                f.write_str("[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Struct(fields) => {
                f.write_str("{")?;
                for (i, x) in fields.iter().enumerate() {
                    f.write_str(if i > 0 { ", " } else { " " })?;
                    write!(f, "{}: {}", x.name, x.value)?;
                }
                f.write_str(" }")
            }
            Value::Invalid(why) => write!(f, "invalid ({why})"),
        }
    }
}

/// Write text with control characters (Unicode category Cc) and
/// bidirectional formatting characters escaped as Rust escapes (`\n`,
/// `\u{1b}`, `\u{202e}`), so that a value cannot start a new line, move the
/// cursor or reorder the text around it.
fn write_escaped(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    use fmt::Write;
    for c in s.chars() {
        let bidi = matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if c.is_control() || bidi {
            write!(f, "{}", c.escape_default())?;
        } else {
            f.write_char(c)?;
        }
    }
    Ok(())
}

/// Write a raw MISP time count (MISB ST 0603) as
/// `YYYY-MM-DDThh:mm:ss.ffffff MISP`, e.g. `2008-10-24T00:13:29.913000 MISP`, on a
/// calendar of 86,400-second days with no leap-second correction. This
/// equals UTC only for encoders that write POSIX time; for ST
/// 0603-conformant MISP time it is ahead of UTC by (TAI - UTC) - 8.000082
/// s (ST 0601.19 section 6.4). Years after 9999 print with more than four
/// digits, outside RFC 3339.
fn write_time(f: &mut fmt::Formatter<'_>, us: u64) -> fmt::Result {
    const US_PER_DAY: u64 = 86_400_000_000;
    let days = us / US_PER_DAY;
    let rem = us % US_PER_DAY;
    let (y, m, d) = civil_from_days(days);
    let secs = rem / 1_000_000;
    let frac = rem % 1_000_000;
    write!(
        f,
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06} MISP",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's
/// `civil_from_days`, restricted to non-negative days). Works for every day
/// a u64 microsecond count can reach.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of a year.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097; // day of 400-year era, 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // March-based month, 0..=11
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// One decoded item of a local set.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Item {
    /// Local tag number.
    pub tag: u64,
    /// Name from the standard, e.g. "Sensor Latitude"; "Unknown" for
    /// undefined tags.
    pub name: &'static str,
    /// Units string, e.g. "deg", "m", "m/s", "" when none.
    pub units: &'static str,
    /// Decoded value.
    pub value: Value,
    /// The value bytes exactly as received; empty for valid values when
    /// [`Config::keep_raw`](crate::Config::keep_raw) is off, and for a
    /// zero-length item. Left out of the JSON when empty.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser::hex", skip_serializing_if = "Vec::is_empty"))]
    pub raw: Vec<u8>,
}

impl Item {
    /// An item, for building packets in tests and tools.
    #[must_use]
    pub fn new(tag: u64, name: &'static str, units: &'static str, value: Value, raw: Vec<u8>) -> Item {
        Item { tag, name, units, value, raw }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>3} {}: {}", self.tag, self.name, self.value)?;
        let numeric = matches!(self.value, Value::Float(_) | Value::Uint(_) | Value::Int(_));
        if numeric && !self.units.is_empty() {
            write!(f, " {}", self.units)?;
        }
        Ok(())
    }
}

/// The seal on [`TagKey`]: only this crate implements it.
pub(crate) mod sealed {
    /// Implemented by the types [`TagKey`](super::TagKey) is implemented for.
    pub trait Sealed {}
}

/// A tag to look an item up by in [`Packet::get`], [`Packet::item`] and
/// [`Packet::get_all`]: a bare tag number (`u8`, `u16`, `u32`, `u64`), or
/// the `Tag` enum of [`st0601`](crate::st0601),
/// [`st0102`](crate::st0102), [`st0806`](crate::st0806) or
/// [`st0903`](crate::st0903), which also names its standard. Sealed: it
/// cannot be implemented outside this crate.
pub trait TagKey: sealed::Sealed + Copy {
    /// The local tag number.
    fn number(self) -> u64;
    /// The standard the tag belongs to; `None` for a bare number, which is
    /// looked up in the packet's own standard.
    fn standard(self) -> Option<Standard>;
}

macro_rules! number_keys {
    ($($t:ty),*) => {$(
        impl sealed::Sealed for $t {}
        impl TagKey for $t {
            fn number(self) -> u64 {
                u64::from(self)
            }
            fn standard(self) -> Option<Standard> {
                None
            }
        }
    )*};
}
number_keys!(u8, u16, u32, u64);

/// Implement [`TagKey`] for a standards module's `Tag` enum.
macro_rules! tag_key {
    ($tag:ty, $standard:expr) => {
        impl $crate::value::sealed::Sealed for $tag {}
        impl $crate::value::TagKey for $tag {
            fn number(self) -> u64 {
                u64::from(self)
            }
            fn standard(self) -> Option<$crate::Standard> {
                Some($standard)
            }
        }
    };
}
pub(crate) use tag_key;

/// 16 bytes as an RFC 4122 UUID string: lowercase hex digits hyphenated
/// 8-4-4-4-12, e.g. `f81d4fae-7dec-11d0-a765-00a0c91e6bf6`. Used for every
/// UUID this crate decodes to text (ST 0601 tag 143, ST 0903 VTracker
/// Track ID), except the MISB ST 1204 identifiers, which follow that
/// standard's own canonical form (upper case, groups of four).
pub(crate) fn uuid_text(b: &[u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(36);
    for (i, &byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(char::from(DIGITS[usize::from(byte >> 4)]));
        s.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    s
}

/// Which set a (possibly nested) local set follows. Top-level packets are
/// always ST 0601; the others appear nested inside it.
///
/// With the `serde` feature it serializes as a snake_case string, e.g.
/// `"st0601"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Standard {
    /// MISB ST 0601 UAS Datalink Local Set.
    St0601,
    /// MISB ST 0102 Security Metadata Local Set (ST 0601 tag 48).
    St0102,
    /// MISB ST 0806 Remote Video Terminal Local Set (ST 0601 tag 73).
    St0806,
    /// MISB ST 0903 Video Moving Target Indicator Local Set (ST 0601 tag 74).
    St0903,
}

impl Standard {
    /// Document number, e.g. "ST 0601".
    pub fn name(self) -> &'static str {
        match self {
            Standard::St0601 => "ST 0601",
            Standard::St0102 => "ST 0102",
            Standard::St0806 => "ST 0806",
            Standard::St0903 => "ST 0903",
        }
    }

    /// The revision of the document this crate's tables follow, e.g. "ST
    /// 0601.19", for audit records: an encoder's own revision is in its
    /// packets (ST 0601 tag 65), not this.
    #[must_use]
    pub fn revision(self) -> &'static str {
        match self {
            Standard::St0601 => "ST 0601.19",
            Standard::St0102 => "ST 0102.12",
            Standard::St0806 => "ST 0806.4",
            Standard::St0903 => "ST 0903.6",
        }
    }

    /// Document title, e.g. "UAS Datalink Local Set".
    pub fn title(self) -> &'static str {
        match self {
            Standard::St0601 => "UAS Datalink Local Set",
            Standard::St0102 => "Security Metadata Local Set",
            Standard::St0806 => "Remote Video Terminal Local Set",
            Standard::St0903 => "Video Moving Target Indicator Local Set",
        }
    }
}

impl fmt::Display for Standard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Outcome of a packet checksum check.
///
/// With the `serde` feature it serializes like [`Value`]:
/// `{"type":"valid"}`, `{"type":"mismatch","value":{"expected":1,
/// "computed":2}}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "value", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Checksum {
    /// The checksum item matches the computed value.
    Valid,
    /// The checksum item does not match. Also reported when damage moved
    /// the item boundaries so that the checksum item is no longer the last
    /// item, but the packet still ends with `01 02 hi lo` and its bytes do
    /// not sum to `hi lo`.
    Mismatch {
        /// Value carried in the packet.
        expected: u16,
        /// Value computed over the packet bytes.
        computed: u16,
    },
    /// The standard requires a checksum but the packet has none as its last
    /// item (ST 0601.8-11). The packet's integrity cannot be checked, so
    /// [`Packet::is_ok`] is false and
    /// [`Config::reject_bad_checksum`](crate::Config::reject_bad_checksum)
    /// drops it.
    Missing,
    /// No checksum applies: nested sets, standards without one, or checking
    /// turned off in [`Config::verify_checksum`](crate::Config::verify_checksum).
    NotApplicable,
}

/// A decoded ST 0601 packet or a set nested inside one.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Packet {
    /// The standard the set follows: [`Standard::St0601`] for top-level
    /// packets.
    pub standard: Standard,
    /// Items in the order received.
    pub items: Vec<Item>,
    /// Checksum outcome.
    pub checksum: Checksum,
    /// Set when parsing stopped early (malformed item); items decoded so far
    /// are kept.
    pub error: Option<Error>,
}

impl Packet {
    /// An empty packet of this standard, for building packets in tests and
    /// tools.
    #[must_use]
    pub fn new(standard: Standard) -> Packet {
        Packet { standard, items: Vec::new(), checksum: Checksum::NotApplicable, error: None }
    }

    /// Value of the first item with this tag: a standard's `Tag` enum,
    /// such as [`misb::st0601::Tag`](crate::st0601::Tag), or a bare tag
    /// number (`u8`, `u16`, `u32` or `u64`; see [`TagKey`]).
    ///
    /// A `Tag` of another standard than [`Packet::standard`] finds nothing:
    /// ST 0102 tag 1 is not ST 0601 tag 1, so step into tag 48's
    /// [`Value::Set`] first. A bare number is looked up in whatever
    /// standard the packet follows. Some tags may repeat; see
    /// [`Packet::get_all`].
    ///
    /// ```
    /// use misb::{st0102, st0601, Item, Packet, Standard, Value};
    /// let mut packet = Packet::new(Standard::St0601);
    /// packet.items.push(Item::new(13, "Sensor Latitude", "deg", Value::Float(60.18), vec![]));
    /// let lat = packet.get(st0601::Tag::SensorLatitude).and_then(Value::as_f64);
    /// assert_eq!(lat, Some(60.18));
    /// assert_eq!(packet.get(13u8), packet.get(st0601::Tag::SensorLatitude));
    /// // ST 0102 tag 13 belongs to the nested security set, not to ST 0601.
    /// assert_eq!(packet.get(st0102::Tag::ObjectCountryCodes), None);
    /// ```
    ///
    /// Anything else is not a tag:
    ///
    /// ```compile_fail,E0277
    /// let packet = misb::Packet::new(misb::Standard::St0601);
    /// packet.get(true);
    /// ```
    #[must_use]
    pub fn get<K: TagKey>(&self, tag: K) -> Option<&Value> {
        self.item(tag).map(|i| &i.value)
    }

    /// The first item with this tag; see [`Packet::get`].
    #[must_use]
    pub fn item<K: TagKey>(&self, tag: K) -> Option<&Item> {
        self.get_all(tag).next()
    }

    /// Every item with this tag, in order: for tags a standard allows to
    /// repeat, such as ST 0601 tags 100, 101, 102 and 115. Tags match as
    /// in [`Packet::get`].
    pub fn get_all<K: TagKey>(&self, tag: K) -> impl Iterator<Item = &Item> + '_ {
        let n = tag.number();
        let same_standard = tag.standard().map_or(true, |s| s == self.standard);
        self.items.iter().filter(move |i| same_standard && i.tag == n)
    }

    /// Items in order.
    pub fn iter(&self) -> std::slice::Iter<'_, Item> {
        self.items.iter()
    }

    /// Number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the packet has no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// True when this packet and every set nested in it parsed without
    /// error, and the checksum is not a mismatch and, for a top-level ST
    /// 0601 packet, not missing (ST 0601.8-11). With
    /// [`Config::verify_checksum`](crate::Config::verify_checksum) off the
    /// checksum is not checked at all.
    ///
    /// Individual values can still be [`Value::Invalid`] or
    /// [`Value::OutOfRange`]; check [`Value::is_valid`] for the items you
    /// use.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.shallow_ok() && !self.any_nested(|p| !p.shallow_ok())
    }

    /// [`Packet::is_ok`] for this level only.
    fn shallow_ok(&self) -> bool {
        let checksum_ok = match self.checksum {
            Checksum::Valid | Checksum::NotApplicable => true,
            Checksum::Mismatch { .. } => false,
            Checksum::Missing => self.standard != Standard::St0601,
        };
        self.error.is_none() && checksum_ok
    }

    /// True when a set nested at any depth stopped with an error.
    pub(crate) fn has_nested_error(&self) -> bool {
        self.any_nested(|p| p.error.is_some())
    }

    /// True when `f` holds for any packet nested in this one, at any depth.
    /// Iterative, so a deep tree cannot exhaust the stack.
    fn any_nested(&self, f: impl Fn(&Packet) -> bool) -> bool {
        fn container(v: &&Value) -> bool {
            matches!(v, Value::Set(_) | Value::List(_) | Value::Struct(_))
        }
        // Only containers are stacked, so a flat packet allocates nothing.
        let mut stack: Vec<&Value> = Vec::new();
        stack.extend(self.items.iter().map(|i| &i.value).filter(container));
        while let Some(v) = stack.pop() {
            match v {
                Value::Set(p) => {
                    if f(p) {
                        return true;
                    }
                    stack.extend(p.items.iter().map(|i| &i.value).filter(container));
                }
                Value::List(l) => stack.extend(l.iter().filter(container)),
                Value::Struct(fields) => stack.extend(fields.iter().map(|x| &x.value).filter(container)),
                _ => {}
            }
        }
        false
    }
}

impl<'a> IntoIterator for &'a Packet {
    type Item = &'a Item;
    type IntoIter = std::slice::Iter<'a, Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.standard.name(), self.standard.title())?;
        match self.checksum {
            Checksum::Valid => f.write_str(" checksum ok")?,
            Checksum::Mismatch { expected, computed } => {
                write!(f, " checksum MISMATCH (carried {expected:04X}, computed {computed:04X})")?
            }
            Checksum::Missing => f.write_str(" checksum missing")?,
            Checksum::NotApplicable => {}
        }
        for item in &self.items {
            write!(f, "\n  {item}")?;
        }
        if let Some(e) = &self.error {
            write!(f, "\n  error: {e}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(us: u64) -> String {
        Value::Time(us).to_string()
    }

    #[test]
    fn time_display() {
        assert_eq!(time(0), "1970-01-01T00:00:00.000000 MISP");
        // MISB ST 0601 section 8 example: tag 2 = 0x0004_59F4_A6AA_4AA8.
        assert_eq!(time(0x0004_59F4_A6AA_4AA8), "2008-10-24T00:13:29.913000 MISP");
        // Leap day and end of a century leap year.
        assert_eq!(time(951_782_400_000_000), "2000-02-29T00:00:00.000000 MISP");
        assert_eq!(time(978_307_199_999_999), "2000-12-31T23:59:59.999999 MISP");
        // 1900 was not a leap year; 2100 will not be.
        assert_eq!(time(4_107_456_000_000_000), "2100-02-28T00:00:00.000000 MISP");
        assert_eq!(time(4_107_542_400_000_000), "2100-03-01T00:00:00.000000 MISP");
        // Largest representable instant does not panic.
        assert_eq!(time(u64::MAX), "586524-01-19T08:01:49.551615 MISP");
    }

    #[test]
    fn civil_matches_day_by_day_walk() {
        // Walk 1970..2401 one day at a time and compare.
        let mut y = 1970u64;
        let mut m = 1u64;
        let mut d = 1u64;
        let leap = |y: u64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        for days in 0..157_000u64 {
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
            let mdays = match m {
                2 if leap(y) => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > mdays {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    #[test]
    fn accessors() {
        assert_eq!(Value::Float(1.5).as_f64(), Some(1.5));
        assert_eq!(Value::Uint(3).as_f64(), Some(3.0));
        assert_eq!(Value::Int(-3).as_f64(), Some(-3.0));
        assert_eq!(Value::Text("x".into()).as_f64(), None);
        assert_eq!(Value::Uint(3).as_u64(), Some(3));
        assert_eq!(Value::Int(-1).as_u64(), None);
        assert_eq!(Value::Int(4).as_u64(), Some(4));
        assert_eq!(Value::Enum { code: 7, label: None }.as_u64(), Some(7));
        assert_eq!(Value::Uint(u64::MAX).as_i64(), None);
        assert_eq!(Value::Uint(5).as_i64(), Some(5));
        assert_eq!(Value::Int(-5).as_i64(), Some(-5));
        assert_eq!(Value::Text("abc".into()).as_str(), Some("abc"));
        assert_eq!(Value::Bytes(vec![1]).as_bytes(), Some(&[1u8][..]));
        assert_eq!(Value::Time(9).as_time(), Some(9));
        assert_eq!(Value::Uint(9).as_time(), None);
        let set = Value::Set(Box::new(Packet::new(Standard::St0102)));
        assert_eq!(set.as_set().unwrap().standard, Standard::St0102);
        let list = Value::List(vec![Value::Uint(1)]);
        assert_eq!(list.as_list().unwrap().len(), 1);
        let st = Value::Struct(vec![Field { name: "a", value: Value::Uint(1) }]);
        assert_eq!(st.field("a"), Some(&Value::Uint(1)));
        assert_eq!(st.field("b"), None);
        assert!(Value::Uint(0).is_valid());
        assert!(!Value::OutOfRange.is_valid());
        assert!(!Value::Invalid("x").is_valid());
        assert!(Value::Unknown.is_valid());
        for v in [Value::Unknown] {
            assert_eq!(
                (v.as_f64(), v.as_u64(), v.as_i64(), v.as_str(), v.as_bytes(), v.as_time()),
                (None, None, None, None, None, None)
            );
            assert!(v.as_set().is_none() && v.as_list().is_none() && v.as_fields().is_none());
        }
    }

    #[test]
    fn display() {
        assert_eq!(Value::Uint(3).to_string(), "3");
        assert_eq!(Value::Int(-3).to_string(), "-3");
        assert_eq!(Value::Float(2.5).to_string(), "2.5");
        assert_eq!(Value::Bytes(vec![0x0A, 0xFF]).to_string(), "0A FF");
        assert_eq!(Value::Enum { code: 1, label: Some("On") }.to_string(), "On (1)");
        assert_eq!(Value::Enum { code: 1, label: None }.to_string(), "1");
        assert_eq!(Value::OutOfRange.to_string(), "out of range");
        assert_eq!(Value::Unknown.to_string(), "unknown");
        assert_eq!(Value::Unknown, Value::Unknown);
        assert_ne!(Value::Unknown, Value::Bytes(Vec::new()));
        assert_eq!(Value::Invalid("bad length").to_string(), "invalid (bad length)");
        assert_eq!(Value::List(vec![Value::Uint(1), Value::Uint(2)]).to_string(), "[1, 2]");
        let st = Value::Struct(vec![
            Field { name: "a", value: Value::Uint(1) },
            Field { name: "b", value: Value::Text("x".into()) },
        ]);
        assert_eq!(st.to_string(), "{ a: 1, b: x }");
        let mut p = Packet::new(Standard::St0102);
        p.items.push(Item { tag: 1, name: "N", units: "", value: Value::Uint(2), raw: vec![2] });
        assert_eq!(Value::Set(Box::new(p)).to_string(), "ST 0102 { N: 2 }");
    }

    #[test]
    fn packet_lookup() {
        let mut p = Packet::new(Standard::St0601);
        assert!(p.is_empty());
        p.items.push(Item { tag: 2, name: "A", units: "", value: Value::Uint(1), raw: vec![1] });
        p.items.push(Item { tag: 2, name: "A", units: "", value: Value::Uint(9), raw: vec![9] });
        p.items.push(Item { tag: 5, name: "B", units: "m", value: Value::Float(1.0), raw: vec![] });
        assert_eq!(p.get(2u64), Some(&Value::Uint(1)));
        assert_eq!(p.item(5u8).unwrap().name, "B");
        assert_eq!(p.get(6u32), None);
        assert_eq!(p.iter().count(), 3);
        assert_eq!((&p).into_iter().count(), 3);
        assert_eq!(p.len(), 3);
        assert!(p.is_ok());
        p.checksum = Checksum::Mismatch { expected: 1, computed: 2 };
        assert!(!p.is_ok());
        p.checksum = Checksum::Valid;
        p.error = Some(Error::BadTag);
        assert!(!p.is_ok());
        let text = p.to_string();
        assert!(text.starts_with("ST 0601 UAS Datalink Local Set checksum ok"));
        assert!(text.contains("  5 B: 1 m"));
        assert!(text.ends_with("error: malformed BER-OID tag"));
    }

    fn item(tag: u64, value: Value) -> Item {
        Item { tag, name: "N", units: "", value, raw: vec![] }
    }

    #[test]
    fn is_ok_covers_missing_checksums_and_nested_errors() {
        let mut p = Packet::new(Standard::St0601);
        p.items.push(item(3, Value::Uint(1)));
        p.checksum = Checksum::Missing;
        assert!(!p.is_ok(), "a top-level ST 0601 packet must carry tag 1");
        p.checksum = Checksum::Valid;
        assert!(p.is_ok());

        // A cut-short nested set, inside a list inside a struct.
        let mut inner = Packet::new(Standard::St0102);
        inner.error = Some(Error::Truncated { needed: 9, available: 3 });
        let set = Value::Set(Box::new(inner));
        let mut top = p.clone();
        top.items.push(item(48, set.clone()));
        assert!(!top.is_ok());
        assert!(top.to_string().contains("error: truncated"), "{top}");
        let mut top = p.clone();
        let deep = Value::Struct(vec![Field { name: "a", value: Value::List(vec![Value::Uint(1), set]) }]);
        top.items.push(item(74, deep));
        assert!(!top.is_ok());

        // Valid nested sets keep the packet ok.
        let mut fine = Packet::new(Standard::St0102);
        fine.items.push(item(1, Value::Uint(1)));
        let mut top = p.clone();
        top.items.push(item(48, Value::Set(Box::new(fine))));
        assert!(top.is_ok());
    }

    #[test]
    fn nested_set_display_shows_its_error() {
        let mut inner = Packet::new(Standard::St0102);
        inner.error = Some(Error::TooDeep);
        assert_eq!(Value::Set(Box::new(inner.clone())).to_string(), "ST 0102 { error: sets nested too deeply }");
        inner.items.push(item(1, Value::Uint(2)));
        assert_eq!(Value::Set(Box::new(inner)).to_string(), "ST 0102 { N: 2, error: sets nested too deeply }");
    }

    #[test]
    fn text_display_escapes_control_characters() {
        let v = Value::Text("a\nb\x1b[2J\t\u{202E}z".into());
        assert_eq!(v.to_string(), "a\\nb\\u{1b}[2J\\t\\u{202e}z");
        assert_eq!(v.as_str(), Some("a\nb\x1b[2J\t\u{202E}z"));
        let mut p = Packet::new(Standard::St0601);
        p.items.push(item(3, Value::Text("X\n  1 Checksum: 0\r\n  error: none".into())));
        p.items.push(item(4, Value::Uint(1)));
        assert_eq!(p.to_string().lines().count(), 3);
        assert_eq!(Value::Text("plain text, ok".into()).to_string(), "plain text, ok");
    }

    #[test]
    fn nan_equals_nan() {
        assert_eq!(Value::Float(f64::NAN), Value::Float(f64::NAN));
        assert_eq!(Value::Float(0.0), Value::Float(-0.0));
        assert_ne!(Value::Float(1.0), Value::Float(f64::NAN));
        assert_ne!(Value::Float(1.0), Value::Uint(1));
        let mut p = Packet::new(Standard::St0601);
        p.items.push(item(5, crate::imapb::decode(0.0, 100.0, &[0xD0, 0])));
        assert_eq!(p, p.clone());
    }

    #[test]
    fn constructors_and_repeated_tags() {
        let mut p = Packet::new(Standard::St0601);
        p.items.push(Item::new(100, "Segment Local Set", "", Value::Uint(1), vec![1]));
        p.items.push(Item::new(2, "T", "", Value::Struct(vec![Field::new("a", Value::Uint(1))]), vec![]));
        p.items.push(Item::new(100, "Segment Local Set", "", Value::Uint(2), vec![2]));
        assert_eq!(p.get_all(100u8).count(), 2);
        assert_eq!(p.get_all(100u8).nth(1).unwrap().value, Value::Uint(2));
        assert_eq!(p.get_all(7u8).count(), 0);
        assert_eq!(p.get(2u8).unwrap().field("a"), Some(&Value::Uint(1)));
    }

    #[test]
    fn tag_keys_name_their_standard() {
        let mut p = Packet::new(Standard::St0601);
        p.items.push(item(1, Value::Uint(7)));
        p.items.push(item(22, Value::Uint(9)));
        assert_eq!(p.get(crate::st0601::Tag::Checksum), Some(&Value::Uint(7)));
        assert_eq!(p.get(1u16), Some(&Value::Uint(7)));
        assert_eq!(p.get(1u32), Some(&Value::Uint(7)));
        // Another standard's tag with the same number finds nothing.
        assert_eq!(p.get(crate::st0102::Tag::SecurityClassification), None);
        assert_eq!(p.get(crate::st0102::Tag::Version), None);
        assert_eq!(p.item(crate::st0806::Tag::Checksum), None);
        assert_eq!(p.get_all(crate::st0903::Tag::Checksum).count(), 0);
        let mut security = Packet::new(Standard::St0102);
        security.items.push(item(22, Value::Uint(12)));
        assert_eq!(security.get(crate::st0102::Tag::Version), Some(&Value::Uint(12)));
        assert_eq!(security.get(crate::st0601::Tag::SensorRelativeRollAngle), None);
        assert_eq!(crate::st0102::Tag::Version.number(), 22);
        assert_eq!(crate::st0102::Tag::Version.standard(), Some(Standard::St0102));
        assert_eq!(crate::st0806::Tag::Checksum.standard(), Some(Standard::St0806));
        assert_eq!(crate::st0903::Tag::VTargetSeries.number(), 101);
        assert_eq!(crate::st0903::Tag::VTargetSeries.standard(), Some(Standard::St0903));
        assert_eq!(crate::st0601::Tag::MetadataSubstreamIdPack.standard(), Some(Standard::St0601));
        assert_eq!((5u8.number(), 5u8.standard()), (5, None));
    }

    #[test]
    fn uuid_text_is_lowercase_rfc_4122() {
        let b = [0xF8, 0x1D, 0x4F, 0xAE, 0x7D, 0xEC, 0x11, 0xD0, 0xA7, 0x65, 0x00, 0xA0, 0xC9, 0x1E, 0x6B, 0xF6];
        assert_eq!(uuid_text(&b), "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    }

    #[test]
    fn common_traits() {
        use std::collections::{BTreeSet, HashSet};
        let s: BTreeSet<Standard> = [Standard::St0903, Standard::St0601].into_iter().collect();
        assert_eq!(s.into_iter().next(), Some(Standard::St0601));
        let c: HashSet<Checksum> = [Checksum::Valid, Checksum::Missing, Checksum::Valid].into_iter().collect();
        assert_eq!(c.len(), 2);
        assert_eq!(Standard::St0102.revision(), "ST 0102.12");
        assert_eq!(Standard::St0806.revision(), "ST 0806.4");
        assert_eq!(Standard::St0903.revision(), "ST 0903.6");
    }

    #[test]
    fn standard_names() {
        assert_eq!(Standard::St0601.name(), "ST 0601");
        assert_eq!(Standard::St0601.title(), "UAS Datalink Local Set");
        assert_eq!(Standard::St0903.to_string(), "ST 0903");
        assert_eq!(Standard::St0806.title(), "Remote Video Terminal Local Set");
    }
}
