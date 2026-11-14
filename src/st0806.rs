//! MISB ST 0806 Remote Video Terminal Local Set.
//!
//! Decoded where ST 0601 embeds it: tag 73, RVT Local Set. The value is the
//! bare set, without the 16-byte RVT key or its length (ST 0601.19 section
//! 6.3.3 and section 8.73). Tags and types follow ST 0806.4 Table 8-1.
//!
//! The RVT set embeds three subordinate local sets, each carried as the
//! bare set in one item and each repeatable (section 7.3, 7.4): User
//! Defined (tag 11), Point of Interest (tag 12) and Area of Interest (tag
//! 13). Each item decodes to a [`Value::Struct`] with one field per item
//! of the subordinate set, named as in ST 0806.4 Tables 8-2 to 8-4. A tag
//! the subordinate set does not define becomes a field named `Unknown`
//! whose value is a struct of its `Tag` ([`Value::Uint`]) and `Value`
//! ([`Value::Bytes`]). A subordinate set that is malformed, holds more than
//! [`Config::max_items`] items, or lies deeper than [`Config::max_depth`]
//! is [`Value::Invalid`] as a whole; [`Item::raw`] keeps its bytes.
//!
//! Point of Interest fields (Table 8-2), units in parentheses:
//!
//! | tag | field | value |
//! |-----|-------|-------|
//! | 1 | `POI/AOI Number` | [`Value::Uint`] |
//! | 2 | `POI Latitude` | [`Value::Float`] (deg), int32 mapped to +/-90; [`Value::OutOfRange`] for the error value 0x80000000 |
//! | 3 | `POI Longitude` | [`Value::Float`] (deg), int32 mapped to +/-180; [`Value::OutOfRange`] for 0x80000000 |
//! | 4 | `POI Altitude` | [`Value::Float`] (m above MSL), uint16 mapped to -900 to 19,000 |
//! | 5 | `POI/AOI Type` | [`Value::Enum`]: 1 Friendly, 2 Hostile, 3 Target, 4 Unknown |
//! | 6 | `POI/AOI Text` | [`Value::Text`], at most 2048 characters |
//! | 7 | `POI Source Icon` | [`Value::Text`], a MIL-STD-2525B symbol code, at most 127 |
//! | 8 | `POI/AOI Source ID` | [`Value::Text`], at most 255 |
//! | 9 | `POI/AOI Label` | [`Value::Text`], at most 16 |
//! | 10 | `Operation ID` | [`Value::Text`], at most 127 |
//!
//! Area of Interest fields (Table 8-3): tag 1 as in the POI set; tags 2 to
//! 5 `Corner Latitude Point 1 (Decimal Degrees)`, `Corner Longitude Point 1
//! (Decimal Degrees)` (the north-west, upper left corner), `Corner Latitude
//! Point 3 (Decimal Degrees)` and `Corner Longitude Point 3 (Decimal
//! Degrees)` (the south-east, lower right corner), mapped like the POI
//! latitude and longitude; tag 6 `POI/AOI Type` (1 Friendly, 2 Hostile, 3
//! Reserved, 4 Unknown); tags 7 to 10 `POI/AOI Text`, `POI/AOI Source ID`,
//! `POI/AOI Label` and `Operation ID` as POI tags 6 and 8 to 10.
//!
//! User Defined fields (Table 8-4): tag 1 `Numeric ID for Data Type`, a
//! struct of `Data Type` ([`Value::Enum`] of bits 8 and 7: 0 String, 1 INT,
//! 2 UINT, 3 Experimental) and `Numeric ID` ([`Value::Uint`] of bits 6 to
//! 1, 0 to 63); tag 2 `User Data`, read as that data type: [`Value::Text`],
//! [`Value::Int`] or [`Value::Uint`] of the item's length (1 to 8 bytes),
//! or [`Value::Bytes`] for Experimental data or when the set has no valid
//! tag 1.
//!
//! A zero-length item means the value is unknown (MISB ST 0107, which ST
//! 0806.4 invokes) and decodes to [`Value::Unknown`], both in the RVT set
//! and in its subordinate sets, except where ST 0107 forbids it: for the CRC
//! (tag 1), for the subordinate sets (tags 11 to 13, which may repeat), and
//! for the items a subordinate set must contain (POI tags 1 to 3,
//! requirements ST 0806.4-08 to -10; AOI tags 1 to 6, Table 8-3; User
//! Defined tags 1 and 2, ST 0806.4-21 and -22). Those are
//! [`Value::Invalid`].
//!
//! A value of the wrong length is [`Value::Invalid`], as is text longer than
//! the maximum its table states, an MGRS zone outside 1 to 60, an MGRS
//! easting or northing above 99,999 m, or an MGRS latitude band and grid
//! square that is not three MGRS letters. Enumeration codes the standard
//! does not define keep their code with no label.
//!
//! The standard's rules on item presence and order (time stamp first, CRC
//! last, required POI/AOI items, one item per tag) are not enforced; a
//! consumer can check them from the decoded items.

use crate::{Config, Field, Item, Value};

/// Tags of the Remote Video Terminal Local Set (ST 0806.4 Table 8-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tag {
    /// CRC 32: CRC-32/MPEG-2 ([`crate::checksum::crc32_mpeg2`]) of an
    /// independent RVT packet, its last item (requirements ST 0806.4-03 and
    /// -04, Appendix). Decoded as the carried [`Value::Uint`] and not
    /// verified: a set nested in ST 0601 leaves the CRC out (ST 0601.19
    /// section 6.3.3), and the CRC's coverage, which starts at the 16-byte
    /// RVT key (Table 8-1), does not exist for a nested set.
    Checksum = 1,
    /// User Defined Time Stamp: microseconds since 1970, the MISB ST 0603
    /// Precision Time Stamp; first item of an independent packet
    /// (requirements ST 0806.4-01 and -02).
    PrecisionTimeStamp = 2,
    /// Platform True Airspeed: uint16, m/s.
    PlatformTrueAirspeed = 3,
    /// Platform Indicated Airspeed: uint16, m/s.
    PlatformIndicatedAirspeed = 4,
    /// Telemetry Accuracy Indicator: uint8, reserved for future use.
    TelemetryAccuracyIndicator = 5,
    /// Frag Circle Radius: uint16, m, the fragmentation circle the aircrew
    /// selected.
    FragCircleRadius = 6,
    /// Frame Code: uint32 counter running at 60 Hz.
    FrameCode = 7,
    /// UAS LS Version Number: uint8 ST 0806 revision (0 pre-release or
    /// test data, 4 for ST 0806.4).
    VersionNumber = 8,
    /// Video Data rate: uint32, bits per second for digital video or Hz
    /// for analog FM.
    VideoDataRate = 9,
    /// Digital Video File Format: ISO-7 text such as `H.264`, at most 127
    /// characters.
    DigitalVideoFileFormat = 10,
    /// User Defined LS (Table 8-4), repeatable.
    UserDefinedLocalSet = 11,
    /// Point of Interest LS (Table 8-2), repeatable.
    PointOfInterestLocalSet = 12,
    /// Area of Interest LS (Table 8-3), repeatable.
    AreaOfInterestLocalSet = 13,
    /// MGRS Zone of the aircraft: uint8 UTM zone 1 to 60.
    MgrsZone = 14,
    /// MGRS Latitude Band and Grid Square of the aircraft: three letters,
    /// the latitude band then the 100 km grid square.
    MgrsLatitudeBandAndGridSquare = 15,
    /// MGRS Easting of the aircraft: uint24, 0 to 99,999 m.
    MgrsEasting = 16,
    /// MGRS Northing of the aircraft: uint24, 0 to 99,999 m.
    MgrsNorthing = 17,
    /// MGRS Zone of the frame center (Second Value).
    MgrsZoneSecondValue = 18,
    /// MGRS Latitude Band and Grid Square of the frame center (Second
    /// Value).
    MgrsLatitudeBandAndGridSquareSecondValue = 19,
    /// MGRS Easting of the frame center (Second Value).
    MgrsEastingSecondValue = 20,
    /// MGRS Northing of the frame center (Second Value).
    MgrsNorthingSecondValue = 21,
}

impl Tag {
    /// The tag with this number, if the standard defines it.
    pub fn from_u64(n: u64) -> Option<Tag> {
        Some(match n {
            1 => Tag::Checksum,
            2 => Tag::PrecisionTimeStamp,
            3 => Tag::PlatformTrueAirspeed,
            4 => Tag::PlatformIndicatedAirspeed,
            5 => Tag::TelemetryAccuracyIndicator,
            6 => Tag::FragCircleRadius,
            7 => Tag::FrameCode,
            8 => Tag::VersionNumber,
            9 => Tag::VideoDataRate,
            10 => Tag::DigitalVideoFileFormat,
            11 => Tag::UserDefinedLocalSet,
            12 => Tag::PointOfInterestLocalSet,
            13 => Tag::AreaOfInterestLocalSet,
            14 => Tag::MgrsZone,
            15 => Tag::MgrsLatitudeBandAndGridSquare,
            16 => Tag::MgrsEasting,
            17 => Tag::MgrsNorthing,
            18 => Tag::MgrsZoneSecondValue,
            19 => Tag::MgrsLatitudeBandAndGridSquareSecondValue,
            20 => Tag::MgrsEastingSecondValue,
            21 => Tag::MgrsNorthingSecondValue,
            _ => return None,
        })
    }

    /// Name from the standard (ST 0806.4 Table 8-1, as printed).
    pub fn name(self) -> &'static str {
        match self {
            Tag::Checksum => "CRC 32",
            Tag::PrecisionTimeStamp => "User Defined Time Stamp -Microseconds Since 1970",
            Tag::PlatformTrueAirspeed => "Platform True Airspeed",
            Tag::PlatformIndicatedAirspeed => "Platform Indicated Airspeed",
            Tag::TelemetryAccuracyIndicator => "Telemetry Accuracy Indicator",
            Tag::FragCircleRadius => "Frag Circle Radius",
            Tag::FrameCode => "Frame Code",
            Tag::VersionNumber => "UAS LS Version Number",
            Tag::VideoDataRate => "Video Data rate",
            Tag::DigitalVideoFileFormat => "Digital Video File Format",
            Tag::UserDefinedLocalSet => "User Defined LS",
            Tag::PointOfInterestLocalSet => "Point of Interest LS",
            Tag::AreaOfInterestLocalSet => "Area of Interest LS",
            Tag::MgrsZone => "MGRS Zone",
            Tag::MgrsLatitudeBandAndGridSquare => "MGRS Latitude Band and Grid Square",
            Tag::MgrsEasting => "MGRS Easting",
            Tag::MgrsNorthing => "MGRS Northing",
            Tag::MgrsZoneSecondValue => "MGRS Zone Second Value",
            Tag::MgrsLatitudeBandAndGridSquareSecondValue => {
                "MGRS Latitude Band and Grid Square Second Value"
            }
            Tag::MgrsEastingSecondValue => "MGRS Easting Second Value",
            Tag::MgrsNorthingSecondValue => "MGRS Northing Second Value",
        }
    }

    /// Units string; "" when none.
    pub fn units(self) -> &'static str {
        match self {
            Tag::PrecisionTimeStamp => "us",
            Tag::PlatformTrueAirspeed | Tag::PlatformIndicatedAirspeed => "m/s",
            Tag::FragCircleRadius
            | Tag::MgrsEasting
            | Tag::MgrsNorthing
            | Tag::MgrsEastingSecondValue
            | Tag::MgrsNorthingSecondValue => "m",
            Tag::VideoDataRate => "bps or Hz",
            _ => "",
        }
    }
}

impl From<Tag> for u64 {
    fn from(t: Tag) -> u64 {
        t as u64
    }
}

crate::value::tag_key!(Tag, crate::Standard::St0806);

/// Reason given for a zero-length item the standard does not allow (MISB
/// ST 0107: never for a mandatory item or one that may repeat).
const NO_ZLI: &str = "zero-length item not allowed for this tag";

/// A zero-length item: unknown (MISB ST 0107), unless `forbidden`.
fn zero_length(forbidden: bool) -> Value {
    if forbidden {
        Value::Invalid(NO_ZLI)
    } else {
        Value::Unknown
    }
}

/// Decode one item of the set. Never panics. `depth` is the nesting level
/// of the RVT set; its subordinate sets lie one level deeper.
pub(crate) fn decode_item(tag: u64, value: &[u8], depth: usize, cfg: &Config) -> Item {
    let Some(t) = Tag::from_u64(tag) else {
        return crate::registry::unknown_item(tag, value, depth, cfg);
    };
    let decoded = decode_value(t, value, depth, cfg);
    crate::registry::item(tag, t.name(), t.units(), decoded, value, cfg)
}

/// The value of one item of a known tag (ST 0806.4 Table 8-1).
fn decode_value(t: Tag, v: &[u8], depth: usize, cfg: &Config) -> Value {
    if v.is_empty() {
        let forbidden = matches!(
            t,
            Tag::Checksum | Tag::UserDefinedLocalSet | Tag::PointOfInterestLocalSet | Tag::AreaOfInterestLocalSet
        );
        return zero_length(forbidden);
    }
    match t {
        Tag::Checksum => fixed_uint(v, 4),
        Tag::PrecisionTimeStamp => match fixed_uint(v, 8) {
            Value::Uint(us) => Value::Time(us),
            other => other,
        },
        Tag::PlatformTrueAirspeed | Tag::PlatformIndicatedAirspeed | Tag::FragCircleRadius => {
            fixed_uint(v, 2)
        }
        Tag::TelemetryAccuracyIndicator | Tag::VersionNumber => fixed_uint(v, 1),
        Tag::FrameCode | Tag::VideoDataRate => fixed_uint(v, 4),
        Tag::DigitalVideoFileFormat => text_max(v, 127),
        Tag::UserDefinedLocalSet => subordinate(v, depth, cfg, user_defined),
        Tag::PointOfInterestLocalSet => subordinate(v, depth, cfg, poi),
        Tag::AreaOfInterestLocalSet => subordinate(v, depth, cfg, aoi),
        Tag::MgrsZone | Tag::MgrsZoneSecondValue => mgrs_zone(v),
        Tag::MgrsLatitudeBandAndGridSquare | Tag::MgrsLatitudeBandAndGridSquareSecondValue => {
            mgrs_band_and_square(v)
        }
        Tag::MgrsEasting
        | Tag::MgrsNorthing
        | Tag::MgrsEastingSecondValue
        | Tag::MgrsNorthingSecondValue => mgrs_metres(v),
    }
}

/// One item of a subordinate set: its tag and value bytes.
type SubItem<'a> = (u64, &'a [u8]);

/// Walk a subordinate set (the bare set inside RVT tag 11, 12 or 13) one
/// level below the RVT set at `depth`, and build its fields with `fields`.
fn subordinate(
    v: &[u8],
    depth: usize,
    cfg: &Config,
    fields: fn(&[SubItem<'_>]) -> Vec<Field>,
) -> Value {
    if depth.saturating_add(1) > cfg.depth_limit() {
        return Value::Invalid("sets nested too deeply");
    }
    let mut items = Vec::new();
    for item in crate::klv::local_set(v) {
        let Ok(item) = item else { return Value::Invalid("malformed subordinate local set") };
        if items.len() >= cfg.max_items {
            return Value::Invalid("subordinate local set has more than Config::max_items items");
        }
        items.push((item.tag, item.value));
    }
    Value::Struct(fields(&items))
}

/// A tag the subordinate set does not define.
fn unknown_field(tag: u64, v: &[u8]) -> Field {
    Field {
        name: "Unknown",
        value: Value::Struct(vec![
            Field { name: "Tag", value: Value::Uint(tag) },
            Field { name: "Value", value: Value::Bytes(v.to_vec()) },
        ]),
    }
}

/// Point of Interest LS fields (ST 0806.4 Table 8-2). Tags 1 to 3 are
/// required (ST 0806.4-08 to -10).
fn poi(items: &[SubItem<'_>]) -> Vec<Field> {
    let field = |&(tag, v): &SubItem<'_>| {
        let Some(&name) = usize::try_from(tag).ok().and_then(|t| POI_NAMES.get(t.wrapping_sub(1))) else {
            return unknown_field(tag, v);
        };
        let value = match tag {
            _ if v.is_empty() => zero_length(tag <= 3),
            1 => fixed_uint(v, 2),
            2 => angle(v, 90.0),
            3 => angle(v, 180.0),
            4 => altitude(v),
            5 => interest_type(v, POI_TYPES),
            6 => text_max(v, 2048),
            7 => text_max(v, 127),
            8 => text_max(v, 255),
            9 => text_max(v, 16),
            _ => text_max(v, 127),
        };
        Field { name, value }
    };
    items.iter().map(field).collect()
}

/// Area of Interest LS fields (ST 0806.4 Table 8-3). The AOI set has no
/// altitude or source icon, so tags 6 to 10 differ from the POI set. Tags 1
/// to 6 are required (Table 8-3).
fn aoi(items: &[SubItem<'_>]) -> Vec<Field> {
    let field = |&(tag, v): &SubItem<'_>| {
        let Some(&name) = usize::try_from(tag).ok().and_then(|t| AOI_NAMES.get(t.wrapping_sub(1))) else {
            return unknown_field(tag, v);
        };
        let value = match tag {
            _ if v.is_empty() => zero_length(tag <= 6),
            1 => fixed_uint(v, 2),
            2 | 4 => angle(v, 90.0),
            3 | 5 => angle(v, 180.0),
            6 => interest_type(v, AOI_TYPES),
            7 => text_max(v, 2048),
            8 => text_max(v, 255),
            9 => text_max(v, 16),
            _ => text_max(v, 127),
        };
        Field { name, value }
    };
    items.iter().map(field).collect()
}

/// User Defined LS fields (ST 0806.4 Table 8-4). Tag 2 is read as the data
/// type of the first valid tag 1, which requirements ST 0806.4-21 and -22
/// place first and second.
fn user_defined(items: &[SubItem<'_>]) -> Vec<Field> {
    let data_type = items.iter().find_map(|&(tag, v)| match (tag, v) {
        (1, &[b]) => Some(b >> 6),
        _ => None,
    });
    // Both items are required (ST 0806.4-21, -22), so never unknown.
    let field = |&(tag, v): &SubItem<'_>| match tag {
        1 if v.is_empty() => Field { name: UD_NAMES[0], value: zero_length(true) },
        2 if v.is_empty() => Field { name: UD_NAMES[1], value: zero_length(true) },
        1 => Field { name: UD_NAMES[0], value: numeric_id(v) },
        2 => Field { name: UD_NAMES[1], value: user_data(v, data_type) },
        _ => unknown_field(tag, v),
    };
    items.iter().map(field).collect()
}

/// User Defined tag 1: bits 8 and 7 (MSB first) give the data type, bits 6
/// to 1 the numeric ID.
fn numeric_id(v: &[u8]) -> Value {
    let &[b] = v else { return Value::Invalid("Numeric ID for Data Type is not 1 byte") };
    let data_type = b >> 6;
    let label = match data_type {
        0 => "String",
        1 => "INT",
        2 => "UINT",
        _ => "Experimental",
    };
    Value::Struct(vec![
        Field {
            name: "Data Type",
            value: Value::Enum { code: u64::from(data_type), label: Some(label) },
        },
        Field { name: "Numeric ID", value: Value::Uint(u64::from(b & 0x3F)) },
    ])
}

/// User Defined tag 2: "variant (uint16, uint32, etc.) extracted from the
/// overall pack length" (Table 8-4).
fn user_data(v: &[u8], data_type: Option<u8>) -> Value {
    match data_type {
        Some(0) => Value::Text(String::from_utf8_lossy(v).into_owned()),
        Some(1) => match crate::klv::be_int(v) {
            Some(n) => Value::Int(n),
            None => Value::Invalid("INT user data is not 1 to 8 bytes"),
        },
        Some(2) => match crate::klv::be_uint(v) {
            Some(n) => Value::Uint(n),
            None => Value::Invalid("UINT user data is not 1 to 8 bytes"),
        },
        // Experimental, or no data type to read it as.
        _ => Value::Bytes(v.to_vec()),
    }
}

/// Field names of POI tags 1 to 10 (Table 8-2).
const POI_NAMES: [&str; 10] = [
    "POI/AOI Number",
    "POI Latitude",
    "POI Longitude",
    "POI Altitude",
    "POI/AOI Type",
    "POI/AOI Text",
    "POI Source Icon",
    "POI/AOI Source ID",
    "POI/AOI Label",
    "Operation ID",
];

/// Field names of AOI tags 1 to 10 (Table 8-3).
const AOI_NAMES: [&str; 10] = [
    "POI/AOI Number",
    "Corner Latitude Point 1 (Decimal Degrees)",
    "Corner Longitude Point 1 (Decimal Degrees)",
    "Corner Latitude Point 3 (Decimal Degrees)",
    "Corner Longitude Point 3 (Decimal Degrees)",
    "POI/AOI Type",
    "POI/AOI Text",
    "POI/AOI Source ID",
    "POI/AOI Label",
    "Operation ID",
];

/// Field names of User Defined tags 1 and 2 (Table 8-4).
const UD_NAMES: [&str; 2] = ["Numeric ID for Data Type", "User Data"];

/// POI/AOI Type labels, POI set tag 5 (Table 8-2).
const POI_TYPES: [&str; 4] = ["Friendly", "Hostile", "Target", "Unknown"];

/// POI/AOI Type labels, AOI set tag 6 (Table 8-3): code 3 is "Reserved"
/// there.
const AOI_TYPES: [&str; 4] = ["Friendly", "Hostile", "Reserved", "Unknown"];

/// POI/AOI Type: an int8 enumeration of codes 1 to 4. Other codes keep
/// their byte value with no label.
fn interest_type(v: &[u8], labels: [&'static str; 4]) -> Value {
    let &[b] = v else { return Value::Invalid("POI/AOI Type is not 1 byte") };
    let label = usize::from(b).checked_sub(1).and_then(|i| labels.get(i)).copied();
    Value::Enum { code: u64::from(b), label }
}

/// POI/AOI latitude (`range` 90) or longitude (`range` 180): int32 with
/// -(2^31 - 1)..=(2^31 - 1) mapped to -range..=range and -(2^31) the
/// "error" indicator (Tables 8-2 and 8-3).
fn angle(v: &[u8], range: f64) -> Value {
    let &[a, b, c, d] = v else { return Value::Invalid("POI/AOI coordinate is not 4 bytes") };
    match i32::from_be_bytes([a, b, c, d]) {
        i32::MIN => Value::OutOfRange,
        n => Value::Float(f64::from(n) / f64::from(i32::MAX) * range),
    }
}

/// POI Altitude: uint16 with 0..=65535 mapped to -900..=19,000 m (Table
/// 8-2). There is no error value.
fn altitude(v: &[u8]) -> Value {
    let &[a, b] = v else { return Value::Invalid("POI Altitude is not 2 bytes") };
    Value::Float(f64::from(u16::from_be_bytes([a, b])) / 65535.0 * 19_900.0 - 900.0)
}

/// A big-endian unsigned integer of exactly `len` bytes.
fn fixed_uint(v: &[u8], len: usize) -> Value {
    match crate::klv::be_uint(v) {
        Some(n) if v.len() == len => Value::Uint(n),
        _ => Value::Invalid(match len {
            1 => "value is not 1 byte",
            2 => "value is not 2 bytes",
            3 => "value is not 3 bytes",
            4 => "value is not 4 bytes",
            _ => "value is not 8 bytes",
        }),
    }
}

/// ISO-7 (ISO/IEC 646) text of at most `max` characters, one byte each.
/// Bytes above 0x7F, which ISO-7 does not define, are read as lossy UTF-8.
fn text_max(v: &[u8], max: usize) -> Value {
    if v.len() > max {
        return Value::Invalid("text is longer than the standard's maximum");
    }
    Value::Text(String::from_utf8_lossy(v).into_owned())
}

/// MGRS Zone (tags 14 and 18): uint8 UTM zone 1 to 60.
fn mgrs_zone(v: &[u8]) -> Value {
    match *v {
        [z @ 1..=60] => Value::Uint(u64::from(z)),
        [_] => Value::Invalid("MGRS zone is not 1 to 60"),
        _ => Value::Invalid("value is not 1 byte"),
    }
}

/// MGRS Latitude Band and Grid Square (tags 15 and 19): three ISO-7
/// characters, the latitude band and two grid square letters. MGRS letters
/// are A to Z without I and O (UTM bands C to X and UPS bands A, B, Y, Z).
fn mgrs_band_and_square(v: &[u8]) -> Value {
    let letter = |b: &u8| b.is_ascii_uppercase() && *b != b'I' && *b != b'O';
    if v.len() == 3 && v.iter().all(letter) {
        Value::Text(String::from_utf8_lossy(v).into_owned())
    } else {
        Value::Invalid("not an MGRS latitude band and grid square")
    }
}

/// MGRS Easting or Northing (tags 16, 17, 20, 21): uint24, 0 to 99,999 m.
fn mgrs_metres(v: &[u8]) -> Value {
    match fixed_uint(v, 3) {
        Value::Uint(m) if m > 99_999 => Value::Invalid("MGRS easting or northing above 99,999 m"),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::decode_set;
    use crate::{Packet, Standard};

    fn cfg() -> Config {
        Config::default()
    }

    fn item(tag: u64, v: &[u8]) -> Value {
        decode_item(tag, v, 1, &cfg()).value
    }

    /// Encode (tag, value) pairs as a local set with BER lengths (short
    /// form below 128, else two-byte long form).
    fn set(items: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, v) in items {
            out.push(*tag);
            match u8::try_from(v.len()) {
                Ok(n) if n < 0x80 => out.push(n),
                _ => {
                    out.push(0x82);
                    out.extend(u16::try_from(v.len()).unwrap().to_be_bytes());
                }
            }
            out.extend_from_slice(v);
        }
        out
    }

    fn float(v: Option<&Value>) -> f64 {
        v.and_then(Value::as_f64).unwrap()
    }

    #[test]
    fn tag_table() {
        for n in 0..=255u64 {
            match Tag::from_u64(n) {
                Some(t) => {
                    assert!((1..=21).contains(&n));
                    assert_eq!(u64::from(t), n);
                    assert!(!t.name().is_empty());
                }
                None => assert!(n == 0 || n > 21, "{n}"),
            }
        }
        assert_eq!(Tag::MgrsNorthingSecondValue.name(), "MGRS Northing Second Value");
        assert_eq!(Tag::PlatformTrueAirspeed.units(), "m/s");
        assert_eq!(Tag::FrameCode.units(), "");
    }

    #[test]
    fn st0601_figure_5_nested_set() {
        // ST 0601.19 section 6.3.3 Figure 5: Video Data Rate, Digital Video
        // Format "H.264" and Version Number nested in tag 73.
        let v = set(&[(9, &[0x00, 0x11, 0x22, 0x33]), (10, b"H.264"), (8, &[0x00])]);
        let p: Packet = decode_set(Standard::St0806, &v, 1, &cfg());
        assert!(p.is_ok());
        assert_eq!(p.standard, Standard::St0806);
        assert_eq!(p.get(Tag::VideoDataRate), Some(&Value::Uint(0x0011_2233)));
        assert_eq!(p.get(Tag::DigitalVideoFileFormat), Some(&Value::Text("H.264".into())));
        assert_eq!(p.get(Tag::VersionNumber), Some(&Value::Uint(0)));
        assert_eq!(p.items[0].to_string(), "  9 Video Data rate: 1122867 bps or Hz");
    }

    #[test]
    fn nested_in_st0601_tag_73() {
        // An ST 0601 packet carrying an RVT set with a POI in tag 73.
        let poi = set(&[(1, &[0, 7]), (2, &[0x7F, 0xFF, 0xFF, 0xFF]), (3, &[0, 0, 0, 0])]);
        let rvt = set(&[(8, &[4]), (12, &poi)]);
        let mut body = set(&[(73, &rvt)]);
        body.extend([1, 2]);
        let mut pkt = crate::st0601::KEY.to_vec();
        pkt.push(u8::try_from(body.len() + 2).unwrap());
        pkt.extend(body);
        let sum = crate::checksum::st0601_checksum(&pkt);
        pkt.extend(sum.to_be_bytes());
        let p = crate::decode(&pkt).unwrap();
        assert_eq!(p.checksum, crate::Checksum::Valid);
        let rvt = p.get(73u64).and_then(Value::as_set).unwrap();
        assert_eq!(rvt.standard, Standard::St0806);
        assert!(rvt.is_ok());
        assert_eq!(rvt.get(Tag::VersionNumber), Some(&Value::Uint(4)));
        let poi = rvt.get(Tag::PointOfInterestLocalSet).unwrap();
        assert_eq!(poi.field("POI/AOI Number"), Some(&Value::Uint(7)));
        assert_eq!(poi.field("POI Latitude"), Some(&Value::Float(90.0)));
    }

    #[test]
    fn scalar_items() {
        // ST 0601.19 tag 2 example time stamp 0x0004_59F4_A6AA_4AA8.
        let ts = [0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8];
        assert_eq!(item(2, &ts), Value::Time(0x0004_59F4_A6AA_4AA8));
        assert_eq!(item(2, &ts[..7]), Value::Invalid("value is not 8 bytes"));
        assert_eq!(item(1, &[0x82, 0x35, 0x32, 0x10]), Value::Uint(0x8235_3210));
        assert_eq!(item(1, &[0x82, 0x35]), Value::Invalid("value is not 4 bytes"));
        assert_eq!(item(3, &[0x01, 0x02]), Value::Uint(258));
        assert_eq!(item(4, &[0xFF, 0xFF]), Value::Uint(65_535));
        assert_eq!(item(4, &[0xFF]), Value::Invalid("value is not 2 bytes"));
        assert_eq!(item(5, &[0x07]), Value::Uint(7));
        assert_eq!(item(5, &[]), Value::Unknown);
        assert_eq!(item(6, &[0x01, 0xF4]), Value::Uint(500));
        assert_eq!(item(7, &[0xFF, 0xFF, 0xFF, 0xFF]), Value::Uint(u64::from(u32::MAX)));
        assert_eq!(item(8, &[0x04]), Value::Uint(4));
        assert_eq!(item(8, &[0x00, 0x04]), Value::Invalid("value is not 1 byte"));
        assert_eq!(item(9, &[0, 0x98, 0x96, 0x80]), Value::Uint(10_000_000));
    }

    #[test]
    fn text_items() {
        assert_eq!(item(10, b"MPEG2"), Value::Text("MPEG2".into()));
        assert_eq!(item(10, &[b'a'; 127]), Value::Text("a".repeat(127)));
        assert_eq!(
            item(10, &[b'a'; 128]),
            Value::Invalid("text is longer than the standard's maximum")
        );
        assert_eq!(item(10, b""), Value::Unknown);
    }

    #[test]
    fn mgrs_items() {
        for tag in [14, 18] {
            assert_eq!(item(tag, &[1]), Value::Uint(1));
            assert_eq!(item(tag, &[60]), Value::Uint(60));
            assert_eq!(item(tag, &[0]), Value::Invalid("MGRS zone is not 1 to 60"));
            assert_eq!(item(tag, &[61]), Value::Invalid("MGRS zone is not 1 to 60"));
            assert_eq!(item(tag, &[1, 2]), Value::Invalid("value is not 1 byte"));
        }
        for tag in [15, 19] {
            assert_eq!(item(tag, b"SUV"), Value::Text("SUV".into()));
            assert_eq!(item(tag, b"ZAB"), Value::Text("ZAB".into()));
            let bad = Value::Invalid("not an MGRS latitude band and grid square");
            for v in [&b"SU"[..], b"SUVW", b"IUV", b"SOV", b"suv", b"S1V"] {
                assert_eq!(item(tag, v), bad, "{v:?}");
            }
        }
        for tag in [16, 17, 20, 21] {
            assert_eq!(item(tag, &[0x01, 0x86, 0x9F]), Value::Uint(99_999));
            assert_eq!(item(tag, &[0, 0, 0]), Value::Uint(0));
            assert_eq!(
                item(tag, &[0x01, 0x86, 0xA0]),
                Value::Invalid("MGRS easting or northing above 99,999 m")
            );
            assert_eq!(item(tag, &[0x01, 0x86]), Value::Invalid("value is not 3 bytes"));
            assert_eq!(decode_item(tag, &[0, 0, 5], 1, &cfg()).units, "m");
        }
    }

    #[test]
    fn point_of_interest() {
        // Coordinates shared with the ST 0601.19 tag 23/24 examples (the
        // same int32 mapping) and the ST 0601 tag 38 altitude mapping.
        let v = set(&[
            (1, &[0x00, 0x05]),
            (2, &[0xF1, 0x01, 0xA2, 0x29]),
            (3, &[0x14, 0xBC, 0x08, 0x2B]),
            (4, &[0xCA, 0x35]),
            (5, &[0x02]),
            (6, b"bridge"),
            (7, b"SHGPUCFRMS-----"),
            (8, b"src"),
            (9, b"POI 5"),
            (10, b"OP ALPHA"),
        ]);
        let poi = item(12, &v);
        let f = poi.as_fields().unwrap();
        assert_eq!(f.len(), 10);
        assert_eq!(poi.field("POI/AOI Number"), Some(&Value::Uint(5)));
        assert!((float(poi.field("POI Latitude")) - -10.542_388_633_146_132).abs() < 1e-12);
        assert!((float(poi.field("POI Longitude")) - 29.157_890_122_923_014).abs() < 1e-12);
        assert!((float(poi.field("POI Altitude")) - 14_818.677).abs() < 1e-3);
        assert_eq!(
            poi.field("POI/AOI Type"),
            Some(&Value::Enum { code: 2, label: Some("Hostile") })
        );
        assert_eq!(poi.field("POI/AOI Text"), Some(&Value::Text("bridge".into())));
        assert_eq!(poi.field("POI Source Icon"), Some(&Value::Text("SHGPUCFRMS-----".into())));
        assert_eq!(poi.field("POI/AOI Source ID"), Some(&Value::Text("src".into())));
        assert_eq!(poi.field("POI/AOI Label"), Some(&Value::Text("POI 5".into())));
        assert_eq!(poi.field("Operation ID"), Some(&Value::Text("OP ALPHA".into())));
    }

    #[test]
    fn coordinate_mapping_limits() {
        assert_eq!(angle(&[0x7F, 0xFF, 0xFF, 0xFF], 90.0), Value::Float(90.0));
        assert_eq!(angle(&[0x80, 0x00, 0x00, 0x01], 90.0), Value::Float(-90.0));
        assert_eq!(angle(&[0x7F, 0xFF, 0xFF, 0xFF], 180.0), Value::Float(180.0));
        assert_eq!(angle(&[0x80, 0x00, 0x00, 0x01], 180.0), Value::Float(-180.0));
        assert_eq!(angle(&[0, 0, 0, 0], 90.0), Value::Float(0.0));
        // 0x80000000 is the "error" indicator.
        assert_eq!(angle(&[0x80, 0, 0, 0], 90.0), Value::OutOfRange);
        assert_eq!(angle(&[0x80, 0, 0, 0], 180.0), Value::OutOfRange);
        assert_eq!(angle(&[0, 0, 0], 90.0), Value::Invalid("POI/AOI coordinate is not 4 bytes"));
        // jMISB PoiLatitudeTest vector.
        let lat = angle(&[0x85, 0xA1, 0x5A, 0x39], 90.0).as_f64().unwrap();
        assert!((lat - -86.041_207_348_947).abs() < 1e-9);
        assert_eq!(altitude(&[0, 0]), Value::Float(-900.0));
        assert_eq!(altitude(&[0xFF, 0xFF]), Value::Float(19_000.0));
        assert_eq!(altitude(&[0xFF]), Value::Invalid("POI Altitude is not 2 bytes"));
    }

    #[test]
    fn area_of_interest() {
        let v = set(&[
            (1, &[0x01, 0x00]),
            (2, &[0x7F, 0xFF, 0xFF, 0xFF]),
            (3, &[0x80, 0x00, 0x00, 0x01]),
            (4, &[0x80, 0x00, 0x00, 0x00]),
            (5, &[0x00, 0x00, 0x00, 0x00]),
            (6, &[0x03]),
            (7, b"area"),
            (8, b"id"),
            (9, b"lbl"),
            (10, b"op"),
        ]);
        let aoi = item(13, &v);
        assert_eq!(aoi.as_fields().unwrap().len(), 10);
        assert_eq!(aoi.field("POI/AOI Number"), Some(&Value::Uint(256)));
        assert_eq!(
            aoi.field("Corner Latitude Point 1 (Decimal Degrees)"),
            Some(&Value::Float(90.0))
        );
        assert_eq!(
            aoi.field("Corner Longitude Point 1 (Decimal Degrees)"),
            Some(&Value::Float(-180.0))
        );
        assert_eq!(
            aoi.field("Corner Latitude Point 3 (Decimal Degrees)"),
            Some(&Value::OutOfRange)
        );
        assert_eq!(
            aoi.field("Corner Longitude Point 3 (Decimal Degrees)"),
            Some(&Value::Float(0.0))
        );
        // Code 3 is "Reserved" in the AOI set but "Target" in the POI set.
        assert_eq!(
            aoi.field("POI/AOI Type"),
            Some(&Value::Enum { code: 3, label: Some("Reserved") })
        );
        let poi = item(12, &set(&[(5, &[0x03])]));
        assert_eq!(
            poi.field("POI/AOI Type"),
            Some(&Value::Enum { code: 3, label: Some("Target") })
        );
        assert_eq!(aoi.field("POI/AOI Text"), Some(&Value::Text("area".into())));
        assert_eq!(aoi.field("POI/AOI Source ID"), Some(&Value::Text("id".into())));
        assert_eq!(aoi.field("POI/AOI Label"), Some(&Value::Text("lbl".into())));
        assert_eq!(aoi.field("Operation ID"), Some(&Value::Text("op".into())));
        // The AOI set has no altitude: its tag 4 is a corner latitude.
        assert_eq!(aoi.field("POI Altitude"), None);
    }

    #[test]
    fn interest_types() {
        for (code, label) in (1u8..).zip(POI_TYPES) {
            assert_eq!(
                interest_type(&[code], POI_TYPES),
                Value::Enum { code: u64::from(code), label: Some(label) }
            );
        }
        assert_eq!(interest_type(&[0], POI_TYPES), Value::Enum { code: 0, label: None });
        assert_eq!(interest_type(&[5], AOI_TYPES), Value::Enum { code: 5, label: None });
        assert_eq!(interest_type(&[0xFF], AOI_TYPES), Value::Enum { code: 255, label: None });
        assert_eq!(interest_type(&[], AOI_TYPES), Value::Invalid("POI/AOI Type is not 1 byte"));
    }

    #[test]
    fn zero_length_items() {
        // MISB ST 0107: a zero-length item is unknown, except for the CRC
        // and the subordinate sets, which may repeat.
        for tag in 1..=21u64 {
            let it = decode_item(tag, &[], 1, &cfg());
            let want = if matches!(tag, 1 | 11 | 12 | 13) { Value::Invalid(NO_ZLI) } else { Value::Unknown };
            assert_eq!(it.value, want, "tag {tag}");
            assert!(it.raw.is_empty());
        }
        // Inside the subordinate sets, the items a POI, AOI or User Defined
        // set must contain cannot be unknown.
        let empty_items = |tags: std::ops::RangeInclusive<u8>| -> Vec<u8> { tags.flat_map(|t| [t, 0]).collect() };
        let poi = item(12, &empty_items(1..=10));
        let aoi = item(13, &empty_items(1..=10));
        let ud = item(11, &empty_items(1..=2));
        for (v, required) in [(&poi, 3), (&aoi, 6), (&ud, 2)] {
            let fields = v.as_fields().unwrap();
            for (i, f) in fields.iter().enumerate() {
                let want = if i < required { Value::Invalid(NO_ZLI) } else { Value::Unknown };
                assert_eq!(f.value, want, "{}", f.name);
            }
        }
        assert_eq!(poi.as_fields().unwrap().len(), 10);
        assert_eq!(aoi.as_fields().unwrap().len(), 10);
    }

    #[test]
    fn poi_text_limits() {
        let long = [b'x'; 17];
        let poi = item(12, &set(&[(9, &long[..16]), (7, &[b'i'; 127])]));
        assert_eq!(poi.field("POI/AOI Label"), Some(&Value::Text("x".repeat(16))));
        assert_eq!(poi.field("POI Source Icon"), Some(&Value::Text("i".repeat(127))));
        let poi = item(12, &set(&[(9, &long), (10, &[b'o'; 128])]));
        let too_long = Value::Invalid("text is longer than the standard's maximum");
        assert_eq!(poi.field("POI/AOI Label"), Some(&too_long));
        assert_eq!(poi.field("Operation ID"), Some(&too_long));
        // POI/AOI Text allows 2048 characters; long-form BER length.
        let mut v = vec![6, 0x82, 0x08, 0x00];
        v.extend([b't'; 2048]);
        assert_eq!(item(12, &v).field("POI/AOI Text"), Some(&Value::Text("t".repeat(2048))));
        let mut v = vec![6, 0x82, 0x08, 0x01];
        v.extend([b't'; 2049]);
        assert_eq!(item(12, &v).field("POI/AOI Text"), Some(&too_long));
    }

    #[test]
    fn user_defined_data_types() {
        let data = |id: u8, v: &[u8]| item(11, &set(&[(1, &[id]), (2, v)]));
        // String, numeric ID 5.
        let s = data(0x05, b"hello");
        let id = s.field("Numeric ID for Data Type").unwrap();
        assert_eq!(id.field("Data Type"), Some(&Value::Enum { code: 0, label: Some("String") }));
        assert_eq!(id.field("Numeric ID"), Some(&Value::Uint(5)));
        assert_eq!(s.field("User Data"), Some(&Value::Text("hello".into())));
        // INT of each width.
        let int = data(0x40 | 63, &[0xFF, 0xFE]);
        let id = int.field("Numeric ID for Data Type").unwrap();
        assert_eq!(id.field("Data Type"), Some(&Value::Enum { code: 1, label: Some("INT") }));
        assert_eq!(id.field("Numeric ID"), Some(&Value::Uint(63)));
        assert_eq!(int.field("User Data"), Some(&Value::Int(-2)));
        assert_eq!(data(0x40, &[0x80]).field("User Data"), Some(&Value::Int(-128)));
        assert_eq!(
            data(0x40, &[0x7F; 8]).field("User Data"),
            Some(&Value::Int(0x7F7F_7F7F_7F7F_7F7F))
        );
        let bad_int = Value::Invalid("INT user data is not 1 to 8 bytes");
        assert_eq!(data(0x40, &[]).field("User Data"), Some(&Value::Invalid(NO_ZLI)));
        assert_eq!(data(0x40, &[0; 9]).field("User Data"), Some(&bad_int));
        // UINT.
        let uint = data(0x80 | 2, &[0xFF, 0xFE]);
        let id = uint.field("Numeric ID for Data Type").unwrap();
        assert_eq!(id.field("Data Type"), Some(&Value::Enum { code: 2, label: Some("UINT") }));
        assert_eq!(uint.field("User Data"), Some(&Value::Uint(0xFFFE)));
        let bad_uint = Value::Invalid("UINT user data is not 1 to 8 bytes");
        assert_eq!(data(0x80, &[]).field("User Data"), Some(&Value::Invalid(NO_ZLI)));
        assert_eq!(data(0x80, &[0; 9]).field("User Data"), Some(&bad_uint));
        // Experimental data stays bytes.
        let exp = data(0xC0 | 1, &[1, 2, 3]);
        let id = exp.field("Numeric ID for Data Type").unwrap();
        assert_eq!(
            id.field("Data Type"),
            Some(&Value::Enum { code: 3, label: Some("Experimental") })
        );
        assert_eq!(exp.field("User Data"), Some(&Value::Bytes(vec![1, 2, 3])));
    }

    #[test]
    fn user_defined_without_a_valid_type() {
        // No tag 1: the data has no type to read it as.
        let v = item(11, &set(&[(2, &[1, 2])]));
        assert_eq!(v.field("User Data"), Some(&Value::Bytes(vec![1, 2])));
        // A malformed tag 1 is invalid and does not type the data.
        let v = item(11, &set(&[(1, &[0x40, 0x00]), (2, &[1, 2])]));
        assert_eq!(
            v.field("Numeric ID for Data Type"),
            Some(&Value::Invalid("Numeric ID for Data Type is not 1 byte"))
        );
        assert_eq!(v.field("User Data"), Some(&Value::Bytes(vec![1, 2])));
        // Out of order (against ST 0806.4-21/22): the type still applies.
        let v = item(11, &set(&[(2, &[0xFF]), (1, &[0x40])]));
        assert_eq!(v.field("User Data"), Some(&Value::Int(-1)));
        // Tags other than 1 and 2 (against ST 0806.4-23) are kept.
        let v = item(11, &set(&[(1, &[0x00]), (3, &[9])]));
        let unknown = v.as_fields().unwrap()[1].clone();
        assert_eq!(unknown.name, "Unknown");
        assert_eq!(unknown.value.field("Tag"), Some(&Value::Uint(3)));
        assert_eq!(unknown.value.field("Value"), Some(&Value::Bytes(vec![9])));
    }

    #[test]
    fn subordinate_set_errors() {
        // A zero-length subordinate set is not allowed (it may repeat).
        assert_eq!(item(12, &[]), Value::Invalid(NO_ZLI));
        // Truncated item.
        let malformed = Value::Invalid("malformed subordinate local set");
        assert_eq!(item(12, &[1, 2, 0]), malformed);
        assert_eq!(item(13, &[1, 0x80]), malformed);
        assert_eq!(item(11, &[0x81]), malformed);
        // A truncation after good items still makes the whole set invalid.
        let mut v = set(&[(1, &[0, 1])]);
        v.extend([2, 4, 0]);
        let it = decode_item(12, &v, 1, &cfg());
        assert_eq!(it.value, malformed);
        assert_eq!(it.raw, v);
        // Unknown tags, including multi-byte BER-OID tags.
        let v = item(12, &[0x81, 0x00, 1, 0xAB, 1, 2, 0, 7]);
        let f = v.as_fields().unwrap();
        assert_eq!(f[0].name, "Unknown");
        assert_eq!(f[0].value.field("Tag"), Some(&Value::Uint(128)));
        assert_eq!(f[1].name, "POI/AOI Number");
        // Repeated items are all kept, in order.
        let v = item(12, &set(&[(1, &[0, 1]), (1, &[0, 2])]));
        assert_eq!(v.as_fields().unwrap().len(), 2);
        assert_eq!(v.field("POI/AOI Number"), Some(&Value::Uint(1)));
    }

    #[test]
    fn subordinate_sets_respect_limits() {
        let v = set(&[(1, &[0, 1]), (2, &[0, 0, 0, 0]), (3, &[0, 0, 0, 0])]);
        let mut c = cfg();
        c.max_items = 3;
        assert!(matches!(decode_item(12, &v, 1, &c).value, Value::Struct(_)));
        c.max_items = 2;
        assert_eq!(
            decode_item(12, &v, 1, &c).value,
            Value::Invalid("subordinate local set has more than Config::max_items items")
        );
        // The subordinate set lies one level below the RVT set.
        let mut c = cfg();
        c.max_depth = 2;
        assert!(matches!(decode_item(12, &v, 1, &c).value, Value::Struct(_)));
        let deep = Value::Invalid("sets nested too deeply");
        assert_eq!(decode_item(12, &v, 2, &c).value, deep);
        assert_eq!(decode_item(11, &v, 2, &c).value, deep);
        assert_eq!(decode_item(13, &v, usize::MAX, &c).value, deep);
        // Through the registry: an RVT set at depth 1 with max_depth 1
        // decodes its own items but not its subordinate sets.
        c.max_depth = 1;
        let rvt = set(&[(8, &[4]), (12, &v)]);
        let p = decode_set(Standard::St0806, &rvt, 1, &c);
        assert_eq!(p.error, None);
        assert_eq!(p.get(Tag::VersionNumber), Some(&Value::Uint(4)));
        assert_eq!(p.get(Tag::PointOfInterestLocalSet), Some(&deep));
    }

    #[test]
    fn rvt_set_with_subordinates_and_crc() {
        // A set as jMISB frames an independent packet body, CRC last; the
        // CRC is reported, not verified.
        let poi1 = set(&[(1, &[0, 1]), (2, &[0, 0, 0, 0]), (3, &[0, 0, 0, 0])]);
        let poi2 = set(&[(1, &[0, 2]), (2, &[0, 0, 0, 1]), (3, &[0, 0, 0, 1]), (7, b"SFGP")]);
        let ud = set(&[(1, &[0x81]), (2, &[0x2A])]);
        let rvt = set(&[
            (2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]),
            (12, &poi1),
            (12, &poi2),
            (11, &ud),
            (1, &[0xDE, 0xAD, 0xBE, 0xEF]),
        ]);
        let p = decode_set(Standard::St0806, &rvt, 1, &cfg());
        assert!(p.is_ok());
        assert_eq!(p.items.len(), 5);
        let pois: Vec<_> = p.iter().filter(|i| i.tag == 12).collect();
        assert_eq!(pois.len(), 2);
        assert_eq!(pois[1].value.field("POI/AOI Number"), Some(&Value::Uint(2)));
        assert_eq!(pois[1].value.field("POI Source Icon"), Some(&Value::Text("SFGP".into())));
        assert_eq!(
            p.get(Tag::UserDefinedLocalSet).unwrap().field("User Data"),
            Some(&Value::Uint(42))
        );
        assert_eq!(p.get(Tag::Checksum), Some(&Value::Uint(0xDEAD_BEEF)));
        assert_eq!(p.item(Tag::Checksum).unwrap().name, "CRC 32");
        let shown = p.to_string();
        assert!(shown.contains("POI/AOI Number: 2"), "{shown}");
    }

    #[test]
    fn unknown_rvt_tags_are_raw() {
        let it = decode_item(22, &[1], 1, &cfg());
        assert_eq!(it.name, "Unknown");
        assert_eq!(it.value, Value::Bytes(vec![1]));
    }

    #[test]
    fn hostile_values_never_panic() {
        let mut buf = Vec::new();
        for len in 0..70usize {
            for fill in [0x00u8, 0x01, 0x7F, 0x80, 0x81, 0xFF] {
                buf.clear();
                buf.extend((0..len).map(|i| fill.wrapping_mul(i as u8 | 1)));
                for tag in 0..=24 {
                    for depth in [0, 1, 7, 8, 9] {
                        let it = decode_item(tag, &buf, depth, &cfg());
                        assert_eq!(it.raw, buf);
                    }
                }
            }
        }
    }

    /// A small xorshift generator so the random tests are repeatable.
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    /// A well-framed set of up to `n - 1` items with tags below `tags`,
    /// random values, and for RVT tags 11 to 13 (when `nest`) a random
    /// well-framed subordinate set.
    fn random_set(next: &mut dyn FnMut() -> u64, n: u64, tags: u64, nest: bool) -> Vec<u8> {
        let mut set = Vec::new();
        for _ in 0..next() % n {
            let tag = (next() % tags) as u8;
            let value: Vec<u8> = if nest && (11..=13).contains(&tag) {
                random_set(next, 6, 12, false)
            } else {
                let len = next() % 24;
                (0..len).map(|_| next() as u8).collect()
            };
            set.push(tag);
            set.push(u8::try_from(value.len()).unwrap());
            set.extend(value);
        }
        set
    }

    #[test]
    fn random_sets_never_panic() {
        let mut next = rng(0x2545_F491_4F6C_DD1D);
        let mut structs = 0;
        for _ in 0..5_000 {
            let set = random_set(&mut next, 8, 24, true);
            let p = decode_set(Standard::St0806, &set, 1, &cfg());
            assert_eq!(p.error, None);
            structs += p.iter().filter(|i| matches!(i.value, Value::Struct(_))).count();
            // Random bytes, mostly malformed.
            let len = (next() % 64) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let p = decode_set(Standard::St0806, &junk, 1, &cfg());
            assert!(p.items.len() <= junk.len());
            for tag in 11..=13 {
                let _ = decode_item(tag, &junk, 1, &cfg());
            }
        }
        // The generator reaches the subordinate set decoders.
        assert!(structs > 1_000, "{structs}");
    }
}
