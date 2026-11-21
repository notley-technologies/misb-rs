//! MISB ST 0601 UAS Datalink Local Set.
//!
//! ST 0601 is the metadata local set unmanned aircraft systems embed in
//! motion imagery: platform position and attitude, sensor pointing, frame
//! corners, time stamps and mission data. A packet is [`KEY`], a BER length
//! and a run of items, each a BER-OID tag, a BER length and a value (ST 0601
//! section 6). [`Tag`] lists all 143 items of ST 0601.19 (02 March 2023)
//! Table 1, and every item decodes into a [`Value`] following its section 8
//! summary table. Tag numbers are never reassigned between revisions, so
//! packets from earlier revisions (tag 65 below 19) decode with the same
//! table.
//!
//! # How values decode
//!
//! | ST 0601 format | [`Value`] |
//! |---|---|
//! | `uintN` mapped to a range | [`Value::Float`] `= (range / (2^N - 1)) * x + offset` |
//! | `intN` mapped to `+/-R` | [`Value::Float`] `= (2R / (2^N - 2)) * x` |
//! | unmapped `uint` / `int` | [`Value::Uint`] / [`Value::Int`] |
//! | time stamps (tags 2, 72, 131) | [`Value::Time`], microseconds since 1970 in MISP time (ST 0603): no leap seconds, so not UTC |
//! | `utf8` strings | [`Value::Text`], lossy UTF-8 (older revisions used ISO 646, a subset) |
//! | enumerations | [`Value::Enum`] with the standard's label |
//! | `IMAPB` (MISB ST 1201) | [`Value::Float`] through [`Imapb`](crate::imapb::Imapb), any length from 1 byte to the item's maximum |
//! | nested local sets (48, 73, 74, 100, 101) | [`Value::Set`] |
//! | packs and lists | [`Value::Struct`] / [`Value::List`] with the field names of the standard |
//! | zero-length item (section 6.5) | [`Value::Unknown`] |
//!
//! The formulas are the ones in each item's summary table; `span` is
//! `2^N - 1` for unsigned and `2^N - 2` for signed items because the most
//! negative signed code is not part of the mapping. All arithmetic is `f64`,
//! as in the standard's own examples.
//!
//! Special codes of signed mapped items (the most negative code, `0x8000` or
//! `0x8000_0000`) are checked before any arithmetic:
//!
//! - "Out of Range" (tags 6, 7, 50 to 52, 79, 80, 90 to 93) and the tag 81
//!   "error" indicator decode to [`Value::OutOfRange`].
//! - "Reserved" (tags 13, 14, 19, 67, 68) also decodes to
//!   [`Value::OutOfRange`]: it carries no position, and ST 0601.8 defined
//!   the same code as an "error" indicator, which legacy encoders still send.
//! - "N/A (Off-Earth)" (tags 23, 24, 26 to 33, 40, 41, 82 to 89) is a
//!   meaningful state (the point lies above the horizon), not an error, so it
//!   decodes to [`Value::Enum`] with the code as received and the label
//!   `"N/A (Off-Earth)"`.
//!
//! Enumeration codes the standard marks Reserved get the label `"Reserved"`;
//! codes it does not mention at all get no label. Bit flags decode by
//! meaning: tag 47 to a [`Value::Struct`] with one [`Value::Enum`] per
//! defined bit, tag 124 to a [`Value::List`] of the set flags, and tag 139 to
//! a [`Value::List`] of the active payload identifiers.
//!
//! Inside packs, a field the standard lets the producer mark as unknown with
//! a zero length (the countries of tag 122, the locations of tag 130, the
//! pairs of tag 142) is [`Value::Unknown`]. A field the producer truncated
//! is left out of the [`Value::Struct`], except where the standard gives a
//! default: the tag 127 denominator defaults to 1 and a missing tag 130
//! recovery location equals the take-off location. A record
//! of a list (tags 128, 138, 140, 141) that does not decode becomes
//! [`Value::Invalid`] in the list without hiding the records around it.
//! Lists hold at most [`Config::max_items`] elements; a longer list is
//! [`Value::Invalid`].
//!
//! A zero-length item (ZLI) means the producer reports the value as now
//! unknown (ST 0601 section 6.5, MISB ST 0107) and decodes to
//! [`Value::Unknown`]. The mandatory items (1, 2, 65) and the items that may
//! repeat (100, 101, 102, 115) may not be zero length, and such an item is
//! [`Value::Invalid`].
//!
//! A value whose length the standard does not allow is [`Value::Invalid`]
//! with a short reason; the bytes stay in [`Item::raw`]. Strings longer than
//! the 127 (tag 129: 32) bytes of their summary table still decode, as the
//! standard calls that limit a suggested maximum.
//!
//! The SAR Motion Imagery, Range Image, Geo-Registration and Composite
//! Imaging sets (tags 95, 97, 98, 99) and the deprecated tag 66 stay
//! [`Value::Bytes`]. Packet-level rules (tag 2 first, tag 1 last, tag 65
//! present, no repeats except where allowed, tag 143 only inside tags 100 and
//! 101, which of two representations takes precedence) are left to the
//! application; the checksum (tag 1) is verified when the packet is decoded.
//!
//! # Units
//!
//! [`Item::units`] and [`Tag::units`] use this vocabulary:
//!
//! | units | meaning |
//! |---|---|
//! | `deg` | degrees: angles, and WGS84 latitude and longitude |
//! | `deg/s` | degrees per second |
//! | `m` | metres |
//! | `km` | kilometres |
//! | `m/s` | metres per second |
//! | `mbar` | millibar |
//! | `C` | degrees Celsius |
//! | `%` | percent |
//! | `kg` | kilograms |
//! | `s` | seconds |
//! | `us` | microseconds |
//! | `pixels` | image pixels |
//! | `rpm` | revolutions per minute |
//! | `Hz` | hertz (frames per second) |
//! | `MHz` | megahertz |
//! | `GB` | gigabytes |
//! | `nm` | nanometres |
//! | empty | no units: text, codes, counts, identifiers, flags, sets, and packs whose fields mix units |
//!
//! The units of pack fields are given in each [`Tag`]'s documentation.

use crate::imapb;
use crate::klv::{be_int, be_uint};
use crate::registry::{decode_set, unknown_item};
use crate::{Config, Field, Item, Standard, Value};

#[cfg(feature = "encode")]
pub(crate) mod encode;

/// The 16-byte key that starts every ST 0601 UAS Datalink Local Set packet
/// (ST 0601.19 section 6.2, registered in MISB ST 0807).
pub const KEY: [u8; 16] = [
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

// Integer spans of the mapped formats (ST 0601.19 section 8 summary tables):
// 2^N - 1 for unsigned items, 2^N - 2 for signed items.
const U8: f64 = 255.0;
const U16: f64 = 65_535.0;
const U32: f64 = 4_294_967_295.0;
const S16: f64 = 65_534.0;
const S32: f64 = 4_294_967_294.0;

// Reasons given in Value::Invalid.
const BAD_LENGTH: &str = "wrong length for this tag";
const TOO_LONG: &str = "longer than this tag allows";
const NO_ZLI: &str = "zero-length item not allowed for this tag";
const BAD_PACK: &str = "pack is truncated or malformed";
const TRAILING: &str = "unexpected bytes after the last pack field";
const TOO_MANY: &str = "list longer than Config::max_items";

/// Allowed value lengths.
#[derive(Clone, Copy, Debug)]
enum Len {
    /// Exactly this many bytes (the summary table's "Required Length").
    Exact(usize),
    /// 1 up to this many bytes ("Variable" with a "Max Length"); empty
    /// values are zero-length items, handled before any codec.
    UpTo(usize),
}

impl Len {
    fn check(self, v: &[u8]) -> Result<&[u8], &'static str> {
        match self {
            Len::Exact(n) if v.len() != n => Err(BAD_LENGTH),
            Len::UpTo(n) if v.len() > n => Err(TOO_LONG),
            _ => Ok(v),
        }
    }
}

/// What the most negative code of a signed mapped item means.
#[derive(Clone, Copy, Debug)]
enum Special {
    /// "Out of Range" indicator.
    OutOfRange,
    /// "error" indicator (tag 81 latitudes and longitudes).
    Error,
    /// "Reserved".
    Reserved,
    /// "N/A (Off-Earth)" indicator.
    OffEarth,
}

impl Special {
    fn value(self, code: u64) -> Value {
        match self {
            Special::OutOfRange | Special::Error | Special::Reserved => Value::OutOfRange,
            Special::OffEarth => Value::Enum { code, label: Some("N/A (Off-Earth)") },
        }
    }
}

/// How one item's value decodes.
#[derive(Clone, Copy)]
enum Codec {
    /// Unmapped unsigned integer: [`Value::Uint`].
    Uint(Len),
    /// Unmapped two's complement integer: [`Value::Int`].
    Int(Len),
    /// Unsigned microseconds since 1970 (MISB ST 0603): [`Value::Time`].
    Time(Len),
    /// Unsigned integer times a factor: [`Value::Uint`].
    Scaled { len: usize, factor: u64 },
    /// Unsigned integer mapped as `range / (2^N - 1) * x + offset`:
    /// [`Value::Float`]. The table keeps the range rather than the scale so
    /// that the encoder can apply the standard's forward formula `round((x -
    /// offset) * (2^N - 1) / range)` exactly.
    Unsigned { len: usize, range: f64, offset: f64 },
    /// Signed integer mapped as `range / (2^N - 2) * x` (the item covers
    /// `+/-range/2`), the most negative code special.
    Signed { len: usize, range: f64, special: Special },
    /// MISB ST 1201 IMAPB over `[min, max]`, 1 to `max_len` bytes.
    Imapb { min: f64, max: f64, max_len: usize },
    /// UTF-8 string: [`Value::Text`].
    Text,
    /// One-byte enumeration: [`Value::Enum`].
    Enum(&'static Labels),
    /// Nested local set: [`Value::Set`].
    Set(Standard),
    /// Kept as [`Value::Bytes`].
    Bytes,
    /// Pack, list or other structured value.
    Pack(fn(&[u8], &Config) -> Result<Value, &'static str>),
}

/// Labels of an enumeration whose codes start at 0.
struct Labels {
    /// Label of code `i` at index `i`.
    names: &'static [&'static str],
    /// Codes from `names.len()` through this one are marked Reserved by the
    /// standard; 0 when none are.
    reserved_to: u64,
}

impl Labels {
    fn label(&self, code: u64) -> Option<&'static str> {
        match usize::try_from(code).ok().and_then(|i| self.names.get(i)) {
            Some(name) => Some(name),
            None if code <= self.reserved_to => Some("Reserved"),
            None => None,
        }
    }

    fn value(&self, code: u64) -> Value {
        Value::Enum { code, label: self.label(code) }
    }
}

/// Static description of one tag.
struct Desc {
    tag: Tag,
    name: &'static str,
    units: &'static str,
    codec: Codec,
}

// Mappings shared by several tags (ST 0601.19 section 8 summary tables).
const HEADING: Codec = Codec::Unsigned { len: 2, range: 360.0, offset: 0.0 };
const ALTITUDE: Codec = Codec::Unsigned { len: 2, range: 19_900.0, offset: -900.0 };
const FIELD_OF_VIEW: Codec = Codec::Unsigned { len: 2, range: 180.0, offset: 0.0 };
const ANGLE_U32: Codec = Codec::Unsigned { len: 4, range: 360.0, offset: 0.0 };
const RANGE_U32: Codec = Codec::Unsigned { len: 4, range: 5_000_000.0, offset: 0.0 };
const PRESSURE: Codec = Codec::Unsigned { len: 2, range: 5_000.0, offset: 0.0 };
const TEN_THOUSAND: Codec = Codec::Unsigned { len: 2, range: 10_000.0, offset: 0.0 };
const HUNDRED_U8: Codec = Codec::Unsigned { len: 1, range: 100.0, offset: 0.0 };
const ERROR_ESTIMATE: Codec = Codec::Unsigned { len: 2, range: 4_095.0, offset: 0.0 };
const ANGLE_20: Codec = Codec::Signed { len: 2, range: 40.0, special: Special::OutOfRange };
const VELOCITY: Codec = Codec::Signed { len: 2, range: 654.0, special: Special::OutOfRange };
const FULL_90: Codec = Codec::Signed { len: 4, range: 180.0, special: Special::OutOfRange };
const LAT_RESERVED: Codec = Codec::Signed { len: 4, range: 180.0, special: Special::Reserved };
const LON_RESERVED: Codec = Codec::Signed { len: 4, range: 360.0, special: Special::Reserved };
const LAT_OFF_EARTH: Codec = Codec::Signed { len: 4, range: 180.0, special: Special::OffEarth };
const LON_OFF_EARTH: Codec = Codec::Signed { len: 4, range: 360.0, special: Special::OffEarth };
const CORNER_OFFSET: Codec = Codec::Signed { len: 2, range: 0.15, special: Special::OffEarth };
const HEIGHT_EXTENDED: Codec = Codec::Imapb { min: -900.0, max: 40_000.0, max_len: 8 };
const HEIGHT_AGL: Codec = Codec::Imapb { min: -900.0, max: 40_000.0, max_len: 4 };
const ANGLE_RATE: Codec = Codec::Imapb { min: -1_000.0, max: 1_000.0, max_len: 4 };
const TEXT: Codec = Codec::Text;
const TIME: Codec = Codec::Time(Len::Exact(8));

/// Defines [`Tag`] and the descriptor table from one list, so the two cannot
/// drift apart. Entries must be in tag order; a unit test checks it.
macro_rules! tags {
    ($( $(#[doc = $doc:literal])* $tag:literal, $variant:ident, $name:literal, $units:literal, $codec:expr; )*) => {
        /// Items of the UAS Datalink Local Set (ST 0601.19 Table 1).
        ///
        /// The documentation of each item cites its ST 0601.19 section and
        /// says how it decodes. Converts into the tag number with
        /// `u64::from`, so `packet.get(Tag::SensorLatitude)` works.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[non_exhaustive]
        pub enum Tag {
            $( $(#[doc = $doc])* $variant = $tag, )*
        }

        /// One descriptor per tag: `DESCS[n - 1]` describes tag `n`.
        static DESCS: [Desc; 143] = [
            $( Desc { tag: Tag::$variant, name: $name, units: $units, codec: $codec }, )*
        ];
    };
}

tags! {
    /// Item 1 (8.1): uint16 checksum over the whole packet ([`Value::Uint`]).
    /// Mandatory, the last item; verified when the packet is decoded.
    1, Checksum, "Checksum", "", Codec::Uint(Len::Exact(2));
    /// Item 2 (8.2): uint64 microseconds since 1970 in MISP time
    /// ([`Value::Time`], MISB ST 0603; no leap seconds, see tag 136).
    /// Mandatory, the first item.
    2, PrecisionTimeStamp, "Precision Time Stamp", "us", TIME;
    /// Item 3 (8.3): free text mission identifier ([`Value::Text`]).
    3, MissionId, "Mission ID", "", TEXT;
    /// Item 4 (8.4): platform tail number ([`Value::Text`]).
    4, PlatformTailNumber, "Platform Tail Number", "", TEXT;
    /// Item 5 (8.5): uint16 mapped to 0..360 deg from true north.
    5, PlatformHeadingAngle, "Platform Heading Angle", "deg", HEADING;
    /// Item 6 (8.6): int16 mapped to +/-20 deg, nose up positive;
    /// `0x8000` is [`Value::OutOfRange`]. Tag 90 is the full-range form.
    6, PlatformPitchAngle, "Platform Pitch Angle", "deg", ANGLE_20;
    /// Item 7 (8.7): int16 mapped to +/-50 deg, right wing down positive;
    /// `0x8000` is [`Value::OutOfRange`]. Tag 91 is the full-range form.
    7, PlatformRollAngle, "Platform Roll Angle", "deg",
        Codec::Signed { len: 2, range: 100.0, special: Special::OutOfRange };
    /// Item 8 (8.8): uint8, 0..255 m/s ([`Value::Uint`]).
    8, PlatformTrueAirspeed, "Platform True Airspeed", "m/s", Codec::Uint(Len::Exact(1));
    /// Item 9 (8.9): uint8, 0..255 m/s ([`Value::Uint`]).
    9, PlatformIndicatedAirspeed, "Platform Indicated Airspeed", "m/s", Codec::Uint(Len::Exact(1));
    /// Item 10 (8.10): platform model name ([`Value::Text`]).
    10, PlatformDesignation, "Platform Designation", "", TEXT;
    /// Item 11 (8.11): image source sensor name ([`Value::Text`]).
    11, ImageSourceSensor, "Image Source Sensor", "", TEXT;
    /// Item 12 (8.12): image coordinate system name ([`Value::Text`]).
    12, ImageCoordinateSystem, "Image Coordinate System", "", TEXT;
    /// Item 13 (8.13): int32 mapped to +/-90 deg, WGS84; `0x8000_0000`
    /// ("Reserved") is [`Value::OutOfRange`].
    13, SensorLatitude, "Sensor Latitude", "deg", LAT_RESERVED;
    /// Item 14 (8.14): int32 mapped to +/-180 deg, WGS84; `0x8000_0000`
    /// ("Reserved") is [`Value::OutOfRange`].
    14, SensorLongitude, "Sensor Longitude", "deg", LON_RESERVED;
    /// Item 15 (8.15): uint16 mapped to -900..19000 m above MSL. Tag 75
    /// (HAE) takes precedence.
    15, SensorTrueAltitude, "Sensor True Altitude", "m", ALTITUDE;
    /// Item 16 (8.16): uint16 mapped to 0..180 deg.
    16, SensorHorizontalFieldOfView, "Sensor Horizontal Field of View", "deg", FIELD_OF_VIEW;
    /// Item 17 (8.17): uint16 mapped to 0..180 deg.
    17, SensorVerticalFieldOfView, "Sensor Vertical Field of View", "deg", FIELD_OF_VIEW;
    /// Item 18 (8.18): uint32 mapped to 0..360 deg from the platform
    /// longitudinal axis.
    18, SensorRelativeAzimuthAngle, "Sensor Relative Azimuth Angle", "deg", ANGLE_U32;
    /// Item 19 (8.19): int32 mapped to +/-180 deg, down negative;
    /// `0x8000_0000` ("Reserved") is [`Value::OutOfRange`].
    19, SensorRelativeElevationAngle, "Sensor Relative Elevation Angle", "deg", LON_RESERVED;
    /// Item 20 (8.20): uint32 mapped to 0..360 deg about the lens axis.
    20, SensorRelativeRollAngle, "Sensor Relative Roll Angle", "deg", ANGLE_U32;
    /// Item 21 (8.21): uint32 mapped to 0..5,000,000 m.
    21, SlantRange, "Slant Range", "m", RANGE_U32;
    /// Item 22 (8.22): uint16 mapped to 0..10,000 m. Tag 96 is the extended
    /// form.
    22, TargetWidth, "Target Width", "m", TEN_THOUSAND;
    /// Item 23 (8.23): int32 mapped to +/-90 deg, WGS84; `0x8000_0000` is
    /// `Enum` "N/A (Off-Earth)".
    23, FrameCenterLatitude, "Frame Center Latitude", "deg", LAT_OFF_EARTH;
    /// Item 24 (8.24): int32 mapped to +/-180 deg, WGS84; `0x8000_0000` is
    /// `Enum` "N/A (Off-Earth)".
    24, FrameCenterLongitude, "Frame Center Longitude", "deg", LON_OFF_EARTH;
    /// Item 25 (8.25): uint16 mapped to -900..19000 m above MSL. Tag 78
    /// (HAE) takes precedence.
    25, FrameCenterElevation, "Frame Center Elevation", "m", ALTITUDE;
    /// Item 26 (8.26): int16 mapped to +/-0.075 deg, upper left corner
    /// latitude minus tag 23; `0x8000` is `Enum` "N/A (Off-Earth)".
    26, OffsetCornerLatitudePoint1, "Offset Corner Latitude Point 1", "deg", CORNER_OFFSET;
    /// Item 27 (8.27): int16 mapped to +/-0.075 deg, upper left corner
    /// longitude minus tag 24; `0x8000` is `Enum` "N/A (Off-Earth)".
    27, OffsetCornerLongitudePoint1, "Offset Corner Longitude Point 1", "deg", CORNER_OFFSET;
    /// Item 28 (8.28): as tag 26 for the upper right corner.
    28, OffsetCornerLatitudePoint2, "Offset Corner Latitude Point 2", "deg", CORNER_OFFSET;
    /// Item 29 (8.29): as tag 27 for the upper right corner.
    29, OffsetCornerLongitudePoint2, "Offset Corner Longitude Point 2", "deg", CORNER_OFFSET;
    /// Item 30 (8.30): as tag 26 for the lower right corner.
    30, OffsetCornerLatitudePoint3, "Offset Corner Latitude Point 3", "deg", CORNER_OFFSET;
    /// Item 31 (8.31): as tag 27 for the lower right corner.
    31, OffsetCornerLongitudePoint3, "Offset Corner Longitude Point 3", "deg", CORNER_OFFSET;
    /// Item 32 (8.32): as tag 26 for the lower left corner.
    32, OffsetCornerLatitudePoint4, "Offset Corner Latitude Point 4", "deg", CORNER_OFFSET;
    /// Item 33 (8.33): as tag 27 for the lower left corner.
    33, OffsetCornerLongitudePoint4, "Offset Corner Longitude Point 4", "deg", CORNER_OFFSET;
    /// Item 34 (8.34): uint8 enumeration: 0 Detector off, 1 No icing
    /// Detected, 2 Icing Detected.
    34, IcingDetected, "Icing Detected", "", Codec::Enum(&ICING);
    /// Item 35 (8.35): uint16 mapped to 0..360 deg, the direction the wind
    /// comes from.
    35, WindDirection, "Wind Direction", "deg", HEADING;
    /// Item 36 (8.36): uint8 mapped to 0..100 m/s.
    36, WindSpeed, "Wind Speed", "m/s", HUNDRED_U8;
    /// Item 37 (8.37): uint16 mapped to 0..5000 mbar.
    37, StaticPressure, "Static Pressure", "mbar", PRESSURE;
    /// Item 38 (8.38): uint16 mapped to -900..19000 m. Tag 103 is the
    /// extended form.
    38, DensityAltitude, "Density Altitude", "m", ALTITUDE;
    /// Item 39 (8.39): int8, -128..127 degrees Celsius ([`Value::Int`]).
    39, OutsideAirTemperature, "Outside Air Temperature", "C", Codec::Int(Len::Exact(1));
    /// Item 40 (8.40): int32 mapped to +/-90 deg, WGS84; `0x8000_0000` is
    /// `Enum` "N/A (Off-Earth)".
    40, TargetLocationLatitude, "Target Location Latitude", "deg", LAT_OFF_EARTH;
    /// Item 41 (8.41): int32 mapped to +/-180 deg, WGS84; `0x8000_0000` is
    /// `Enum` "N/A (Off-Earth)".
    41, TargetLocationLongitude, "Target Location Longitude", "deg", LON_OFF_EARTH;
    /// Item 42 (8.42): uint16 mapped to -900..19000 m; above MSL when only
    /// tag 25 is in the stream, above the ellipsoid when tag 78 is.
    42, TargetLocationElevation, "Target Location Elevation", "m", ALTITUDE;
    /// Item 43 (8.43): uint8 times 2, 0..510 pixels ([`Value::Uint`]).
    43, TargetTrackGateWidth, "Target Track Gate Width", "pixels", Codec::Scaled { len: 1, factor: 2 };
    /// Item 44 (8.44): uint8 times 2, 0..510 pixels ([`Value::Uint`]).
    44, TargetTrackGateHeight, "Target Track Gate Height", "pixels", Codec::Scaled { len: 1, factor: 2 };
    /// Item 45 (8.45): uint16 mapped to 0..4095 m.
    45, TargetErrorEstimateCe90, "Target Error Estimate - CE90", "m", ERROR_ESTIMATE;
    /// Item 46 (8.46): uint16 mapped to 0..4095 m.
    46, TargetErrorEstimateLe90, "Target Error Estimate - LE90", "m", ERROR_ESTIMATE;
    /// Item 47 (8.47, Table 3): bit flags as a [`Value::Struct`] of
    /// [`Value::Enum`] fields (code 0 or 1 with the meaning as label):
    /// "Laser Range", "Auto-Track", "IR Polarity", "Icing Status", "Slant
    /// Range", "Image Invalid". Exactly one byte with bits 6 and 7 zero
    /// (Required Length 1, ST 0601.13-29; DECISIONS P-4), anything else is
    /// [`Value::Invalid`]; ST 0601.13 to .16 inverted the meanings by
    /// mistake.
    47, GenericFlagData, "Generic Flag Data", "", Codec::Pack(generic_flag_data);
    /// Item 48 (8.48): nested MISB ST 0102 Security Metadata Local Set
    /// ([`Value::Set`] of [`Standard::St0102`]).
    48, SecurityLocalSet, "Security Local Set", "", Codec::Set(Standard::St0102);
    /// Item 49 (8.49): uint16 mapped to 0..5000 mbar.
    49, DifferentialPressure, "Differential Pressure", "mbar", PRESSURE;
    /// Item 50 (8.50): int16 mapped to +/-20 deg; `0x8000` is
    /// [`Value::OutOfRange`]. Tag 92 is the full-range form.
    50, PlatformAngleOfAttack, "Platform Angle of Attack", "deg", ANGLE_20;
    /// Item 51 (8.51): int16 mapped to +/-180 m/s, ascending positive;
    /// `0x8000` is [`Value::OutOfRange`].
    51, PlatformVerticalSpeed, "Platform Vertical Speed", "m/s",
        Codec::Signed { len: 2, range: 360.0, special: Special::OutOfRange };
    /// Item 52 (8.52): int16 mapped to +/-20 deg; `0x8000` is
    /// [`Value::OutOfRange`]. Tag 93 is the full-range form.
    52, PlatformSideslipAngle, "Platform Sideslip Angle", "deg", ANGLE_20;
    /// Item 53 (8.53): uint16 mapped to 0..5000 mbar.
    53, AirfieldBarometricPressure, "Airfield Barometric Pressure", "mbar", PRESSURE;
    /// Item 54 (8.54): uint16 mapped to -900..19000 m.
    54, AirfieldElevation, "Airfield Elevation", "m", ALTITUDE;
    /// Item 55 (8.55): uint8 mapped to 0..100 %.
    55, RelativeHumidity, "Relative Humidity", "%", HUNDRED_U8;
    /// Item 56 (8.56): uint8, 0..255 m/s ([`Value::Uint`]).
    56, PlatformGroundSpeed, "Platform Ground Speed", "m/s", Codec::Uint(Len::Exact(1));
    /// Item 57 (8.57): uint32 mapped to 0..5,000,000 m.
    57, GroundRange, "Ground Range", "m", RANGE_U32;
    /// Item 58 (8.58): uint16 mapped to 0..10,000 kg.
    58, PlatformFuelRemaining, "Platform Fuel Remaining", "kg", TEN_THOUSAND;
    /// Item 59 (8.59): call sign ([`Value::Text`]).
    59, PlatformCallSign, "Platform Call Sign", "", TEXT;
    /// Item 60 (8.60): two bytes of nibbles as a [`Value::Struct`] of
    /// [`Value::Uint`]: "Station Number", "Substation Number", "Weapon
    /// Type", "Weapon Variant". Replaced by tag 140.
    60, WeaponLoad, "Weapon Load", "", Codec::Pack(weapon_load);
    /// Item 61 (8.61): one byte of nibbles as a [`Value::Struct`]: "Station
    /// Number", "Substation Number" (the first byte of tag 60 per 8.61.1).
    /// Replaced by tag 140.
    61, WeaponFired, "Weapon Fired", "", Codec::Pack(weapon_fired);
    /// Item 62 (8.62): uint16 laser pulse repetition frequency code
    /// ([`Value::Uint`]): three or four digits, each 1 to 8. Other values
    /// are [`Value::Invalid`].
    62, LaserPrfCode, "Laser PRF Code", "", Codec::Pack(laser_prf_code);
    /// Item 63 (8.63, Table 4): uint8 enumeration of lens names, 0
    /// Ultranarrow through 8 Continuous Zoom (the summary table's maximum of
    /// 7 predates code 8).
    63, SensorFieldOfViewName, "Sensor Field of View Name", "", Codec::Enum(&FIELD_OF_VIEW_NAMES);
    /// Item 64 (8.64): uint16 mapped to 0..360 deg from magnetic north.
    64, PlatformMagneticHeading, "Platform Magnetic Heading", "deg", HEADING;
    /// Item 65 (8.65): uint8 ST 0601 revision used by the producer
    /// ([`Value::Uint`]; 19 for ST 0601.19, 0 for pre-release or test data).
    /// Mandatory.
    65, UasDatalinkLsVersionNumber, "UAS Datalink LS Version Number", "", Codec::Uint(Len::Exact(1));
    /// Item 66 (8.66): deprecated (formerly the target location covariance
    /// matrix, now carried by tag 102). Kept as [`Value::Bytes`].
    66, Deprecated, "Deprecated", "", Codec::Bytes;
    /// Item 67 (8.67): int32 mapped to +/-90 deg, WGS84; `0x8000_0000`
    /// ("Reserved") is [`Value::OutOfRange`].
    67, AlternatePlatformLatitude, "Alternate Platform Latitude", "deg", LAT_RESERVED;
    /// Item 68 (8.68): int32 mapped to +/-180 deg, WGS84; `0x8000_0000`
    /// ("Reserved") is [`Value::OutOfRange`].
    68, AlternatePlatformLongitude, "Alternate Platform Longitude", "deg", LON_RESERVED;
    /// Item 69 (8.69): uint16 mapped to -900..19000 m above MSL.
    69, AlternatePlatformAltitude, "Alternate Platform Altitude", "m", ALTITUDE;
    /// Item 70 (8.70): alternate platform name ([`Value::Text`]).
    70, AlternatePlatformName, "Alternate Platform Name", "", TEXT;
    /// Item 71 (8.71): uint16 mapped to 0..360 deg from true north.
    71, AlternatePlatformHeading, "Alternate Platform Heading", "deg", HEADING;
    /// Item 72 (8.72): uint64 microseconds since 1970 in MISP time
    /// ([`Value::Time`]).
    72, EventStartTime, "Event Start Time", "us", TIME;
    /// Item 73 (8.73): nested MISB ST 0806 Remote Video Terminal Local Set
    /// ([`Value::Set`] of [`Standard::St0806`]).
    73, RvtLocalSet, "RVT Local Set", "", Codec::Set(Standard::St0806);
    /// Item 74 (8.74): nested MISB ST 0903 VMTI Local Set ([`Value::Set`] of
    /// [`Standard::St0903`]).
    74, VmtiLocalSet, "VMTI Local Set", "", Codec::Set(Standard::St0903);
    /// Item 75 (8.75): uint16 mapped to -900..19000 m above the WGS84
    /// ellipsoid. Tag 104 is the extended form.
    75, SensorEllipsoidHeight, "Sensor Ellipsoid Height", "m", ALTITUDE;
    /// Item 76 (8.76): uint16 mapped to -900..19000 m above the WGS84
    /// ellipsoid. Tag 105 is the extended form.
    76, AlternatePlatformEllipsoidHeight, "Alternate Platform Ellipsoid Height", "m", ALTITUDE;
    /// Item 77 (8.77, Table 5): uint8 enumeration: 0 Other, 1 Operational,
    /// 2 Training, 3 Exercise, 4 Maintenance, 5 Test.
    77, OperationalMode, "Operational Mode", "", Codec::Enum(&OPERATIONAL_MODES);
    /// Item 78 (8.78): uint16 mapped to -900..19000 m above the WGS84
    /// ellipsoid.
    78, FrameCenterHeightAboveEllipsoid, "Frame Center Height Above Ellipsoid", "m", ALTITUDE;
    /// Item 79 (8.79): int16 mapped to +/-327 m/s, north positive; `0x8000`
    /// is [`Value::OutOfRange`].
    79, SensorNorthVelocity, "Sensor North Velocity", "m/s", VELOCITY;
    /// Item 80 (8.80): int16 mapped to +/-327 m/s, east positive; `0x8000`
    /// is [`Value::OutOfRange`].
    80, SensorEastVelocity, "Sensor East Velocity", "m/s", VELOCITY;
    /// Item 81 (8.81, Table 6): [`Value::Struct`] of "Start x0", "Start
    /// y0", "End x1", "End y1" (uint8 percent of the image width or height,
    /// 0 to 100) and then, as far as present, "Start Latitude", "Start
    /// Longitude", "End Latitude", "End Longitude" (int32 mapped to +/-90 or
    /// +/-180 deg; `0x8000_0000` "error" is [`Value::OutOfRange`]). Table 6
    /// marks each of the four geographic values optional, so 4, 8, 12, 16
    /// and 20 bytes are accepted.
    81, ImageHorizonPixelPack, "Image Horizon Pixel Pack", "", Codec::Pack(image_horizon_pixel_pack);
    /// Item 82 (8.82): int32 mapped to +/-90 deg, upper left corner, WGS84;
    /// `0x8000_0000` is `Enum` "N/A (Off-Earth)".
    82, CornerLatitudePoint1Full, "Corner Latitude Point 1 (Full)", "deg", LAT_OFF_EARTH;
    /// Item 83 (8.83): int32 mapped to +/-180 deg, upper left corner, WGS84;
    /// `0x8000_0000` is `Enum` "N/A (Off-Earth)".
    83, CornerLongitudePoint1Full, "Corner Longitude Point 1 (Full)", "deg", LON_OFF_EARTH;
    /// Item 84 (8.84): as tag 82 for the upper right corner.
    84, CornerLatitudePoint2Full, "Corner Latitude Point 2 (Full)", "deg", LAT_OFF_EARTH;
    /// Item 85 (8.85): as tag 83 for the upper right corner.
    85, CornerLongitudePoint2Full, "Corner Longitude Point 2 (Full)", "deg", LON_OFF_EARTH;
    /// Item 86 (8.86): as tag 82 for the lower right corner.
    86, CornerLatitudePoint3Full, "Corner Latitude Point 3 (Full)", "deg", LAT_OFF_EARTH;
    /// Item 87 (8.87): as tag 83 for the lower right corner.
    87, CornerLongitudePoint3Full, "Corner Longitude Point 3 (Full)", "deg", LON_OFF_EARTH;
    /// Item 88 (8.88): as tag 82 for the lower left corner.
    88, CornerLatitudePoint4Full, "Corner Latitude Point 4 (Full)", "deg", LAT_OFF_EARTH;
    /// Item 89 (8.89): as tag 83 for the lower left corner.
    89, CornerLongitudePoint4Full, "Corner Longitude Point 4 (Full)", "deg", LON_OFF_EARTH;
    /// Item 90 (8.90): int32 mapped to +/-90 deg; `0x8000_0000` is
    /// [`Value::OutOfRange`].
    90, PlatformPitchAngleFull, "Platform Pitch Angle (Full)", "deg", FULL_90;
    /// Item 91 (8.91): int32 mapped to +/-90 deg; `0x8000_0000` is
    /// [`Value::OutOfRange`].
    91, PlatformRollAngleFull, "Platform Roll Angle (Full)", "deg", FULL_90;
    /// Item 92 (8.92): int32 mapped to +/-90 deg; `0x8000_0000` is
    /// [`Value::OutOfRange`].
    92, PlatformAngleOfAttackFull, "Platform Angle of Attack (Full)", "deg", FULL_90;
    /// Item 93 (8.93): int32 mapped to +/-180 deg; `0x8000_0000` is
    /// [`Value::OutOfRange`].
    93, PlatformSideslipAngleFull, "Platform Sideslip Angle (Full)", "deg",
        Codec::Signed { len: 4, range: 360.0, special: Special::OutOfRange };
    /// Item 94 (8.94): MISB ST 1204 MIIS Core Identifier, binary value
    /// without the ST 1204 key and length; decoded by the crate's ST 1204
    /// module.
    94, MiisCoreIdentifier, "MIIS Core Identifier", "", Codec::Pack(miis_core_identifier);
    /// Item 95 (8.95): nested MISB ST 1206 SAR Motion Imagery Local Set,
    /// kept as [`Value::Bytes`].
    95, SarMotionImageryLocalSet, "SAR Motion Imagery Local Set", "", Codec::Bytes;
    /// Item 96 (8.96): IMAPB(0, 1500000), 1 to 8 bytes.
    96, TargetWidthExtended, "Target Width Extended", "m",
        Codec::Imapb { min: 0.0, max: 1_500_000.0, max_len: 8 };
    /// Item 97 (8.97): nested MISB ST 1002 Range Image Local Set, kept as
    /// [`Value::Bytes`].
    97, RangeImageLocalSet, "Range Image Local Set", "", Codec::Bytes;
    /// Item 98 (8.98): nested MISB ST 1601 Geo-Registration Local Set, kept
    /// as [`Value::Bytes`].
    98, GeoRegistrationLocalSet, "Geo-Registration Local Set", "", Codec::Bytes;
    /// Item 99 (8.99): nested MISB ST 1602 Composite Imaging Local Set, kept
    /// as [`Value::Bytes`].
    99, CompositeImagingLocalSet, "Composite Imaging Local Set", "", Codec::Bytes;
    /// Item 100 (8.100, section 7.6): MISB ST 1607 Segment Local Set of ST
    /// 0601 items ([`Value::Set`] of [`Standard::St0601`]). May repeat.
    100, SegmentLocalSet, "Segment Local Set", "", Codec::Set(Standard::St0601);
    /// Item 101 (8.101, section 7.6): MISB ST 1607 Amend Local Set of ST
    /// 0601 items ([`Value::Set`] of [`Standard::St0601`]). May repeat.
    101, AmendLocalSet, "Amend Local Set", "", Codec::Set(Standard::St0601);
    /// Item 102 (8.102): MISB ST 1010 Standard Deviation and Cross
    /// Correlation Floating Length Pack for the items before it; decoded by
    /// the crate's ST 1010 module. May repeat.
    102, SdccFlp, "SDCC-FLP", "", Codec::Pack(sdcc_flp);
    /// Item 103 (8.103): IMAPB(-900, 40000), 1 to 8 bytes.
    103, DensityAltitudeExtended, "Density Altitude Extended", "m", HEIGHT_EXTENDED;
    /// Item 104 (8.104): IMAPB(-900, 40000), 1 to 8 bytes, above the WGS84
    /// ellipsoid.
    104, SensorEllipsoidHeightExtended, "Sensor Ellipsoid Height Extended", "m", HEIGHT_EXTENDED;
    /// Item 105 (8.105): IMAPB(-900, 40000), 1 to 8 bytes, above the WGS84
    /// ellipsoid.
    105, AlternatePlatformEllipsoidHeightExtended, "Alternate Platform Ellipsoid Height Extended",
        "m", HEIGHT_EXTENDED;
    /// Item 106 (8.106): stream designator ([`Value::Text`]).
    106, StreamDesignator, "Stream Designator", "", TEXT;
    /// Item 107 (8.107): operational base name ([`Value::Text`]).
    107, OperationalBase, "Operational Base", "", TEXT;
    /// Item 108 (8.108): broadcast source name ([`Value::Text`]).
    108, BroadcastSource, "Broadcast Source", "", TEXT;
    /// Item 109 (8.109): IMAPB(0, 21000), 1 to 4 bytes.
    109, RangeToRecoveryLocation, "Range To Recovery Location", "km",
        Codec::Imapb { min: 0.0, max: 21_000.0, max_len: 4 };
    /// Item 110 (8.110): uint of 1 to 4 bytes, seconds airborne
    /// ([`Value::Uint`]).
    110, TimeAirborne, "Time Airborne", "s", Codec::Uint(Len::UpTo(4));
    /// Item 111 (8.111): uint of 1 to 4 bytes, revolutions per minute
    /// ([`Value::Uint`]).
    111, PropulsionUnitSpeed, "Propulsion Unit Speed", "rpm", Codec::Uint(Len::UpTo(4));
    /// Item 112 (8.112): IMAPB(0, 360), 1 to 8 bytes, from true north.
    112, PlatformCourseAngle, "Platform Course Angle", "deg",
        Codec::Imapb { min: 0.0, max: 360.0, max_len: 8 };
    /// Item 113 (8.113): IMAPB(-900, 40000), 1 to 4 bytes.
    113, AltitudeAgl, "Altitude AGL", "m", HEIGHT_AGL;
    /// Item 114 (8.114): IMAPB(-900, 40000), 1 to 4 bytes.
    114, RadarAltimeter, "Radar Altimeter", "m", HEIGHT_AGL;
    /// Item 115 (8.115, Table 7): [`Value::Struct`] of "Command ID"
    /// (BER-OID, [`Value::Uint`]), "Command String" ([`Value::Text`]) and,
    /// when present, "Command Time" ([`Value::Time`]; when absent it is the
    /// packet's tag 2). May repeat.
    115, ControlCommand, "Control Command", "", Codec::Pack(control_command);
    /// Item 116 (8.116): [`Value::List`] of acknowledged tag 115 command
    /// IDs (BER-OID, [`Value::Uint`]).
    116, ControlCommandVerificationList, "Control Command Verification List", "",
        Codec::Pack(control_command_verification_list);
    /// Item 117 (8.117): IMAPB(-1000, 1000), 1 to 4 bytes, clockwise seen
    /// from above positive.
    117, SensorAzimuthRate, "Sensor Azimuth Rate", "deg/s", ANGLE_RATE;
    /// Item 118 (8.118): IMAPB(-1000, 1000), 1 to 4 bytes.
    118, SensorElevationRate, "Sensor Elevation Rate", "deg/s", ANGLE_RATE;
    /// Item 119 (8.119): IMAPB(-1000, 1000), 1 to 4 bytes.
    119, SensorRollRate, "Sensor Roll Rate", "deg/s", ANGLE_RATE;
    /// Item 120 (8.120): IMAPB(0, 100), 1 to 3 bytes.
    120, OnBoardMiStoragePercentFull, "On-board MI Storage Percent Full", "%",
        Codec::Imapb { min: 0.0, max: 100.0, max_len: 3 };
    /// Item 121 (8.121, Table 14): [`Value::List`] of wavelength IDs
    /// (BER-OID) as [`Value::Enum`], labelled for the predefined IDs (0
    /// "Empty List", 1 "VIS" to 6 "FIR", 7 to 20 Reserved). ID 0 must be
    /// alone (ST 0601.17-38).
    121, ActiveWavelengthList, "Active Wavelength List", "", Codec::Pack(active_wavelength_list);
    /// Item 122 (8.122, Table 9): [`Value::Struct`] of "Coding Method"
    /// ([`Value::Enum`] from ST 0102 Table 2 item 12) and the country codes
    /// that are present: "Overflight Country", "Operator Country", "Country
    /// of Manufacture" ([`Value::Text`], or [`Value::Unknown`] for a zero
    /// length).
    122, CountryCodes, "Country Codes", "", Codec::Pack(country_codes);
    /// Item 123 (8.123): uint8 count of navigation satellites
    /// ([`Value::Uint`]).
    123, NumberOfNavsatsInView, "Number of NAVSATs in View", "", Codec::Uint(Len::Exact(1));
    /// Item 124 (8.124, Table 10): [`Value::List`] of the set flags as
    /// [`Value::Enum`] (code = bit number, label = positioning method). No
    /// bit set is [`Value::Invalid`]; up to 8 bytes are read, as 8.124.1
    /// adds future methods in more significant bytes.
    124, PositioningMethodSource, "Positioning Method Source", "", Codec::Pack(positioning_method_source);
    /// Item 125 (8.125, Table 11): uint8 enumeration of platform status, 0
    /// Active through 12 Landed-Parked.
    125, PlatformStatus, "Platform Status", "", Codec::Enum(&PLATFORM_STATUS);
    /// Item 126 (8.126, Table 12): uint8 enumeration of sensor control
    /// modes, 0 Off through 6 Auto - Tracking.
    126, SensorControlMode, "Sensor Control Mode", "", Codec::Enum(&SENSOR_CONTROL_MODES);
    /// Item 127 (8.127, Table 13): [`Value::Struct`] of "Numerator" and
    /// "Denominator" (BER-OID, [`Value::Uint`]; the denominator defaults to
    /// 1 and may not be 0). The frame rate is Numerator / Denominator Hz.
    127, SensorFrameRatePack, "Sensor Frame Rate Pack", "Hz", Codec::Pack(sensor_frame_rate_pack);
    /// Item 128 (8.128, Table 15): [`Value::List`] of [`Value::Struct`]
    /// records: "Wavelength ID" (BER-OID), "Minimum Wavelength" and "Maximum
    /// Wavelength" (IMAPB(0, 1e9, 4) nm), "Wavelength Name" (text).
    128, WavelengthsList, "Wavelengths List", "nm", Codec::Pack(wavelengths_list);
    /// Item 129 (8.129): target identifier ([`Value::Text`]).
    129, TargetId, "Target ID", "", TEXT;
    /// Item 130 (8.130, Table 16): [`Value::Struct`] of "Take-off Location"
    /// and "Recovery Location", each a [`Value::Struct`] of "Latitude"
    /// (IMAPB(-90, 90, 4) deg), "Longitude" (IMAPB(-180, 180, 4) deg) and an
    /// optional "HAE" (IMAPB(-900, 9000, 3) m). An unknown (zero-length)
    /// location is [`Value::Unknown`]; a missing recovery location equals the
    /// take-off location (8.130.1).
    130, AirbaseLocations, "Airbase Locations", "", Codec::Pack(airbase_locations);
    /// Item 131 (8.131): uint of 1 to 8 bytes, microseconds since 1970 in
    /// MISP time ([`Value::Time`]).
    131, TakeOffTime, "Take-off Time", "us", Codec::Time(Len::UpTo(8));
    /// Item 132 (8.132): IMAPB(1, 99999), 1 to 4 bytes.
    132, TransmissionFrequency, "Transmission Frequency", "MHz",
        Codec::Imapb { min: 1.0, max: 99_999.0, max_len: 4 };
    /// Item 133 (8.133): uint of 1 to 4 bytes, gigabytes ([`Value::Uint`]).
    133, OnBoardMiStorageCapacity, "On-board MI Storage Capacity", "GB", Codec::Uint(Len::UpTo(4));
    /// Item 134 (8.134): IMAPB(0, 100), 1 to 4 bytes.
    134, ZoomPercentage, "Zoom Percentage", "%", Codec::Imapb { min: 0.0, max: 100.0, max_len: 4 };
    /// Item 135 (8.135): communications method ([`Value::Text`]).
    135, CommunicationsMethod, "Communications Method", "", TEXT;
    /// Item 136 (8.136): two's complement int of 1 to 4 bytes, leap seconds
    /// since the MISP epoch ([`Value::Int`]): `round(TAI - UTC - 8.000082 s)`,
    /// 29 for instants since 2017-01-01. UTC is approximately tag 2 *minus*
    /// this many seconds (to within the 82 us the rounding drops; an exact
    /// conversion uses a leap second table, see [`crate::MispTime`])
    /// (DECISIONS X-5, P-3).
    136, LeapSeconds, "Leap Seconds", "s", Codec::Int(Len::UpTo(4));
    /// Item 137 (8.137): two's complement int of 1 to 8 bytes, microseconds
    /// to add to tag 2 ([`Value::Int`]).
    137, CorrectionOffset, "Correction Offset", "us", Codec::Int(Len::UpTo(8));
    /// Item 138 (8.138, Tables 17 to 20): [`Value::Struct`] of "Payload
    /// Count" (BER-OID) and "Payload Records", a [`Value::List`] of
    /// [`Value::Struct`] with "Payload ID" (BER-OID), "Payload Type"
    /// ([`Value::Enum`], Table 17) and "Payload Name" (text).
    138, PayloadList, "Payload List", "", Codec::Pack(payload_list);
    /// Item 139 (8.139): [`Value::List`] of the active payload IDs
    /// ([`Value::Uint`], ascending); bit n of the big-endian value is
    /// payload n.
    139, ActivePayloads, "Active Payloads", "", Codec::Pack(active_payloads);
    /// Item 140 (8.140, Tables 21 to 23): [`Value::List`] of
    /// [`Value::Struct`] records: "Station ID", "Hardpoint ID", "Carriage
    /// ID", "Store ID" (BER-OID), "General Status" ([`Value::Enum`], Table
    /// 21, bits 0 to 7 of the status), "Fuze Enabled", "Laser Enabled",
    /// "Target Enabled", "Weapon Armed" ([`Value::Enum`] 0 or 1, Table 22,
    /// bits 8 to 11) and "Weapon Type" (text).
    140, WeaponsStores, "Weapons Stores", "", Codec::Pack(weapons_stores);
    /// Item 141 (8.141, Table 24): [`Value::List`] of [`Value::Struct`]
    /// records: "Waypoint ID" (BER-OID), "Prosecution Order" (int16,
    /// [`Value::Int`]; 32767 means cancelled, negative historical) and, when
    /// present, "Mode" and "Source" ([`Value::Enum`] from the info value)
    /// and "Location" (as in tag 130).
    141, WaypointList, "Waypoint List", "", Codec::Pack(waypoint_list);
    /// Item 142 (8.142, Table 25): [`Value::Struct`] of the pairs present
    /// (both fields [`Value::Unknown`] for a zero-length pair):
    /// "Azimuth Start" (IMAPB(0, 360)), "Elevation Start" (IMAPB(-180,
    /// 180)), "Roll Start" (IMAPB(0, 360)), each followed by its "Azimuth
    /// Range", "Elevation Range" or "Roll Range" (IMAPB(0, 360)), in deg.
    142, ViewDomain, "View Domain", "deg", Codec::Pack(view_domain);
    /// Item 143 (8.143): [`Value::Struct`] of "Local Id" (BER-OID) and, when
    /// the local id is 0, "Universal Id" (the UUID as [`Value::Text`] in
    /// lowercase RFC 4122 form, `8-4-4-4-12` hex digits, as for every UUID
    /// the crate decodes except ST 1204's). Only allowed inside tags 100 and
    /// 101.
    143, MetadataSubstreamIdPack, "Metadata Substream ID Pack", "", Codec::Pack(metadata_substream_id_pack);
}

impl Tag {
    /// The tag with this number, if ST 0601 defines it.
    pub fn from_u64(n: u64) -> Option<Tag> {
        let i = usize::try_from(n.checked_sub(1)?).ok()?;
        DESCS.get(i).map(|d| d.tag)
    }

    /// Name from ST 0601.19 Table 1, e.g. "Sensor Latitude".
    pub fn name(self) -> &'static str {
        self.desc().name
    }

    /// Units string from the vocabulary in the module documentation; ""
    /// when none.
    pub fn units(self) -> &'static str {
        self.desc().units
    }

    fn desc(self) -> &'static Desc {
        // Every variant is in the table (checked by a unit test), so the
        // fallback is never taken.
        DESCS.get((self as usize).wrapping_sub(1)).unwrap_or(&DESCS[0])
    }
}

impl From<Tag> for u64 {
    fn from(t: Tag) -> u64 {
        t as u64
    }
}

crate::value::tag_key!(Tag, crate::Standard::St0601);

/// Decode one item of the set. Never panics.
pub(crate) fn decode_item(tag: u64, value: &[u8], depth: usize, cfg: &Config) -> Item {
    let Some(t) = Tag::from_u64(tag) else {
        return unknown_item(tag, value, depth, cfg);
    };
    let d = t.desc();
    let decoded = decode_value(t, d.codec, value, depth, cfg);
    crate::registry::item(tag, d.name, d.units, decoded, value, cfg)
}

fn decode_value(tag: Tag, codec: Codec, v: &[u8], depth: usize, cfg: &Config) -> Value {
    if v.is_empty() {
        return if zero_length_allowed(tag) { Value::Unknown } else { Value::Invalid(NO_ZLI) };
    }
    let value = match codec {
        Codec::Uint(len) => len.check(v).and_then(uint).map(Value::Uint),
        Codec::Int(len) => len.check(v).and_then(int).map(Value::Int),
        Codec::Time(len) => len.check(v).and_then(uint).map(Value::Time),
        Codec::Scaled { len, factor } => {
            Len::Exact(len).check(v).and_then(uint).map(|x| Value::Uint(x.saturating_mul(factor)))
        }
        Codec::Unsigned { len, range, offset } => {
            Len::Exact(len).check(v).and_then(uint).map(|x| Value::Float(range / span_u(len) * x as f64 + offset))
        }
        Codec::Signed { len, range, special } => {
            Len::Exact(len).check(v).and_then(|v| signed(v, range / span_s(len), special))
        }
        Codec::Imapb { min, max, max_len } => {
            Len::UpTo(max_len).check(v).map(|v| imapb::decode(min, max, v))
        }
        Codec::Text => Ok(text(v)),
        Codec::Enum(labels) => Len::Exact(1).check(v).and_then(uint).map(|code| labels.value(code)),
        Codec::Set(standard) => {
            Ok(Value::Set(Box::new(decode_set(standard, v, depth.saturating_add(1), cfg))))
        }
        Codec::Bytes => Ok(Value::Bytes(v.to_vec())),
        Codec::Pack(decode) => decode(v, cfg),
    };
    value.unwrap_or_else(Value::Invalid)
}

/// `2^N - 1` for an N-byte unsigned mapped item (1, 2 or 4 bytes).
fn span_u(len: usize) -> f64 {
    match len {
        1 => U8,
        2 => U16,
        _ => U32,
    }
}

/// `2^N - 2` for an N-byte signed mapped item (2 or 4 bytes).
fn span_s(len: usize) -> f64 {
    match len {
        2 => S16,
        _ => S32,
    }
}

/// ST 0601.19 section 6.5: every item may be a zero-length item except the
/// mandatory items (1, 2, 65) and the items with Multiples Allowed (100, 101,
/// 102, 115).
fn zero_length_allowed(tag: Tag) -> bool {
    !matches!(
        tag,
        Tag::Checksum
            | Tag::PrecisionTimeStamp
            | Tag::UasDatalinkLsVersionNumber
            | Tag::SegmentLocalSet
            | Tag::AmendLocalSet
            | Tag::SdccFlp
            | Tag::ControlCommand
    )
}

/// Big-endian unsigned integer of up to 8 bytes.
fn uint(v: &[u8]) -> Result<u64, &'static str> {
    be_uint(v).ok_or(TOO_LONG)
}

/// Big-endian two's complement integer of 1 to 8 bytes.
fn int(v: &[u8]) -> Result<i64, &'static str> {
    be_int(v).ok_or(TOO_LONG)
}

/// Signed mapped integer: `scale * x`, except for the most negative code
/// (`0x80` then zero bytes), which ST 0601 reserves as a special value and
/// is tested on the raw bits before any arithmetic.
fn signed(v: &[u8], scale: f64, special: Special) -> Result<Value, &'static str> {
    if let Some((&0x80, rest)) = v.split_first() {
        if rest.iter().all(|&b| b == 0) {
            return Ok(special.value(uint(v)?));
        }
    }
    Ok(Value::Float(scale * int(v)? as f64))
}

/// ISO 646 / UTF-8 text; invalid sequences become U+FFFD. The single byte
/// `00` is the empty string (MISB ST 0107.4 section 6.3.3.2: "The empty
/// string uses a single null character (0x00)"; DECISIONS P-1), so that
/// decoding then encoding gives the same bytes.
fn text(v: &[u8]) -> Value {
    if v == [0] {
        return Value::Text(String::new());
    }
    Value::Text(String::from_utf8_lossy(v).into_owned())
}

fn field(name: &'static str, value: Value) -> Field {
    Field { name, value }
}

/// One bit of a flag set as an enumeration with the standard's meaning for
/// each state.
fn flag(set: bool, zero: &'static str, one: &'static str) -> Value {
    Value::Enum { code: u64::from(set), label: Some(if set { one } else { zero }) }
}

/// Cursor over a pack value. Every read is bounds checked and returns `None`
/// when the pack ends early or a field is malformed.
#[derive(Clone, Copy, Debug)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    /// BER-OID integer (ISO/IEC 8825-1 8.19, ST 0601 section 6.3): seven
    /// bits per byte, most significant first, the top bit set on every byte
    /// but the last. Leading `0x80` padding is tolerated, as the crate does
    /// for tags.
    fn oid(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for (i, &b) in self.0.iter().enumerate() {
            if v > u64::MAX >> 7 {
                return None;
            }
            v = (v << 7) | u64::from(b & 0x7F);
            if b & 0x80 == 0 {
                self.0 = self.0.get(i + 1..)?;
                return Some(v);
            }
        }
        None
    }

    /// BER length, short or long form (SMPTE ST 336 section 5.3). The
    /// indefinite form `0x80` and the reserved `0xFF` are malformed here.
    fn ber_len(&mut self) -> Option<usize> {
        let (&first, rest) = self.0.split_first()?;
        if first < 0x80 {
            self.0 = rest;
            return Some(usize::from(first));
        }
        if first == 0x80 || first == 0xFF {
            return None;
        }
        let n = usize::from(first & 0x7F);
        let mut len: usize = 0;
        for &b in rest.get(..n)? {
            if len > usize::MAX >> 8 {
                return None;
            }
            len = (len << 8) | usize::from(b);
        }
        self.0 = rest.get(n..)?;
        Some(len)
    }

    /// A BER length and that many bytes.
    fn prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.ber_len()?;
        self.take(n)
    }

    /// Fails when bytes are left over.
    fn finish(self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(TRAILING)
        }
    }
}

/// Item 47 flags, bit 0 first (Table 3): field name, meaning of 0, of 1.
const GENERIC_FLAGS: [(&str, &str, &str); 6] = [
    ("Laser Range", "Laser off", "Laser on"),
    ("Auto-Track", "Auto-Track off", "Auto-Track on"),
    ("IR Polarity", "White Hot", "Black Hot"),
    ("Icing Status", "No Icing Detected", "Icing Detected"),
    ("Slant Range", "Calculated", "Measured"),
    ("Image Invalid", "Image Valid", "Image Invalid"),
];

/// Item 47 (8.47, Table 3).
fn generic_flag_data(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    // Required Length 1 (ST 0601.13-29: exactly that many bytes) and bits 6
    // and 7 reserved as 0 (Table 3, R-ST0601-ENCODE-42). 8.47.1 foresees
    // flags in more significant bytes, but no revision defines one, and
    // accepting them would let decode and encode disagree (DECISIONS P-4).
    let [bits] = <[u8; 1]>::try_from(v).map_err(|_| BAD_LENGTH)?;
    if bits & 0xC0 != 0 {
        return Err("generic flag data bits 6 and 7 must be 0");
    }
    let fields = GENERIC_FLAGS
        .iter()
        .enumerate()
        .map(|(bit, &(name, zero, one))| field(name, flag((bits >> bit) & 1 == 1, zero, one)))
        .collect();
    Ok(Value::Struct(fields))
}

/// Item 60 (8.60.1): station and substation nibbles, then weapon type and
/// variant nibbles, most significant nibble first.
fn weapon_load(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let [location, kind] = <[u8; 2]>::try_from(v).map_err(|_| BAD_LENGTH)?;
    Ok(Value::Struct(vec![
        field("Station Number", Value::Uint(u64::from(location >> 4))),
        field("Substation Number", Value::Uint(u64::from(location & 0x0F))),
        field("Weapon Type", Value::Uint(u64::from(kind >> 4))),
        field("Weapon Variant", Value::Uint(u64::from(kind & 0x0F))),
    ]))
}

/// Item 61 (8.61.1): same layout as the first byte of tag 60. (The summary
/// table's "byte 2" contradicts 8.61.1 and the nibble names.)
fn weapon_fired(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let [location] = <[u8; 1]>::try_from(v).map_err(|_| BAD_LENGTH)?;
    Ok(Value::Struct(vec![
        field("Station Number", Value::Uint(u64::from(location >> 4))),
        field("Substation Number", Value::Uint(u64::from(location & 0x0F))),
    ]))
}

/// Item 62 (8.62): "a three or four digit number consisting of the values
/// 1..8", so only 111..8888 without the digits 0 and 9.
fn laser_prf_code(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let code = uint(Len::Exact(2).check(v)?)?;
    let mut rest = code;
    let mut ok = (111..=8888).contains(&code);
    while ok && rest > 0 {
        ok = matches!(rest % 10, 1..=8);
        rest /= 10;
    }
    if ok {
        Ok(Value::Uint(code))
    } else {
        Err("laser PRF code must be 3 or 4 digits of 1 to 8")
    }
}

/// Item 81 (8.81.4, Table 6). Each of the four geographic values is marked
/// optional ("O") in Table 6 and a DLP may be truncated (section 6.3.2), so
/// 4 to 20 bytes in steps of 4 are accepted. jMISB and cbrl/klv accept only
/// 4 and 20; both of those decode the same here.
fn image_horizon_pixel_pack(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    if !matches!(v.len(), 4 | 8 | 12 | 16 | 20) {
        return Err("image horizon pixel pack must be 4, 8, 12, 16 or 20 bytes");
    }
    let mut r = Reader(v);
    let mut fields = Vec::with_capacity(8);
    for name in ["Start x0", "Start y0", "End x1", "End y1"] {
        let p = uint(r.take(1).ok_or(BAD_PACK)?)?;
        let value = if p <= 100 { Value::Uint(p) } else { Value::Invalid("percentage above 100") };
        fields.push(field(name, value));
    }
    // Table 6: mapped like tags 82 and 83, with -(2^31) as the "error"
    // indicator.
    const GEO: [(&str, f64); 4] = [
        ("Start Latitude", 180.0 / S32),
        ("Start Longitude", 360.0 / S32),
        ("End Latitude", 180.0 / S32),
        ("End Longitude", 360.0 / S32),
    ];
    for &(name, scale) in &GEO {
        if r.is_empty() {
            break;
        }
        let b = r.take(4).ok_or(BAD_PACK)?;
        fields.push(field(name, signed(b, scale, Special::Error)?));
    }
    Ok(Value::Struct(fields))
}

/// Item 94 (8.94): the MISB ST 1204 binary value.
fn miis_core_identifier(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    Ok(crate::st1204::decode(v))
}

/// Item 102 (8.102): the MISB ST 1010 SDCC-FLP, its lists bounded by
/// [`Config::max_items`].
fn sdcc_flp(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    Ok(crate::st1010::decode_with(v, cfg))
}

/// Item 115 (8.115.1, Figure 61, Table 7): Command ID (BER-OID), Command
/// String Length (BER), Command String (utf8), optional Command Time
/// (uint64, 8 bytes).
fn control_command(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let id = r.oid().ok_or(BAD_PACK)?;
    let command = r.prefixed().ok_or(BAD_PACK)?;
    let mut fields = vec![field("Command ID", Value::Uint(id)), field("Command String", text(command))];
    match r.rest() {
        [] => {}
        time if time.len() == 8 => fields.push(field("Command Time", Value::Time(uint(time)?))),
        _ => return Err("control command time must be 8 bytes"),
    }
    Ok(Value::Struct(fields))
}

/// A run of BER-OID values with no lengths between them (ST 0601 tags 116
/// and 121), at most `cfg.max_items` of them.
fn oid_list(v: &[u8], cfg: &Config) -> Result<Vec<u64>, &'static str> {
    let mut r = Reader(v);
    let mut out = Vec::new();
    while !r.is_empty() {
        if out.len() >= cfg.max_items {
            return Err(TOO_MANY);
        }
        out.push(r.oid().ok_or(BAD_PACK)?);
    }
    Ok(out)
}

/// Item 116 (8.116.1, Figure 62).
fn control_command_verification_list(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    Ok(Value::List(oid_list(v, cfg)?.into_iter().map(Value::Uint).collect()))
}

/// Item 121 (8.121.1, Figure 63, Table 14).
fn active_wavelength_list(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    let ids = oid_list(v, cfg)?;
    // ST 0601.17-38: ID 0 (no active wavelengths) excludes every other ID.
    if ids.len() > 1 && ids.contains(&0) {
        return Err("wavelength ID 0 must be the only ID");
    }
    Ok(Value::List(ids.into_iter().map(|id| WAVELENGTHS.value(id)).collect()))
}

/// Item 122 (8.122.1, Figure 65, Table 9): four BER-length-prefixed values.
/// The pack may end after the overflight or the operator country, and a
/// zero length marks an unknown country ([`Value::Unknown`]).
fn country_codes(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let method = r.prefixed().ok_or(BAD_PACK)?;
    if method.is_empty() || method.len() > 8 {
        return Err("country coding method must be 1 to 8 bytes");
    }
    let code = uint(method)?;
    let mut fields = vec![field("Coding Method", Value::Enum { code, label: country_coding_method(code) })];
    if r.is_empty() {
        return Err("country codes pack has no overflight country");
    }
    for name in ["Overflight Country", "Operator Country", "Country of Manufacture"] {
        if r.is_empty() {
            break;
        }
        let country = r.prefixed().ok_or(BAD_PACK)?;
        fields.push(field(name, if country.is_empty() { Value::Unknown } else { text(country) }));
    }
    r.finish()?;
    Ok(Value::Struct(fields))
}

/// Item 127 (8.127.1, Figure 67, Table 13): two-element truncation pack.
fn sensor_frame_rate_pack(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let numerator = r.oid().ok_or(BAD_PACK)?;
    // "If the pack does not include the second value, the denominator
    // defaults to a value of one (1)."
    let denominator = if r.is_empty() { 1 } else { r.oid().ok_or(BAD_PACK)? };
    r.finish()?;
    if denominator == 0 {
        return Err("frame rate denominator is zero");
    }
    Ok(Value::Struct(vec![
        field("Numerator", Value::Uint(numerator)),
        field("Denominator", Value::Uint(denominator)),
    ]))
}

/// A variable length pack of BER-length-prefixed records (ST 0601 section
/// 6.3.2), at most `cfg.max_items` of them. A record that does not decode
/// becomes [`Value::Invalid`]; framing errors fail the whole list.
fn records(
    v: &[u8],
    cfg: &Config,
    record: fn(&[u8]) -> Result<Value, &'static str>,
) -> Result<Vec<Value>, &'static str> {
    let mut r = Reader(v);
    let mut out = Vec::new();
    while !r.is_empty() {
        if out.len() >= cfg.max_items {
            return Err(TOO_MANY);
        }
        let bytes = r.prefixed().ok_or(BAD_PACK)?;
        out.push(record(bytes).unwrap_or_else(Value::Invalid));
    }
    Ok(out)
}

/// Item 128 (8.128.1, Figures 68 and 69, Table 15).
fn wavelengths_list(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    Ok(Value::List(records(v, cfg, wavelength_record)?))
}

/// Wavelength record FLP: ID (BER-OID), minimum and maximum wavelength
/// (IMAPB(0, 1e9, 4) nm each), name (utf8, the rest of the record).
fn wavelength_record(b: &[u8]) -> Result<Value, &'static str> {
    let mut r = Reader(b);
    let id = r.oid().ok_or(BAD_PACK)?;
    let min = r.take(4).ok_or(BAD_PACK)?;
    let max = r.take(4).ok_or(BAD_PACK)?;
    Ok(Value::Struct(vec![
        field("Wavelength ID", Value::Uint(id)),
        field("Minimum Wavelength", imapb::decode(0.0, 1e9, min)),
        field("Maximum Wavelength", imapb::decode(0.0, 1e9, max)),
        field("Wavelength Name", text(r.rest())),
    ]))
}

/// Item 130 (8.130.1, Figure 71): BER-length-prefixed take-off and recovery
/// locations.
fn airbase_locations(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let take_off = optional_location(r.prefixed().ok_or(BAD_PACK)?)?;
    let recovery = if r.is_empty() {
        // 8.130.1 (1): "if the Recovery Location is absent then the Recovery
        // Location is set equal to the Take-Off location".
        take_off.clone()
    } else {
        optional_location(r.prefixed().ok_or(BAD_PACK)?)?
    };
    r.finish()?;
    Ok(Value::Struct(vec![field("Take-off Location", take_off), field("Recovery Location", recovery)]))
}

/// A location whose length 0 means unknown (8.130.1 (2)):
/// [`Value::Unknown`].
fn optional_location(b: &[u8]) -> Result<Value, &'static str> {
    if b.is_empty() {
        Ok(Value::Unknown)
    } else {
        location(b)
    }
}

/// Location DLP (8.130.1, Figure 70, Table 16): latitude IMAPB(-90, 90, 4),
/// longitude IMAPB(-180, 180, 4), optional HAE IMAPB(-900, 9000, 3).
fn location(b: &[u8]) -> Result<Value, &'static str> {
    if b.len() != 8 && b.len() != 11 {
        return Err("location must be 8 or 11 bytes");
    }
    let mut r = Reader(b);
    let lat = r.take(4).ok_or(BAD_PACK)?;
    let lon = r.take(4).ok_or(BAD_PACK)?;
    let mut fields = vec![
        field("Latitude", imapb::decode(-90.0, 90.0, lat)),
        field("Longitude", imapb::decode(-180.0, 180.0, lon)),
    ];
    if !r.is_empty() {
        fields.push(field("HAE", imapb::decode(-900.0, 9_000.0, r.rest())));
    }
    Ok(Value::Struct(fields))
}

/// Item 138 (8.138.1, Figure 73, Tables 19 and 20): Payload Count
/// (BER-OID), then BER-length-prefixed payload records.
fn payload_list(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let count = r.oid().ok_or(BAD_PACK)?;
    let list = records(r.rest(), cfg, payload_record)?;
    Ok(Value::Struct(vec![
        field("Payload Count", Value::Uint(count)),
        field("Payload Records", Value::List(list)),
    ]))
}

/// Payload record (Figure 72): ID (BER-OID), Type (BER-OID), Name Length
/// (BER), Name (utf8). 8.138.1 says the name length "enables future
/// expansion", so bytes after the name are left for future fields.
fn payload_record(b: &[u8]) -> Result<Value, &'static str> {
    let mut r = Reader(b);
    let id = r.oid().ok_or(BAD_PACK)?;
    let kind = r.oid().ok_or(BAD_PACK)?;
    let name = r.prefixed().ok_or(BAD_PACK)?;
    Ok(Value::Struct(vec![
        field("Payload ID", Value::Uint(id)),
        field("Payload Type", PAYLOAD_TYPES.value(kind)),
        field("Payload Name", text(name)),
    ]))
}

/// Item 139 (8.139.1, Figure 75): bit n of the big-endian value, counted
/// from the least significant bit of the last byte, marks payload n active.
fn active_payloads(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    let mut ids = Vec::new();
    for (i, &byte) in v.iter().rev().enumerate() {
        for bit in 0..8u64 {
            if (byte >> bit) & 1 == 0 {
                continue;
            }
            if ids.len() >= cfg.max_items {
                return Err(TOO_MANY);
            }
            let id = u64::try_from(i)
                .ok()
                .and_then(|i| i.checked_mul(8))
                .and_then(|i| i.checked_add(bit))
                .ok_or(TOO_LONG)?;
            ids.push(Value::Uint(id));
        }
    }
    Ok(Value::List(ids))
}

/// Item 140 (8.140.1, Figures 77 and 79).
fn weapons_stores(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    Ok(Value::List(records(v, cfg, weapons_record)?))
}

/// Weapons record (Figure 77, Table 23): Station, Hardpoint, Carriage and
/// Store IDs and the Weapon Status (BER-OID each), Weapon Type length (BER)
/// and Weapon Type (utf8). Bytes after the type are left for future fields,
/// as for payload records.
fn weapons_record(b: &[u8]) -> Result<Value, &'static str> {
    let mut r = Reader(b);
    let station = r.oid().ok_or(BAD_PACK)?;
    let hardpoint = r.oid().ok_or(BAD_PACK)?;
    let carriage = r.oid().ok_or(BAD_PACK)?;
    let store = r.oid().ok_or(BAD_PACK)?;
    let status = r.oid().ok_or(BAD_PACK)?;
    let kind = r.prefixed().ok_or(BAD_PACK)?;
    // 8.140.1, Figure 78: "The least significant eight (8) bits are the
    // General Status, the next four (4) bits are the Engagement Status".
    // (jMISB masks the general status with 0x7F; Table 21 only defines codes
    // up to 127 either way.)
    let bit = |n: u32| (status >> n) & 1 == 1;
    Ok(Value::Struct(vec![
        field("Station ID", Value::Uint(station)),
        field("Hardpoint ID", Value::Uint(hardpoint)),
        field("Carriage ID", Value::Uint(carriage)),
        field("Store ID", Value::Uint(store)),
        field("General Status", GENERAL_STATUS.value(status & 0xFF)),
        field("Fuze Enabled", flag(bit(8), "Fuze functions are not set", "Fuze functions are set")),
        field("Laser Enabled", flag(bit(9), "Laser functions are not set", "Laser functions are set")),
        field("Target Enabled", flag(bit(10), "Target functions are not set", "Target functions are set")),
        field("Weapon Armed", flag(bit(11), "Master Arm is not set", "Master Arm is set")),
        field("Weapon Type", text(kind)),
    ]))
}

/// Item 141 (8.141.1, Figures 83 and 84).
fn waypoint_list(v: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    Ok(Value::List(records(v, cfg, waypoint_record)?))
}

/// Waypoint record DLP (Figure 83, Table 24): Waypoint ID (BER-OID),
/// Prosecution Order (int16), then the optional Info Value (BER-OID) and
/// Location (the tag 130 location DLP), truncated from the end.
fn waypoint_record(b: &[u8]) -> Result<Value, &'static str> {
    let mut r = Reader(b);
    let id = r.oid().ok_or(BAD_PACK)?;
    let order = <[u8; 2]>::try_from(r.take(2).ok_or(BAD_PACK)?).map_err(|_| BAD_PACK)?;
    let mut fields = vec![
        field("Waypoint ID", Value::Uint(id)),
        field("Prosecution Order", Value::Int(i64::from(i16::from_be_bytes(order)))),
    ];
    if !r.is_empty() {
        // Figure 82: bit 0 is the Mode, bit 1 the Source.
        let info = r.oid().ok_or(BAD_PACK)?;
        fields.push(field("Mode", flag(info & 1 == 1, "Automated", "Manual")));
        fields.push(field("Source", flag((info >> 1) & 1 == 1, "Pre-planned", "Ad hoc")));
        if !r.is_empty() {
            fields.push(field("Location", location(r.rest())?));
        }
    }
    Ok(Value::Struct(fields))
}

/// Item 142 (8.142.1, Figure 87, Table 25): up to three BER-length-prefixed
/// pairs, each a start and a range of half the pair length. A zero pair
/// length marks an unknown pair (both fields [`Value::Unknown`]); trailing
/// pairs may be truncated.
fn view_domain(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    const PAIRS: [(&str, &str, f64, f64); 3] = [
        ("Azimuth Start", "Azimuth Range", 0.0, 360.0),
        ("Elevation Start", "Elevation Range", -180.0, 180.0),
        ("Roll Start", "Roll Range", 0.0, 360.0),
    ];
    let mut r = Reader(v);
    let mut fields = Vec::with_capacity(6);
    for &(start, range, min, max) in &PAIRS {
        if r.is_empty() {
            break;
        }
        let pair = r.prefixed().ok_or(BAD_PACK)?;
        if pair.is_empty() {
            fields.push(field(start, Value::Unknown));
            fields.push(field(range, Value::Unknown));
            continue;
        }
        if pair.len() % 2 != 0 || pair.len() > 16 {
            return Err("view domain pair length must be even and at most 16");
        }
        let (s, rg) = pair.split_at(pair.len() / 2);
        fields.push(field(start, imapb::decode(min, max, s)));
        fields.push(field(range, imapb::decode(0.0, 360.0, rg)));
    }
    r.finish()?;
    Ok(Value::Struct(fields))
}

/// Item 143 (8.143.1, Figure 90): Local Id (BER-OID) and, only when it is 0,
/// a 16-byte Universal Id (ST 0601.19-46, ST 0601.19-47).
fn metadata_substream_id_pack(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    let mut r = Reader(v);
    let local = r.oid().ok_or(BAD_PACK)?;
    let universal = r.rest();
    let mut fields = vec![field("Local Id", Value::Uint(local))];
    match (local, universal.len()) {
        (0, 16) => {
            let id = <&[u8; 16]>::try_from(universal).map_err(|_| BAD_PACK)?;
            fields.push(field("Universal Id", Value::Text(crate::value::uuid_text(id))));
        }
        (0, _) => return Err("local id 0 must be followed by a 16-byte universal id"),
        (_, 0) => {}
        _ => return Err("a nonzero local id must not be followed by a universal id"),
    }
    Ok(Value::Struct(fields))
}

/// Item 124 (8.124.1, Table 10).
fn positioning_method_source(v: &[u8], _: &Config) -> Result<Value, &'static str> {
    // Future methods go into more significant bytes (8.124.1).
    let bits = uint(Len::UpTo(8).check(v)?)?;
    if bits == 0 {
        return Err("positioning method source has no bit set");
    }
    const NAMES: [&str; 8] = [
        "On-board Inertial Navigation System",
        "GPS",
        "Galileo",
        "QZSS",
        "NAVIC",
        "GLONASS",
        "BeiDou-1",
        "BeiDou-2",
    ];
    let set = (0..64u32)
        .filter(|&b| (bits >> b) & 1 == 1)
        .map(|b| Value::Enum { code: u64::from(b), label: NAMES.get(b as usize).copied() })
        .collect();
    Ok(Value::List(set))
}

/// Item 122 coding method: MISB ST 0102.12 Table 2, item 12 (Object
/// Country Coding Method), as 8.122.1 specifies. (KWIVER decodes it with
/// the item 2 table, which numbers 0x03 to 0x05 differently.)
fn country_coding_method(code: u64) -> Option<&'static str> {
    Some(match code {
        0x01 => "ISO-3166 Two Letter",
        0x02 => "ISO-3166 Three Letter",
        0x03 => "ISO-3166 Numeric",
        0x04 => "FIPS 10-4 Two Letter",
        0x05 => "FIPS 10-4 Four Letter",
        0x06 => "1059 Two Letter",
        0x07 => "1059 Three Letter",
        0x08..=0x0C => "Omitted Value",
        0x0D => "GENC Two Letter",
        0x0E => "GENC Three Letter",
        0x0F => "GENC Numeric",
        0x40 => "GENC AdminSub",
        _ => return None,
    })
}

/// Item 34 (8.34). Codes 3 to 255 are outside the KLV range.
static ICING: Labels =
    Labels { names: &["Detector off", "No icing Detected", "Icing Detected"], reserved_to: 0 };

/// Item 63 (Table 4): 9 to 255 Reserved.
static FIELD_OF_VIEW_NAMES: Labels = Labels {
    names: &[
        "Ultranarrow",
        "Narrow",
        "Medium",
        "Wide",
        "Ultrawide",
        "Narrow Medium",
        "2x Ultranarrow",
        "4x Ultranarrow",
        "Continuous Zoom",
    ],
    reserved_to: 255,
};

/// Item 77 (Table 5): 6 to 255 Reserved.
static OPERATIONAL_MODES: Labels = Labels {
    names: &["Other", "Operational", "Training", "Exercise", "Maintenance", "Test"],
    reserved_to: 255,
};

/// Item 125 (Table 11): 13 to 255 Reserved.
static PLATFORM_STATUS: Labels = Labels {
    names: &[
        "Active",
        "Pre-flight",
        "Pre-flight-taxiing",
        "Run-up",
        "Take-off",
        "Ingress",
        "Manual operation",
        "Automated-orbit",
        "Transitioning",
        "Egress",
        "Landing",
        "Landed-taxiing",
        "Landed-Parked",
    ],
    reserved_to: 255,
};

/// Item 126 (Table 12): 7 to 255 Reserved.
static SENSOR_CONTROL_MODES: Labels = Labels {
    names: &[
        "Off",
        "Home Position",
        "Uncontrolled",
        "Manual Control",
        "Calibrating",
        "Auto - Holding Position",
        "Auto - Tracking",
    ],
    reserved_to: 255,
};

/// Items 121 and 128 (Table 14): predefined wavelengths; 7 to 20 Reserved,
/// custom records from 21.
static WAVELENGTHS: Labels =
    Labels { names: &["Empty List", "VIS", "IR", "NIR", "MIR", "LIR", "FIR"], reserved_to: 20 };

/// Item 138 (Table 17).
static PAYLOAD_TYPES: Labels = Labels {
    names: &["Electro Optical MI Sensor", "LIDAR", "RADAR", "SIGINT", "SAR"],
    reserved_to: 0,
};

/// Item 140 (Table 21): 12 to 127 Reserved.
static GENERAL_STATUS: Labels = Labels {
    names: &[
        "Off",
        "Initialization",
        "Ready/Degraded",
        "Ready/All Up Round",
        "Launch",
        "Free Flight",
        "Abort",
        "Miss Fire",
        "Hang Fire",
        "Jettisoned",
        "Stepped Over",
        "No Status Available",
    ],
    reserved_to: 127,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Checksum, Error, Packet};

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Decode one item written as in the ST 0601 examples: tag, length,
    /// value, in hex.
    fn tlv(s: &str) -> Item {
        let bytes = hex(s);
        let mut items = crate::klv::local_set(&bytes);
        let i = items.next().unwrap().unwrap();
        assert!(items.next().is_none(), "{s}: exactly one item expected");
        decode_item(i.tag, i.value, 0, &Config::default())
    }

    fn dec(tag: u64, v: &[u8]) -> Value {
        decode_item(tag, v, 0, &Config::default()).value
    }

    fn float(v: &Value) -> f64 {
        match v {
            Value::Float(f) => *f,
            other => panic!("not a float: {other:?}"),
        }
    }

    fn close(v: &Value, want: f64, tol: f64) {
        let got = float(v);
        assert!((got - want).abs() <= tol, "{got} != {want} +/- {tol}");
    }

    fn get<'a>(v: &'a Value, name: &str) -> &'a Value {
        v.field(name).unwrap_or_else(|| panic!("missing field {name}"))
    }

    fn names(v: &Value) -> Vec<&'static str> {
        v.as_fields().unwrap().iter().map(|f| f.name).collect()
    }

    fn label(code: u64, label: &'static str) -> Value {
        Value::Enum { code, label: Some(label) }
    }

    fn is_invalid(v: &Value) -> bool {
        matches!(v, Value::Invalid(_))
    }

    #[test]
    fn table_is_complete_and_in_tag_order() {
        let units = [
            "", "deg", "deg/s", "m", "km", "m/s", "mbar", "C", "%", "kg", "s", "us", "pixels",
            "rpm", "Hz", "MHz", "GB", "nm",
        ];
        let mut seen = std::collections::HashSet::new();
        for (i, d) in DESCS.iter().enumerate() {
            let n = i as u64 + 1;
            assert_eq!(u64::from(d.tag), n);
            assert_eq!(Tag::from_u64(n), Some(d.tag));
            assert_eq!(d.tag.name(), d.name);
            assert_eq!(d.tag.units(), d.units);
            assert!(units.contains(&d.units), "tag {n} units {:?}", d.units);
            assert!(!d.name.is_empty() && d.name.is_ascii(), "tag {n}");
            assert!(seen.insert(d.name), "duplicate name {}", d.name);
        }
        assert_eq!(DESCS.len(), 143);
        for n in [0, 144, 255, 256, 1 << 32, u64::MAX] {
            assert_eq!(Tag::from_u64(n), None);
        }
        assert_eq!(Tag::SensorLatitude.name(), "Sensor Latitude");
        assert_eq!(Tag::SensorLatitude.units(), "deg");
        assert_eq!(Tag::TargetErrorEstimateCe90.name(), "Target Error Estimate - CE90");
        assert_eq!(Tag::MetadataSubstreamIdPack.name(), "Metadata Substream ID Pack");
        assert_eq!(u64::from(Tag::MetadataSubstreamIdPack), 143);
        assert_eq!(u64::from(Tag::Deprecated), 66);
    }

    #[test]
    fn unknown_tags_are_raw() {
        for tag in [0, 144, 200, 1 << 20] {
            let item = decode_item(tag, &[1, 2], 0, &Config::default());
            assert_eq!(item.name, "Unknown");
            assert_eq!(item.value, Value::Bytes(vec![1, 2]));
        }
    }

    /// ST 0601.19 section 8 examples of linearly mapped items: the bytes
    /// decode to the printed software value within half an LSB. (Tags 26 to
    /// 33, 80, 82 to 89 and 93 print the value before quantization.)
    #[test]
    fn spec_examples_mapped_integers() {
        const L90: f64 = 180.0 / S32;
        const L180: f64 = 360.0 / S32;
        const ALT: f64 = 19_900.0 / U16;
        const CORNER: f64 = 0.15 / S16;
        let cases: &[(&str, f64, f64)] = &[
            ("05 02 71C2", 159.974365, 360.0 / U16),
            ("06 02 FD3D", -0.431531724, 40.0 / S16),
            ("07 02 08B8", 3.40586566, 100.0 / S16),
            ("0D 04 5595 B66D", 60.176822966978335, L90),
            ("0E 04 5B53 60C4", 128.42675904204452, L180),
            ("0F 02 C221", 14190.7195, ALT),
            ("10 02 CD9C", 144.571298, 180.0 / U16),
            ("11 02 D917", 152.643626, 180.0 / U16),
            ("12 04 724A 0A20", 160.71921143697557, 360.0 / U32),
            ("13 04 87F8 4B86", -168.79232483394085, L180),
            ("14 04 7DC5 5ECE", 176.86543764939194, 360.0 / U32),
            ("15 04 0383 0926", 68590.983298744770, 5e6 / U32),
            ("16 02 1281", 722.819867, 10_000.0 / U16),
            ("17 04 F101 A229", -10.542388633146132, L90),
            ("18 04 14BC 082B", 29.157890122923014, L180),
            ("19 02 34F3", 3216.03723, ALT),
            ("1A 02 1750", 0.0136602540, CORNER),
            ("1B 02 063F", 0.0036602540, CORNER),
            ("1C 02 F9C1", -0.0036602540, CORNER),
            ("1D 02 1750", 0.0136602540, CORNER),
            ("1E 02 ED1F", -0.0110621778, CORNER),
            ("1F 02 F732", -0.0051602540, CORNER),
            ("20 02 01D0", 0.0010621778, CORNER),
            ("21 02 EB3F", -0.0121602540, CORNER),
            ("23 02 A7C4", 235.924010, 360.0 / U16),
            ("24 01 B2", 69.8039216, 100.0 / U8),
            ("25 02 BEBA", 3725.18502, 5000.0 / U16),
            ("26 02 CA35", 14818.6770, ALT),
            ("28 04 8F69 5262", -79.163850051892850, L90),
            ("29 04 7654 57F2", 166.40081296041646, L180),
            ("2A 02 F823", 18389.0471, ALT),
            ("2D 02 1A95", 425.215152, 4095.0 / U16),
            ("2E 02 2611", 608.9231, 4095.0 / U16),
            ("31 02 3D07", 1191.95850, 5000.0 / U16),
            ("32 02 C883", -8.67030854, 40.0 / S16),
            ("33 02 D3FE", -61.8878750, 360.0 / S16),
            ("34 02 DF79", -5.08255257, 40.0 / S16),
            ("35 02 6AF4", 2088.96010, 5000.0 / U16),
            ("36 02 7670", 8306.80552, ALT),
            ("37 01 81", 50.5882353, 100.0 / U8),
            ("39 04 B38E ACF1", 3506979.0316063400, 5e6 / U32),
            ("3A 02 A45D", 6420.53864, 10_000.0 / U16),
            ("40 02 DDC5", 311.868162, 360.0 / U16),
            ("43 04 85A1 5A39", -86.041207348947040, L90),
            ("44 04 001C 501C", 0.15552755452484243, L180),
            ("45 02 0BB3", 9.44533455, ALT),
            ("47 02 172F", 32.6024262, 360.0 / U16),
            ("4B 02 C221", 14190.7195, ALT),
            ("4C 02 0BB3", 9.44533455, ALT),
            ("4E 02 0BB3", 9.44533455, ALT),
            ("4F 02 09FB", 25.4977569, 654.0 / S16),
            ("50 02 04BC", 12.1, 654.0 / S16),
            ("52 04 F106 9B63", -10.528728379108287, L90),
            ("53 04 14BC B2C0", 29.161550376960857, L180),
            ("54 04 F100 4D00", -10.546048887183977, L90),
            ("55 04 14BE 84C8", 29.171550376960860, L180),
            ("56 04 F0FD 9B17", -10.553450810972622, L90),
            ("57 04 14BB 17AF", 29.152729868885170, L180),
            ("58 04 F102 052A", -10.541326455319641, L90),
            ("59 04 14B9 D176", 29.145729868885170, L180),
            ("5A 04 FF62 E2F2", -0.43152510208614414, L90),
            ("5B 04 04D8 04DF", 3.4058139815022304, L90),
            ("5C 04 F3AB 48EF", -8.6701769841230370, L90),
            ("5D 04 DE17 9323", -47.683, L180),
        ];
        for &(t, want, lsb) in cases {
            let item = tlv(t);
            assert!(!item.units.is_empty(), "{t}");
            close(&item.value, want, lsb / 2.0);
        }
    }

    /// ST 0601.19 IMAPB examples: (item, exact decode, printed value, LSB).
    /// ST 1201 truncates when encoding, so the printed value lies within one
    /// LSB above the decode.
    #[test]
    fn spec_examples_imapb() {
        let cases: &[(&str, f64, f64, f64)] = &[
            ("60 03 00D9 2A", 13898.5, 13898.5463, 0.25),
            ("67 03 2F92 1E", 23456.234375, 23456.24, 1.0 / 128.0),
            ("68 03 2F92 1E", 23456.234375, 23456.24, 1.0 / 128.0),
            ("69 03 2F92 1E", 23456.234375, 23456.24, 1.0 / 128.0),
            ("6D 03 0001 A0", 1.625, 1.625, 1.0 / 256.0),
            ("70 02 1F40", 125.0, 125.0, 1.0 / 64.0),
            ("71 03 05F5 00", 2150.0, 2150.0, 1.0 / 128.0),
            ("72 03 05F7 40", 2154.5, 2154.5, 1.0 / 128.0),
            ("75 02 3E90", 1.0, 1.0, 1.0 / 16.0),
            ("76 03 3E80 11", 0.004150390625, 0.004176, 1.0 / 4096.0),
            ("77 02 3B60", -50.0, -50.0, 1.0 / 16.0),
            ("78 02 4800", 72.0, 72.0, 1.0 / 256.0),
            ("8104 03 0257 C0", 2400.0, 2400.0, 1.0 / 64.0),
            ("8106 02 3700", 55.0, 55.0, 1.0 / 256.0),
        ];
        for &(t, exact, printed, lsb) in cases {
            let item = tlv(t);
            close(&item.value, exact, 1e-9);
            close(&item.value, printed, lsb);
        }
    }

    #[test]
    fn spec_examples_other_items() {
        let cases: &[(&str, Value)] = &[
            ("01 02 8CED", Value::Uint(0x8CED)),
            ("02 08 0004 59F4 A6AA 4AA8", Value::Time(1_224_807_209_913_000)),
            ("03 09 4D49 5353 494F 4E30 31", Value::Text("MISSION01".into())),
            ("04 06 4146 2D31 3031", Value::Text("AF-101".into())),
            ("08 01 93", Value::Uint(147)),
            ("09 01 9F", Value::Uint(159)),
            ("0A 05 4D51 312D 42", Value::Text("MQ1-B".into())),
            ("0B 02 454F", Value::Text("EO".into())),
            ("0C 0E 4765 6F64 6574 6963 2057 4753 3834", Value::Text("Geodetic WGS84".into())),
            ("22 01 02", label(2, "Icing Detected")),
            ("27 01 54", Value::Int(84)),
            ("2B 01 03", Value::Uint(6)),
            ("2C 01 0F", Value::Uint(30)),
            ("38 01 8C", Value::Uint(140)),
            ("3B 07 544F 5020 4755 4E", Value::Text("TOP GUN".into())),
            ("3E 02 06CF", Value::Uint(1743)),
            ("3F 01 02", label(2, "Medium")),
            ("41 01 0D", Value::Uint(13)),
            ("46 06 4150 4143 4845", Value::Text("APACHE".into())),
            ("48 08 0002 D5D0 2466 0180", Value::Time(798_039_894_000_000)),
            ("4D 01 01", label(1, "Operational")),
            ("6A 04 424C 5545", Value::Text("BLUE".into())),
            ("6B 06 4241 5345 3031", Value::Text("BASE01".into())),
            ("6C 04 484F 4D45", Value::Text("HOME".into())),
            ("6E 02 4DAF", Value::Uint(19887)),
            ("6F 02 0BB8", Value::Uint(3000)),
            ("7B 01 07", Value::Uint(7)),
            ("7D 01 09", label(9, "Egress")),
            ("7E 01 05", label(5, "Auto - Holding Position")),
            ("8101 04 4131 3233", Value::Text("A123".into())),
            ("8103 07 05 6F27 1B5E 41B7", Value::Time(1_529_588_637_122_999)),
            ("8105 02 2710", Value::Uint(10_000)),
            (
                "8107 14 4672 6571 7565 6E63 7920 4D6F 6475 6C61 7469 6F6E",
                Value::Text("Frequency Modulation".into()),
            ),
            ("8108 01 1E", Value::Int(30)),
            ("8109 05 012B 8DC6 35", Value::Int(5_025_678_901)),
            ("810B 01 0B", Value::List(vec![Value::Uint(0), Value::Uint(1), Value::Uint(3)])),
            ("74 02 0307", Value::List(vec![Value::Uint(3), Value::Uint(7)])),
            ("79 02 0103", Value::List(vec![label(1, "VIS"), label(3, "NIR")])),
            (
                "7C 01 03",
                Value::List(vec![label(0, "On-board Inertial Navigation System"), label(1, "GPS")]),
            ),
        ];
        for (t, want) in cases {
            assert_eq!(&tlv(t).value, want, "{t}");
        }
        // Time stamps display as MISP time.
        assert_eq!(tlv("48 08 0002 D5D0 2466 0180").value.to_string(), "1995-04-16T13:44:54.000000 MISP");
        assert_eq!(tlv("8103 07 05 6F27 1B5E 41B7").value.to_string(), "2018-06-21T13:43:57.122999 MISP");
    }

    #[test]
    fn empty_string_is_a_single_null() {
        // MISB ST 0107.4 6.3.3.2 (DECISIONS P-1): 00 is "", a ZLI is unknown.
        assert_eq!(dec(3, &[0x00]), Value::Text(String::new()));
        assert_eq!(dec(3, &[]), Value::Unknown);
        assert_eq!(dec(3, &[0x00, 0x00]), Value::Text("\u{0}\u{0}".into()));
    }

    #[test]
    fn spec_example_generic_flags() {
        // 0x31: Laser on, Slant Range measured, Image Invalid.
        let v = tlv("2F 01 31").value;
        assert_eq!(
            names(&v),
            ["Laser Range", "Auto-Track", "IR Polarity", "Icing Status", "Slant Range", "Image Invalid"]
        );
        assert_eq!(get(&v, "Laser Range"), &label(1, "Laser on"));
        assert_eq!(get(&v, "Auto-Track"), &label(0, "Auto-Track off"));
        assert_eq!(get(&v, "IR Polarity"), &label(0, "White Hot"));
        assert_eq!(get(&v, "Icing Status"), &label(0, "No Icing Detected"));
        assert_eq!(get(&v, "Slant Range"), &label(1, "Measured"));
        assert_eq!(get(&v, "Image Invalid"), &label(1, "Image Invalid"));
        let all = dec(47, &[0x3F]);
        assert_eq!(get(&all, "IR Polarity"), &label(1, "Black Hot"));
        assert_eq!(get(&all, "Icing Status"), &label(1, "Icing Detected"));
        // Exactly one byte, bits 6 and 7 zero (DECISIONS P-4).
        assert!(is_invalid(&dec(47, &[0x00, 0x31])));
        assert!(is_invalid(&dec(47, &[0x71])));
        assert!(is_invalid(&dec(47, &[0x80])));
    }

    #[test]
    fn spec_example_weapon_load_and_fired() {
        let v = tlv("3C 02 AFD8").value;
        assert_eq!(get(&v, "Station Number"), &Value::Uint(10));
        assert_eq!(get(&v, "Substation Number"), &Value::Uint(15));
        assert_eq!(get(&v, "Weapon Type"), &Value::Uint(13));
        assert_eq!(get(&v, "Weapon Variant"), &Value::Uint(8));
        let v = tlv("3D 01 BA").value;
        assert_eq!(names(&v), ["Station Number", "Substation Number"]);
        assert_eq!(get(&v, "Station Number"), &Value::Uint(11));
        assert_eq!(get(&v, "Substation Number"), &Value::Uint(10));
        assert!(is_invalid(&dec(60, &[1])));
        assert!(is_invalid(&dec(60, &[1, 2, 3])));
        assert!(is_invalid(&dec(61, &[1, 2])));
    }

    #[test]
    fn spec_example_image_horizon() {
        let v = tlv("51 04 0024 3800").value;
        assert_eq!(names(&v), ["Start x0", "Start y0", "End x1", "End y1"]);
        assert_eq!(get(&v, "Start y0"), &Value::Uint(36));
        assert_eq!(get(&v, "End x1"), &Value::Uint(56));
        // Every truncation of Table 6 at a value boundary is accepted.
        let mut full = hex("00 24 38 00");
        full.extend(hex("5595B66D 5B5360C4 80000000 F101A229"));
        for len in [8, 12, 16, 20] {
            let v = dec(81, &full[..len]);
            assert_eq!(v.as_fields().unwrap().len(), 4 + (len - 4) / 4, "{len}");
        }
        let v = dec(81, &full);
        close(get(&v, "Start Latitude"), 60.176822966978335, 1e-12);
        close(get(&v, "Start Longitude"), 128.42675904204452, 1e-12);
        assert_eq!(get(&v, "End Latitude"), &Value::OutOfRange);
        close(get(&v, "End Longitude"), -10.542388633146132 * 2.0, 1e-9);
        for len in [1, 3, 5, 7, 11, 19, 21, 24] {
            assert!(is_invalid(&dec(81, &vec![0; len])), "{len}");
        }
        let v = dec(81, &[101, 0, 100, 0]);
        assert!(is_invalid(get(&v, "Start x0")));
        assert_eq!(get(&v, "End x1"), &Value::Uint(100));
    }

    #[test]
    fn spec_example_miis_core_identifier() {
        let t = "5E 22 0170 F592 F023 7336 4AF8 AA91 62C0 0F2E B2DA 16B7 4341 0008 41A0 BE36 5B5A B96A 3645";
        let item = tlv(t);
        assert_eq!(item.name, "MIIS Core Identifier");
        assert_eq!(item.raw.len(), 34);
        assert_eq!(item.value, crate::st1204::decode(&item.raw));
    }

    #[test]
    fn spec_example_control_command() {
        let v = tlv("73 13 0511 466C 7920 746F 2057 6179 706F 696E 7420 31").value;
        assert_eq!(names(&v), ["Command ID", "Command String"]);
        assert_eq!(get(&v, "Command ID"), &Value::Uint(5));
        assert_eq!(get(&v, "Command String"), &Value::Text("Fly to Waypoint 1".into()));
        // With the optional time, a multi-byte ID and an empty string.
        let v = dec(115, &hex("8100 00 0004 59F4 A6AA 4AA8"));
        assert_eq!(get(&v, "Command ID"), &Value::Uint(128));
        assert_eq!(get(&v, "Command String"), &Value::Text(String::new()));
        assert_eq!(get(&v, "Command Time"), &Value::Time(1_224_807_209_913_000));
        // Malformed: truncated ID, string past the end, short time, bad BER.
        for bad in ["85", "05", "05 03 41 42", "05 01 41 0000 0000 0000 00", "05 80 41", "05 FF"] {
            assert!(is_invalid(&dec(115, &hex(bad))), "{bad}");
        }
    }

    #[test]
    fn spec_example_country_codes() {
        let v = tlv("7A 0B 010E 0343 414E 0003 4652 41").value;
        // The operator country is unknown (length 0).
        assert_eq!(names(&v), ["Coding Method", "Overflight Country", "Operator Country", "Country of Manufacture"]);
        assert_eq!(get(&v, "Operator Country"), &Value::Unknown);
        assert_eq!(get(&v, "Coding Method"), &label(0x0E, "GENC Three Letter"));
        assert_eq!(get(&v, "Overflight Country"), &Value::Text("CAN".into()));
        assert_eq!(get(&v, "Country of Manufacture"), &Value::Text("FRA".into()));
        // Truncated after the overflight country; ST 0102 item 12 codes.
        let v = dec(122, &hex("01 03 03 43 41 4E"));
        assert_eq!(names(&v), ["Coding Method", "Overflight Country"]);
        assert_eq!(get(&v, "Coding Method"), &label(3, "ISO-3166 Numeric"));
        assert_eq!(get(&dec(122, &hex("01 40 00")), "Coding Method"), &label(0x40, "GENC AdminSub"));
        assert_eq!(get(&dec(122, &hex("01 0A 00")), "Coding Method"), &label(0x0A, "Omitted Value"));
        assert_eq!(get(&dec(122, &hex("01 10 00")), "Coding Method"), &Value::Enum { code: 0x10, label: None });
        let v = dec(122, &hex("01 0E 00 00 00"));
        assert_eq!(names(&v), ["Coding Method", "Overflight Country", "Operator Country", "Country of Manufacture"]);
        assert!(v.as_fields().unwrap()[1..].iter().all(|f| f.value == Value::Unknown));
        for bad in [
            "00 00",                        // no coding method
            "09 000000000000000001 00",     // coding method of 9 bytes
            "01 0E",                        // no overflight country
            "01 0E 05 41 42",               // country past the end
            "01 0E 00 00 00 00",            // a fifth value
            "01 0E 80",                     // indefinite length
        ] {
            assert!(is_invalid(&dec(122, &hex(bad))), "{bad}");
        }
    }

    #[test]
    fn spec_example_frame_rate() {
        let v = tlv("7F 05 83D4 6087 69").value;
        assert_eq!(get(&v, "Numerator"), &Value::Uint(60_000));
        assert_eq!(get(&v, "Denominator"), &Value::Uint(1001));
        // The denominator defaults to 1.
        let v = dec(127, &[30]);
        assert_eq!(get(&v, "Denominator"), &Value::Uint(1));
        for bad in ["1E 00", "1E 01 01", "83", "1E 83"] {
            assert!(is_invalid(&dec(127, &hex(bad))), "{bad}");
        }
    }

    #[test]
    fn spec_example_wavelengths() {
        let v = tlv("8100 0E 0D15 0000 07D0 0000 0FA0 4E4E 4952").value;
        let list = v.as_list().unwrap();
        assert_eq!(list.len(), 1);
        let r = &list[0];
        assert_eq!(get(r, "Wavelength ID"), &Value::Uint(21));
        assert_eq!(get(r, "Minimum Wavelength"), &Value::Float(1000.0));
        assert_eq!(get(r, "Maximum Wavelength"), &Value::Float(2000.0));
        assert_eq!(get(r, "Wavelength Name"), &Value::Text("NNIR".into()));
        // A short record is invalid without hiding the next one.
        let v = dec(128, &hex("03 15 0000 0D15 0000 07D0 0000 0FA0 4E4E 4952"));
        let list = v.as_list().unwrap();
        assert!(is_invalid(&list[0]));
        assert_eq!(get(&list[1], "Wavelength ID"), &Value::Uint(21));
        // A record running past the end fails the list.
        assert!(is_invalid(&dec(128, &hex("0E 15 0000"))));
        // The active wavelength list labels the predefined IDs only.
        assert_eq!(dec(121, &[0]), Value::List(vec![label(0, "Empty List")]));
        assert_eq!(dec(121, &[7]), Value::List(vec![label(7, "Reserved")]));
        assert_eq!(dec(121, &[21]), Value::List(vec![Value::Enum { code: 21, label: None }]));
        assert!(is_invalid(&dec(121, &[0, 1])));
        assert!(is_invalid(&dec(121, &[1, 0x81])));
    }

    #[test]
    fn spec_example_airbase_locations() {
        let v = tlv("8102 18 0B40 6BC2 0919 BDA5 5407 0E00 0B40 783C B819 A292 7407 C600").value;
        assert_eq!(names(&v), ["Take-off Location", "Recovery Location"]);
        let t = get(&v, "Take-off Location");
        close(get(t, "Latitude"), 38.841859, 2f64.powi(-23));
        close(get(t, "Longitude"), -77.036784, 2f64.powi(-22));
        close(get(t, "HAE"), 3.0, 1e-9);
        let r = get(&v, "Recovery Location");
        close(get(r, "Latitude"), 38.939353, 2f64.powi(-23));
        close(get(r, "Longitude"), -77.459811, 2f64.powi(-22));
        close(get(r, "HAE"), 95.0, 1e-9);
        // No recovery location: it equals the take-off location.
        let v = dec(130, &hex("0B 406BC209 19BDA554 070E00"));
        assert_eq!(get(&v, "Recovery Location"), get(&v, "Take-off Location"));
        // Unknown take-off, recovery without HAE.
        let v = dec(130, &hex("00 08 40783CB8 19A29274"));
        assert_eq!(names(&v), ["Take-off Location", "Recovery Location"]);
        assert_eq!(get(&v, "Take-off Location"), &Value::Unknown);
        assert_eq!(names(get(&v, "Recovery Location")), ["Latitude", "Longitude"]);
        // An unknown take-off location and no recovery location: both unknown.
        let unknown = Value::Struct(vec![field("Take-off Location", Value::Unknown), field("Recovery Location", Value::Unknown)]);
        assert_eq!(dec(130, &[0]), unknown);
        for bad in ["05 0000000000", "00 09 000000000000000000", "00 00 00", "0B 00"] {
            assert!(is_invalid(&dec(130, &hex(bad))), "{bad}");
        }
    }

    #[test]
    fn spec_example_payload_list() {
        let t = "810A 3F 0312 0000 0F56 4953 204E 6F73 6520 4361 6D65 7261 1501 0012 4143 4D45 \
                 2056 4953 204D 6F64 656C 2031 3233 1402 0011 4143 4D45 2049 5220 4D6F 6465 6C20 \
                 3435 36";
        let v = tlv(t).value;
        assert_eq!(get(&v, "Payload Count"), &Value::Uint(3));
        let list = get(&v, "Payload Records").as_list().unwrap();
        let want = ["VIS Nose Camera", "ACME VIS Model 123", "ACME IR Model 456"];
        assert_eq!(list.len(), 3);
        for (i, (r, name)) in list.iter().zip(want).enumerate() {
            assert_eq!(get(r, "Payload ID"), &Value::Uint(i as u64));
            assert_eq!(get(r, "Payload Type"), &label(0, "Electro Optical MI Sensor"));
            assert_eq!(get(r, "Payload Name"), &Value::Text(name.into()));
        }
        // Count only; future bytes after the name; a type outside Table 17;
        // a name past the end of its record.
        let v = dec(138, &[5]);
        assert_eq!(get(&v, "Payload Records"), &Value::List(vec![]));
        let v = dec(138, &hex("05 06 04 04 02 4142 FF 03 01 09 05"));
        let list = get(&v, "Payload Records").as_list().unwrap();
        assert_eq!(get(&list[0], "Payload Type"), &label(4, "SAR"));
        assert_eq!(get(&list[0], "Payload Name"), &Value::Text("AB".into()));
        assert!(is_invalid(&list[1]));
        assert!(is_invalid(&dec(138, &hex("05 06 04"))));
        assert!(is_invalid(&dec(138, &hex("85"))));
    }

    #[test]
    fn active_payload_bits() {
        assert_eq!(dec(139, &[0x00]), Value::List(vec![]));
        assert_eq!(dec(139, &[0x01, 0x00]), Value::List(vec![Value::Uint(8)]));
        assert_eq!(dec(139, &[0x80, 0x01]), Value::List(vec![Value::Uint(0), Value::Uint(15)]));
    }

    #[test]
    fn spec_example_weapons_stores() {
        // The printed length 0x2D disagrees with the 44 printed value bytes
        // (a spec erratum); 0x2C is self-consistent.
        let t = "810C 2C 0E01 0101 0382 0307 4861 7270 6F6F 6E0F 0101 0202 9E04 0848 656C 6C66 \
                 6972 650C 0102 0101 0306 4742 552D 3135";
        let v = tlv(t).value;
        let list = v.as_list().unwrap();
        assert_eq!(list.len(), 3);
        let harpoon = &list[0];
        assert_eq!(
            names(harpoon),
            [
                "Station ID",
                "Hardpoint ID",
                "Carriage ID",
                "Store ID",
                "General Status",
                "Fuze Enabled",
                "Laser Enabled",
                "Target Enabled",
                "Weapon Armed",
                "Weapon Type"
            ]
        );
        assert_eq!(get(harpoon, "Store ID"), &Value::Uint(3));
        assert_eq!(get(harpoon, "General Status"), &label(3, "Ready/All Up Round"));
        assert_eq!(get(harpoon, "Fuze Enabled"), &label(1, "Fuze functions are set"));
        assert_eq!(get(harpoon, "Weapon Armed"), &label(0, "Master Arm is not set"));
        assert_eq!(get(harpoon, "Weapon Type"), &Value::Text("Harpoon".into()));
        let hellfire = &list[1];
        assert_eq!(get(hellfire, "Carriage ID"), &Value::Uint(2));
        assert_eq!(get(hellfire, "General Status"), &label(4, "Launch"));
        for f in ["Fuze Enabled", "Laser Enabled", "Target Enabled", "Weapon Armed"] {
            assert_eq!(get(hellfire, f).as_u64(), Some(1), "{f}");
        }
        assert_eq!(get(hellfire, "Weapon Type"), &Value::Text("Hellfire".into()));
        let gbu = &list[2];
        assert_eq!(get(gbu, "Hardpoint ID"), &Value::Uint(2));
        assert_eq!(get(gbu, "General Status"), &label(3, "Ready/All Up Round"));
        assert_eq!(get(gbu, "Laser Enabled"), &label(0, "Laser functions are not set"));
        assert_eq!(get(gbu, "Weapon Type"), &Value::Text("GBU-15".into()));
        // Reserved and undefined general status codes, a truncated record.
        let v = dec(140, &hex("06 01 01 01 01 0C 00 07 01 01 01 01 81 48 00 03 01 01 01"));
        let list = v.as_list().unwrap();
        assert_eq!(get(&list[0], "General Status"), &label(12, "Reserved"));
        assert_eq!(get(&list[1], "General Status"), &Value::Enum { code: 200, label: None });
        assert!(is_invalid(&list[2]));
        // The erratum's printed length runs one byte past the value.
        assert!(crate::klv::local_set(&hex(&t.replace("2C", "2D"))).next().unwrap().is_err());
    }

    #[test]
    fn spec_example_waypoint_list() {
        let t = "810D 40 0F00 0001 0340 71D8 9419 BDBF E708 9800 0F01 0002 0240 71D3 8819 BCCE \
                 2408 FC00 0F02 7FFF 0140 71E3 0819 BF2C 1B07 D000 0F03 FFFE 0040 71E5 AF19 BF5A \
                 A709 6000";
        let v = tlv(t).value;
        let list = v.as_list().unwrap();
        // (ID, order, mode, source, lat, lon, HAE) from the example software
        // value, which prints the info value as (source, mode).
        let want = [
            (0, 1, 1, 1, 38.889422, -77.035162, 200.0),
            (1, 2, 0, 1, 38.889268, -77.049918, 250.0),
            (2, 32767, 1, 0, 38.889741, -77.012933, 100.0),
            (3, -2, 0, 0, 38.889822, -77.010092, 300.0),
        ];
        assert_eq!(list.len(), 4);
        for (r, &(id, order, mode, source, lat, lon, hae)) in list.iter().zip(&want) {
            assert_eq!(get(r, "Waypoint ID"), &Value::Uint(id));
            assert_eq!(get(r, "Prosecution Order"), &Value::Int(order));
            assert_eq!(get(r, "Mode").as_u64(), Some(mode));
            assert_eq!(get(r, "Source").as_u64(), Some(source));
            let l = get(r, "Location");
            close(get(l, "Latitude"), lat, 2f64.powi(-23) + 5e-7);
            close(get(l, "Longitude"), lon, 2f64.powi(-22) + 5e-7);
            close(get(l, "HAE"), hae, 1e-9);
        }
        assert_eq!(get(&list[0], "Mode"), &label(1, "Manual"));
        assert_eq!(get(&list[3], "Source"), &label(0, "Pre-planned"));
        // Info and location are optional; a bad location or a short order
        // invalidates only that record.
        let v = dec(141, &hex("03 05 FFFF 04 06 0001 02 00 00 00 08 07 0003 01 0000000000 02 08 00"));
        let list = v.as_list().unwrap();
        assert_eq!(names(&list[0]), ["Waypoint ID", "Prosecution Order"]);
        assert_eq!(get(&list[0], "Prosecution Order"), &Value::Int(-1));
        assert_eq!(names(&list[1]), ["Waypoint ID", "Prosecution Order", "Mode", "Source"]);
        assert_eq!(get(&list[1], "Source"), &label(1, "Ad hoc"));
        assert!(is_invalid(&list[2]));
        assert!(is_invalid(&list[3]));
        assert!(is_invalid(&dec(141, &hex("0F 00"))));
    }

    #[test]
    fn spec_example_view_domain() {
        let v = tlv("810E 0E 0634 8000 4B00 0006 1A40 000C 8000").value;
        assert_eq!(names(&v), ["Azimuth Start", "Azimuth Range", "Elevation Start", "Elevation Range"]);
        assert_eq!(get(&v, "Azimuth Start"), &Value::Float(210.0));
        assert_eq!(get(&v, "Azimuth Range"), &Value::Float(300.0));
        assert_eq!(get(&v, "Elevation Start"), &Value::Float(-75.0));
        assert_eq!(get(&v, "Elevation Range"), &Value::Float(50.0));
        // Figure 89: unknown azimuth, then elevation and roll.
        let v = dec(142, &hex("00 06 1A4000 0C8000 04 5780 0500"));
        assert_eq!(
            names(&v),
            ["Azimuth Start", "Azimuth Range", "Elevation Start", "Elevation Range", "Roll Start", "Roll Range"]
        );
        assert_eq!((get(&v, "Azimuth Start"), get(&v, "Azimuth Range")), (&Value::Unknown, &Value::Unknown));
        assert_eq!(get(&v, "Roll Start"), &Value::Float(350.0));
        assert_eq!(get(&v, "Roll Range"), &Value::Float(20.0));
        for bad in ["03 000000", "12 000000000000000000000000000000000000", "00 00 00 00", "06 0000"] {
            assert!(is_invalid(&dec(142, &hex(bad))), "{bad}");
        }
    }

    #[test]
    fn spec_example_metadata_substream_id() {
        let v = tlv("810F 11 008D C4F4 623E A25A 859C 5D0A F0C9 5E8C 39").value;
        assert_eq!(get(&v, "Local Id"), &Value::Uint(0));
        assert_eq!(get(&v, "Universal Id"), &Value::Text("8dc4f462-3ea2-5a85-9c5d-0af0c95e8c39".into()));
        let v = dec(143, &[5]);
        assert_eq!(names(&v), ["Local Id"]);
        let mut with_uuid = vec![5];
        with_uuid.extend([0; 16]);
        for (case, bad) in [
            ("nonzero local ID with UUID", &with_uuid[..]),
            ("missing UUID", &[0]),
            ("short UUID", &with_uuid[1..16]),
            ("incomplete local ID", &[0x85]),
        ] {
            assert!(is_invalid(&dec(143, bad)), "{case}");
        }
    }

    #[test]
    fn positioning_method_flags() {
        assert!(is_invalid(&dec(124, &[0])));
        assert_eq!(dec(124, &[0x80]), Value::List(vec![label(7, "BeiDou-2")]));
        // A future method in a more significant byte has no label yet.
        assert_eq!(
            dec(124, &[0x01, 0x02]),
            Value::List(vec![label(1, "GPS"), Value::Enum { code: 8, label: None }])
        );
        assert!(is_invalid(&dec(124, &[1; 9])));
    }

    #[test]
    fn laser_prf_codes() {
        for ok in [111u16, 888, 1111, 1743, 8888] {
            assert_eq!(dec(62, &ok.to_be_bytes()), Value::Uint(u64::from(ok)));
        }
        for bad in [0u16, 110, 119, 999, 1009, 8889, 9999, 50895] {
            assert!(is_invalid(&dec(62, &bad.to_be_bytes())), "{bad}");
        }
        assert!(is_invalid(&dec(62, &[1])));
    }

    #[test]
    fn enumerations() {
        let cases: &[(u64, u8, Option<&str>)] = &[
            (34, 0, Some("Detector off")),
            (34, 1, Some("No icing Detected")),
            (34, 3, None),
            (63, 0, Some("Ultranarrow")),
            (63, 7, Some("4x Ultranarrow")),
            (63, 8, Some("Continuous Zoom")),
            (63, 9, Some("Reserved")),
            (63, 255, Some("Reserved")),
            (77, 0, Some("Other")),
            (77, 5, Some("Test")),
            (77, 6, Some("Reserved")),
            (125, 0, Some("Active")),
            (125, 11, Some("Landed-taxiing")),
            (125, 12, Some("Landed-Parked")),
            (125, 13, Some("Reserved")),
            (126, 0, Some("Off")),
            (126, 6, Some("Auto - Tracking")),
            (126, 7, Some("Reserved")),
        ];
        for &(tag, code, want) in cases {
            assert_eq!(dec(tag, &[code]), Value::Enum { code: u64::from(code), label: want }, "{tag} {code}");
        }
        for tag in [34, 63, 77, 125, 126] {
            assert!(is_invalid(&dec(tag, &[0, 0])), "{tag}");
        }
    }

    /// Range end points of every linearly mapped unsigned item, written out
    /// from the ST 0601.19 summary tables independently of the codec table.
    const UNSIGNED: &[(u64, usize, f64, f64)] = &[
        (5, 2, 0.0, 360.0),
        (15, 2, -900.0, 19_000.0),
        (16, 2, 0.0, 180.0),
        (17, 2, 0.0, 180.0),
        (18, 4, 0.0, 360.0),
        (20, 4, 0.0, 360.0),
        (21, 4, 0.0, 5_000_000.0),
        (22, 2, 0.0, 10_000.0),
        (25, 2, -900.0, 19_000.0),
        (35, 2, 0.0, 360.0),
        (36, 1, 0.0, 100.0),
        (37, 2, 0.0, 5_000.0),
        (38, 2, -900.0, 19_000.0),
        (42, 2, -900.0, 19_000.0),
        (45, 2, 0.0, 4_095.0),
        (46, 2, 0.0, 4_095.0),
        (49, 2, 0.0, 5_000.0),
        (53, 2, 0.0, 5_000.0),
        (54, 2, -900.0, 19_000.0),
        (55, 1, 0.0, 100.0),
        (57, 4, 0.0, 5_000_000.0),
        (58, 2, 0.0, 10_000.0),
        (64, 2, 0.0, 360.0),
        (69, 2, -900.0, 19_000.0),
        (71, 2, 0.0, 360.0),
        (75, 2, -900.0, 19_000.0),
        (76, 2, -900.0, 19_000.0),
        (78, 2, -900.0, 19_000.0),
    ];

    /// Kinds of the most negative code of a signed mapped item.
    #[derive(Clone, Copy, PartialEq)]
    enum Sp {
        OutOfRange,
        Reserved,
        OffEarth,
    }

    /// Every signed mapped item: (tag, length, +/- range, special code).
    const SIGNED: &[(u64, usize, f64, Sp)] = &[
        (6, 2, 20.0, Sp::OutOfRange),
        (7, 2, 50.0, Sp::OutOfRange),
        (13, 4, 90.0, Sp::Reserved),
        (14, 4, 180.0, Sp::Reserved),
        (19, 4, 180.0, Sp::Reserved),
        (23, 4, 90.0, Sp::OffEarth),
        (24, 4, 180.0, Sp::OffEarth),
        (26, 2, 0.075, Sp::OffEarth),
        (27, 2, 0.075, Sp::OffEarth),
        (28, 2, 0.075, Sp::OffEarth),
        (29, 2, 0.075, Sp::OffEarth),
        (30, 2, 0.075, Sp::OffEarth),
        (31, 2, 0.075, Sp::OffEarth),
        (32, 2, 0.075, Sp::OffEarth),
        (33, 2, 0.075, Sp::OffEarth),
        (40, 4, 90.0, Sp::OffEarth),
        (41, 4, 180.0, Sp::OffEarth),
        (50, 2, 20.0, Sp::OutOfRange),
        (51, 2, 180.0, Sp::OutOfRange),
        (52, 2, 20.0, Sp::OutOfRange),
        (67, 4, 90.0, Sp::Reserved),
        (68, 4, 180.0, Sp::Reserved),
        (79, 2, 327.0, Sp::OutOfRange),
        (80, 2, 327.0, Sp::OutOfRange),
        (82, 4, 90.0, Sp::OffEarth),
        (83, 4, 180.0, Sp::OffEarth),
        (84, 4, 90.0, Sp::OffEarth),
        (85, 4, 180.0, Sp::OffEarth),
        (86, 4, 90.0, Sp::OffEarth),
        (87, 4, 180.0, Sp::OffEarth),
        (88, 4, 90.0, Sp::OffEarth),
        (89, 4, 180.0, Sp::OffEarth),
        (90, 4, 90.0, Sp::OutOfRange),
        (91, 4, 90.0, Sp::OutOfRange),
        (92, 4, 90.0, Sp::OutOfRange),
        (93, 4, 180.0, Sp::OutOfRange),
    ];

    /// Every IMAPB item: (tag, min, max, maximum length).
    const IMAPB: &[(u64, f64, f64, usize)] = &[
        (96, 0.0, 1_500_000.0, 8),
        (103, -900.0, 40_000.0, 8),
        (104, -900.0, 40_000.0, 8),
        (105, -900.0, 40_000.0, 8),
        (109, 0.0, 21_000.0, 4),
        (112, 0.0, 360.0, 8),
        (113, -900.0, 40_000.0, 4),
        (114, -900.0, 40_000.0, 4),
        (117, -1_000.0, 1_000.0, 4),
        (118, -1_000.0, 1_000.0, 4),
        (119, -1_000.0, 1_000.0, 4),
        (120, 0.0, 100.0, 3),
        (132, 1.0, 99_999.0, 4),
        (134, 0.0, 100.0, 4),
    ];

    #[test]
    fn boundary_lists_cover_every_mapped_item() {
        for d in &DESCS {
            let n = u64::from(d.tag);
            match d.codec {
                Codec::Unsigned { .. } => assert!(UNSIGNED.iter().any(|c| c.0 == n), "tag {n}"),
                Codec::Signed { .. } => assert!(SIGNED.iter().any(|c| c.0 == n), "tag {n}"),
                Codec::Imapb { .. } => assert!(IMAPB.iter().any(|c| c.0 == n), "tag {n}"),
                _ => {}
            }
        }
    }

    #[test]
    fn unsigned_boundaries() {
        for &(tag, len, min, max) in UNSIGNED {
            assert_eq!(dec(tag, &vec![0; len]), Value::Float(min), "tag {tag}");
            close(&dec(tag, &vec![0xFF; len]), max, max.abs() * 1e-12);
            assert!(is_invalid(&dec(tag, &vec![0; len - 1])) || len == 1, "tag {tag}");
            assert!(is_invalid(&dec(tag, &vec![0; len + 1])), "tag {tag}");
        }
    }

    #[test]
    fn signed_boundaries() {
        for &(tag, len, range, sp) in SIGNED {
            let mut top = vec![0xFF; len];
            top[0] = 0x7F;
            let mut bottom = vec![0; len];
            bottom[0] = 0x80;
            *bottom.last_mut().unwrap() = 0x01;
            let mut special = vec![0; len];
            special[0] = 0x80;
            close(&dec(tag, &top), range, range * 1e-12);
            close(&dec(tag, &bottom), -range, range * 1e-12);
            assert_eq!(dec(tag, &vec![0; len]), Value::Float(0.0), "tag {tag}");
            close(&dec(tag, &vec![0xFF; len]), -range / (2f64.powi(8 * len as i32 - 1) - 1.0), 1e-15);
            let code = if len == 2 { 0x8000 } else { 0x8000_0000 };
            let want = match sp {
                Sp::OutOfRange | Sp::Reserved => Value::OutOfRange,
                Sp::OffEarth => label(code, "N/A (Off-Earth)"),
            };
            assert_eq!(dec(tag, &special), want, "tag {tag}");
            assert!(is_invalid(&dec(tag, &vec![0; len - 1])), "tag {tag}");
            assert!(is_invalid(&dec(tag, &vec![0; len + 1])), "tag {tag}");
        }
    }

    #[test]
    fn imapb_boundaries() {
        for &(tag, min, max, max_len) in IMAPB {
            for len in 1..=max_len {
                let lsb = 2f64.powf((max - min).log2().ceil() - (8 * len - 1) as f64);
                // y = 0 is the range minimum, shifted by at most one LSB
                // where the zero offset applies (ST 1201 section 8.1.1).
                close(&dec(tag, &vec![0; len]), min, lsb);
                let mut below = vec![0; len];
                below[0] = 0xE0;
                assert_eq!(dec(tag, &below), Value::OutOfRange, "tag {tag} len {len}");
                let mut inf = vec![0; len];
                inf[0] = 0xC8;
                assert_eq!(dec(tag, &inf), Value::Float(f64::INFINITY), "tag {tag} len {len}");
                // The real maximum: the integer the forward mapping gives for
                // max (ST 1201.5 section 7.2.1) decodes to max within an LSB.
                let map = crate::imapb::Imapb::new(min, max, len).unwrap();
                let y_max = map.real_to_int(max).unwrap();
                let top = float(&dec(tag, &y_max.to_be_bytes()[8 - len..]));
                assert!(top >= max - lsb && top <= max, "tag {tag} len {len}: {top}");
                // A normal-pattern integer above it lies outside the range,
                // which no conforming encoder produces: invalid.
                let above = [&[0x7F][..], &vec![0xFF; len - 1]].concat();
                if crate::klv::be_uint(&above).unwrap() > y_max {
                    assert_eq!(dec(tag, &above), Value::Invalid("IMAPB value above range maximum"), "tag {tag} len {len}");
                }
            }
            assert!(is_invalid(&dec(tag, &vec![0; max_len + 1])), "tag {tag}");
        }
    }

    #[test]
    fn integers_and_times() {
        assert_eq!(dec(1, &[0x12, 0x34]), Value::Uint(0x1234));
        assert!(is_invalid(&dec(1, &[0x12])));
        assert!(is_invalid(&dec(1, &[0, 0, 0])));
        assert_eq!(dec(2, &[0xFF; 8]), Value::Time(u64::MAX));
        assert!(is_invalid(&dec(2, &[0; 7])));
        assert!(is_invalid(&dec(72, &[0; 9])));
        assert!(is_invalid(&dec(8, &[0, 0])));
        assert_eq!(dec(39, &[0x80]), Value::Int(-128));
        assert_eq!(dec(39, &[0xFF]), Value::Int(-1));
        assert_eq!(dec(43, &[0xFF]), Value::Uint(510));
        assert!(is_invalid(&dec(44, &[0, 0])));
        assert_eq!(dec(65, &[19]), Value::Uint(19));
        for tag in [110, 111, 133] {
            for len in 1..=4 {
                assert_eq!(dec(tag, &vec![0xFF; len]), Value::Uint((1u64 << (8 * len)) - 1));
            }
            assert!(is_invalid(&dec(tag, &[0; 5])));
        }
        assert_eq!(dec(131, &[0x01]), Value::Time(1));
        assert_eq!(dec(131, &[0xFF; 8]), Value::Time(u64::MAX));
        assert!(is_invalid(&dec(131, &[0; 9])));
        assert_eq!(dec(136, &[0xFF]), Value::Int(-1));
        assert_eq!(dec(136, &[0x80, 0, 0, 0]), Value::Int(i64::from(i32::MIN)));
        assert!(is_invalid(&dec(136, &[0; 5])));
        assert_eq!(dec(137, &[0x80, 0, 0, 0, 0, 0, 0, 0]), Value::Int(i64::MIN));
        assert_eq!(dec(137, &[0x7F, 0xFF]), Value::Int(0x7FFF));
        assert!(is_invalid(&dec(137, &[0; 9])));
        assert_eq!(dec(123, &[0xFF]), Value::Uint(255));
        assert!(is_invalid(&dec(123, &[0, 0])));
    }

    #[test]
    fn text_is_lossy_and_unbounded() {
        assert_eq!(dec(3, b"\xFFab"), Value::Text("\u{FFFD}ab".into()));
        // The 127-byte maximum is a suggestion in the standard.
        let long = vec![b'x'; 300];
        assert_eq!(dec(59, &long), Value::Text("x".repeat(300)));
        assert_eq!(dec(129, &long[..40]), Value::Text("x".repeat(40)));
    }

    #[test]
    fn zero_length_items() {
        // ST 0601.19 section 6.5: every item may be unknown except the
        // mandatory ones and those that may repeat.
        let forbidden = [1, 2, 65, 100, 101, 102, 115];
        for tag in 1..=143u64 {
            let item = decode_item(tag, &[], 0, &Config::default());
            if forbidden.contains(&tag) {
                assert_eq!(item.value, Value::Invalid(NO_ZLI), "tag {tag}");
            } else {
                assert_eq!(item.value, Value::Unknown, "tag {tag}");
                assert!(item.value.is_valid());
            }
            assert!(item.raw.is_empty());
        }
        // Inside a Segment Local Set the same rules apply.
        let seg = decode_item(100, &[13, 0, 2, 0], 0, &Config::default());
        let seg = seg.value.as_set().unwrap();
        assert_eq!(seg.get(Tag::SensorLatitude), Some(&Value::Unknown));
        assert_eq!(seg.get(Tag::PrecisionTimeStamp), Some(&Value::Invalid(NO_ZLI)));
        // Unknown tags keep their (empty) bytes as they are.
        assert_eq!(dec(200, &[]), Value::Bytes(Vec::new()));
    }

    #[test]
    fn opaque_items() {
        for tag in [66, 95, 97, 98, 99] {
            assert_eq!(dec(tag, &[1, 2, 3]), Value::Bytes(vec![1, 2, 3]), "tag {tag}");
        }
        let raw = [0x01, 0x02];
        assert_eq!(dec(102, &raw), crate::st1010::decode(&raw));
        // Tag 102's lists are bounded by the packet's Config.
        let mut cfg = Config::default();
        cfg.max_items = 1;
        let mut pack = vec![0x03, 0x40];
        pack.extend([0u8; 12]);
        assert!(crate::st1010::decode(&pack).is_valid());
        assert!(is_invalid(&decode_item(102, &pack, 0, &cfg).value));
    }

    #[test]
    fn list_limits() {
        let mut cfg = Config::default();
        cfg.max_items = 2;
        let d = |tag, v: &[u8]| decode_item(tag, v, 0, &cfg).value;
        assert_eq!(d(116, &[1, 2]), Value::List(vec![Value::Uint(1), Value::Uint(2)]));
        assert_eq!(d(116, &[1, 2, 3]), Value::Invalid(TOO_MANY));
        assert_eq!(d(121, &[1, 2, 3]), Value::Invalid(TOO_MANY));
        assert_eq!(d(139, &[0x07]), Value::Invalid(TOO_MANY));
        assert_eq!(d(128, &[0, 0, 0]), Value::Invalid(TOO_MANY));
        assert_eq!(d(141, &[0, 0, 0]), Value::Invalid(TOO_MANY));
        assert_eq!(d(140, &[0, 0, 0]), Value::Invalid(TOO_MANY));
        assert_eq!(get(&d(138, &[3, 0, 0]), "Payload Records").as_list().unwrap().len(), 2);
        assert_eq!(d(138, &[3, 0, 0, 0]), Value::Invalid(TOO_MANY));
    }

    /// Build a local set from (tag, value) items with BER-OID tags and BER
    /// lengths.
    fn set(items: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, v) in items {
            if *tag >= 128 {
                out.extend([0x80 | (*tag >> 7) as u8, (*tag & 0x7F) as u8]);
            } else {
                out.push(*tag as u8);
            }
            if v.len() < 128 {
                out.push(v.len() as u8);
            } else {
                out.extend([0x82, (v.len() >> 8) as u8, v.len() as u8]);
            }
            out.extend(v);
        }
        out
    }

    #[test]
    fn nested_sets() {
        let security = set(&[(1, vec![1]), (2, vec![7]), (3, b"//USA".to_vec())]);
        let rvt = set(&[(10, b"H.264".to_vec()), (8, vec![3])]);
        let vmti = set(&[(3, b"DSTO_ADSS_VMTI".to_vec()), (4, vec![6]), (5, vec![28])]);
        let segment = set(&[(143, vec![5]), (13, hex("5595B66D")), (3, b"PIP".to_vec())]);
        let mut msid = vec![0];
        msid.extend(hex("8DC4F4623EA25A859C5D0AF0C95E8C39"));
        let amend = set(&[(143, msid), (14, hex("5B5360C4"))]);
        let top = set(&[
            (48, security),
            (73, rvt),
            (74, vmti),
            (100, segment.clone()),
            (100, segment),
            (101, amend),
        ]);
        let p = decode_set(Standard::St0601, &top, 0, &Config::default());
        assert!(p.error.is_none(), "{:?}", p.error);
        let nested = |i: usize| p.items[i].value.as_set().unwrap();
        let tags = |p: &Packet| p.items.iter().map(|i| i.tag).collect::<Vec<_>>();
        assert_eq!(nested(0).standard, Standard::St0102);
        assert_eq!(tags(nested(0)), [1, 2, 3]);
        assert_eq!(nested(1).standard, Standard::St0806);
        assert_eq!(tags(nested(1)), [10, 8]);
        assert_eq!(nested(2).standard, Standard::St0903);
        assert_eq!(tags(nested(2)), [3, 4, 5]);
        assert_eq!(nested(1).checksum, Checksum::NotApplicable);
        // Segments and amends hold ST 0601 items, decoded with this table.
        for i in [3, 4] {
            let s = nested(i);
            assert_eq!(s.standard, Standard::St0601);
            assert_eq!(get(s.get(Tag::MetadataSubstreamIdPack).unwrap(), "Local Id"), &Value::Uint(5));
            close(s.get(Tag::SensorLatitude).unwrap(), 60.176822966978335, 1e-12);
            assert_eq!(s.get(Tag::MissionId), Some(&Value::Text("PIP".into())));
        }
        let a = nested(5);
        assert_eq!(a.items[0].name, "Metadata Substream ID Pack");
        close(a.get(Tag::SensorLongitude).unwrap(), 128.42675904204452, 1e-12);
        assert_eq!(p.items[5].name, "Amend Local Set");
    }

    #[test]
    fn nesting_depth_is_bounded() {
        // Segment sets nested ten deep.
        let mut v = set(&[(65, vec![19])]);
        for _ in 0..10 {
            v = set(&[(100, v)]);
        }
        let mut cfg = Config::default();
        cfg.max_depth = 3;
        let p = decode_set(Standard::St0601, &v, 0, &cfg);
        // Depths 0 to 3 decode; the set at depth 4 is refused.
        let mut level = &p;
        for _ in 0..=3 {
            assert!(level.error.is_none());
            level = level.items[0].value.as_set().unwrap();
        }
        assert_eq!(level.error, Some(Error::TooDeep));
        assert!(level.items.is_empty());
    }

    /// The two complete ST 0601 packets MISB publishes, ST 0902.8 Annex C
    /// Tables 10 and 11 (ST 0601 version 6), through the public decoder.
    #[test]
    fn st0902_example_packets() {
        let a = hex(
            "060E2B34020B01010E01030101000000 81D2 0208000460 50584E0180 030A4D697373696F6E203132
             050271C2 0602FD3D 070208B8 0A085072656461746F72 0B07454F204E6F7365
             0C0E47656F646574696320574753383 4 0D045595B66D 0E045B5360C4 0F02C221 1002CD9C
             1102D917 1204724A0A20 130487F84B86 14047DC55ECE 150403830926 16021281 1704F101A229
             180414BC082B 190234F3
             301C 010101 020107 03052F2F555341 0C0107 0D06005500530041 1602000A
             410106 5E220170F592F0237336 4AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645
             01023E1E",
        );
        assert_eq!(a.len(), 228);
        let p = crate::decode(&a).unwrap();
        assert_eq!(p.checksum, Checksum::Valid);
        assert!(p.is_ok());
        let tags: Vec<u64> = p.items.iter().map(|i| i.tag).collect();
        assert_eq!(
            tags,
            [2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 48, 65, 94, 1]
        );
        assert_eq!(p.get(Tag::PrecisionTimeStamp), Some(&Value::Time(1_231_798_102_000_000)));
        assert_eq!(p.get(Tag::MissionId), Some(&Value::Text("Mission 12".into())));
        assert_eq!(p.get(Tag::PlatformDesignation), Some(&Value::Text("Predator".into())));
        assert_eq!(p.get(Tag::ImageSourceSensor), Some(&Value::Text("EO Nose".into())));
        close(p.get(Tag::PlatformHeadingAngle).unwrap(), 159.974365, 180.0 / U16);
        close(p.get(Tag::SensorLatitude).unwrap(), 60.176822966978335, 90.0 / S32);
        close(p.get(Tag::FrameCenterElevation).unwrap(), 3216.03723, 9_950.0 / U16);
        let security = p.get(Tag::SecurityLocalSet).unwrap().as_set().unwrap();
        assert_eq!(security.standard, Standard::St0102);
        assert_eq!(security.items.iter().map(|i| i.tag).collect::<Vec<_>>(), [1, 2, 3, 12, 13, 22]);
        assert_eq!(p.get(Tag::UasDatalinkLsVersionNumber), Some(&Value::Uint(6)));
        assert_eq!(p.item(Tag::MiisCoreIdentifier).unwrap().raw.len(), 34);
        assert_eq!(p.get(Tag::Checksum), Some(&Value::Uint(0x3E1E)));
        assert!(!p.to_string().is_empty());

        let b = hex(
            "060E2B34020B01010E01030101000000 61 0208000460 50584E0180 050271C2 0602FD3D 070208B8
             0D045595B66D 0E045B5360C4 0F02C221 1002CD9C 1102D917 1204724A0A20 130487F84B86
             14047DC55ECE 150403830926 16021281 1704F101A229 180414BC082B 190234F3 410106 01025C2B",
        );
        assert_eq!(b.len(), 114);
        let p = crate::decode(&b).unwrap();
        assert_eq!(p.checksum, Checksum::Valid);
        assert_eq!(p.len(), 19);
        close(p.get(Tag::SensorRelativeElevationAngle).unwrap(), -168.79232483394085, 180.0 / S32);
        close(p.get(Tag::FrameCenterLatitude).unwrap(), -10.542388633146132, 90.0 / S32);
        assert!(p.items.iter().all(|i| i.value.is_valid()));
    }

    #[test]
    fn hostile_input_never_panics() {
        // Deterministic pseudo-random values of every length up to 64 for
        // every tag, plus nested segments of the same.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let cfg = Config::default();
        for tag in 0..=150u64 {
            for len in 0..=64usize {
                for _ in 0..8 {
                    let v: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                    let item = decode_item(tag, &v, 0, &cfg);
                    let _ = item.to_string();
                    let nested = set(&[(tag, v)]);
                    let _ = decode_item(100, &nested, 0, &cfg);
                }
                for fill in [0x00, 0x7F, 0x80, 0xFF] {
                    let _ = decode_item(tag, &vec![fill; len], 0, &cfg);
                }
            }
        }
        // Lengths that overflow, inside packs.
        for v in [
            hex("05 88 FFFFFFFFFFFFFFFF"),
            hex("8F FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            hex("FFFFFFFFFFFFFFFFFFFFFF7F"),
        ] {
            for tag in [115, 122, 128, 130, 138, 140, 141, 142, 143] {
                assert!(is_invalid(&decode_item(tag, &v, 0, &cfg).value), "tag {tag} {v:02X?}");
            }
        }
    }
}
