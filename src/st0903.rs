//! MISB ST 0903 Video Moving Target Indicator (VMTI) Local Set.
//!
//! Decoded where ST 0601 embeds it: the value of ST 0601 tag 74 is a VMTI
//! Local Set without its universal key and length (MISB ST 0601.19 section
//! 6.3.3, ST 0903.6 section 8.2). The tables follow ST 0903.6 (21 October
//! 2021) Tables 9 to 20. Items that ST 0903.6 deprecates are still decoded as
//! earlier revisions defined them, because ST 0903.6 Appendix C asks readers
//! to accept data written to ST 0903.5.
//!
//! # Representation
//!
//! The VMTI Local Set itself is a [`Packet`](crate::Packet) of
//! [`Standard::St0903`](crate::Standard::St0903) whose items carry the tags of
//! [`Tag`]. Everything inside it is built from [`Value`]s:
//!
//! - The VTarget Series (tag 101) is a [`Value::List`] with one
//!   [`Value::Struct`] per VTarget Pack. Its first field is `"Target ID"`,
//!   then each item of the pack follows as one field, in the order received.
//! - The VMask, VObject, VFeature, VTracker, VChip, Algorithm and Ontology
//!   Local Sets are [`Value::Struct`]s built the same way, and every Series
//!   is a [`Value::List`] of its elements.
//! - The Location, Velocity and Acceleration packs, the target color, the FPA
//!   index and the pixel runs of a bit mask are [`Value::Struct`]s with one
//!   field per element.
//!
//! These sets are not [`Value::Set`]s on purpose. A
//! [`Packet`](crate::Packet) names its standard and there is no
//! [`Standard`](crate::Standard) for a VTarget Pack or a VMask; marked as
//! [`Standard::St0903`](crate::Standard::St0903) their tags would read as VMTI
//! Local Set tags (VTarget tag 1 is Target Centroid, VMTI tag 1 is Checksum).
//! [`Value::field`] looks a field up by its name:
//!
//! ```
//! fn print_targets(vmti: &misb::Packet) {
//!     let series = vmti.get(misb::st0903::Tag::VTargetSeries);
//!     for target in series.and_then(|v| v.as_list()).unwrap_or(&[]) {
//!         let id = target.field("Target ID").and_then(|v| v.as_u64());
//!         let location = target.field("Target Location");
//!         let latitude = location.and_then(|l| l.field("Latitude")).and_then(|v| v.as_f64());
//!         println!("{id:?} {latitude:?}");
//!     }
//! }
//! ```
//!
//! # Decoding rules
//!
//! - Tags. The VMTI Local Set uses BER-OID tags; the VTarget Pack and every
//!   other local set inside it use one-byte tags (ST 0903.6 section 9.2, and
//!   section 10.2 for the VTarget Pack). Lengths are BER short or long form
//!   everywhere. Every tag ST 0903.6 defines is below 128, so the two tag
//!   forms only differ for unknown tags.
//! - Unknown tags are kept (MISB ST 0107 asks decoders to skip them without
//!   harm to the rest of the set): in the VMTI Local Set as an item named
//!   `"Unknown"`, inside other sets as a field named `"Unknown"` holding a
//!   struct of `"Tag"` and `"Value"` (the bytes).
//! - Malformed structure. When an item of a set runs past the end of the
//!   set, or a Series element runs past the end of the Series, the set ends
//!   with a field named `"Error"` and the list with an element, both a
//!   [`Value::Invalid`] that says why. What was decoded before is kept. The
//!   same marker ends a set or list that holds more than
//!   [`Config::max_items`](crate::Config::max_items) entries.
//! - A zero-length item means the value is unknown (MISB ST 0903.4-01
//!   invokes ST 0107) and decodes as [`Value::Unknown`]. Every item is used
//!   at most once per set (ST 0903.5-98), so any item may be unknown except
//!   those a set must contain, for which a zero-length item is
//!   [`Value::Invalid`]: the VMTI LS checksum (tag 1, which only a
//!   standalone set carries) and version number (tag 4, ST 0903.5-99), the
//!   VChip image type (tag 1, ST 0903.6-134), the Algorithm ID, name and
//!   version (tags 1 to 3, ST 0903.5-102 to -104), and the Ontology ID,
//!   ontology IRI and entity IRI (tags 1, 3 and 4, ST 0903.5-105, -107,
//!   -108). An empty element of a Series is not an item and is
//!   [`Value::Invalid`].
//! - Integers. `uint Vn` items take 1 to n bytes (ST 0903.6 section 9.1);
//!   values padded with leading zeros up to n bytes, as revisions before
//!   ST 0903.6 allowed, are accepted (Appendix C). Fixed-size integers must
//!   have their exact size. A value outside the valid values the standard
//!   gives for the item (for example a Target Priority of 0) is
//!   [`Value::Invalid`].
//! - Floating point items use MISB ST 1201 IMAPB, decoded with the length the
//!   item arrives with (ST 1201.5 section 7.4; the lengths in ST 0903.6 are
//!   nominal, section 9.2.4), 1 to 8 bytes, except where the table gives a
//!   maximum. ST 0903.6 section 9.1.1 defines the "Invalid" signal, an IMAP
//!   user defined value of `0xC1` padded with zero bytes; it decodes as
//!   [`Value::OutOfRange`], like the ST 1201 below-minimum and above-maximum
//!   signals. A mapped value above the range maximum is [`Value::Invalid`].
//!   The other ST 1201 special values decode as
//!   [`Imapb::decode`](crate::imapb::Imapb::decode) describes.
//! - Text is UTF-8, decoded lossily; an item longer than the character limit
//!   of the table is [`Value::Invalid`].
//! - The checksum (tag 1) belongs to standalone VMTI only: ST 0903.6-120 and
//!   ST 0601.19 section 6.3.3 omit it from a nested set. If present it is
//!   reported as received and not verified, as it covers the universal key
//!   of a standalone set, which a nested set does not have.
//! - Not enforced, as they do not change how the data parses: required
//!   items, item order, items used at most once per set (ST 0903.5-98, a
//!   repeated item is kept each time), unique Target IDs (ST 0903.6-126),
//!   minimum counts (three Pixel Contour points, two Location vertices in a
//!   Series, one item after a Target ID), limits that need the frame size
//!   (ST 0903.5-100, -101), the Image Type values ("jpeg" or "png" since ST
//!   0903.6-136) and references between sets (Algorithm ID, Ontology ID).
//! - Version. The decoder applies the mappings of ST 0903.4 and later
//!   (VMTI LS Version Number 4 and above). Sets that ST 0903.3 and earlier
//!   wrote (version 0 to 3) encode tags 11 and 12 and VTarget tags 10 to 16
//!   as plain integers with other scales and the same lengths, so their
//!   values decode wrongly here; check [`Tag::VersionNumber`].
//!
//! # Nesting depth
//!
//! Every local set below the VMTI Local Set is one nesting level deeper than
//! its parent and obeys [`Config::max_depth`](crate::Config::max_depth): the
//! VTarget Packs and the Algorithm and Ontology Local Sets sit one level
//! below the VMTI Local Set, the VMask, VObject, VFeature, VTracker and VChip
//! sets one level below their VTarget Pack, and the VFeature sets of a
//! VObject's VFeature Series one level below that VObject. With ST 0601 at
//! level 0 the VMTI Local Set is at level 1 and the deepest set ST 0903.6
//! defines at level 4. A set or Series of sets that would go deeper decodes
//! as [`Value::Invalid`]. No ST 0903 set can contain itself, so recursion is
//! bounded by the structure as well as by the limit.
//!
//! # Tables
//!
//! Field names and how each value decodes. "IMAPB(a, b)" is ST 1201 IMAPB
//! over a to b decoded to [`Value::Float`]; "uint Vn" is [`Value::Uint`] of 1
//! to n bytes; "Time" is [`Value::Time`]; a pixel number counts from 1 at the
//! top left pixel, row by row (ST 0903.6 section 9.2.3.1).
//!
//! VTarget Pack (ST 0903.6 Table 10; the Target ID is a BER-OID of at most 9
//! bytes before the items):
//!
//! | Tag | Field | Units | Value |
//! |-----|-------|-------|-------|
//! | - | Target ID | | uint, BER-OID, at most 9 bytes |
//! | 1 | Target Centroid | | pixel number, uint V6, 1 or more |
//! | 2 | Bounding Box Top Left | | pixel number, uint V6, 1 or more |
//! | 3 | Bounding Box Bottom Right | | pixel number, uint V6, 1 or more |
//! | 4 | Target Priority | | uint, 1 byte, 1 to 255 (1 is highest) |
//! | 5 | Target Confidence Level | percent | uint, 1 byte, 0 to 100 |
//! | 6 | Target History | | uint V2 |
//! | 7 | Percentage of Target Pixels | percent | uint, 1 byte, 1 to 100 |
//! | 8 | Target Color | | struct of Red, Green, Blue, 1 byte each |
//! | 9 | Target Intensity | | uint V3 |
//! | 10 | Target Location Latitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 11 | Target Location Longitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 12 | Target Height | m (HAE) | IMAPB(-900, 19000) |
//! | 13 | Bounding Box Top Left Latitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 14 | Bounding Box Top Left Longitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 15 | Bounding Box Bottom Right Latitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 16 | Bounding Box Bottom Right Longitude Offset | deg | IMAPB(-19.2, 19.2) |
//! | 17 | Target Location | | Location pack |
//! | 18 | Geospatial Contour Series | | list of Location packs |
//! | 19 | Centroid Pixel Row | | uint V4, 1 or more |
//! | 20 | Centroid Pixel Column | | uint V4, 1 or more |
//! | 21 | FPA Index (deprecated) | | struct of Row, Column, 1 byte each |
//! | 22 | Algorithm ID | | uint V3 |
//! | 23 | Detection Status | | enum, 1 byte, codes of Table 5 (below) |
//! | 101 | VMask | | VMask struct |
//! | 102 | VObject (deprecated) | | VObject struct |
//! | 103 | VFeature (deprecated) | | VFeature struct |
//! | 104 | VTracker | | VTracker struct |
//! | 105 | VChip | | VChip struct |
//! | 106 | VChip Series | | list of VChip structs |
//! | 107 | VObject Series | | list of VObject structs |
//!
//! Detection Status codes (Table 5): 0 Inactive, 1 Active-Moving, 2 Dropped,
//! 3 Active-Stopped, 4 Active-Coasting; other codes have no label.
//!
//! Location pack (Table 18; 10, 16 or 22 bytes): Latitude IMAPB(-90, 90)
//! deg, Longitude IMAPB(-180, 180) deg, Height IMAPB(-900, 19000) m HAE, then
//! optionally Sigma East, Sigma North, Sigma Up IMAPB(0, 650) m, then
//! optionally Rho East-North, Rho East-Up, Rho North-Up IMAPB(-1, 1), 4, 4
//! and 2 bytes then 2 bytes each. Velocity and Acceleration packs (Tables 19
//! and 20; 6, 12 or 18 bytes): East, North, Up IMAPB(-900, 900) in m/s or
//! m/s^2, then the same sigma (in m/s or m/s^2) and rho groups, 2 bytes each.
//!
//! VMask (Table 11): 1 Pixel Contour, a list of pixel numbers (uint V6, 1 or
//! more); 2 Bit Mask Series, a list of structs of Pixel (pixel number) and
//! Run Length (uint, a BER length).
//!
//! VObject (Table 12): 1 Ontology (deprecated, text), 2 Ontology Class
//! (deprecated, text), 3 Ontology ID (uint V8), 4 Confidence (percent,
//! IMAPB(0, 100), 1 to 3 bytes), 5 VFeature Series (list of VFeature
//! structs).
//!
//! VFeature (Table 13): 1 Schema (deprecated, text), 2 Schema Feature
//! (deprecated, text), 3 Ontology ID (uint V8), 4 Confidence (percent,
//! IMAPB(0, 100), 1 to 3 bytes).
//!
//! VTracker (Table 14): 1 Track ID (16-byte UUID as lowercase RFC 4122
//! text, `8-4-4-4-12` hex digits, as ST 0601 tag 143), 2 Detection Status (deprecated; enum: 0
//! Inactive, 1 Active, 2 Dropped, 3 Stopped as in ST 0903.5, names confirmed
//! by ST 0903.6 Table 21), 3 First Observation Time (Time), 4 Latest
//! Observation Time (Time), 5 Track Boundary Series (list of Location packs),
//! 6 Algorithm (deprecated, text), 7 Confidence Level (percent, uint, 1 byte,
//! 0 to 100), 8 Number of Track Points (deprecated, uint V2), 9 Track History
//! Series (list of Location packs), 10 Velocity (Velocity pack), 11
//! Acceleration (Acceleration pack), 12 Algorithm ID (uint V8).
//!
//! VChip (Table 15): 1 Image Type (text), 2 Image IRI (text), 3 Embedded
//! Image ([`Value::Bytes`]).
//!
//! Algorithm (Table 16): 1 Algorithm ID (uint V8), 2 Name, 3 Version, 4
//! Class (text), 5 Number of Frames (uint V8).
//!
//! Ontology (Table 17): 1 Ontology ID (uint V8), 2 Parent ID (uint V8), 3
//! Ontology IRI, 4 Entity IRI, 5 Version IRI, 6 Label (text).

#[cfg(feature = "encode")]
#[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
pub mod encode;

use crate::imapb;
use crate::klv::be_uint;
use crate::{Config, Field, Item, Value};
use smpte_klv::ber;
use smpte_klv::{ErrorKind, LengthEncoding, LocalSet, TagEncoding, VariableLengthPack};

/// Tags of the Video Moving Target Indicator Local Set (ST 0903.6 Table 9).
///
/// Names are the descriptive names of ST 0903.5; each variant's
/// documentation gives the ST 0903.6 item name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tag {
    /// `checkSum`: [`Value::Uint`], 2 bytes. Only standalone VMTI carries it
    /// (ST 0903.6-120); reported as received and not verified.
    Checksum = 1,
    /// `precisionTimeStamp`: [`Value::Time`], 8 bytes (MISB ST 0603).
    PrecisionTimeStamp = 2,
    /// `vmtiSystemName`: [`Value::Text`], at most 32 characters.
    VmtiSystemName = 3,
    /// `vmtiLsVersionNum`: [`Value::Uint`], 1 to 2 bytes; N is ST 0903.N.
    VersionNumber = 4,
    /// `totalNumTargetsDetected`: [`Value::Uint`], 1 to 3 bytes.
    TotalNumberOfTargetsDetected = 5,
    /// `numTargetsReported`: [`Value::Uint`], 1 to 3 bytes.
    NumberOfReportedTargets = 6,
    /// Motion Imagery Frame Number, deprecated by ST 0903.6:
    /// [`Value::Uint`], 1 to 3 bytes.
    MotionImageryFrameNumber = 7,
    /// `frameWidth`: [`Value::Uint`], 1 to 3 bytes, 1 or more.
    FrameWidth = 8,
    /// `frameHeight`: [`Value::Uint`], 1 to 3 bytes, 1 or more.
    FrameHeight = 9,
    /// `vmtiSourceSensor`: [`Value::Text`], at most 128 characters.
    VmtiSourceSensor = 10,
    /// `vmtiHorizontalFov`: [`Value::Float`] degrees, IMAPB(0, 180, 2).
    VmtiHorizontalFieldOfView = 11,
    /// `vmtiVerticalFov`: [`Value::Float`] degrees, IMAPB(0, 180, 2).
    VmtiVerticalFieldOfView = 12,
    /// `miisId`: MISB ST 1204 Core Identifier.
    MiisId = 13,
    /// `vTargetSeries`: [`Value::List`] of one [`Value::Struct`] per VTarget
    /// Pack (see the module documentation).
    VTargetSeries = 101,
    /// `algorithmSeries`: [`Value::List`] of Algorithm Local Set structs.
    AlgorithmSeries = 102,
    /// `ontologySeries`: [`Value::List`] of Ontology Local Set structs.
    OntologySeries = 103,
}

impl Tag {
    /// The tag with this number, if the standard defines it.
    pub fn from_u64(n: u64) -> Option<Tag> {
        Some(match n {
            1 => Tag::Checksum,
            2 => Tag::PrecisionTimeStamp,
            3 => Tag::VmtiSystemName,
            4 => Tag::VersionNumber,
            5 => Tag::TotalNumberOfTargetsDetected,
            6 => Tag::NumberOfReportedTargets,
            7 => Tag::MotionImageryFrameNumber,
            8 => Tag::FrameWidth,
            9 => Tag::FrameHeight,
            10 => Tag::VmtiSourceSensor,
            11 => Tag::VmtiHorizontalFieldOfView,
            12 => Tag::VmtiVerticalFieldOfView,
            13 => Tag::MiisId,
            101 => Tag::VTargetSeries,
            102 => Tag::AlgorithmSeries,
            103 => Tag::OntologySeries,
            _ => return None,
        })
    }

    /// Name from the standard.
    pub fn name(self) -> &'static str {
        match self {
            Tag::Checksum => "Checksum",
            Tag::PrecisionTimeStamp => "Precision Time Stamp",
            Tag::VmtiSystemName => "VMTI System Name",
            Tag::VersionNumber => "VMTI LS Version Number",
            Tag::TotalNumberOfTargetsDetected => "Total Number of Targets Detected",
            Tag::NumberOfReportedTargets => "Number of Reported Targets",
            Tag::MotionImageryFrameNumber => "Motion Imagery Frame Number",
            Tag::FrameWidth => "Frame Width",
            Tag::FrameHeight => "Frame Height",
            Tag::VmtiSourceSensor => "VMTI Source Sensor",
            Tag::VmtiHorizontalFieldOfView => "VMTI Horizontal Field of View",
            Tag::VmtiVerticalFieldOfView => "VMTI Vertical Field of View",
            Tag::MiisId => "MIIS ID",
            Tag::VTargetSeries => "VTarget Series",
            Tag::AlgorithmSeries => "Algorithm Series",
            Tag::OntologySeries => "Ontology Series",
        }
    }

    /// Units string; "" when none.
    pub fn units(self) -> &'static str {
        match self {
            Tag::PrecisionTimeStamp => "us",
            Tag::FrameWidth | Tag::FrameHeight => "pixels",
            Tag::VmtiHorizontalFieldOfView | Tag::VmtiVerticalFieldOfView => "deg",
            _ => "",
        }
    }

    /// Whether a zero-length item may stand for an unknown value: every
    /// item but the checksum (ST 0903.4-15, -120) and the version number
    /// (ST 0903.5-99).
    fn zero_length_allowed(self) -> bool {
        !matches!(self, Tag::Checksum | Tag::VersionNumber)
    }

    /// How the value decodes (ST 0903.6 Table 9).
    fn kind(self) -> Kind {
        match self {
            Tag::Checksum => Kind::Checksum,
            Tag::PrecisionTimeStamp => Kind::Time,
            Tag::VmtiSystemName => Kind::Text(Some((32, "longer than 32 characters"))),
            Tag::VersionNumber => uint_v(2, 0),
            Tag::TotalNumberOfTargetsDetected
            | Tag::NumberOfReportedTargets
            | Tag::MotionImageryFrameNumber => uint_v(3, 0),
            // Section 10.1.8 and 10.1.9: "Do not use a value of zero."
            Tag::FrameWidth | Tag::FrameHeight => uint_v(3, 1),
            Tag::VmtiSourceSensor => Kind::Text(Some((128, "longer than 128 characters"))),
            Tag::VmtiHorizontalFieldOfView | Tag::VmtiVerticalFieldOfView => imapb_k(0.0, 180.0),
            Tag::MiisId => Kind::Miis,
            Tag::VTargetSeries => Kind::VTargetSeries,
            Tag::AlgorithmSeries => Kind::SetSeries(&ALGORITHM),
            Tag::OntologySeries => Kind::SetSeries(&ONTOLOGY),
        }
    }
}

impl From<Tag> for u64 {
    fn from(t: Tag) -> u64 {
        t as u64
    }
}

crate::value::tag_key!(Tag, crate::Standard::St0903);

/// Decode one item of the VMTI Local Set found at nesting level `depth`.
/// Never panics.
pub(crate) fn decode_item(tag: u64, value: &[u8], depth: usize, cfg: &Config) -> Item {
    match Tag::from_u64(tag) {
        Some(t) => {
            let decoded = if value.is_empty() && !t.zero_length_allowed() {
                Value::Invalid(NO_ZLI)
            } else {
                decode_value(t.kind(), value, depth, cfg)
            };
            crate::registry::item(tag, t.name(), t.units(), decoded, value, cfg)
        }
        None => crate::registry::unknown_item(tag, value, depth, cfg),
    }
}

/// Reason given for a zero-length item the set must contain a value for
/// (MISB ST 0107: mandatory items are never zero length).
const NO_ZLI: &str = "zero-length item not allowed for this tag";
/// Reason given for an empty element of a Series.
const EMPTY_ELEMENT: &str = "empty series element";
/// Reason given for a set deeper than `Config::max_depth`.
const TOO_DEEP: &str = "sets nested too deeply";
/// Reason given when a set or list holds more than `Config::max_items`.
const TOO_MANY: &str = "more entries than Config::max_items";

/// How a value decodes.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Unsigned big-endian integer of 1 to `max_len` bytes, at least `min`.
    UintV { max_len: usize, min: u64 },
    /// Unsigned integer of exactly one byte from `min` to `max`.
    Uint8 { min: u8, max: u8, why: &'static str },
    /// The 2-byte checksum.
    Checksum,
    /// MISB ST 0603 Precision Time Stamp, 8 bytes.
    Time,
    /// UTF-8 text with an optional character limit and the reason given
    /// when it is exceeded.
    Text(Option<(usize, &'static str)>),
    /// Opaque bytes.
    Bytes,
    /// ST 1201 IMAPB over `min..=max`, 1 to `max_len` bytes.
    Imapb { min: f64, max: f64, max_len: usize },
    /// One-byte enumeration; `labels[code]` names the code.
    Enum(&'static [&'static str]),
    /// VTarget tag 8: red, green and blue bytes.
    Color,
    /// VTarget tag 21: row and column bytes.
    Fpa,
    /// VTracker tag 1: 16-byte UUID.
    Uuid,
    /// Location truncation pack (Table 18).
    Location,
    /// Velocity or Acceleration truncation pack (Tables 19 and 20).
    Motion,
    /// Series of Location packs (BoundarySeries, section 10.11).
    LocationSeries,
    /// VMask tag 1: array of pixel numbers.
    PixelContour,
    /// VMask tag 2: series of pixel runs.
    BitMaskSeries,
    /// MISB ST 1204 MIIS Core Identifier.
    Miis,
    /// A nested local set.
    Set(&'static SetDef),
    /// A Series of nested local sets.
    SetSeries(&'static SetDef),
    /// VMTI tag 101: Series of VTarget Packs.
    VTargetSeries,
}

const fn uint_v(max_len: usize, min: u64) -> Kind {
    Kind::UintV { max_len, min }
}

const fn imapb_k(min: f64, max: f64) -> Kind {
    Kind::Imapb { min, max, max_len: 8 }
}

/// One item of a nested set table.
#[derive(Debug)]
struct FieldDef {
    tag: u8,
    name: &'static str,
    kind: Kind,
    /// The set must contain the item, so a zero-length item is invalid.
    required: bool,
}

/// A nested local set: its item table.
#[derive(Debug)]
struct SetDef {
    fields: &'static [FieldDef],
}

const fn f(tag: u8, name: &'static str, kind: Kind) -> FieldDef {
    FieldDef { tag, name, kind, required: false }
}

/// An item the set must contain.
const fn required(tag: u8, name: &'static str, kind: Kind) -> FieldDef {
    FieldDef { tag, name, kind, required: true }
}

/// Pixel numbers: "All integer values from 1 to 0xFFFFFFFFFFFF" (section
/// 10.2.2.2). ST 0903.6 gives no maximum size for the pixel numbers of a
/// VMask; they take the same 1 to 6 bytes.
const PIXEL: Kind = uint_v(6, 1);
const OFFSET: Kind = imapb_k(-19.2, 19.2);
const PERCENT: Kind = Kind::Uint8 { min: 0, max: 100, why: "percentage above 100" };
const CONFIDENCE: Kind = Kind::Imapb { min: 0.0, max: 100.0, max_len: 3 };

/// ST 0903.6 Table 5 Detection Status values.
const DETECTION_STATUS: [&str; 5] =
    ["Inactive", "Active-Moving", "Dropped", "Active-Stopped", "Active-Coasting"];
/// ST 0903.5 VTracker Detection Status values (names in ST 0903.6 Table 21).
const TRACKER_STATUS: [&str; 4] = ["Inactive", "Active", "Dropped", "Stopped"];

/// VTarget Pack items (ST 0903.6 Table 10, section 10.2.2).
static VTARGET: SetDef = SetDef {
    fields: &[
        f(1, "Target Centroid", PIXEL),
        f(2, "Bounding Box Top Left", PIXEL),
        f(3, "Bounding Box Bottom Right", PIXEL),
        f(4, "Target Priority", Kind::Uint8 { min: 1, max: 255, why: "target priority 0 (valid: 1 to 255)" }),
        f(5, "Target Confidence Level", PERCENT),
        f(6, "Target History", uint_v(2, 0)),
        f(
            7,
            "Percentage of Target Pixels",
            Kind::Uint8 { min: 1, max: 100, why: "percentage outside 1 to 100" },
        ),
        f(8, "Target Color", Kind::Color),
        f(9, "Target Intensity", uint_v(3, 0)),
        f(10, "Target Location Latitude Offset", OFFSET),
        f(11, "Target Location Longitude Offset", OFFSET),
        f(12, "Target Height", imapb_k(-900.0, 19_000.0)),
        f(13, "Bounding Box Top Left Latitude Offset", OFFSET),
        f(14, "Bounding Box Top Left Longitude Offset", OFFSET),
        f(15, "Bounding Box Bottom Right Latitude Offset", OFFSET),
        f(16, "Bounding Box Bottom Right Longitude Offset", OFFSET),
        f(17, "Target Location", Kind::Location),
        f(18, "Geospatial Contour Series", Kind::LocationSeries),
        // Sections 10.2.2.20 and 10.2.2.21: 1 to 2^32 - 1.
        f(19, "Centroid Pixel Row", uint_v(4, 1)),
        f(20, "Centroid Pixel Column", uint_v(4, 1)),
        f(21, "FPA Index", Kind::Fpa),
        f(22, "Algorithm ID", uint_v(3, 0)),
        f(23, "Detection Status", Kind::Enum(&DETECTION_STATUS)),
        f(101, "VMask", Kind::Set(&VMASK)),
        f(102, "VObject", Kind::Set(&VOBJECT)),
        f(103, "VFeature", Kind::Set(&VFEATURE)),
        f(104, "VTracker", Kind::Set(&VTRACKER)),
        f(105, "VChip", Kind::Set(&VCHIP)),
        f(106, "VChip Series", Kind::SetSeries(&VCHIP)),
        f(107, "VObject Series", Kind::SetSeries(&VOBJECT)),
    ],
};

/// VMask Local Set (Table 11, section 10.3).
static VMASK: SetDef = SetDef {
    fields: &[f(1, "Pixel Contour", Kind::PixelContour), f(2, "Bit Mask Series", Kind::BitMaskSeries)],
};

/// VObject Local Set (Table 12, section 10.4). Tags 1 and 2 are deprecated.
static VOBJECT: SetDef = SetDef {
    fields: &[
        f(1, "Ontology", Kind::Text(None)),
        f(2, "Ontology Class", Kind::Text(None)),
        f(3, "Ontology ID", uint_v(8, 0)),
        f(4, "Confidence", CONFIDENCE),
        f(5, "VFeature Series", Kind::SetSeries(&VFEATURE)),
    ],
};

/// VFeature Local Set (Table 13, section 10.5). Tags 1 and 2 are deprecated.
static VFEATURE: SetDef = SetDef {
    fields: &[
        f(1, "Schema", Kind::Text(None)),
        f(2, "Schema Feature", Kind::Text(None)),
        f(3, "Ontology ID", uint_v(8, 0)),
        f(4, "Confidence", CONFIDENCE),
    ],
};

/// VTracker Local Set (Table 14, section 10.6). Tags 2, 6 and 8 are
/// deprecated.
static VTRACKER: SetDef = SetDef {
    fields: &[
        f(1, "Track ID", Kind::Uuid),
        f(2, "Detection Status", Kind::Enum(&TRACKER_STATUS)),
        f(3, "First Observation Time", Kind::Time),
        f(4, "Latest Observation Time", Kind::Time),
        f(5, "Track Boundary Series", Kind::LocationSeries),
        f(6, "Algorithm", Kind::Text(None)),
        f(7, "Confidence Level", PERCENT),
        f(8, "Number of Track Points", uint_v(2, 0)),
        f(9, "Track History Series", Kind::LocationSeries),
        f(10, "Velocity", Kind::Motion),
        f(11, "Acceleration", Kind::Motion),
        // "uint V" with no maximum: 1 to 8 bytes, like the Algorithm LS IDs
        // it refers to.
        f(12, "Algorithm ID", uint_v(8, 0)),
    ],
};

/// VChip Local Set (Table 15, section 10.7). Every VChip contains the
/// image type (ST 0903.6-134).
static VCHIP: SetDef = SetDef {
    fields: &[
        required(1, "Image Type", Kind::Text(None)),
        f(2, "Image IRI", Kind::Text(None)),
        f(3, "Embedded Image", Kind::Bytes),
    ],
};

/// Algorithm Local Set (Table 16, section 10.8). Tags 1 to 3 are required
/// (ST 0903.5-102 to -104).
static ALGORITHM: SetDef = SetDef {
    fields: &[
        required(1, "Algorithm ID", uint_v(8, 0)),
        required(2, "Name", Kind::Text(None)),
        required(3, "Version", Kind::Text(None)),
        f(4, "Class", Kind::Text(None)),
        f(5, "Number of Frames", uint_v(8, 0)),
    ],
};

/// Ontology Local Set (Table 17, section 10.9). Tags 1, 3 and 4 are
/// required (ST 0903.5-105, -107, -108).
static ONTOLOGY: SetDef = SetDef {
    fields: &[
        required(1, "Ontology ID", uint_v(8, 0)),
        f(2, "Parent ID", uint_v(8, 0)),
        required(3, "Ontology IRI", Kind::Text(None)),
        required(4, "Entity IRI", Kind::Text(None)),
        f(5, "Version IRI", Kind::Text(None)),
        f(6, "Label", Kind::Text(None)),
    ],
};

/// Decode a value of `kind` that belongs to a set at nesting level `level`.
/// An empty value is a zero-length item: unknown (MISB ST 0107). The caller
/// checks first whether the item may be unknown.
fn decode_value(kind: Kind, v: &[u8], level: usize, cfg: &Config) -> Value {
    if v.is_empty() {
        return Value::Unknown;
    }
    match kind {
        Kind::UintV { max_len, min } => uint(v, max_len, min),
        Kind::Uint8 { min, max, why } => match v {
            [b] if (min..=max).contains(b) => Value::Uint(u64::from(*b)),
            [_] => Value::Invalid(why),
            _ => Value::Invalid("integer is not 1 byte"),
        },
        Kind::Checksum => match v {
            [hi, lo] => Value::Uint(u64::from(u16::from_be_bytes([*hi, *lo]))),
            _ => Value::Invalid("checksum is not 2 bytes"),
        },
        Kind::Time => match be_uint(v) {
            Some(us) if v.len() == 8 => Value::Time(us),
            _ => Value::Invalid("time stamp is not 8 bytes"),
        },
        Kind::Text(limit) => text(v, limit),
        Kind::Bytes => Value::Bytes(v.to_vec()),
        Kind::Imapb { min, max, max_len } => {
            if v.len() > max_len {
                return Value::Invalid(if max_len == 3 {
                    "IMAPB value longer than 3 bytes"
                } else {
                    "IMAPB value longer than 8 bytes"
                });
            }
            imapb_0903(min, max, v)
        }
        Kind::Enum(labels) => match v {
            [code] => Value::Enum {
                code: u64::from(*code),
                label: labels.get(usize::from(*code)).copied(),
            },
            _ => Value::Invalid("enumeration is not 1 byte"),
        },
        Kind::Color => match v {
            [r, g, b] => Value::Struct(vec![
                Field { name: "Red", value: Value::Uint(u64::from(*r)) },
                Field { name: "Green", value: Value::Uint(u64::from(*g)) },
                Field { name: "Blue", value: Value::Uint(u64::from(*b)) },
            ]),
            _ => Value::Invalid("target color is not 3 bytes"),
        },
        Kind::Fpa => match v {
            [row, column] => Value::Struct(vec![
                Field { name: "Row", value: Value::Uint(u64::from(*row)) },
                Field { name: "Column", value: Value::Uint(u64::from(*column)) },
            ]),
            _ => Value::Invalid("FPA index is not 2 bytes"),
        },
        Kind::Uuid => uuid(v),
        Kind::Location => location(v),
        Kind::Motion => truncation_pack(v, &MOTION, [6, 12, 18], BAD_MOTION),
        Kind::LocationSeries => series(v, cfg, location),
        Kind::PixelContour => series(v, cfg, |e| uint(e, 6, 1)),
        Kind::BitMaskSeries => series(v, cfg, pixel_run),
        Kind::Miis => crate::st1204::decode(v),
        Kind::Set(def) => nested_set(def, v, level.saturating_add(1), cfg),
        Kind::SetSeries(def) => {
            if level.saturating_add(1) > cfg.depth_limit() {
                return Value::Invalid(TOO_DEEP);
            }
            series(v, cfg, |e| match e {
                [] => Value::Invalid(EMPTY_ELEMENT),
                e => nested_set(def, e, level + 1, cfg),
            })
        }
        Kind::VTargetSeries => {
            // VMTI tag 101 (section 10.1.14): each element is a VTarget Pack,
            // whose items form a set one level below the VMTI LS.
            if level.saturating_add(1) > cfg.depth_limit() {
                return Value::Invalid(TOO_DEEP);
            }
            series(v, cfg, |e| vtarget(e, level + 1, cfg))
        }
    }
}

/// `uint Vn` (section 9.1): big-endian, 1 to `max_len` bytes, at least `min`.
fn uint(v: &[u8], max_len: usize, min: u64) -> Value {
    if v.is_empty() {
        return Value::Invalid("integer is empty");
    }
    if v.len() > max_len {
        return Value::Invalid(match max_len {
            2 => "integer longer than 2 bytes",
            3 => "integer longer than 3 bytes",
            4 => "integer longer than 4 bytes",
            6 => "integer longer than 6 bytes",
            _ => "integer longer than 8 bytes",
        });
    }
    match be_uint(v) {
        Some(n) if n >= min => Value::Uint(n),
        Some(_) => Value::Invalid("zero where the standard requires 1 or more"),
        None => Value::Invalid("integer longer than 8 bytes"),
    }
}

/// UTF-8 text, decoded lossily, with an optional character limit (ST 0903.6
/// counts characters, each up to four bytes: sections 10.1.3 and 10.1.10).
fn text(v: &[u8], limit: Option<(usize, &'static str)>) -> Value {
    // MISB ST 0107.4 6.3.3.2: a single 00 byte is the empty string
    // (DECISIONS P-1).
    if v == [0] {
        return Value::Text(String::new());
    }
    let s = String::from_utf8_lossy(v);
    if let Some((max, why)) = limit {
        if s.chars().count() > max {
            return Value::Invalid(why);
        }
    }
    Value::Text(s.into_owned())
}

/// A 16-byte UUID (ISO/IEC 9834-8) as lowercase RFC 4122 `8-4-4-4-12` hex
/// text, the form ST 0601 tag 143 decodes to as well.
fn uuid(v: &[u8]) -> Value {
    match <&[u8; 16]>::try_from(v) {
        Ok(id) => Value::Text(crate::value::uuid_text(id)),
        Err(_) => Value::Invalid("track ID is not 16 bytes"),
    }
}

/// An ST 1201 IMAPB value as ST 0903.6 section 9.1.1 qualifies it: `0xC1`
/// followed by zero bytes is the "Invalid" signal. Otherwise
/// [`imapb::decode`], which also rejects a mapped value above the range
/// maximum (ST 1201.5 section 7.2.1).
fn imapb_0903(min: f64, max: f64, v: &[u8]) -> Value {
    if let Some((0xC1, rest)) = v.split_first() {
        if rest.iter().all(|&b| b == 0) {
            return Value::OutOfRange;
        }
    }
    imapb::decode(min, max, v)
}

/// One IMAPB element of a Defined-Length Truncation Pack.
struct PackField {
    name: &'static str,
    min: f64,
    max: f64,
    len: usize,
}

const fn p(name: &'static str, min: f64, max: f64, len: usize) -> PackField {
    PackField { name, min, max, len }
}

/// Location pack (Table 18): coordinates, standard deviations, correlation
/// coefficients.
const LOCATION: [PackField; 9] = [
    p("Latitude", -90.0, 90.0, 4),
    p("Longitude", -180.0, 180.0, 4),
    p("Height", -900.0, 19_000.0, 2),
    p("Sigma East", 0.0, 650.0, 2),
    p("Sigma North", 0.0, 650.0, 2),
    p("Sigma Up", 0.0, 650.0, 2),
    p("Rho East-North", -1.0, 1.0, 2),
    p("Rho East-Up", -1.0, 1.0, 2),
    p("Rho North-Up", -1.0, 1.0, 2),
];

/// Velocity and Acceleration packs (Tables 19 and 20).
const MOTION: [PackField; 9] = [
    p("East", -900.0, 900.0, 2),
    p("North", -900.0, 900.0, 2),
    p("Up", -900.0, 900.0, 2),
    p("Sigma East", 0.0, 650.0, 2),
    p("Sigma North", 0.0, 650.0, 2),
    p("Sigma Up", 0.0, 650.0, 2),
    p("Rho East-North", -1.0, 1.0, 2),
    p("Rho East-Up", -1.0, 1.0, 2),
    p("Rho North-Up", -1.0, 1.0, 2),
];

const BAD_LOCATION: &str = "Location pack is not 10, 16 or 22 bytes";
const BAD_MOTION: &str = "Velocity or Acceleration pack is not 6, 12 or 18 bytes";

/// A Location pack (Table 18).
fn location(v: &[u8]) -> Value {
    truncation_pack(v, &LOCATION, [10, 16, 22], BAD_LOCATION)
}

/// A Defined-Length Truncation Pack of three groups, truncated a whole group
/// at a time from the end (section 10.10, ST 0903.4-62): `lengths` are the
/// three valid sizes.
fn truncation_pack(v: &[u8], fields: &[PackField], lengths: [usize; 3], why: &'static str) -> Value {
    if !lengths.contains(&v.len()) {
        return Value::Invalid(why);
    }
    let mut out = Vec::with_capacity(fields.len());
    let mut rest = v;
    for pf in fields {
        let (Some(bytes), Some(after)) = (rest.get(..pf.len), rest.get(pf.len..)) else { break };
        out.push(Field { name: pf.name, value: imapb_0903(pf.min, pf.max, bytes) });
        rest = after;
    }
    Value::Struct(out)
}

/// One pixel run of a Bit Mask Series (section 10.3.2, Figure 19): the
/// pixel number as a BER length and that many bytes, then the run length
/// as a BER length.
fn pixel_run(e: &[u8]) -> Value {
    let Ok((ber::Length::Definite(n), used)) = ber::decode_length(e) else {
        return Value::Invalid("malformed pixel number length");
    };
    let end = usize::try_from(n).ok().and_then(|n| n.checked_add(used));
    let (Some(pixel), Some(rest)) = (end.and_then(|end| e.get(used..end)), end.and_then(|end| e.get(end..)))
    else {
        return Value::Invalid("pixel number runs past the end of the pixel run");
    };
    let run = match ber::decode_length(rest) {
        Ok((ber::Length::Definite(run), used)) if used == rest.len() => Value::Uint(run),
        Ok((ber::Length::Definite(_), _)) => return Value::Invalid("bytes left over after the run length"),
        _ => return Value::Invalid("malformed run length"),
    };
    Value::Struct(vec![Field { name: "Pixel", value: uint(pixel, 6, 1) }, Field { name: "Run Length", value: run }])
}

/// The reason a `smpte-klv` error gives for a malformed set or series.
fn error_text(e: &smpte_klv::Error) -> &'static str {
    match e.kind() {
        ErrorKind::UnexpectedEnd { .. } => "truncated: an entry runs past the end of its container",
        ErrorKind::IndefiniteLength => "indefinite BER length (0x80) inside a set or series",
        ErrorKind::ReservedLength => "reserved BER length (0xFF)",
        ErrorKind::LengthOverflow => "BER length too large",
        _ => "malformed KLV",
    }
}

/// The elements of a Series, as framed.
fn elements(v: &[u8]) -> smpte_klv::VariableLengthPack<'_> {
    VariableLengthPack::new(v, LengthEncoding::Ber).with_options(crate::klv::OPTIONS)
}

/// The items of a nested local set (one-byte tags, BER lengths: section
/// 9.2), as framed.
fn set_items(v: &[u8]) -> LocalSet<'_> {
    LocalSet::new(v, TagEncoding::U8, LengthEncoding::Ber).with_options(crate::klv::OPTIONS)
}

/// Room for the entries a header walk of a set or Series finds, up to one
/// past [`Config::max_items`] (where decoding stops with a marker), so that
/// the list or struct is allocated once.
fn capacity(entries: usize, cfg: &Config) -> usize {
    entries.min(cfg.max_items.saturating_add(1))
}

/// A Series (section 9.1.3, Figure 9): elements, each a BER length and that
/// many bytes, decoded with `element`.
fn series(v: &[u8], cfg: &Config, mut element: impl FnMut(&[u8]) -> Value) -> Value {
    let walk = elements(v).into_iter().take(cfg.max_items.saturating_add(1)).count();
    let mut out = Vec::with_capacity(capacity(walk, cfg));
    for e in elements(v) {
        match e {
            Ok(e) => {
                if out.len() >= cfg.max_items {
                    out.push(Value::Invalid(TOO_MANY));
                    break;
                }
                out.push(element(e.value));
            }
            Err(err) => {
                out.push(Value::Invalid(error_text(&err)));
                break;
            }
        }
    }
    Value::List(out)
}

/// Number of items a header walk of a nested set finds, at most one past
/// [`Config::max_items`].
fn count_items(v: &[u8], cfg: &Config) -> usize {
    set_items(v).iter().take(cfg.max_items.saturating_add(1)).count()
}

/// A nested local set at nesting level `level`, as a struct.
fn nested_set(def: &SetDef, v: &[u8], level: usize, cfg: &Config) -> Value {
    if level > cfg.depth_limit() {
        return Value::Invalid(TOO_DEEP);
    }
    let mut fields = Vec::with_capacity(capacity(count_items(v, cfg), cfg));
    set_fields(def, v, level, cfg, &mut fields);
    Value::Struct(fields)
}

/// Append the items of a nested local set (one-byte tags, BER lengths:
/// section 9.2) at level `level` to `out`. A zero-length item is
/// [`Value::Unknown`], or [`Value::Invalid`] when the set must contain the
/// item.
fn set_fields(def: &SetDef, v: &[u8], level: usize, cfg: &Config, out: &mut Vec<Field>) {
    let mut count = 0usize;
    for item in set_items(v).iter() {
        match item {
            Ok(item) => {
                if count >= cfg.max_items {
                    out.push(Field { name: "Error", value: Value::Invalid(TOO_MANY) });
                    break;
                }
                count += 1;
                out.push(match def.fields.iter().find(|fd| u64::from(fd.tag) == item.tag) {
                    Some(fd) if fd.required && item.value.is_empty() => {
                        Field { name: fd.name, value: Value::Invalid(NO_ZLI) }
                    }
                    Some(fd) => Field { name: fd.name, value: decode_value(fd.kind, item.value, level, cfg) },
                    None => Field {
                        name: "Unknown",
                        value: Value::Struct(vec![
                            Field { name: "Tag", value: Value::Uint(item.tag) },
                            Field { name: "Value", value: Value::Bytes(item.value.to_vec()) },
                        ]),
                    },
                });
            }
            Err(err) => {
                out.push(Field { name: "Error", value: Value::Invalid(error_text(&err)) });
                break;
            }
        }
    }
}

/// One VTarget Pack (section 10.2, Figure 15): a BER-OID Target ID with no
/// tag or length, then the items of a local set at level `level`.
fn vtarget(e: &[u8], level: usize, cfg: &Config) -> Value {
    let (id, used) = match ber::decode_oid(e, crate::klv::OPTIONS.strict_oid) {
        Ok(x) => x,
        Err(err) => {
            return Value::Invalid(match err.kind() {
                ErrorKind::UnexpectedEnd { .. } => "VTarget Pack without a complete target ID",
                _ => "target ID does not fit in 64 bits",
            })
        }
    };
    // Table 10: "BER-OID V9".
    let id = if used > 9 { Value::Invalid("target ID longer than 9 bytes") } else { Value::Uint(id) };
    let items = e.get(used..).unwrap_or(&[]);
    let mut fields = Vec::with_capacity(1 + capacity(count_items(items, cfg), cfg));
    fields.push(Field { name: "Target ID", value: id });
    set_fields(&VTARGET, items, level, cfg, &mut fields);
    Value::Struct(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imapb::Imapb;
    use crate::registry::decode_set;
    use crate::{Packet, Standard};

    /// A BER length.
    fn ber_len(n: usize) -> Vec<u8> {
        if n < 128 {
            vec![n as u8]
        } else {
            let be = (n as u64).to_be_bytes();
            let skip = be.iter().take_while(|&&b| b == 0).count();
            let mut out = vec![0x80 | (8 - skip) as u8];
            out.extend(&be[skip..]);
            out
        }
    }

    /// A one-byte-tag item with a BER length.
    fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(ber_len(v.len()));
        out.extend_from_slice(v);
        out
    }

    /// A Series of the given elements.
    fn series_of(elements: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in elements {
            out.extend(ber_len(e.len()));
            out.extend(e);
        }
        out
    }

    fn oid(mut n: u64) -> Vec<u8> {
        let mut out = vec![(n & 0x7F) as u8];
        n >>= 7;
        while n > 0 {
            out.insert(0, 0x80 | (n & 0x7F) as u8);
            n >>= 7;
        }
        out
    }

    /// A VTarget Pack of `id` and items.
    fn vtarget_pack(id: u64, items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = oid(id);
        for i in items {
            out.extend(i);
        }
        out
    }

    fn item(tag: u64, v: &[u8]) -> Item {
        decode_item(tag, v, 1, &Config::default())
    }

    fn val(tag: u64, v: &[u8]) -> Value {
        item(tag, v).value
    }

    fn close(v: &Value, want: f64, tol: f64) {
        let got = v.as_f64().expect("expected a numeric field");
        assert!((got - want).abs() <= tol, "expected {want} within {tol}");
    }

    fn is_invalid(v: &Value) -> bool {
        matches!(v, Value::Invalid(_))
    }

    fn fields(v: &Value) -> &[Field] {
        v.as_fields().expect("expected a struct")
    }

    fn list(v: &Value) -> &[Value] {
        v.as_list().expect("expected a list")
    }

    fn names(v: &Value) -> Vec<&'static str> {
        fields(v).iter().map(|f| f.name).collect()
    }

    fn imapb_bytes(min: f64, max: f64, len: usize, x: f64) -> Vec<u8> {
        let y = Imapb::new(min, max, len).unwrap().real_to_int(x).unwrap();
        y.to_be_bytes()[8 - len..].to_vec()
    }

    fn deep_cfg(max_depth: usize) -> Config {
        let mut cfg = Config::default();
        cfg.max_depth = max_depth;
        cfg
    }

    #[test]
    fn tag_table() {
        let all = [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 101, 102, 103];
        for n in 0..=255u64 {
            match Tag::from_u64(n) {
                Some(t) => {
                    assert!(all.contains(&n), "{n}");
                    assert_eq!(u64::from(t), n);
                    assert!(!t.name().is_empty());
                }
                None => assert!(!all.contains(&n), "{n}"),
            }
        }
        assert_eq!(Tag::from_u64(1 << 40), None);
        assert_eq!(Tag::VmtiHorizontalFieldOfView.units(), "deg");
        assert_eq!(Tag::FrameWidth.units(), "pixels");
        assert_eq!(Tag::PrecisionTimeStamp.units(), "us");
        assert_eq!(Tag::VTargetSeries.units(), "");
        assert_eq!(Tag::VersionNumber.name(), "VMTI LS Version Number");
    }

    #[test]
    fn vmti_item_examples() {
        // ST 0903.6 sections 10.1.2 to 10.1.12 examples.
        let it = item(2, &[0x00, 0x03, 0x82, 0x44, 0x30, 0xF6, 0xCE, 0x40]);
        assert_eq!(it.value, Value::Time(987_654_321_000_000));
        assert_eq!(it.value.to_string(), "2001-04-19T04:25:21.000000 MISP");
        assert_eq!((it.name, it.units, it.raw.len()), ("Precision Time Stamp", "us", 8));
        assert_eq!(val(3, b"DSTO_ADSS_VMTI"), Value::Text("DSTO_ADSS_VMTI".into()));
        assert_eq!(val(4, &[0x06]), Value::Uint(6));
        assert_eq!(val(5, &[0x1C]), Value::Uint(28));
        assert_eq!(val(6, &[0x0E]), Value::Uint(14));
        assert_eq!(val(8, &[0x07, 0x80]), Value::Uint(1920));
        assert_eq!(val(9, &[0x04, 0x38]), Value::Uint(1080));
        assert_eq!(val(10, b"EO Nose"), Value::Text("EO Nose".into()));
        assert_eq!(val(11, &[0x06, 0x40]), Value::Float(12.5));
        assert_eq!(val(12, &[0x05, 0x00]), Value::Float(10.0));
        let it = item(11, &[0x06, 0x40]);
        assert_eq!(it.to_string(), " 11 VMTI Horizontal Field of View: 12.5 deg");
        // Checksum, reported only.
        assert_eq!(val(1, &[0x12, 0x34]), Value::Uint(0x1234));
        assert!(is_invalid(&val(1, &[0x12])));
        // Deprecated frame number still decodes.
        assert_eq!(val(7, &[0x01, 0x02, 0x03]), Value::Uint(0x010203));
        // MIIS ID goes to the ST 1204 decoder; never Invalid for a plausible
        // value, and the raw bytes are kept.
        // ST 1204.3 Appendix E example E6.
        let miis = [
            0x01, 0x40, 0xBC, 0x76, 0xCF, 0xEF, 0x0B, 0xEE, 0x41, 0xA4, 0x96, 0x18, 0xEB, 0x4B, 0x01, 0x0D,
            0x2F, 0x08,
        ];
        let it = item(13, &miis);
        assert_eq!((it.name, it.raw.as_slice()), ("MIIS ID", &miis[..]));
        // Unknown VMTI tags are raw.
        let it = item(200, &[1, 2]);
        assert_eq!((it.name, it.value), ("Unknown", Value::Bytes(vec![1, 2])));
    }

    #[test]
    fn vmti_item_lengths_and_ranges() {
        // uint V2/V3: 1 to n bytes; padded values (Appendix C) accepted.
        assert_eq!(val(4, &[0x00, 0x06]), Value::Uint(6));
        assert!(is_invalid(&val(4, &[0, 0, 6])));
        assert_eq!(val(5, &[0, 0, 0x1C]), Value::Uint(28));
        assert!(is_invalid(&val(5, &[0, 0, 0, 0x1C])));
        assert_eq!(val(5, &[0]), Value::Uint(0));
        // Frame width and height: never zero.
        assert!(is_invalid(&val(8, &[0])));
        assert!(is_invalid(&val(9, &[0, 0])));
        assert_eq!(val(9, &[0xFF, 0xFF, 0xFF]), Value::Uint(0xFF_FFFF));
        // Time stamp: exactly 8 bytes.
        assert!(is_invalid(&val(2, &[0; 7])));
        assert!(is_invalid(&val(2, &[0; 9])));
        // Text limits count characters, not bytes.
        let max32 = "\u{00E9}".repeat(32); // 64 bytes, 32 characters
        assert_eq!(val(3, max32.as_bytes()), Value::Text(max32.clone()));
        assert!(is_invalid(&val(3, "x".repeat(33).as_bytes())));
        assert_eq!(val(10, "y".repeat(128).as_bytes()), Value::Text("y".repeat(128)));
        assert!(is_invalid(&val(10, "y".repeat(129).as_bytes())));
        // Invalid UTF-8 is decoded lossily.
        assert_eq!(val(3, &[b'a', 0xFF]), Value::Text("a\u{FFFD}".into()));
        // Zero-length items are unknown (MISB ST 0107), except the checksum
        // and the version number every VMTI LS must contain (ST 0903.5-99).
        for tag in [2u64, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 101, 102, 103] {
            let it = item(tag, &[]);
            assert_eq!(it.value, Value::Unknown, "tag {tag}");
            assert!(it.raw.is_empty());
        }
        for tag in [1u64, 4] {
            assert_eq!(val(tag, &[]), Value::Invalid(NO_ZLI), "tag {tag}");
        }
    }

    #[test]
    fn field_of_view_lengths_follow_st1201_7_4() {
        // A KLV length other than the nominal 2 recomputes the mapping.
        close(&val(11, &[0x06, 0x40, 0x00]), 12.5, 1e-9);
        assert_eq!(val(11, &[0x5A, 0x00]), Value::Float(180.0));
        assert!(is_invalid(&val(11, &[0x5A, 0x01])));
        assert!(is_invalid(&val(11, &[0; 9])));
        assert_eq!(val(11, &[0xC1, 0x00]), Value::OutOfRange);
        assert_eq!(val(12, &[0xE1, 0x00]), Value::OutOfRange);
    }

    /// Every IMAPB range ST 0903.6 uses, with the length it is used at.
    const RANGES: [(f64, f64, usize, u64); 12] = [
        (0.0, 180.0, 2, 0x5A00),                // VMTI 11, 12
        (-19.2, 19.2, 3, 0x4C_CCCD),            // VTarget 10, 11, 13 to 16
        (-900.0, 19_000.0, 2, 0x4DBC),          // VTarget 12, Location height
        (-90.0, 90.0, 4, 0x5A00_0000),          // Location latitude
        (-180.0, 180.0, 4, 0x5A00_0000),        // Location longitude
        (0.0, 650.0, 2, 0x5140),                // sigma
        (-1.0, 1.0, 2, 0x8000),                 // rho
        (-900.0, 900.0, 2, 0x7080),             // velocity, acceleration
        (0.0, 100.0, 1, 0x64),                  // VObject, VFeature confidence
        (0.0, 100.0, 2, 0x6400),
        (0.0, 100.0, 3, 0x64_0000),
        (-19.2, 19.2, 2, 0x4CCD),
    ];

    fn be(y: u64, len: usize) -> Vec<u8> {
        y.to_be_bytes()[8 - len..].to_vec()
    }

    #[test]
    fn imapb_range_boundaries() {
        for (min, max, len, top) in RANGES {
            let map = Imapb::new(min, max, len).unwrap();
            assert_eq!(map.real_to_int(max), Some(top), "IMAPB({min}, {max}, {len})");
            let lsb = (map.int_to_real(1) - map.int_to_real(0)).abs();
            // Minimum: integer 0 is within one LSB of min (zOffset).
            let lo = imapb_0903(min, max, &be(0, len));
            close(&lo, min, lsb);
            // Maximum: the largest integer is within one LSB of max, never above.
            let hi = imapb_0903(min, max, &be(top, len));
            close(&hi, max, lsb);
            assert!(hi.as_f64().unwrap() <= max + 1e-9);
            // One above: outside the range.
            let above = imapb_0903(min, max, &be(top + 1, len));
            assert!(is_invalid(&above), "IMAPB({min}, {max}, {len}) {above:?}");
            // Largest normal pattern 0x7F FF ..: above the range.
            let mut big = vec![0xFF; len];
            big[0] = 0x7F;
            if be_uint(&big).unwrap() > top {
                assert!(is_invalid(&imapb_0903(min, max, &big)));
            }
            // Zero is exact when the range spans it.
            if min < 0.0 && max > 0.0 {
                let y = map.real_to_int(0.0).unwrap();
                assert_eq!(imapb_0903(min, max, &be(y, len)), Value::Float(0.0));
            }
            // ST 1201 special values and the ST 0903 Invalid signal.
            let special = |first: u8| {
                let mut b = vec![0; len];
                b[0] = first;
                imapb_0903(min, max, &b)
            };
            assert_eq!(special(0xC1), Value::OutOfRange, "Invalid signal");
            assert_eq!(special(0xE0), Value::OutOfRange, "below minimum");
            assert_eq!(special(0xE1), Value::OutOfRange, "above maximum");
            assert_eq!(special(0xC8), Value::Float(f64::INFINITY));
            assert_eq!(special(0xE8), Value::Float(f64::NEG_INFINITY));
            assert!(special(0xD0).as_f64().unwrap().is_nan());
            assert!(is_invalid(&special(0xC0)), "user defined");
            assert!(is_invalid(&special(0xE2)), "reserved MISB value");
            if len > 1 {
                let mut b = vec![0; len];
                b[0] = 0xC1;
                b[len - 1] = 1;
                assert!(is_invalid(&imapb_0903(min, max, &b)), "0xC1 with a payload is user defined");
                b[0] = 0x81;
                assert!(is_invalid(&imapb_0903(min, max, &b)), "reserved");
            }
        }
    }

    #[test]
    fn imapb_spec_examples() {
        // ST 0903.6 sections 10.2.2.11 to 10.2.2.13.
        close(&imapb_0903(-19.2, 19.2, &[0x3A, 0x66, 0x67]), 10.0, 1e-5);
        close(&imapb_0903(-19.2, 19.2, &[0x3E, 0x66, 0x67]), 12.0, 1e-5);
        assert_eq!(imapb_0903(-900.0, 19_000.0, &[0x2A, 0x94]), Value::Float(10_000.0));
        assert_eq!(imapb_bytes(-19.2, 19.2, 3, 10.0), [0x3A, 0x66, 0x67]);
        assert_eq!(imapb_bytes(-19.2, 19.2, 3, 12.0), [0x3E, 0x66, 0x67]);
        assert_eq!(imapb_bytes(0.0, 180.0, 2, 12.5), [0x06, 0x40]);
        // rho 1.0 is the MSB-only pattern, a number, because the range is 2.
        assert_eq!(imapb_0903(-1.0, 1.0, &[0x80, 0x00]), Value::Float(1.0));
        assert_eq!(imapb_0903(-1.0, 1.0, &[0x60, 0x00]), Value::Float(0.5));
        assert_eq!(imapb_0903(-1.0, 1.0, &[0x20, 0x00]), Value::Float(-0.5));
        assert_eq!(imapb_0903(0.0, 100.0, &[0x25]), Value::Float(37.0));
        assert_eq!(imapb_0903(-900.0, 900.0, &[0x38, 0x40]), Value::Float(0.0));
        assert_eq!(imapb_0903(-180.0, 180.0, &[0x11, 0x80, 0x00, 0x00]), Value::Float(-110.0));
        close(&imapb_0903(-90.0, 90.0, &[0x40, 0x66, 0x66, 0x66]), 38.8, 1e-7);
    }

    /// A VTarget Pack holding every item with the ST 0903.6 example values.
    fn full_vtarget() -> Vec<u8> {
        let loc = [imapb_bytes(-90.0, 90.0, 4, 38.8), imapb_bytes(-180.0, 180.0, 4, -110.0), vec![0x03, 0x84]].concat();
        let loc16 = [loc.clone(), imapb_bytes(0.0, 650.0, 2, 650.0), vec![0, 0x20], vec![0, 0]].concat();
        let loc22 = [loc16.clone(), vec![0x60, 0, 0x20, 0, 0x80, 0]].concat();
        vtarget_pack(
            1234,
            &[
                tlv(1, &[0x06, 0x40, 0x00]),
                tlv(2, &[0x06, 0x40, 0x00]),
                tlv(3, &[0x06, 0x40, 0x00]),
                tlv(4, &[0x1B]),
                tlv(5, &[0x50]),
                tlv(6, &[0x0A, 0xCD]),
                tlv(7, &[0x32]),
                tlv(8, &[0xDA, 0xA5, 0x20]),
                tlv(9, &[0x33, 0x54]),
                tlv(10, &[0x3A, 0x66, 0x67]),
                tlv(11, &[0x3E, 0x66, 0x67]),
                tlv(12, &[0x2A, 0x94]),
                tlv(13, &[0x3A, 0x66, 0x67]),
                tlv(14, &[0x3A, 0x66, 0x67]),
                tlv(15, &[0x3A, 0x66, 0x67]),
                tlv(16, &[0x3A, 0x66, 0x67]),
                tlv(17, &loc22),
                tlv(18, &series_of(&[loc.clone(), loc16.clone()])),
                tlv(19, &[0x03, 0x68]),
                tlv(20, &[0x04, 0x71]),
                tlv(21, &[1, 2]),
                tlv(22, &[0x03]),
                tlv(23, &[0x01]),
            ],
        )
    }

    #[test]
    fn vtarget_pack_examples() {
        let v = val(101, &series_of(&[full_vtarget()]));
        let targets = list(&v);
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert_eq!(
            names(t),
            [
                "Target ID",
                "Target Centroid",
                "Bounding Box Top Left",
                "Bounding Box Bottom Right",
                "Target Priority",
                "Target Confidence Level",
                "Target History",
                "Percentage of Target Pixels",
                "Target Color",
                "Target Intensity",
                "Target Location Latitude Offset",
                "Target Location Longitude Offset",
                "Target Height",
                "Bounding Box Top Left Latitude Offset",
                "Bounding Box Top Left Longitude Offset",
                "Bounding Box Bottom Right Latitude Offset",
                "Bounding Box Bottom Right Longitude Offset",
                "Target Location",
                "Geospatial Contour Series",
                "Centroid Pixel Row",
                "Centroid Pixel Column",
                "FPA Index",
                "Algorithm ID",
                "Detection Status",
            ]
        );
        let g = |name| t.field(name).unwrap();
        assert_eq!(g("Target ID"), &Value::Uint(1234));
        assert_eq!(g("Target Centroid"), &Value::Uint(409_600));
        assert_eq!(g("Target Priority"), &Value::Uint(27));
        assert_eq!(g("Target Confidence Level"), &Value::Uint(80));
        assert_eq!(g("Target History"), &Value::Uint(2765));
        assert_eq!(g("Percentage of Target Pixels"), &Value::Uint(50));
        assert_eq!(g("Target Color").to_string(), "{ Red: 218, Green: 165, Blue: 32 }");
        assert_eq!(g("Target Intensity"), &Value::Uint(13_140));
        close(g("Target Location Latitude Offset"), 10.0, 1e-5);
        close(g("Target Location Longitude Offset"), 12.0, 1e-5);
        assert_eq!(g("Target Height"), &Value::Float(10_000.0));
        close(g("Bounding Box Bottom Right Longitude Offset"), 10.0, 1e-5);
        assert_eq!(g("Centroid Pixel Row"), &Value::Uint(872));
        assert_eq!(g("Centroid Pixel Column"), &Value::Uint(1137));
        assert_eq!(g("FPA Index").to_string(), "{ Row: 1, Column: 2 }");
        assert_eq!(g("Algorithm ID"), &Value::Uint(3));
        assert_eq!(g("Detection Status"), &Value::Enum { code: 1, label: Some("Active-Moving") });

        let loc = g("Target Location");
        assert_eq!(
            names(loc),
            [
                "Latitude",
                "Longitude",
                "Height",
                "Sigma East",
                "Sigma North",
                "Sigma Up",
                "Rho East-North",
                "Rho East-Up",
                "Rho North-Up"
            ]
        );
        close(loc.field("Latitude").unwrap(), 38.8, 1e-7);
        assert_eq!(loc.field("Longitude"), Some(&Value::Float(-110.0)));
        assert_eq!(loc.field("Height"), Some(&Value::Float(0.0)));
        assert_eq!(loc.field("Sigma East"), Some(&Value::Float(650.0)));
        assert_eq!(loc.field("Sigma North"), Some(&Value::Float(1.0)));
        assert_eq!(loc.field("Rho East-North"), Some(&Value::Float(0.5)));
        assert_eq!(loc.field("Rho East-Up"), Some(&Value::Float(-0.5)));
        assert_eq!(loc.field("Rho North-Up"), Some(&Value::Float(1.0)));

        let contour = list(g("Geospatial Contour Series"));
        assert_eq!(contour.len(), 2);
        assert_eq!(fields(&contour[0]).len(), 3);
        assert_eq!(fields(&contour[1]).len(), 6);
    }

    #[test]
    fn vtarget_value_rules() {
        let one = |items: Vec<u8>| {
            let mut pack = oid(1);
            pack.extend(items);
            let v = val(101, &series_of(&[pack]));
            let t = list(&v)[0].clone();
            fields(&t)[1].value.clone()
        };
        // Pixel numbers: 1 to 6 bytes, 1 or more.
        assert_eq!(one(tlv(1, &[0xFF; 6])), Value::Uint(0xFFFF_FFFF_FFFF));
        assert!(is_invalid(&one(tlv(1, &[0x01; 7]))));
        assert!(is_invalid(&one(tlv(1, &[0]))));
        assert!(is_invalid(&one(tlv(2, &[0, 0]))));
        // Fixed one-byte integers and their ranges.
        assert!(is_invalid(&one(tlv(4, &[0]))));
        assert_eq!(one(tlv(4, &[255])), Value::Uint(255));
        assert!(is_invalid(&one(tlv(4, &[0, 1]))));
        assert_eq!(one(tlv(5, &[0])), Value::Uint(0));
        assert_eq!(one(tlv(5, &[100])), Value::Uint(100));
        assert!(is_invalid(&one(tlv(5, &[101]))));
        assert!(is_invalid(&one(tlv(7, &[0]))));
        assert_eq!(one(tlv(7, &[100])), Value::Uint(100));
        assert!(is_invalid(&one(tlv(7, &[101]))));
        // V2, V3, V4.
        assert!(is_invalid(&one(tlv(6, &[0, 0, 1]))));
        assert_eq!(one(tlv(9, &[0, 0, 1])), Value::Uint(1));
        assert!(is_invalid(&one(tlv(9, &[0, 0, 0, 1]))));
        assert_eq!(one(tlv(19, &[0xFF; 4])), Value::Uint(0xFFFF_FFFF));
        assert!(is_invalid(&one(tlv(19, &[0; 1]))));
        assert!(is_invalid(&one(tlv(20, &[1; 5]))));
        assert!(is_invalid(&one(tlv(22, &[1; 4]))));
        // Fixed-size packs.
        assert!(is_invalid(&one(tlv(8, &[1, 2]))));
        assert!(is_invalid(&one(tlv(21, &[1]))));
        // Detection status: every Table 5 code, unknown codes unlabelled.
        for (code, label) in DETECTION_STATUS.iter().enumerate() {
            assert_eq!(one(tlv(23, &[code as u8])), Value::Enum { code: code as u64, label: Some(label) });
        }
        assert_eq!(one(tlv(23, &[5])), Value::Enum { code: 5, label: None });
        assert!(is_invalid(&one(tlv(23, &[0, 1]))));
        // Location packs: only 10, 16 or 22 bytes; none is unknown.
        for n in [9usize, 11, 15, 17, 21, 23] {
            let v = one(tlv(17, &vec![0; n]));
            assert!(is_invalid(&v), "unexpectedly accepted {n}-byte location");
        }
        assert_eq!(one(tlv(17, &[])), Value::Unknown);
        // The ST 0903 Invalid signal inside a pack: an unreachable corner.
        let mut loc = vec![0xC1, 0, 0, 0, 0xC1, 0, 0, 0, 0x03, 0x84];
        let v = one(tlv(17, &loc));
        assert_eq!(v.field("Latitude"), Some(&Value::OutOfRange));
        assert_eq!(v.field("Height"), Some(&Value::Float(0.0)));
        // 0x7FFF maps above 19,000 m; 0xFFFF is an ST 1201 signalling NaN.
        loc[8] = 0x7F;
        loc[9] = 0xFF;
        assert!(is_invalid(one(tlv(17, &loc)).field("Height").unwrap()));
        loc[8] = 0xFF;
        assert!(one(tlv(17, &loc)).field("Height").unwrap().as_f64().unwrap().is_nan());
        // Fixed IMAPB items decode at the length they arrive with.
        close(&one(tlv(12, &[0x2A, 0x94, 0x00])), 10_000.0, 1e-9);
        assert!(is_invalid(&one(tlv(10, &[0; 9]))));
    }

    #[test]
    fn target_id() {
        let ids = |pack: Vec<u8>| {
            let v = val(101, &series_of(&[pack]));
            list(&v)[0].clone()
        };
        // ST 0903.6 10.2.2.1: 1234 is 0x89 0x52.
        assert_eq!(ids(vtarget_pack(1234, &[tlv(4, &[1])])).field("Target ID"), Some(&Value::Uint(1234)));
        assert_eq!(oid(1234), [0x89, 0x52]);
        // Nine bytes, 63 bits: the largest the standard allows.
        let max = (1u64 << 63) - 1;
        assert_eq!(oid(max).len(), 9);
        assert_eq!(ids(vtarget_pack(max, &[tlv(4, &[1])])).field("Target ID"), Some(&Value::Uint(max)));
        // Ten bytes: flagged, the items still decode.
        let t = ids(vtarget_pack(u64::MAX, &[tlv(4, &[1])]));
        assert!(is_invalid(t.field("Target ID").unwrap()));
        assert_eq!(t.field("Target Priority"), Some(&Value::Uint(1)));
        // Overflowing u64, unterminated, missing.
        let mut over = vec![0xFF; 10];
        over.push(0x7F);
        assert!(is_invalid(&ids(over)));
        assert!(is_invalid(&ids(vec![0x89])));
        let v = val(101, &[0x00]);
        assert_eq!(list(&v).len(), 1);
        assert!(is_invalid(&list(&v)[0]));
        // A pack with only a Target ID decodes (ST 0903.4-10 is not enforced).
        assert_eq!(fields(&ids(oid(7))).len(), 1);
        // A padded BER-OID (non-minimal) is tolerated like padded tags.
        assert_eq!(ids(vec![0x80, 0x05, 0x04, 0x01, 0x01]).field("Target ID"), Some(&Value::Uint(5)));
    }

    #[test]
    fn st0903_figure_13_example() {
        // ST 0903.6 Figure 13: a VMTI LS nested in ST 0601 tag 74, here
        // decoded as the set ST 0601 tag 74 carries, with target IDs 1 and 2.
        let p1 = vtarget_pack(1, &[tlv(1, &[0x01, 0x23]), tlv(8, &[0x01, 0x23, 0x34]), tlv(4, &[0x01])]);
        let p2 = vtarget_pack(2, &[tlv(1, &[0x02, 0x46]), tlv(10, &[0x02, 0x31, 0x47]), tlv(11, &[0x03, 0x53, 0x23])]);
        assert_eq!((p1.len(), p2.len()), (13, 15));
        let targets = series_of(&[p1, p2]);
        assert_eq!(targets.len(), 30);
        let mut set = Vec::new();
        set.extend(tlv(2, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]));
        set.extend(tlv(5, &[0x03, 0x11]));
        set.extend(tlv(6, &[0x03, 0x01]));
        set.extend(tlv(101, &targets));
        set.extend(tlv(4, &[0x04]));
        let p: Packet = decode_set(Standard::St0903, &set, 1, &Config::default());
        assert!(p.is_ok());
        assert_eq!(p.standard, Standard::St0903);
        assert_eq!(p.len(), 5);
        assert_eq!(p.get(Tag::TotalNumberOfTargetsDetected), Some(&Value::Uint(0x0311)));
        assert_eq!(p.get(Tag::NumberOfReportedTargets), Some(&Value::Uint(0x0301)));
        assert_eq!(p.get(Tag::VersionNumber), Some(&Value::Uint(4)));
        let targets = list(p.get(Tag::VTargetSeries).unwrap());
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0].to_string(),
            "{ Target ID: 1, Target Centroid: 291, Target Color: { Red: 1, Green: 35, Blue: 52 }, Target Priority: 1 }"
        );
        assert_eq!(targets[1].field("Target Centroid"), Some(&Value::Uint(0x0246)));
        assert!(targets[1].field("Target Location Latitude Offset").unwrap().is_valid());
        assert!(targets[1].field("Target Location Longitude Offset").unwrap().is_valid());
    }

    #[test]
    fn nested_sets_examples() {
        // VMask (10.3.1, 10.3.2 examples).
        let vmask = [
            tlv(1, &[0x02, 0x39, 0xAA, 0x02, 0x39, 0xBF, 0x02, 0x3B, 0x0B]),
            tlv(2, &[0x03, 0x01, 0x4A, 0x02, 0x03, 0x01, 0x59, 0x04, 0x03, 0x01, 0x6A, 0x02]),
        ]
        .concat();
        assert_eq!(&vmask[..2], [0x01, 0x09]);
        assert_eq!(&vmask[11..13], [0x02, 0x0C]);
        // VTracker (10.6 examples).
        let track_id = [0xF8, 0x1D, 0x4F, 0xAE, 0x7D, 0xEC, 0x11, 0xD0, 0xA7, 0x65, 0x00, 0xA0, 0xC9, 0x1E, 0x6B, 0xF6];
        let time = [0x00, 0x03, 0x82, 0x44, 0x30, 0xF6, 0xCE, 0x40];
        let loc = [imapb_bytes(-90.0, 90.0, 4, 1.0), imapb_bytes(-180.0, 180.0, 4, 2.0), vec![0x03, 0x84]].concat();
        let motion = [imapb_bytes(-900.0, 900.0, 2, 10.0), vec![0x38, 0x40, 0x38, 0x40]].concat();
        let motion12 = [motion.clone(), vec![0, 0x20, 0, 0x20, 0, 0x20]].concat();
        let motion18 = [motion12.clone(), vec![0x40, 0, 0x40, 0, 0x40, 0]].concat();
        let vtracker = [
            tlv(1, &track_id),
            tlv(2, &[3]),
            tlv(3, &time),
            tlv(4, &time),
            tlv(5, &series_of(&[loc.clone(), loc.clone()])),
            tlv(6, b"kalman"),
            tlv(7, &[0x32]),
            tlv(8, &[0x00, 0x02]),
            tlv(9, &series_of(&[loc.clone()])),
            tlv(10, &motion18),
            tlv(11, &motion),
            tlv(12, &[0x03]),
        ]
        .concat();
        // VObject with a VFeature Series (ST 0903.6 Figure 5 style labels).
        let vfeature = [tlv(3, &[0x11]), tlv(4, &imapb_bytes(0.0, 100.0, 2, 80.0))].concat();
        let vobject = [tlv(3, &[0x0A]), tlv(4, &[90]), tlv(5, &series_of(&[vfeature.clone()]))].concat();
        let vobject_old = [tlv(1, b"http://example.org/o.owl"), tlv(2, b"car"), tlv(4, &[0x50, 0x00, 0x00])].concat();
        let vfeature_old = [tlv(1, b"http://example.org/s.xsd"), tlv(2, b"<gml/>")].concat();
        let vchip = [tlv(1, b"jpeg"), tlv(2, b"http://example.org/c.jpg"), tlv(3, &[0xFF, 0xD8, 0xFF])].concat();
        let pack = vtarget_pack(
            3,
            &[
                tlv(101, &vmask),
                tlv(102, &vobject_old),
                tlv(103, &vfeature_old),
                tlv(104, &vtracker),
                tlv(105, &vchip),
                tlv(106, &series_of(&[vchip.clone(), tlv(1, b"png")])),
                tlv(107, &series_of(&[vobject.clone(), vobject.clone()])),
            ],
        );
        let v = val(101, &series_of(&[pack]));
        let t = &list(&v)[0];

        let vm = t.field("VMask").unwrap();
        let contour: Vec<_> = list(vm.field("Pixel Contour").unwrap()).to_vec();
        assert_eq!(contour, [Value::Uint(14_762), Value::Uint(14_783), Value::Uint(15_115)]);
        let runs = list(vm.field("Bit Mask Series").unwrap());
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].to_string(), "{ Pixel: 74, Run Length: 2 }");
        assert_eq!(runs[1].to_string(), "{ Pixel: 89, Run Length: 4 }");
        assert_eq!(runs[2].to_string(), "{ Pixel: 106, Run Length: 2 }");

        let vo = t.field("VObject").unwrap();
        assert_eq!(vo.field("Ontology"), Some(&Value::Text("http://example.org/o.owl".into())));
        assert_eq!(vo.field("Ontology Class"), Some(&Value::Text("car".into())));
        close(vo.field("Confidence").unwrap(), 80.0, 1e-9);
        let vf = t.field("VFeature").unwrap();
        assert_eq!(names(vf), ["Schema", "Schema Feature"]);

        let tr = t.field("VTracker").unwrap();
        assert_eq!(tr.field("Track ID"), Some(&Value::Text("f81d4fae-7dec-11d0-a765-00a0c91e6bf6".into())));
        assert_eq!(tr.field("Detection Status"), Some(&Value::Enum { code: 3, label: Some("Stopped") }));
        assert_eq!(tr.field("First Observation Time"), Some(&Value::Time(987_654_321_000_000)));
        assert_eq!(tr.field("Latest Observation Time"), Some(&Value::Time(987_654_321_000_000)));
        assert_eq!(list(tr.field("Track Boundary Series").unwrap()).len(), 2);
        assert_eq!(tr.field("Algorithm"), Some(&Value::Text("kalman".into())));
        assert_eq!(tr.field("Confidence Level"), Some(&Value::Uint(50)));
        assert_eq!(tr.field("Number of Track Points"), Some(&Value::Uint(2)));
        let history = list(tr.field("Track History Series").unwrap());
        close(history[0].field("Latitude").unwrap(), 1.0, 1e-7);
        close(history[0].field("Longitude").unwrap(), 2.0, 1e-7);
        let vel = tr.field("Velocity").unwrap();
        assert_eq!(fields(vel).len(), 9);
        assert_eq!(vel.field("East"), Some(&Value::Float(10.0)));
        assert_eq!(vel.field("North"), Some(&Value::Float(0.0)));
        assert_eq!(vel.field("Sigma Up"), Some(&Value::Float(1.0)));
        assert_eq!(vel.field("Rho North-Up"), Some(&Value::Float(0.0)));
        assert_eq!(names(tr.field("Acceleration").unwrap()), ["East", "North", "Up"]);
        assert_eq!(tr.field("Algorithm ID"), Some(&Value::Uint(3)));

        let chip = t.field("VChip").unwrap();
        assert_eq!(chip.field("Image Type"), Some(&Value::Text("jpeg".into())));
        assert_eq!(chip.field("Embedded Image"), Some(&Value::Bytes(vec![0xFF, 0xD8, 0xFF])));
        let chips = list(t.field("VChip Series").unwrap());
        assert_eq!(chips[1].field("Image Type"), Some(&Value::Text("png".into())));

        let objects = list(t.field("VObject Series").unwrap());
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].field("Ontology ID"), Some(&Value::Uint(10)));
        assert_eq!(objects[0].field("Confidence"), Some(&Value::Float(90.0)));
        let features = list(objects[0].field("VFeature Series").unwrap());
        assert_eq!(features[0].field("Ontology ID"), Some(&Value::Uint(0x11)));
        close(features[0].field("Confidence").unwrap(), 80.0, 1e-9);
    }

    #[test]
    fn nested_value_rules() {
        let in_set = |def: &SetDef, items: Vec<u8>| nested_set(def, &items, 2, &Config::default());
        // Confidence: IMAP V3, 1 to 3 bytes.
        assert!(is_invalid(in_set(&VOBJECT, tlv(4, &[0, 0, 0, 0])).field("Confidence").unwrap()));
        assert!(is_invalid(in_set(&VFEATURE, tlv(4, &[101])).field("Confidence").unwrap()));
        assert_eq!(in_set(&VFEATURE, tlv(4, &[0xC1])).field("Confidence"), Some(&Value::OutOfRange));
        // Ontology and algorithm IDs: uint V8.
        assert_eq!(in_set(&ONTOLOGY, tlv(1, &[0xFF; 8])).field("Ontology ID"), Some(&Value::Uint(u64::MAX)));
        assert!(is_invalid(in_set(&ONTOLOGY, tlv(1, &[0xFF; 9])).field("Ontology ID").unwrap()));
        assert!(is_invalid(in_set(&ALGORITHM, tlv(5, &[0; 9])).field("Number of Frames").unwrap()));
        // VTracker: UUID and times are fixed size; confidence 0 to 100.
        assert!(is_invalid(in_set(&VTRACKER, tlv(1, &[0; 15])).field("Track ID").unwrap()));
        assert!(is_invalid(in_set(&VTRACKER, tlv(3, &[0; 4])).field("First Observation Time").unwrap()));
        assert!(is_invalid(in_set(&VTRACKER, tlv(7, &[101])).field("Confidence Level").unwrap()));
        let status = in_set(&VTRACKER, tlv(2, &[9]));
        assert_eq!(status.field("Detection Status"), Some(&Value::Enum { code: 9, label: None }));
        for n in [5usize, 7, 13, 19] {
            let v = in_set(&VTRACKER, tlv(10, &vec![0; n]));
            assert!(is_invalid(v.field("Velocity").unwrap()), "{n}");
        }
        // Zero-length nested items are unknown, unless the set must contain
        // the item (ST 0903.6-134, ST 0903.5-102 to -108).
        assert_eq!(in_set(&VCHIP, tlv(1, &[])).field("Image Type"), Some(&Value::Invalid(NO_ZLI)));
        assert_eq!(in_set(&VCHIP, tlv(3, &[])).field("Embedded Image"), Some(&Value::Unknown));
        for (def, tags) in [(&ALGORITHM, &[1u8, 2, 3][..]), (&ONTOLOGY, &[1, 3, 4])] {
            for fd in def.fields {
                let v = in_set(def, tlv(fd.tag, &[]));
                let want = if tags.contains(&fd.tag) { Value::Invalid(NO_ZLI) } else { Value::Unknown };
                assert_eq!(v.field(fd.name), Some(&want), "{}", fd.name);
            }
        }
        for def in [&VTARGET, &VMASK, &VOBJECT, &VFEATURE, &VTRACKER] {
            for fd in def.fields {
                assert_eq!(in_set(def, tlv(fd.tag, &[])).field(fd.name), Some(&Value::Unknown), "{}", fd.name);
            }
        }
        // A zero-length VMask item of a VTarget Pack is an unknown mask.
        let v = val(101, &series_of(&[vtarget_pack(1, &[tlv(101, &[])])]));
        assert_eq!(list(&v)[0].field("VMask"), Some(&Value::Unknown));
        // Repeated items are all kept (ST 0903.5-98 is not enforced).
        let v = in_set(&VCHIP, [tlv(1, b"jpeg"), tlv(1, b"png")].concat());
        assert_eq!(names(&v), ["Image Type", "Image Type"]);
    }

    #[test]
    fn pixel_contour_and_bit_mask_edge_cases() {
        let mask = |items: Vec<u8>| nested_set(&VMASK, &items, 2, &Config::default());
        // Pixel numbers of 1 to 6 bytes, never 0.
        let v = mask(tlv(1, &[0x01, 0x05, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00]));
        let c = list(v.field("Pixel Contour").unwrap());
        assert_eq!(c[0], Value::Uint(5));
        assert_eq!(c[1], Value::Uint(0xFFFF_FFFF_FFFF));
        assert!(is_invalid(&c[2]));
        assert!(is_invalid(&c[3]), "an empty element");
        let v = mask(tlv(1, &[0x07, 1, 1, 1, 1, 1, 1, 1]));
        assert!(is_invalid(&list(v.field("Pixel Contour").unwrap())[0]));
        // Truncated contour: the list ends with the reason.
        let v = mask(tlv(1, &[0x01, 0x05, 0x03, 0x01]));
        let c = list(v.field("Pixel Contour").unwrap());
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], Value::Uint(5));
        assert!(is_invalid(&c[1]));
        // Run lengths in BER long form.
        let v = mask(tlv(2, &series_of(&[vec![0x01, 0x10, 0x82, 0x01, 0x00]])));
        assert_eq!(list(v.field("Bit Mask Series").unwrap())[0].to_string(), "{ Pixel: 16, Run Length: 256 }");
        // Malformed runs.
        for bad in [
            vec![0x01, 0x10],                   // no run length
            vec![0x01, 0x10, 0x02, 0x00],       // left over byte
            vec![0x03, 0x10],                   // pixel past the end
            vec![0x01, 0x10, 0x80],             // indefinite run length
            vec![0xFF],                         // reserved length
            vec![0x01, 0x10, 0x82, 0x01],       // truncated long form
            vec![],                             // empty element
        ] {
            let v = mask(tlv(2, &series_of(&[bad.clone()])));
            let runs = list(v.field("Bit Mask Series").unwrap());
            assert_eq!(runs.len(), 1);
            assert!(is_invalid(&runs[0]), "{bad:02X?}");
        }
        // A pixel number of 0 or 7 bytes leaves the run length readable.
        let v = mask(tlv(2, &series_of(&[vec![0x01, 0x00, 0x05]])));
        let run = &list(v.field("Bit Mask Series").unwrap())[0];
        assert!(is_invalid(run.field("Pixel").unwrap()));
        assert_eq!(run.field("Run Length"), Some(&Value::Uint(5)));
    }

    #[test]
    fn algorithm_and_ontology_series_examples() {
        // ST 0903.6 sections 10.8.1 to 10.8.5 and 7.3.1 / Appendix A.
        let alg = [
            tlv(1, &[0x09]),
            tlv(2, b"k6_yolo_9000_tracker"),
            tlv(3, b"2.6a"),
            tlv(4, b"kalmann"),
            tlv(5, &[0x0A]),
        ]
        .concat();
        assert_eq!(&alg[3..5], [0x02, 0x14]);
        let v = val(102, &series_of(&[alg.clone(), alg]));
        let algs = list(&v);
        assert_eq!(algs.len(), 2);
        assert_eq!(
            algs[0].to_string(),
            "{ Algorithm ID: 9, Name: k6_yolo_9000_tracker, Version: 2.6a, Class: kalmann, Number of Frames: 10 }"
        );
        let ont = [
            tlv(1, &[17]),
            tlv(2, &[10]),
            tlv(3, b"http://purl.obolibrary.org/obo/envo.owl"),
            tlv(4, b"http://purl.obolibrary.org/obo/ENVO_01000605"),
            tlv(5, b"http://purl.obolibrary.org/obo/envo/releases/2021-05-14/envo.owl"),
            tlv(6, b"car"),
        ]
        .concat();
        let v = val(103, &series_of(&[ont]));
        let o = &list(&v)[0];
        assert_eq!(
            names(o),
            ["Ontology ID", "Parent ID", "Ontology IRI", "Entity IRI", "Version IRI", "Label"]
        );
        assert_eq!(o.field("Ontology ID"), Some(&Value::Uint(17)));
        assert_eq!(o.field("Label"), Some(&Value::Text("car".into())));
    }

    #[test]
    fn unknown_and_high_tags_in_nested_sets() {
        // Unknown tags keep their number and bytes; one-byte tags mean 0x81
        // is tag 129, not a BER-OID prefix.
        let items = [tlv(9, &[1, 2]), vec![0x81, 0x01, 0xAA], tlv(1, b"png")].concat();
        let v = nested_set(&VCHIP, &items, 2, &Config::default());
        assert_eq!(names(&v), ["Unknown", "Unknown", "Image Type"]);
        assert_eq!(fields(&v)[0].value.to_string(), "{ Tag: 9, Value: 01 02 }");
        assert_eq!(fields(&v)[1].value.to_string(), "{ Tag: 129, Value: AA }");
        // In a VTarget Pack too.
        let pack = vtarget_pack(1, &[vec![0xC8, 0x01, 0x07], tlv(4, &[2])]);
        let v = val(101, &series_of(&[pack]));
        assert_eq!(names(&list(&v)[0]), ["Target ID", "Unknown", "Target Priority"]);
    }

    #[test]
    fn malformed_sets_and_series_keep_earlier_entries() {
        // A truncated item ends the VTarget Pack with an Error field.
        let mut pack = vtarget_pack(1, &[tlv(4, &[2])]);
        pack.extend([5, 3, 1]);
        let v = val(101, &series_of(&[pack]));
        let t = &list(&v)[0];
        assert_eq!(names(t), ["Target ID", "Target Priority", "Error"]);
        assert!(is_invalid(t.field("Error").unwrap()));
        // Bad lengths inside a nested set.
        let mut overflow = vec![0x01, 0x89];
        overflow.extend([0xFF; 9]);
        for bad in [vec![0x01, 0x80], vec![0x01, 0xFF], overflow] {
            let v = nested_set(&VCHIP, &[tlv(1, b"png"), bad.clone()].concat(), 2, &Config::default());
            assert_eq!(names(&v), ["Image Type", "Error"], "{bad:02X?}");
        }
        // A series that runs past its end: elements before are kept.
        let good = vtarget_pack(1, &[tlv(4, &[2])]);
        let mut s = series_of(&[good.clone(), good]);
        s.extend([0x05, 0x01]);
        let v = val(101, &s);
        let l = list(&v);
        assert_eq!(l.len(), 3);
        assert!(l[0].is_valid() && l[1].is_valid());
        assert!(is_invalid(&l[2]));
        // A single trailing byte: an element of length 0 or a truncation.
        let v = val(101, &[series_of(&[vtarget_pack(1, &[tlv(4, &[2])])]), vec![0x07]].concat());
        assert!(is_invalid(&list(&v)[1]));
        // Indefinite and reserved lengths in a series.
        for b in [0x80u8, 0xFF] {
            let v = val(102, &[b]);
            assert_eq!(list(&v).len(), 1);
            assert!(is_invalid(&list(&v)[0]));
        }
        // A huge long-form length does not allocate or panic.
        let v = val(103, &[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(is_invalid(&list(&v)[0]));
        // An empty element of a series is not an item, so not a zero-length
        // item: it is invalid.
        let v = val(102, &[0x00]);
        assert_eq!(list(&v), [Value::Invalid(EMPTY_ELEMENT)]);
    }

    #[test]
    fn max_items_bounds_sets_and_lists() {
        let mut cfg = Config::default();
        cfg.max_items = 2;
        let packs: Vec<_> = (1..=3).map(|i| vtarget_pack(i, &[tlv(4, &[1])])).collect();
        let v = decode_item(101, &series_of(&packs), 1, &cfg).value;
        let l = list(&v);
        assert_eq!(l.len(), 3);
        assert_eq!(l[2], Value::Invalid(TOO_MANY));
        let pack = vtarget_pack(9, &[tlv(4, &[1]), tlv(5, &[1]), tlv(7, &[1])]);
        let v = decode_item(101, &series_of(&[pack]), 1, &cfg).value;
        assert_eq!(names(&list(&v)[0]), ["Target ID", "Target Priority", "Target Confidence Level", "Error"]);
        let v = decode_item(102, &series_of(&[tlv(1, &[1]), tlv(1, &[2]), tlv(1, &[3])]), 1, &cfg).value;
        assert_eq!(list(&v).len(), 3);
        cfg.max_items = 0;
        let v = decode_item(102, &series_of(&[tlv(1, &[1])]), 1, &cfg).value;
        assert_eq!(list(&v), [Value::Invalid(TOO_MANY)]);
    }

    /// A VMTI LS item that reaches the deepest ST 0903.6 path: VTarget Pack,
    /// VObject Series, VObject, VFeature Series, VFeature.
    fn deepest() -> Vec<u8> {
        let vfeature = tlv(3, &[1]);
        let vobject = tlv(5, &series_of(&[vfeature]));
        let pack = vtarget_pack(1, &[tlv(107, &series_of(&[vobject])), tlv(101, &tlv(1, &[1, 1]))]);
        series_of(&[pack])
    }

    #[test]
    fn depth_bound_holds_at_every_level() {
        let bytes = deepest();
        // VMTI LS at level 1 (under ST 0601 at level 0).
        let at = |max_depth: usize| decode_item(101, &bytes, 1, &deep_cfg(max_depth)).value;

        // max_depth 1: the VTarget Packs (level 2) are too deep.
        assert_eq!(at(1), Value::Invalid(TOO_DEEP));
        assert_eq!(at(0), Value::Invalid(TOO_DEEP));
        // max_depth 2: VTarget decoded, its VObject and VMask sets are not.
        let v = at(2);
        let t = &list(&v)[0];
        assert_eq!(t.field("VObject Series"), Some(&Value::Invalid(TOO_DEEP)));
        assert_eq!(t.field("VMask"), Some(&Value::Invalid(TOO_DEEP)));
        // max_depth 3: VObjects decoded, their VFeature Series is not.
        let v = at(3);
        let objects = list(list(&v)[0].field("VObject Series").unwrap()).to_vec();
        assert_eq!(objects[0].field("VFeature Series"), Some(&Value::Invalid(TOO_DEEP)));
        assert!(list(&v)[0].field("VMask").unwrap().is_valid());
        // max_depth 4: everything.
        let v = at(4);
        let objects = list(list(&v)[0].field("VObject Series").unwrap()).to_vec();
        let features = list(objects[0].field("VFeature Series").unwrap()).to_vec();
        assert_eq!(features[0].field("Ontology ID"), Some(&Value::Uint(1)));
        assert_eq!(at(8), v);

        // The Algorithm and Ontology series are one level down.
        let alg = series_of(&[tlv(1, &[1])]);
        assert_eq!(decode_item(102, &alg, 1, &deep_cfg(1)).value, Value::Invalid(TOO_DEEP));
        assert!(decode_item(102, &alg, 1, &deep_cfg(2)).value.is_valid());
        assert_eq!(decode_item(103, &alg, 3, &deep_cfg(3)).value, Value::Invalid(TOO_DEEP));

        // The registry applies the bound to the VMTI LS itself.
        let set = tlv(101, &bytes);
        assert_eq!(decode_set(Standard::St0903, &set, 1, &deep_cfg(0)).error, Some(crate::Error::TooDeep));
        let p = decode_set(Standard::St0903, &set, 1, &deep_cfg(1));
        assert_eq!(p.get(Tag::VTargetSeries), Some(&Value::Invalid(TOO_DEEP)));
    }

    #[test]
    fn nesting_cannot_recurse_through_unknown_tags() {
        // Sets placed where the standard has none stay raw bytes: a VTarget
        // Pack inside a VFeature (no tag 101 there) is Unknown.
        let mut inner = deepest();
        for _ in 0..200 {
            inner = tlv(101, &series_of(&[vtarget_pack(1, &[tlv(107, &series_of(&[tlv(5, &series_of(&[inner]))]))])]));
            if inner.len() > 60_000 {
                break;
            }
        }
        let outer = series_of(&[vtarget_pack(1, &[tlv(107, &series_of(&[inner]))])]);
        let v = decode_item(101, &outer, 1, &Config::default()).value;
        fn depth(v: &Value) -> usize {
            match v {
                Value::List(l) => 1 + l.iter().map(depth).max().unwrap_or(0),
                Value::Struct(f) => 1 + f.iter().map(|f| depth(&f.value)).max().unwrap_or(0),
                _ => 0,
            }
        }
        // VTarget series/pack, VObject series/set, VFeature series/set and
        // the Unknown struct: bounded whatever the input.
        assert!(depth(&v) <= 8, "{}", depth(&v));
    }

    #[test]
    fn hostile_input_never_panics() {
        // Deterministic xorshift noise and mutations of a valid set.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let tags = [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 101, 102, 103, 104, 250];
        let mut cfgs = vec![Config::default(), deep_cfg(2), deep_cfg(3)];
        let mut small = Config::default();
        small.max_items = 3;
        cfgs.push(small);
        let mut seed = Vec::new();
        seed.extend(tlv(101, &deepest()));
        seed.extend(tlv(101, &series_of(&[full_vtarget()])));
        for round in 0..4000 {
            let len = (next() % 96) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 2 == 1 {
                // Mutate the valid seed: flip, truncate.
                buf = seed.clone();
                for _ in 0..1 + next() % 4 {
                    let i = (next() as usize) % buf.len();
                    buf[i] = next() as u8;
                }
                buf.truncate((next() as usize) % (buf.len() + 1));
            }
            let cfg = &cfgs[round % cfgs.len()];
            for &tag in &tags {
                let it = decode_item(tag, &buf, 1, cfg);
                assert_eq!(it.raw, buf);
                let _ = it.to_string();
            }
            let p = decode_set(Standard::St0903, &buf, 1, cfg);
            let _ = p.to_string();
            let _ = vtarget(&buf, 2, cfg);
            let _ = pixel_run(&buf);
        }
    }

    #[test]
    fn display_of_a_decoded_set() {
        let set = [tlv(4, &[6]), tlv(101, &series_of(&[vtarget_pack(5, &[tlv(23, &[4])])]))].concat();
        let p = decode_set(Standard::St0903, &set, 1, &Config::default());
        assert_eq!(
            Value::Set(Box::new(p)).to_string(),
            "ST 0903 { VMTI LS Version Number: 6, \
             VTarget Series: [{ Target ID: 5, Detection Status: Active-Coasting (4) }] }"
        );
    }
}
