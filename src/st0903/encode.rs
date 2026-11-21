//! MISB ST 0903.6 VMTI Local Set encoding (feature `encode`): the value of
//! ST 0601 tag 74, following `docs/standards/nested-encode.md` sections A,
//! B and D to H (rules R-NESTED-ENCODE-001 to -022, -050 to -150) and
//! DECISIONS.md (version `04 01 06`, item 6 always, no checksum inside tag
//! 74, unique BER-OID target ids of at most 9 bytes, the ST 1201 special
//! patterns, P-2).
//!
//! Two ways in:
//!
//! - [`Vmti`] and the types it holds ([`VTarget`], [`Location`],
//!   [`Motion`], [`VMask`], [`VObject`], [`VFeature`], [`VTracker`],
//!   [`VChip`], [`Algorithm`], [`Ontology`], and the ST 1204
//!   [`CoreIdentifier`]) build a set from typed values and check every
//!   rule of the standard: required items, ranges, lengths, codes, pairs,
//!   references between sets, unique identifiers.
//! - Re-encoding a decoded set ([`crate::Value::Set`] of
//!   [`crate::Standard::St0903`] given for ST 0601 tag 74, for example by
//!   [`crate::encode::encode_packet`]): items whose recorded bytes still
//!   decode to their value are copied, so IMAPB below-minimum, above-maximum
//!   and "Invalid" signals, which all decode to [`crate::Value::OutOfRange`],
//!   survive (DECISIONS P-2, D-33). Inside a changed item the same holds for
//!   each unchanged element, set and field. Everything else is encoded from
//!   its value with the decoder's own tables, so every value the decoder
//!   accepts as valid encodes back to the same value; rules between items
//!   (counts, references, pairs) are only the builder's.
//!
//! Both are driven by the decoder's tag tables (`super::VTARGET` and the
//! other set tables, the Location and Velocity/Acceleration pack tables
//! and [`Tag`]'s value kinds), so ranges, lengths and names cannot drift
//! between the decoder and the encoder.
//!
//! # Output
//!
//! [`Vmti::encode`] returns the bare VMTI LS items: no universal key, no
//! length and no checksum item (R-NESTED-ENCODE-001, -002, -052), ready for
//! ST 0601 tag 74 as [`crate::encode::Input::Set`]. Items are written in
//! ascending tag order with item 2 first (R-NESTED-ENCODE-022, -054, D-01),
//! lengths are minimal BER (-012), integers use the fewest bytes (-015,
//! -070), IMAPB items their table length (-076, D-14).
//!
//! ```
//! use misb::st0903::encode::{DetectionStatus, VTarget, Vmti};
//! let mut vmti = Vmti::new();
//! vmti.frame_width = Some(1920);
//! let mut target = VTarget::new(1);
//! target.centroid = Some(409_600);
//! target.status = Some(DetectionStatus::ActiveMoving);
//! vmti.targets.push(target);
//! // nested-encode.md 3.12 example C.
//! assert_eq!(
//!     vmti.encode()?,
//!     [4, 1, 6, 6, 1, 1, 8, 2, 7, 0x80, 0x65, 0x0A, 9, 1, 1, 3, 6, 0x40, 0, 0x17, 1, 1]
//! );
//! # Ok::<(), misb::encode::EncodeError>(())
//! ```
//!
//! # Policies
//!
//! Under [`Policy::Strict`](crate::encode::Policy::Strict) (the default) every rule is an error. Under
//! [`Policy::Clamp`](crate::encode::Policy::Clamp) a few rules become warnings, as the decisions allow:
//! an IMAPB value outside its range is sent as IMAP_BELOW_MINIMUM or
//! IMAP_ABOVE_MAXIMUM (ST 0903.6 section 9.1.1; a VMTI value is never
//! clamped, D-15), NaN and infinity as their ST 1201 patterns (D-15, D-16),
//! text with control characters or surrounding blanks is cleaned (D-32), a
//! UUID of another version is accepted (D-29), offset items whose timing
//! cannot be checked are written (D-11), and a malformed image chip or IRI
//! is written (D-21). Integers, identifiers and codes are always checked
//! strictly.

use super::{decode_value, elements, set_items, vtarget, Kind, PackField, SetDef, Tag};
use super::{ALGORITHM, LOCATION, MOTION, ONTOLOGY, PIXEL, VCHIP, VFEATURE, VOBJECT, VTARGET, VTRACKER};
use crate::encode::{
    field, put_len, put_oid, put_prefixed, put_uint_min, put_uint_n, same_value, Ctx, EncodeError, EncodeOptions,
    ErrorKind, View, Warning,
};
use crate::imapb::{Imapb, Special};
use crate::{Config, Field, MispTime, Packet, Standard, Value};

use crate::st1204::encode::CoreIdentifier;

/// VMTI LS version number this encoder writes in item 4: ST 0903.6
/// (`04 01 06`, R-NESTED-ENCODE-058, D-10).
pub const VMTI_LS_VERSION: u64 = 6;

/// Largest target ID: a BER-OID of at most 9 bytes (R-NESTED-ENCODE-082).
const MAX_TARGET_ID: u64 = (1 << 63) - 1;
/// Largest `uint V3` value (items 5, 6, 8, 9, VTarget 9 and 22).
const MAX_V3: u64 = 0xFF_FFFF;
/// Largest pixel number (R-NESTED-ENCODE-087).
const MAX_PIXEL: u64 = (1 << 48) - 1;
/// Default IMAPB precision of VObject and VFeature confidence, in percent
/// (D-14: 0.1 percent gives 2 bytes).
pub const DEFAULT_CONFIDENCE_PRECISION: f64 = 0.1;

/// Reason given when a decoded [`Value::OutOfRange`] must be encoded
/// without its recorded bytes.
const AMBIGUOUS: &str = "an IMAPB value decoded as OutOfRange may be below minimum, above maximum or Invalid: \
                         keep its recorded bytes or build it with Imap (D-33)";

/// Largest number of elements in one Series or Array and items in one set
/// that a decoder with the default `Config` reads (D-26).
fn max_entries() -> usize {
    Config::default().max_items
}

// ------------------------------------------------------------------ values

/// An ST 1201 IMAPB value of an ST 0903 floating point item (D-15).
///
/// A plain number outside the item's range is an error under
/// [`Policy::Strict`](crate::encode::Policy::Strict) (it usually means a units bug) and is sent as the
/// below-minimum or above-maximum signal under [`Policy::Clamp`](crate::encode::Policy::Clamp);
/// [`Imap::BelowMinimum`] and [`Imap::AboveMaximum`] send the signal on
/// purpose (ST 0903.6 section 9.1.1, R-NESTED-ENCODE-072).
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum Imap {
    /// A value in engineering units, truncated to the item's resolution
    /// (ST 1201.5 section 7.2.1, R-NESTED-ENCODE-140, -150). `-0.0` is
    /// sent as `+0.0` (-147).
    Value(f64),
    /// IMAP_BELOW_MINIMUM, `E0 00..` (R-NESTED-ENCODE-072, -145): the
    /// measured value was below the item's range.
    BelowMinimum,
    /// IMAP_ABOVE_MAXIMUM, `E1 00..`: the measured value was above the
    /// item's range.
    AboveMaximum,
    /// The ST 0903 "Invalid" signal, `C1 00..` (ST 0903.6 section 9.1.1,
    /// R-NESTED-ENCODE-073): an illegal computed value, such as a ray that
    /// does not meet the ground. Not a stand-in for an unknown value: leave
    /// such an item out (D-38).
    Invalid,
    /// Any ST 1201.5 Table 2 or Table 3 pattern, written explicitly
    /// (R-NESTED-ENCODE-144, D-16); MISB-defined and reserved patterns are
    /// refused.
    Special(Special),
}

impl From<f64> for Imap {
    fn from(x: f64) -> Imap {
        Imap::Value(x)
    }
}

impl From<f32> for Imap {
    fn from(x: f32) -> Imap {
        Imap::Value(f64::from(x))
    }
}

/// VTarget detectionStatus (item 23, ST 0903.6 Table 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum DetectionStatus {
    /// 0: the target is not being detected.
    Inactive = 0,
    /// 1: detected and moving.
    ActiveMoving = 1,
    /// 2: no longer managed (normally not reported, R-NESTED-ENCODE-106).
    Dropped = 2,
    /// 3: detected and stopped.
    ActiveStopped = 3,
    /// 4: predicted while not detected.
    ActiveCoasting = 4,
}

impl DetectionStatus {
    /// The status with this code (0 to 4, R-NESTED-ENCODE-101).
    #[must_use]
    pub fn from_code(code: u8) -> Option<DetectionStatus> {
        Some(match code {
            0 => DetectionStatus::Inactive,
            1 => DetectionStatus::ActiveMoving,
            2 => DetectionStatus::Dropped,
            3 => DetectionStatus::ActiveStopped,
            4 => DetectionStatus::ActiveCoasting,
            _ => return None,
        })
    }

    /// The code of Table 5.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// VChip imageType (item 1): exactly `jpeg` or `png` (ST 0903.6-136).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImageType {
    /// `jpeg`.
    Jpeg,
    /// `png`.
    Png,
}

impl ImageType {
    /// The text written in item 1.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ImageType::Jpeg => "jpeg",
            ImageType::Png => "png",
        }
    }

    /// The file signature an embedded image of this type starts with (D-21).
    fn signature(self) -> &'static [u8] {
        match self {
            ImageType::Jpeg => &[0xFF, 0xD8, 0xFF],
            ImageType::Png => &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        }
    }
}

/// A Location pack (ST 0903.6 Table 18, R-NESTED-ENCODE-111): VTarget
/// targetLocation, the vertices of a BoundarySeries and the points of a
/// trackHistorySeries.
///
/// Latitude IMAPB(-90, 90, 4) degrees, longitude IMAPB(-180, 180, 4)
/// degrees and height IMAPB(-900, 19000, 2) metres above the WGS84
/// ellipsoid are always written (10 bytes); the standard deviations add 6
/// bytes and the correlation coefficients, which need them, 6 more
/// (R-NESTED-ENCODE-110). A coordinate that is not known cannot be filled
/// in: leave the whole pack out (D-38).
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Location {
    /// Latitude, degrees, -90 to 90.
    pub latitude: Imap,
    /// Longitude, degrees, -180 to 180.
    pub longitude: Imap,
    /// Height above the ellipsoid, metres, -900 to 19000.
    pub hae: Imap,
    /// Standard deviations east, north and up, metres, 0 to 650.
    pub sigma: Option<[Imap; 3]>,
    /// Correlation coefficients east-north, east-up and north-up, -1 to 1
    /// (only with [`Location::sigma`]).
    pub rho: Option<[Imap; 3]>,
}

impl Location {
    /// A location of three coordinates.
    #[must_use]
    pub fn new(latitude: impl Into<Imap>, longitude: impl Into<Imap>, hae: impl Into<Imap>) -> Location {
        Location { latitude: latitude.into(), longitude: longitude.into(), hae: hae.into(), sigma: None, rho: None }
    }

    /// The same location with standard deviations.
    #[must_use]
    pub fn with_sigma(mut self, east: impl Into<Imap>, north: impl Into<Imap>, up: impl Into<Imap>) -> Location {
        self.sigma = Some([east.into(), north.into(), up.into()]);
        self
    }

    /// The same location with correlation coefficients.
    #[must_use]
    pub fn with_rho(
        mut self,
        east_north: impl Into<Imap>,
        east_up: impl Into<Imap>,
        north_up: impl Into<Imap>,
    ) -> Location {
        self.rho = Some([east_north.into(), east_up.into(), north_up.into()]);
        self
    }

    fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        put_groups(ctx, &LOCATION, [self.latitude, self.longitude, self.hae], self.sigma, self.rho, out)
    }

    /// Latitude and longitude, when both are plain numbers.
    fn lat_lon(&self) -> Option<(f64, f64)> {
        match (self.latitude, self.longitude) {
            (Imap::Value(a), Imap::Value(b)) => Some((a, b)),
            _ => None,
        }
    }
}

/// A Velocity (m/s) or Acceleration (m/s^2) pack (ST 0903.6 Tables 19 and
/// 20, R-NESTED-ENCODE-112, -113): east, north and up IMAPB(-900, 900, 2)
/// always, then optionally the standard deviations IMAPB(0, 650, 2) and,
/// with them, the correlation coefficients IMAPB(-1, 1, 2).
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Motion {
    /// East component, -900 to 900.
    pub east: Imap,
    /// North component, -900 to 900.
    pub north: Imap,
    /// Up component, -900 to 900.
    pub up: Imap,
    /// Standard deviations east, north and up, 0 to 650.
    pub sigma: Option<[Imap; 3]>,
    /// Correlation coefficients east-north, east-up and north-up, -1 to 1
    /// (only with [`Motion::sigma`]).
    pub rho: Option<[Imap; 3]>,
}

impl Motion {
    /// A pack of three components.
    #[must_use]
    pub fn new(east: impl Into<Imap>, north: impl Into<Imap>, up: impl Into<Imap>) -> Motion {
        Motion { east: east.into(), north: north.into(), up: up.into(), sigma: None, rho: None }
    }

    /// The same pack with standard deviations.
    #[must_use]
    pub fn with_sigma(mut self, east: impl Into<Imap>, north: impl Into<Imap>, up: impl Into<Imap>) -> Motion {
        self.sigma = Some([east.into(), north.into(), up.into()]);
        self
    }

    /// The same pack with correlation coefficients.
    #[must_use]
    pub fn with_rho(
        mut self,
        east_north: impl Into<Imap>,
        east_up: impl Into<Imap>,
        north_up: impl Into<Imap>,
    ) -> Motion {
        self.rho = Some([east_north.into(), east_up.into(), north_up.into()]);
        self
    }

    fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        put_groups(ctx, &MOTION, [self.east, self.north, self.up], self.sigma, self.rho, out)
    }
}

/// One run of a VMask bit mask (ST 0903.6 section 10.3.2): `run` pixels
/// from pixel number `pixel` on, within one image row (D-24).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PixelRun {
    /// First pixel number, 1 to 2^48 - 1.
    pub pixel: u64,
    /// Number of pixels, at least 1.
    pub run: u64,
}

impl PixelRun {
    /// A run of `run` pixels from `pixel`.
    #[must_use]
    pub fn new(pixel: u64, run: u64) -> PixelRun {
        PixelRun { pixel, run }
    }
}

/// A VMask Local Set (VTarget item 101, ST 0903.6 section 10.3): a polygon
/// of three or more pixel numbers in clockwise order and/or a bit mask.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VMask {
    /// Item 1 pixelContour: the polygon's vertices as pixel numbers,
    /// clockwise (R-NESTED-ENCODE-120). Empty: not written.
    pub contour: Vec<u64>,
    /// Item 2 bitMaskSeries: the pixel runs (R-NESTED-ENCODE-121). Empty:
    /// not written.
    pub bit_mask: Vec<PixelRun>,
}

impl VMask {
    /// A mask of a polygon.
    #[must_use]
    pub fn polygon(contour: Vec<u64>) -> VMask {
        VMask { contour, bit_mask: Vec::new() }
    }

    /// A mask of pixel runs.
    #[must_use]
    pub fn runs(bit_mask: Vec<PixelRun>) -> VMask {
        VMask { contour: Vec::new(), bit_mask }
    }
}

/// A VFeature Local Set (an element of a VObject's vFeatureSeries, ST
/// 0903.6 section 10.5): a feature label and the confidence in it.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct VFeature {
    /// Item 3 ontologyId: an id of the VMTI LS ontologySeries
    /// (R-NESTED-ENCODE-123, D-25).
    pub ontology_id: u64,
    /// Item 4 confidence, percent, 0 to 100 (R-NESTED-ENCODE-124, D-22).
    pub confidence: Imap,
    /// Precision of the confidence in percent, which sets its length
    /// (ST 1201.5 IMAPA, 1 to 3 bytes; default
    /// [`DEFAULT_CONFIDENCE_PRECISION`], 2 bytes; D-14).
    pub confidence_precision: f64,
}

impl VFeature {
    /// A feature with the default confidence precision.
    #[must_use]
    pub fn new(ontology_id: u64, confidence: impl Into<Imap>) -> VFeature {
        VFeature { ontology_id, confidence: confidence.into(), confidence_precision: DEFAULT_CONFIDENCE_PRECISION }
    }
}

/// A VObject Local Set (an element of VTarget item 107 vObjectSeries, ST
/// 0903.6 section 10.4): an object label, the confidence in it and its
/// features.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct VObject {
    /// Item 3 ontologyId: an id of the VMTI LS ontologySeries
    /// (R-NESTED-ENCODE-122, D-25).
    pub ontology_id: u64,
    /// Item 4 confidence, percent, 0 to 100 (R-NESTED-ENCODE-124, D-22).
    pub confidence: Imap,
    /// Precision of the confidence in percent (see
    /// [`VFeature::confidence_precision`]).
    pub confidence_precision: f64,
    /// Item 5 vFeatureSeries. Empty: not written.
    pub features: Vec<VFeature>,
}

impl VObject {
    /// An object with no features and the default confidence precision.
    #[must_use]
    pub fn new(ontology_id: u64, confidence: impl Into<Imap>) -> VObject {
        VObject {
            ontology_id,
            confidence: confidence.into(),
            confidence_precision: DEFAULT_CONFIDENCE_PRECISION,
            features: Vec::new(),
        }
    }
}

/// A VTracker Local Set (VTarget item 104, ST 0903.6 section 10.6,
/// R-NESTED-ENCODE-125). At least one field must be set (D-23).
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct VTracker {
    /// Item 1 trackId: a UUID (ISO/IEC 9834-8), network byte order.
    pub track_id: Option<[u8; 16]>,
    /// Item 3 firstObsvTime, not after `latest_observation` (D-37).
    pub first_observation: Option<MispTime>,
    /// Item 4 latestObsvTime.
    pub latest_observation: Option<MispTime>,
    /// Item 5 trackBoundarySeries: at least two vertices; two are opposite
    /// corners of a latitude-longitude box (R-NESTED-ENCODE-114). Empty: not
    /// written.
    pub boundary: Vec<Location>,
    /// Item 7 confidenceLevel, percent, 0 to 100.
    pub confidence: Option<u8>,
    /// Item 9 trackHistorySeries, oldest point first (ST 0903.4-56).
    /// Empty: not written.
    pub history: Vec<Location>,
    /// Item 10 velocity; needs an associated location (D-19).
    pub velocity: Option<Motion>,
    /// Item 11 acceleration; needs an associated location (D-19).
    pub acceleration: Option<Motion>,
    /// Item 12 algorithmId: an id of the VMTI LS algorithmSeries (D-25).
    pub algorithm_id: Option<u64>,
}

/// A VChip Local Set (VTarget item 105, or an element of item 106, ST
/// 0903.6 section 10.7): an image chip, referenced or embedded (D-21).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VChip {
    /// Item 1 imageType (R-NESTED-ENCODE-126).
    pub image_type: ImageType,
    /// Item 2 imageIRI: an absolute IRI of an image of `image_type`.
    pub iri: Option<String>,
    /// Item 3 embeddedImage: the image file, written as given; it must
    /// start with the signature of `image_type` (D-21).
    pub image: Option<Vec<u8>>,
}

impl VChip {
    /// A chip referenced by an IRI.
    #[must_use]
    pub fn iri(image_type: ImageType, iri: &str) -> VChip {
        VChip { image_type, iri: Some(iri.to_string()), image: None }
    }

    /// A chip carrying the image file.
    #[must_use]
    pub fn embedded(image_type: ImageType, image: Vec<u8>) -> VChip {
        VChip { image_type, iri: None, image: Some(image) }
    }
}

/// An Algorithm Local Set (an element of VMTI item 102, ST 0903.6 section
/// 10.8, R-NESTED-ENCODE-127).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Algorithm {
    /// Item 1 algorithmId, unique in the series.
    pub id: u64,
    /// Item 2 name, not empty.
    pub name: String,
    /// Item 3 version, not empty.
    pub version: String,
    /// Item 4 class.
    pub class: Option<String>,
    /// Item 5 nFrames.
    pub frames: Option<u64>,
}

impl Algorithm {
    /// An algorithm with its required items.
    #[must_use]
    pub fn new(id: u64, name: &str, version: &str) -> Algorithm {
        Algorithm { id, name: name.to_string(), version: version.to_string(), class: None, frames: None }
    }
}

/// An Ontology Local Set (an element of VMTI item 103, ST 0903.6 section
/// 10.9, R-NESTED-ENCODE-128, -131).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Ontology {
    /// Item 1 ontologyId, unique in the series.
    pub id: u64,
    /// Item 2 parentId: the id of another element of the series;
    /// discouraged since ST 0903.6 (R-NESTED-ENCODE-129, a warning).
    pub parent_id: Option<u64>,
    /// Item 3 ontologyIRI: the IRI of an OWL ontology.
    pub ontology_iri: String,
    /// Item 4 entityIRI: an entity of that ontology.
    pub entity_iri: String,
    /// Item 5 versionIRI.
    pub version_iri: Option<String>,
    /// Item 6 label: the entity's rdfs:label or skos:prefLabel exactly.
    pub label: Option<String>,
}

impl Ontology {
    /// An ontology element with its required items.
    #[must_use]
    pub fn new(id: u64, ontology_iri: &str, entity_iri: &str) -> Ontology {
        Ontology {
            id,
            parent_id: None,
            ontology_iri: ontology_iri.to_string(),
            entity_iri: entity_iri.to_string(),
            version_iri: None,
            label: None,
        }
    }
}

/// A VTarget Pack (an element of VMTI item 101, ST 0903.6 section 10.2,
/// Table 10): the target ID and at least one item (R-NESTED-ENCODE-080,
/// -081).
///
/// Deprecated items (21, 102, 103) are never written (-099). Paired items
/// are typed as pairs, so neither half can be sent alone (-086, D-17).
/// Offset items need the parent packet's frame centre, tags 23 and 24
/// (R-NESTED-ENCODE-008, -010, D-31, checked by the ST 0601 packet
/// builder); [`VTarget::location`] is preferred (-097).
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct VTarget {
    /// targetId, 0 to 2^63 - 1, unique in the series and never reused
    /// (R-NESTED-ENCODE-082, -083).
    pub id: u64,
    /// Item 1 targetCentroid, a pixel number (R-NESTED-ENCODE-087, -075).
    pub centroid: Option<u64>,
    /// Items 2 and 3: pixel bounding box (top left, bottom right) pixel
    /// numbers (R-NESTED-ENCODE-088).
    pub bounding_box: Option<(u64, u64)>,
    /// Item 4 targetPriority, 1 (highest) to 255.
    pub priority: Option<u8>,
    /// Item 5 targetConfidenceLevel, percent, 0 to 100.
    pub confidence: Option<u8>,
    /// Item 6 targetHistory: earlier detections, 0 for a new one.
    pub history: Option<u16>,
    /// Item 7 percentageOfTargetPixels, 1 to 100.
    pub percentage_pixels: Option<u8>,
    /// Item 8 targetColor, red, green, blue (R-NESTED-ENCODE-093).
    pub color: Option<[u8; 3]>,
    /// Item 9 targetIntensity, 0 to 2^24 - 1.
    pub intensity: Option<u32>,
    /// Items 10 and 11: target (latitude, longitude) offsets from the
    /// frame centre, degrees, -19.2 to 19.2 (R-NESTED-ENCODE-095, D-18).
    pub location_offset: Option<(Imap, Imap)>,
    /// Item 12 targetHae, metres, -900 to 19000 (R-NESTED-ENCODE-096).
    pub hae: Option<Imap>,
    /// Items 13 to 16: geospatial bounding box offsets, degrees: top left
    /// latitude, top left longitude, bottom right latitude, bottom right
    /// longitude.
    pub bounding_box_offsets: Option<[Imap; 4]>,
    /// Item 17 targetLocation (preferred over offsets,
    /// R-NESTED-ENCODE-097).
    pub location: Option<Location>,
    /// Item 18 geospatialContourSeries: at least two vertices
    /// (R-NESTED-ENCODE-114). Empty: not written.
    pub contour: Vec<Location>,
    /// Items 19 and 20: centroid (row, column), 1 to 2^32 - 1
    /// (R-NESTED-ENCODE-086, -098).
    pub centroid_row_col: Option<(u32, u32)>,
    /// Item 22 algorithmId: an id of the VMTI LS algorithmSeries, at most
    /// 2^24 - 1 (R-NESTED-ENCODE-100, D-25).
    pub algorithm_id: Option<u32>,
    /// Item 23 detectionStatus (R-NESTED-ENCODE-101; Active-Moving and
    /// Active-Stopped need a centroid, -085).
    pub status: Option<DetectionStatus>,
    /// Item 101 vMask.
    pub mask: Option<VMask>,
    /// Item 104 vTracker.
    pub tracker: Option<VTracker>,
    /// Image chips: one is written as item 105 vChip, two or more as item
    /// 106 vChipSeries, the first from the frame of the detection
    /// (R-NESTED-ENCODE-103, D-21).
    pub chips: Vec<VChip>,
    /// Item 107 vObjectSeries. Empty: not written.
    pub objects: Vec<VObject>,
}

impl VTarget {
    /// A target with this ID and no items yet.
    #[must_use]
    pub fn new(id: u64) -> VTarget {
        VTarget { id, ..VTarget::default() }
    }

    /// Whether the target uses an offset item (10, 11, 13 to 16).
    fn uses_offsets(&self) -> bool {
        self.location_offset.is_some() || self.bounding_box_offsets.is_some()
    }

    /// Whether the target uses a pixel-number item (1, 2, 3, VMask).
    fn uses_pixels(&self) -> bool {
        self.centroid.is_some()
            || self.bounding_box.is_some()
            || self.mask.as_ref().map_or(false, |m| !m.contour.is_empty() || !m.bit_mask.is_empty())
    }
}

/// A MISB ST 0903.6 VMTI Local Set for ST 0601 tag 74 (embedded VMTI).
///
/// One set describes the detections of one VMTI process on one sensor
/// (R-NESTED-ENCODE-009). Item 4 is always 6 (D-10) and item 6 is the
/// number of [`Vmti::targets`] (D-12); neither can be set.
///
/// ```
/// use misb::encode::{Input, St0601Builder};
/// use misb::st0903::encode::{Location, VTarget, Vmti};
/// use misb::{st0601::Tag, MispTime};
///
/// let mut vmti = Vmti::new();
/// let mut target = VTarget::new(7);
/// target.location = Some(Location::new(38.8, -77.0, 30.0));
/// vmti.targets.push(target);
/// let mut b = St0601Builder::new(MispTime::from_micros(1_700_000_000_000_000));
/// // A packet with VMTI carries the frame centre (R-NESTED-ENCODE-008).
/// b.set(Tag::FrameCenterLatitude, 38.8)?.set(Tag::FrameCenterLongitude, -77.0)?;
/// b.set(Tag::VmtiLocalSet, Input::Set(vmti.encode()?))?;
/// let packet = misb::decode(&b.finish()?).unwrap();
/// assert!(packet.is_ok());
/// # Ok::<(), misb::encode::EncodeError>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Vmti {
    /// The VMTI-MI timestamp (item 2). `None`: the same as the parent
    /// packet's tag 2, and item 2 is left out (R-NESTED-ENCODE-053, D-11).
    pub time: Option<MispTime>,
    /// Tag 2 of the ST 0601 packet that carries the set. When it equals
    /// [`Vmti::time`] item 2 is left out unless
    /// [`Vmti::always_write_time`]; it also decides whether offset items
    /// may be used (R-NESTED-ENCODE-056).
    pub parent_time: Option<MispTime>,
    /// Write item 2 even when it equals the parent's tag 2 (D-11).
    pub always_write_time: bool,
    /// The VMTI-MI frame period in microseconds: offset items are refused
    /// when the VMTI time and the parent's tag 2 differ by more than two
    /// periods, or at all when the period is not given
    /// (R-NESTED-ENCODE-056, D-11).
    pub frame_period_us: Option<u64>,
    /// Whether the VMTI process ran on the imagery the stream carries
    /// (D-30, default `true`). When `false`, items 11, 12 and 13 are
    /// required (R-NESTED-ENCODE-065, -066) and item 10 is recommended.
    pub vmti_mi_is_user_mi: bool,
    /// Item 3 vmtiSystemName, at most 32 characters (R-NESTED-ENCODE-057).
    pub system_name: Option<String>,
    /// Item 5 totalNumTargetsDetected, at least the number of targets,
    /// written only when it differs from it (R-NESTED-ENCODE-059, D-12).
    pub total_targets_detected: Option<u64>,
    /// Item 8 frameWidth, pixels, 1 to 2^24 - 1; required with pixel-number
    /// items (R-NESTED-ENCODE-062).
    pub frame_width: Option<u64>,
    /// Item 9 frameHeight, pixels, 1 to 2^24 - 1 (R-NESTED-ENCODE-063).
    pub frame_height: Option<u64>,
    /// Item 10 vmtiSourceSensor, at most 128 characters
    /// (R-NESTED-ENCODE-064).
    pub source_sensor: Option<String>,
    /// Item 11 vmtiHorizontalFov, degrees, 0 to 180 (R-NESTED-ENCODE-065).
    pub horizontal_fov: Option<Imap>,
    /// Item 12 vmtiVerticalFov, degrees, 0 to 180.
    pub vertical_fov: Option<Imap>,
    /// Item 13 miisId, the VMTI-MI's ST 1204 Core Identifier
    /// (R-NESTED-ENCODE-066).
    pub miis_id: Option<CoreIdentifier>,
    /// Item 101 vTargetSeries, written in ascending target ID order (D-02).
    /// Empty: item 101 is left out and item 6 is 0 (D-13).
    pub targets: Vec<VTarget>,
    /// Item 102 algorithmSeries, ascending id (D-02). Empty: not written.
    pub algorithms: Vec<Algorithm>,
    /// Item 103 ontologySeries, ascending id (D-02). Empty: not written.
    pub ontologies: Vec<Ontology>,
}

impl Default for Vmti {
    fn default() -> Vmti {
        Vmti {
            time: None,
            parent_time: None,
            always_write_time: false,
            frame_period_us: None,
            vmti_mi_is_user_mi: true,
            system_name: None,
            total_targets_detected: None,
            frame_width: None,
            frame_height: None,
            source_sensor: None,
            horizontal_fov: None,
            vertical_fov: None,
            miis_id: None,
            targets: Vec::new(),
            algorithms: Vec::new(),
            ontologies: Vec::new(),
        }
    }
}

/// What the items of one VMTI LS need to know about the others.
struct Scope<'s> {
    width: Option<u64>,
    height: Option<u64>,
    /// Sorted algorithm ids of item 102 (D-25).
    algorithms: &'s [u64],
    /// Sorted ontology ids of item 103 (D-25).
    ontologies: &'s [u64],
    /// Why offset items may not be used, if so (R-NESTED-ENCODE-056).
    offsets: Option<&'static str>,
}

impl Vmti {
    /// An empty set: no targets, VMTI-MI the same as the user-MI.
    #[must_use]
    pub fn new() -> Vmti {
        Vmti::default()
    }

    /// The set's items with default options, ready for ST 0601 tag 74
    /// (pass them as [`crate::encode::Input::Set`]).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut warnings = Vec::new();
        self.encode_with(&EncodeOptions::default(), &mut warnings)
    }

    /// As [`Vmti::encode`], under `opts` and collecting warnings.
    pub fn encode_with(&self, opts: &EncodeOptions, warnings: &mut Vec<Warning>) -> Result<Vec<u8>, EncodeError> {
        let mut ctx = Ctx::new(opts, warnings, Standard::St0903);
        let mut out = Vec::new();
        self.write(&mut ctx, &mut out)?;
        Ok(out)
    }

    fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // Targets in ascending ID order, IDs unique (R-NESTED-ENCODE-067,
        // D-02).
        let mut targets: Vec<&VTarget> = self.targets.iter().collect();
        targets.sort_by_key(|t| t.id);
        ctx.tag = Some(101);
        if targets.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(ctx.err(ErrorKind::Duplicate, "two VTarget Packs with the same targetId (R-NESTED-ENCODE-067)"));
        }
        let count = targets.len() as u64;
        if count > MAX_V3 || targets.len() > max_entries() {
            return Err(ctx.err(ErrorKind::TooLarge, "more VTarget Packs than item 6 or a decoder can hold (D-26)"));
        }
        let algorithms = sorted_ids(
            ctx,
            102,
            self.algorithms.iter().map(|a| a.id),
            "two Algorithm LSs with the same algorithmId (R-NESTED-ENCODE-127)",
        )?;
        let ontologies = sorted_ids(
            ctx,
            103,
            self.ontologies.iter().map(|o| o.id),
            "two Ontology LSs with the same ontologyId (R-NESTED-ENCODE-128)",
        )?;

        // Item 8 bounds the pixel numbers; check it before the targets.
        ctx.tag = Some(8);
        let width = match self.frame_width {
            Some(w) => Some(frame_size(ctx, w, "frameWidth is 1 to 2^24 - 1 pixels (R-NESTED-ENCODE-062)")?),
            None if targets.iter().any(|t| t.uses_pixels()) => {
                return Err(ctx.err(ErrorKind::Missing, "frameWidth is required with pixel-number items (R-NESTED-ENCODE-062)"))
            }
            None => None,
        };
        ctx.tag = Some(9);
        let height = match self.frame_height {
            Some(h) => Some(frame_size(ctx, h, "frameHeight is 1 to 2^24 - 1 pixels (R-NESTED-ENCODE-063)")?),
            None => None,
        };
        let offsets = self.offsets_forbidden();
        let scope = Scope { width, height, algorithms: &algorithms, ontologies: &ontologies, offsets };

        // R-NESTED-ENCODE-065, -066, D-30.
        if !self.vmti_mi_is_user_mi {
            let required = [
                (11, self.horizontal_fov.is_some(), "vmtiHorizontalFov is required when the VMTI-MI is not the user-MI (R-NESTED-ENCODE-065)"),
                (12, self.vertical_fov.is_some(), "vmtiVerticalFov is required when the VMTI-MI is not the user-MI (R-NESTED-ENCODE-065)"),
                (13, self.miis_id.is_some(), "miisId is required when the VMTI-MI is not the user-MI (R-NESTED-ENCODE-066)"),
            ];
            for (tag, present, reason) in required {
                if !present {
                    ctx.tag = Some(tag);
                    return Err(ctx.err(ErrorKind::Missing, reason));
                }
            }
            if self.source_sensor.is_none() {
                ctx.tag = Some(10);
                ctx.warn("vmtiSourceSensor is recommended when the VMTI-MI is not the user-MI (R-NESTED-ENCODE-064, D-30)");
            }
        }

        // Item 2 first when written (R-NESTED-ENCODE-053 to -055, D-11).
        let time = match (self.time, self.parent_time) {
            (Some(t), Some(p)) if t == p && !self.always_write_time => None,
            (Some(t), _) => Some(t),
            (None, Some(p)) if self.always_write_time => Some(p),
            (None, _) => None,
        };
        if let Some(t) = time {
            put_tlv(out, 2, &t.as_micros().to_be_bytes());
        }
        if let Some(name) = &self.system_name {
            ctx.tag = Some(3);
            text_item(ctx, Tag::VmtiSystemName.kind(), 3, name, out)?;
        }
        // R-NESTED-ENCODE-058, D-10: 04 01 06.
        put_tlv(out, 4, &[VMTI_LS_VERSION as u8]);
        if let Some(total) = self.total_targets_detected {
            ctx.tag = Some(5);
            if total < count {
                return Err(ctx.err(
                    ErrorKind::OutOfRange,
                    "totalNumTargetsDetected is never below the number of reported targets (D-12)",
                ));
            }
            // R-NESTED-ENCODE-059: only when it differs from item 6.
            if total != count {
                uint_item(
                    ctx,
                    Tag::TotalNumberOfTargetsDetected.kind(),
                    5,
                    total,
                    "totalNumTargetsDetected is at most 2^24 - 1",
                    out,
                )?;
            }
        }
        // R-NESTED-ENCODE-060, D-12: the number of VTarget Packs.
        ctx.tag = Some(6);
        uint_item(ctx, Tag::NumberOfReportedTargets.kind(), 6, count, "numTargetsReported is at most 2^24 - 1", out)?;
        for (t, size) in [(Tag::FrameWidth, width), (Tag::FrameHeight, height)] {
            if let Some(n) = size {
                ctx.tag = Some(u64::from(t));
                uint_item(ctx, t.kind(), t as u8, n, "frameWidth and frameHeight are 1 to 2^24 - 1", out)?;
            }
        }
        if let Some(sensor) = &self.source_sensor {
            ctx.tag = Some(10);
            text_item(ctx, Tag::VmtiSourceSensor.kind(), 10, sensor, out)?;
        }
        // R-NESTED-ENCODE-065: IMAPB(0, 180, 2).
        let fovs = [(Tag::VmtiHorizontalFieldOfView, self.horizontal_fov), (Tag::VmtiVerticalFieldOfView, self.vertical_fov)];
        for (t, fov) in fovs {
            if let Some(x) = fov {
                ctx.tag = Some(u64::from(t));
                imap_item(ctx, t.kind(), t as u8, x, 2, out)?;
            }
        }
        if let Some(id) = &self.miis_id {
            ctx.tag = Some(13);
            let mut v = Vec::new();
            id.write(ctx, &mut v)?;
            put_tlv(out, 13, &v);
        }
        // D-13: no item 101 without targets.
        if !targets.is_empty() {
            ctx.tag = Some(101);
            let mut v = Vec::new();
            let mut e = Vec::new();
            for t in &targets {
                e.clear();
                t.write(ctx, &scope, &mut e)?;
                put_prefixed(&mut v, &e);
            }
            put_tlv(out, 101, &v);
        }
        // R-NESTED-ENCODE-069, D-02: ascending ids, left out when empty.
        if !self.algorithms.is_empty() {
            ctx.tag = Some(102);
            let mut sorted: Vec<&Algorithm> = self.algorithms.iter().collect();
            sorted.sort_by_key(|a| a.id);
            series_item(ctx, 102, &sorted, |a, ctx, e| a.write(ctx, e), out)?;
        }
        if !self.ontologies.is_empty() {
            ctx.tag = Some(103);
            let mut sorted: Vec<&Ontology> = self.ontologies.iter().collect();
            sorted.sort_by_key(|o| o.id);
            series_item(ctx, 103, &sorted, |o, ctx, e| o.write(ctx, &scope, e), out)?;
        }
        ctx.tag = None;
        Ok(())
    }

    /// Why offset items may not be used (R-NESTED-ENCODE-056, D-11).
    fn offsets_forbidden(&self) -> Option<&'static str> {
        match (self.time, self.parent_time) {
            (None, _) => None,
            (Some(t), Some(p)) => {
                let d = t.as_micros().abs_diff(p.as_micros());
                match self.frame_period_us {
                    Some(fp) if d <= fp.saturating_mul(2) => None,
                    Some(_) => Some(
                        "offset items are not used when the VMTI time and tag 2 differ by more than two frame periods (R-NESTED-ENCODE-056)",
                    ),
                    None if d == 0 => None,
                    None => Some("offset items need frame_period_us when the VMTI time differs from tag 2 (R-NESTED-ENCODE-056, D-11)"),
                }
            }
            (Some(_), None) => Some("offset items need parent_time to compare the VMTI time with tag 2 (R-NESTED-ENCODE-056, D-11)"),
        }
    }
}

/// Offsets in degrees of `point` (latitude, longitude) from the frame
/// centre (latitude, longitude) of the same ST 0601 packet, for
/// [`VTarget::location_offset`] and [`VTarget::bounding_box_offsets`]
/// (R-NESTED-ENCODE-010, -095, D-18).
///
/// The frame centre is taken as the receiver decodes it from tags 23 and
/// 24, quantised by their ST 0601 mapping, so that its quantisation error
/// is not added to the offsets; the longitude difference is normalised to
/// (-180, 180], so a target across the antimeridian gets a small offset.
/// An offset outside -19.2 to 19.2 degrees is refused when the target is
/// encoded (or sent as a range signal under [`Policy::Clamp`]): use
/// [`VTarget::location`] instead (R-NESTED-ENCODE-097).
///
/// [`Policy::Clamp`]: crate::encode::Policy::Clamp
///
/// ```
/// let (lat, lon) = misb::st0903::encode::offsets((38.8, 179.9), (38.9, -179.9))?;
/// assert!((lat - 0.1).abs() < 1e-6 && (lon - 0.2).abs() < 1e-6);
/// # Ok::<(), misb::encode::EncodeError>(())
/// ```
pub fn offsets(frame_center: (f64, f64), point: (f64, f64)) -> Result<(f64, f64), EncodeError> {
    let opts = EncodeOptions::default();
    let mut warnings = Vec::new();
    let mut ctx = Ctx::new(&opts, &mut warnings, Standard::St0601);
    let cfg = Config::default();
    let mut quantised = |tag: crate::st0601::Tag, x: f64| -> Result<f64, EncodeError> {
        ctx.tag = Some(u64::from(tag));
        let mut b = Vec::with_capacity(4);
        crate::st0601::encode::encode_value(tag, View::Float(x), None, &mut ctx, &mut b)?;
        match crate::st0601::decode_item(u64::from(tag), &b, 0, &cfg).value {
            Value::Float(q) => Ok(q),
            _ => Err(ctx.err(ErrorKind::OutOfRange, "frame centre latitude or longitude out of range")),
        }
    };
    let lat = quantised(crate::st0601::Tag::FrameCenterLatitude, frame_center.0)?;
    let lon = quantised(crate::st0601::Tag::FrameCenterLongitude, frame_center.1)?;
    let mut d_lon = (point.1 - lon) % 360.0;
    if d_lon > 180.0 {
        d_lon -= 360.0;
    } else if d_lon <= -180.0 {
        d_lon += 360.0;
    }
    Ok((point.0 - lat, d_lon))
}

/// Sorted ids of a series, refusing duplicates.
fn sorted_ids(
    ctx: &mut Ctx<'_>,
    tag: u64,
    ids: impl Iterator<Item = u64>,
    dup: &'static str,
) -> Result<Vec<u64>, EncodeError> {
    let mut v: Vec<u64> = ids.collect();
    v.sort_unstable();
    ctx.tag = Some(tag);
    if v.windows(2).any(|w| w[0] == w[1]) {
        return Err(ctx.err(ErrorKind::Duplicate, dup));
    }
    if v.len() > max_entries() {
        return Err(ctx.err(ErrorKind::TooLarge, "more series elements than a decoder reads (D-26)"));
    }
    Ok(v)
}

/// A frame width or height: `uint V3`, never 0.
fn frame_size(ctx: &Ctx<'_>, v: u64, why: &'static str) -> Result<u64, EncodeError> {
    if (1..=MAX_V3).contains(&v) {
        Ok(v)
    } else {
        Err(ctx.err(ErrorKind::OutOfRange, why))
    }
}

impl VTarget {
    /// The VTarget Pack: target ID then items in ascending tag order (the
    /// series element without its length, R-NESTED-ENCODE-080).
    fn write(&self, ctx: &mut Ctx<'_>, scope: &Scope<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.id > MAX_TARGET_ID {
            return Err(ctx.err(
                ErrorKind::OutOfRange,
                "targetId is 0 to 2^63 - 1, a BER-OID of at most 9 bytes (R-NESTED-ENCODE-082)",
            ));
        }
        // R-NESTED-ENCODE-085: Active-Moving and Active-Stopped need a
        // centroid representation.
        let centroid = self.centroid.is_some() || self.centroid_row_col.is_some() || self.bounding_box.is_some();
        if matches!(self.status, Some(DetectionStatus::ActiveMoving | DetectionStatus::ActiveStopped)) && !centroid {
            return Err(ctx.err(
                ErrorKind::Missing,
                "an Active-Moving or Active-Stopped VTarget needs item 1, items 19 and 20, or items 2 and 3 (R-NESTED-ENCODE-085)",
            ));
        }
        if self.status == Some(DetectionStatus::Dropped) {
            ctx.warn("dropped targets are not in the target list (R-NESTED-ENCODE-106, D-39)");
        }
        if self.uses_offsets() {
            if let Some(reason) = scope.offsets {
                if ctx.strict() {
                    return Err(ctx.err(ErrorKind::NotAllowed, reason));
                }
                ctx.warn(reason);
            }
        }
        // R-NESTED-ENCODE-082: fewest bytes, no tag, no length.
        put_oid(out, self.id);
        let start = out.len();
        if let Some(p) = self.centroid {
            pixel(ctx, scope, p, "VTarget targetCentroid is a pixel number of the frame (R-NESTED-ENCODE-087)")?;
            uint_field(ctx, &VTARGET, 1, p, "VTarget targetCentroid is 1 to 2^48 - 1 (R-NESTED-ENCODE-087)", out)?;
        }
        if let Some((top_left, bottom_right)) = self.bounding_box {
            let why = "VTarget bounding box corners are pixel numbers of the frame (R-NESTED-ENCODE-088)";
            pixel(ctx, scope, top_left, why)?;
            pixel(ctx, scope, bottom_right, why)?;
            if let Some(w) = scope.width {
                let (r0, c0) = row_col(top_left, w);
                let (r1, c1) = row_col(bottom_right, w);
                if r1 < r0 || c1 < c0 {
                    return Err(ctx.err(
                        ErrorKind::OutOfRange,
                        "VTarget boundingBoxBottomRight is above or left of boundingBoxTopLeft (R-NESTED-ENCODE-088)",
                    ));
                }
            }
            uint_field(ctx, &VTARGET, 2, top_left, why, out)?;
            uint_field(ctx, &VTARGET, 3, bottom_right, why, out)?;
        }
        if let Some(p) = self.priority {
            uint_field(ctx, &VTARGET, 4, u64::from(p), "VTarget targetPriority is 1 to 255 (R-NESTED-ENCODE-089)", out)?;
        }
        if let Some(c) = self.confidence {
            uint_field(
                ctx,
                &VTARGET,
                5,
                u64::from(c),
                "VTarget targetConfidenceLevel is 0 to 100 (R-NESTED-ENCODE-090)",
                out,
            )?;
        }
        if let Some(h) = self.history {
            uint_field(ctx, &VTARGET, 6, u64::from(h), "VTarget targetHistory is 0 to 65535 (R-NESTED-ENCODE-091)", out)?;
        }
        if let Some(p) = self.percentage_pixels {
            uint_field(
                ctx,
                &VTARGET,
                7,
                u64::from(p),
                "VTarget percentageOfTargetPixels is 1 to 100 (R-NESTED-ENCODE-092)",
                out,
            )?;
        }
        if let Some(rgb) = self.color {
            // R-NESTED-ENCODE-093: exactly 3 bytes, never shortened.
            put_tlv(out, 8, &rgb);
        }
        if let Some(i) = self.intensity {
            uint_field(
                ctx,
                &VTARGET,
                9,
                u64::from(i),
                "VTarget targetIntensity is 0 to 2^24 - 1 (R-NESTED-ENCODE-094)",
                out,
            )?;
        }
        // R-NESTED-ENCODE-095, D-14: 3-byte offsets.
        if let Some((lat, lon)) = self.location_offset {
            imap_field(ctx, &VTARGET, 10, lat, 3, out)?;
            imap_field(ctx, &VTARGET, 11, lon, 3, out)?;
        }
        if let Some(h) = self.hae {
            // R-NESTED-ENCODE-096: 2 bytes.
            imap_field(ctx, &VTARGET, 12, h, 2, out)?;
        }
        if let Some(corners) = self.bounding_box_offsets {
            for (tag, x) in (13u8..).zip(corners) {
                imap_field(ctx, &VTARGET, tag, x, 3, out)?;
            }
        }
        if let Some(l) = &self.location {
            let mut v = Vec::new();
            l.write(ctx, &mut v)?;
            put_tlv(out, 17, &v);
        }
        if !self.contour.is_empty() {
            boundary_item(ctx, 18, &self.contour, out)?;
        }
        if let Some((row, col)) = self.centroid_row_col {
            let why = "VTarget centroidPixRow and centroidPixCol are 1 to 2^32 - 1 (R-NESTED-ENCODE-098)";
            let (row, col) = (u64::from(row), u64::from(col));
            if scope.height.map_or(false, |h| row > h) || scope.width.map_or(false, |w| col > w) {
                return Err(ctx.err(
                    ErrorKind::OutOfRange,
                    "VTarget centroid row or column outside the frame (R-NESTED-ENCODE-098)",
                ));
            }
            uint_field(ctx, &VTARGET, 19, row, why, out)?;
            uint_field(ctx, &VTARGET, 20, col, why, out)?;
        }
        if let Some(a) = self.algorithm_id {
            reference(
                ctx,
                scope.algorithms,
                u64::from(a),
                "VTarget algorithmId is not in the algorithmSeries (R-NESTED-ENCODE-100, D-25)",
            )?;
            uint_field(ctx, &VTARGET, 22, u64::from(a), "VTarget algorithmId is 0 to 2^24 - 1 (R-NESTED-ENCODE-100)", out)?;
        }
        if let Some(s) = self.status {
            put_tlv(out, 23, &[s.code()]);
        }
        if let Some(m) = &self.mask {
            let mut v = Vec::new();
            m.write(ctx, scope, &mut v)?;
            put_tlv(out, 101, &v);
        }
        if let Some(t) = &self.tracker {
            let mut v = Vec::new();
            t.write(ctx, scope, self.location.is_some(), &mut v)?;
            put_tlv(out, 104, &v);
        }
        // R-NESTED-ENCODE-103, D-21: one chip in 105, several in 106.
        match self.chips.as_slice() {
            [] => {}
            [chip] => {
                let mut v = Vec::new();
                chip.write(ctx, &mut v)?;
                put_tlv(out, 105, &v);
            }
            chips => series_item(ctx, 106, chips, |c, ctx, e| c.write(ctx, e), out)?,
        }
        if !self.objects.is_empty() {
            series_item(ctx, 107, &self.objects, |o, ctx, e| o.write(ctx, scope, e), out)?;
        }
        // R-NESTED-ENCODE-081.
        if out.len() == start {
            return Err(ctx.err(
                ErrorKind::Missing,
                "a VTarget Pack needs at least one item after its targetId (R-NESTED-ENCODE-081)",
            ));
        }
        Ok(())
    }
}

impl VMask {
    fn write(&self, ctx: &mut Ctx<'_>, scope: &Scope<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // D-23: no empty set.
        if self.contour.is_empty() && self.bit_mask.is_empty() {
            return Err(ctx.err(ErrorKind::Missing, "an empty VMask is not written (D-23)"));
        }
        if !self.contour.is_empty() {
            // R-NESTED-ENCODE-120: three or more points, each a pixel of
            // the frame (ST 0903.5-100), clockwise (ST 0903.4-40).
            if self.contour.len() < 3 {
                return Err(ctx.err(
                    ErrorKind::Missing,
                    "a VMask pixelContour has at least three points (R-NESTED-ENCODE-120)",
                ));
            }
            entries(ctx, self.contour.len())?;
            let mut v = Vec::new();
            let mut p = Vec::new();
            for &point in &self.contour {
                pixel(
                    ctx,
                    scope,
                    point,
                    "a VMask pixelContour point is a pixel number of the frame (R-NESTED-ENCODE-120)",
                )?;
                p.clear();
                put_uint(ctx, PIXEL, point, "a VMask pixelContour point is 1 to 2^48 - 1 (R-NESTED-ENCODE-120)", &mut p)?;
                put_prefixed(&mut v, &p);
            }
            if let Some(w) = scope.width {
                if shoelace(&self.contour, w) < 0 {
                    return Err(ctx.err(
                        ErrorKind::OutOfRange,
                        "a VMask pixelContour lists its points clockwise (R-NESTED-ENCODE-120)",
                    ));
                }
            }
            put_tlv(out, 1, &v);
        }
        if !self.bit_mask.is_empty() {
            entries(ctx, self.bit_mask.len())?;
            let mut v = Vec::new();
            let mut e = Vec::new();
            let mut p = Vec::new();
            for r in &self.bit_mask {
                let why = "a VMask pixel run starts at a pixel number of the frame (R-NESTED-ENCODE-121)";
                pixel(ctx, scope, r.pixel, why)?;
                // D-24: at least one pixel, and the run stays in its row.
                if r.run == 0 {
                    return Err(ctx.err(ErrorKind::OutOfRange, "a VMask pixel run has at least one pixel (D-24)"));
                }
                if let Some(w) = scope.width {
                    let (_, col) = row_col(r.pixel, w);
                    if col.checked_add(r.run - 1).map_or(true, |end| end > w) {
                        return Err(ctx.err(
                            ErrorKind::OutOfRange,
                            "a VMask pixel run passes the end of its row (R-NESTED-ENCODE-121, D-24)",
                        ));
                    }
                }
                // R-NESTED-ENCODE-121: [L][pixel][run as a BER length].
                p.clear();
                put_uint(ctx, PIXEL, r.pixel, why, &mut p)?;
                e.clear();
                put_prefixed(&mut e, &p);
                put_len(&mut e, usize::try_from(r.run).map_err(|_| ctx.err(ErrorKind::OutOfRange, "pixel run too long"))?);
                put_prefixed(&mut v, &e);
            }
            put_tlv(out, 2, &v);
        }
        Ok(())
    }
}

impl VFeature {
    fn write(&self, ctx: &mut Ctx<'_>, scope: &Scope<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        labelled(ctx, scope, &VFEATURE, self.ontology_id, self.confidence, self.confidence_precision, out)
    }
}

impl VObject {
    fn write(&self, ctx: &mut Ctx<'_>, scope: &Scope<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        labelled(ctx, scope, &VOBJECT, self.ontology_id, self.confidence, self.confidence_precision, out)?;
        if !self.features.is_empty() {
            series_item(ctx, 5, &self.features, |f, ctx, e| f.write(ctx, scope, e), out)?;
        }
        Ok(())
    }
}

/// Items 3 (ontologyId) and 4 (confidence) of a VObject or VFeature
/// (R-NESTED-ENCODE-122 to -124, D-14, D-22, D-25).
fn labelled(
    ctx: &mut Ctx<'_>,
    scope: &Scope<'_>,
    def: &SetDef,
    ontology_id: u64,
    confidence: Imap,
    precision: f64,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    reference(
        ctx,
        scope.ontologies,
        ontology_id,
        "VObject and VFeature ontologyId must be in the ontologySeries (R-NESTED-ENCODE-122, -123, D-25)",
    )?;
    uint_field(ctx, def, 3, ontology_id, "ontologyId is a uint V8", out)?;
    let len = confidence_len(ctx, precision)?;
    imap_field(ctx, def, 4, confidence, len, out)
}

/// IMAPB length of a VObject or VFeature confidence for precision `g`
/// percent: ST 1201.5 IMAPA (R-NESTED-ENCODE-143), 1 to 3 bytes (D-14).
fn confidence_len(ctx: &Ctx<'_>, g: f64) -> Result<usize, EncodeError> {
    match imapa_len(0.0, 100.0, g) {
        Some(n @ 1..=3) => Ok(n),
        _ => Err(ctx.err(ErrorKind::OutOfRange, "confidence precision must give an IMAPB length of 1 to 3 bytes (D-14)")),
    }
}

/// ST 1201.5 section 7.1.1 IMAPA length for range `[a, b]` and precision
/// `g`: `Lbits = ceil(log2(b - a)) - floor(log2(g)) + 1`, `L = ceil(Lbits /
/// 8)`, at least 1, with exact exponents (R-NESTED-ENCODE-143, D-27).
fn imapa_len(a: f64, b: f64, g: f64) -> Option<usize> {
    let span = b - a;
    if !(span.is_finite() && span > 0.0 && g.is_finite() && g > 0.0) {
        return None;
    }
    let bits = ceil_log2(span) - floor_log2(g) + 1;
    Some(if bits <= 0 { 1 } else { ((bits + 7) / 8) as usize })
}

/// floor(log2(v)) for finite `v > 0`, from the bits of `v` (D-27).
fn floor_log2(v: f64) -> i32 {
    let bits = v.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if exp == 0 {
        -1074 + (63 - frac.leading_zeros() as i32)
    } else {
        exp - 1023
    }
}

/// ceil(log2(v)) for finite `v > 0`, from the bits of `v` (D-27).
fn ceil_log2(v: f64) -> i32 {
    let bits = v.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    let exact = if exp == 0 { frac.is_power_of_two() } else { frac == 0 };
    floor_log2(v) + i32::from(!exact)
}

impl VTracker {
    fn write(
        &self,
        ctx: &mut Ctx<'_>,
        scope: &Scope<'_>,
        target_location: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let start = out.len();
        if let Some(id) = &self.track_id {
            // R-NESTED-ENCODE-125: 16-byte UUID.
            put_tlv(out, 1, id);
        }
        if let (Some(first), Some(latest)) = (self.first_observation, self.latest_observation) {
            if first > latest {
                return Err(ctx.err(ErrorKind::OutOfRange, "VTracker firstObsvTime is after latestObsvTime (D-37)"));
            }
        }
        // R-NESTED-ENCODE-055: 8-byte MISP times.
        if let Some(t) = self.first_observation {
            put_tlv(out, 3, &t.as_micros().to_be_bytes());
        }
        if let Some(t) = self.latest_observation {
            put_tlv(out, 4, &t.as_micros().to_be_bytes());
        }
        if !self.boundary.is_empty() {
            boundary_item(ctx, 5, &self.boundary, out)?;
        }
        if let Some(c) = self.confidence {
            uint_field(ctx, &VTRACKER, 7, u64::from(c), "VTracker confidenceLevel is 0 to 100 (R-NESTED-ENCODE-125)", out)?;
        }
        if !self.history.is_empty() {
            // ST 0903.4-56: chronological, as given.
            series_item(ctx, 9, &self.history, |l, ctx, e| l.write(ctx, e), out)?;
        }
        // D-19: an associated location for velocity and acceleration.
        if (self.velocity.is_some() || self.acceleration.is_some()) && !target_location && self.history.is_empty() {
            return Err(ctx.err(
                ErrorKind::Missing,
                "VTracker velocity and acceleration need a targetLocation or a trackHistorySeries (R-NESTED-ENCODE-112, -113, D-19)",
            ));
        }
        for (tag, m) in [(10u8, &self.velocity), (11, &self.acceleration)] {
            if let Some(m) = m {
                let mut v = Vec::new();
                m.write(ctx, &mut v)?;
                put_tlv(out, tag, &v);
            }
        }
        if let Some(a) = self.algorithm_id {
            reference(
                ctx,
                scope.algorithms,
                a,
                "VTracker algorithmId is not in the algorithmSeries (R-NESTED-ENCODE-125, D-25)",
            )?;
            uint_field(ctx, &VTRACKER, 12, a, "VTracker algorithmId is a uint V8", out)?;
        }
        if out.len() == start {
            return Err(ctx.err(ErrorKind::Missing, "an empty VTracker is not written (D-23)"));
        }
        Ok(())
    }
}

impl VChip {
    fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // R-NESTED-ENCODE-126: imageType in every VChip, "jpeg" or "png".
        put_tlv(out, 1, self.image_type.as_str().as_bytes());
        // D-21: a chip carries an image one way or the other.
        if self.iri.is_none() && self.image.is_none() {
            return Err(ctx.err(ErrorKind::Missing, "a VChip needs imageIRI or embeddedImage (D-21)"));
        }
        if let Some(iri) = &self.iri {
            iri_check(ctx, iri, "VChip imageIRI must be an absolute IRI (D-21)")?;
            text_field(ctx, &VCHIP, 2, iri, out)?;
        }
        if let Some(image) = &self.image {
            if image.is_empty() {
                return Err(ctx.err(ErrorKind::Missing, "VChip embeddedImage is empty (D-23)"));
            }
            if !image.starts_with(self.image_type.signature()) {
                let reason = "VChip embeddedImage does not start with the signature of its imageType (R-NESTED-ENCODE-126, D-21)";
                if ctx.strict() {
                    return Err(ctx.err(ErrorKind::WrongType, reason));
                }
                ctx.warn(reason);
            }
            put_tlv(out, 3, image);
        }
        Ok(())
    }
}

impl Algorithm {
    fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // R-NESTED-ENCODE-127: items 1 to 3 in every instance.
        uint_field(ctx, &ALGORITHM, 1, self.id, "algorithmId is a uint V8", out)?;
        required_text(
            ctx,
            &ALGORITHM,
            2,
            &self.name,
            "Algorithm name is required and not empty (R-NESTED-ENCODE-127)",
            out,
        )?;
        required_text(
            ctx,
            &ALGORITHM,
            3,
            &self.version,
            "Algorithm version is required and not empty (R-NESTED-ENCODE-127)",
            out,
        )?;
        if let Some(class) = &self.class {
            text_field(ctx, &ALGORITHM, 4, class, out)?;
        }
        if let Some(n) = self.frames {
            uint_field(ctx, &ALGORITHM, 5, n, "nFrames is a uint V8", out)?;
        }
        Ok(())
    }
}

impl Ontology {
    fn write(&self, ctx: &mut Ctx<'_>, scope: &Scope<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // R-NESTED-ENCODE-128, -131: items 1, 3 and 4 in every instance.
        uint_field(ctx, &ONTOLOGY, 1, self.id, "ontologyId is a uint V8", out)?;
        if let Some(parent) = self.parent_id {
            // R-NESTED-ENCODE-129, D-25.
            ctx.warn("Ontology parentId is discouraged since ST 0903.6 (R-NESTED-ENCODE-129)");
            if parent == self.id {
                return Err(ctx.err(
                    ErrorKind::InvalidCode,
                    "Ontology parentId names its own element (R-NESTED-ENCODE-129)",
                ));
            }
            reference(
                ctx,
                scope.ontologies,
                parent,
                "Ontology parentId is not in the ontologySeries (R-NESTED-ENCODE-129, D-25)",
            )?;
            uint_field(ctx, &ONTOLOGY, 2, parent, "parentId is a uint V8", out)?;
        }
        let iri = "Ontology IRIs must be absolute IRIs (R-NESTED-ENCODE-128)";
        iri_check(ctx, &self.ontology_iri, iri)?;
        required_text(
            ctx,
            &ONTOLOGY,
            3,
            &self.ontology_iri,
            "Ontology ontologyIRI is required (R-NESTED-ENCODE-128)",
            out,
        )?;
        iri_check(ctx, &self.entity_iri, iri)?;
        required_text(ctx, &ONTOLOGY, 4, &self.entity_iri, "Ontology entityIRI is required (R-NESTED-ENCODE-128)", out)?;
        if let Some(v) = &self.version_iri {
            iri_check(ctx, v, iri)?;
            text_field(ctx, &ONTOLOGY, 5, v, out)?;
        }
        if let Some(label) = &self.label {
            text_field(ctx, &ONTOLOGY, 6, label, out)?;
        }
        Ok(())
    }
}

// ----------------------------------------------------------- builder parts

/// The kind of item `tag` in the decoder's table `def`.
fn kind_of(ctx: &Ctx<'_>, def: &SetDef, tag: u8) -> Result<Kind, EncodeError> {
    def.fields
        .iter()
        .find(|f| f.tag == tag)
        .map(|f| f.kind)
        .ok_or_else(|| ctx.err(ErrorKind::UnknownTag, "tag not in the ST 0903.6 table"))
}

/// One item of a set: tag, BER length, value. The VTarget Pack and every
/// set inside it use one-byte tags (R-NESTED-ENCODE-050, -084); every tag
/// of the VMTI LS is below 128, so its BER-OID tag is one byte too.
fn put_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    put_prefixed(out, value);
}

/// An integer of `kind` from the decoder's table, range checked
/// (R-NESTED-ENCODE-013 to -015, -070).
fn put_uint(ctx: &Ctx<'_>, kind: Kind, n: u64, why: &'static str, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match kind {
        Kind::UintV { max_len, min } => {
            if n < min || (max_len < 8 && n >> (8 * max_len) != 0) {
                return Err(ctx.err(ErrorKind::OutOfRange, why));
            }
            put_uint_min(out, n);
        }
        Kind::Uint8 { min, max, .. } => {
            if n < u64::from(min) || n > u64::from(max) {
                return Err(ctx.err(ErrorKind::OutOfRange, why));
            }
            out.push(n as u8);
        }
        Kind::Checksum => {
            let v = u16::try_from(n).map_err(|_| ctx.err(ErrorKind::OutOfRange, why))?;
            out.extend_from_slice(&v.to_be_bytes());
        }
        Kind::Time => put_uint_n(out, n, 8),
        _ => return Err(ctx.err(ErrorKind::WrongType, "not an integer item")),
    }
    Ok(())
}

/// An integer item: tag, BER length, the integer of `kind`.
fn uint_item(
    ctx: &Ctx<'_>,
    kind: Kind,
    tag: u8,
    n: u64,
    why: &'static str,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let mut v = Vec::with_capacity(8);
    put_uint(ctx, kind, n, why, &mut v)?;
    put_tlv(out, tag, &v);
    Ok(())
}

/// An integer item of set `def` (its kind from the decoder's table).
fn uint_field(
    ctx: &Ctx<'_>,
    def: &SetDef,
    tag: u8,
    n: u64,
    why: &'static str,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let kind = kind_of(ctx, def, tag)?;
    uint_item(ctx, kind, tag, n, why, out)
}

/// An IMAPB item of set `def` in `len` bytes.
fn imap_field(
    ctx: &mut Ctx<'_>,
    def: &SetDef,
    tag: u8,
    x: Imap,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let kind = kind_of(ctx, def, tag)?;
    imap_item(ctx, kind, tag, x, len, out)
}

/// A text item of set `def`.
fn text_field(ctx: &mut Ctx<'_>, def: &SetDef, tag: u8, s: &str, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let kind = kind_of(ctx, def, tag)?;
    text_item(ctx, kind, tag, s, out)
}

/// A pixel number of the frame: 1 to 2^48 - 1 (R-NESTED-ENCODE-087) and,
/// when the frame size is known, at most width x height (ST 0903.5-100,
/// R-NESTED-ENCODE-120, applied to every pixel number).
fn pixel(ctx: &Ctx<'_>, scope: &Scope<'_>, p: u64, why: &'static str) -> Result<(), EncodeError> {
    let inside = match (scope.width, scope.height) {
        (Some(w), Some(h)) => p <= w.saturating_mul(h),
        _ => true,
    };
    if (1..=MAX_PIXEL).contains(&p) && inside {
        Ok(())
    } else {
        Err(ctx.err(ErrorKind::OutOfRange, why))
    }
}

/// Row and column of pixel number `p` in a frame `w` pixels wide, counting
/// from 1 (R-NESTED-ENCODE-075); `p` and `w` are at least 1.
fn row_col(p: u64, w: u64) -> (u64, u64) {
    let w = w.max(1);
    let i = p.saturating_sub(1);
    (i / w + 1, i % w + 1)
}

/// Twice the signed area of a pixel polygon in image coordinates (rows
/// grow downwards): positive for clockwise, negative for counter-clockwise
/// (ST 0903.4-40), zero when degenerate.
fn shoelace(points: &[u64], w: u64) -> i128 {
    let n = points.len();
    let mut sum = 0i128;
    for (i, &p) in points.iter().enumerate() {
        let q = points[(i + 1) % n];
        let (r0, c0) = row_col(p, w);
        let (r1, c1) = row_col(q, w);
        sum += i128::from(c0) * i128::from(r1) - i128::from(c1) * i128::from(r0);
    }
    sum
}

/// A reference to an algorithm or ontology id of the same VMTI LS (D-25).
fn reference(ctx: &Ctx<'_>, ids: &[u64], id: u64, why: &'static str) -> Result<(), EncodeError> {
    if ids.binary_search(&id).is_ok() {
        Ok(())
    } else {
        Err(ctx.err(ErrorKind::Missing, why))
    }
}

/// A Series or Array must stay within what a decoder reads (D-26).
fn entries(ctx: &Ctx<'_>, n: usize) -> Result<(), EncodeError> {
    if n > max_entries() {
        return Err(ctx.err(ErrorKind::TooLarge, "more series elements than a decoder reads (D-26)"));
    }
    Ok(())
}

/// A Series item: each element preceded by its BER length
/// (R-NESTED-ENCODE-068).
fn series_item<T>(
    ctx: &mut Ctx<'_>,
    tag: u8,
    elements: &[T],
    mut write: impl FnMut(&T, &mut Ctx<'_>, &mut Vec<u8>) -> Result<(), EncodeError>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    entries(ctx, elements.len())?;
    let mut v = Vec::new();
    let mut e = Vec::new();
    for x in elements {
        e.clear();
        write(x, ctx, &mut e)?;
        put_prefixed(&mut v, &e);
    }
    put_tlv(out, tag, &v);
    Ok(())
}

/// A BoundarySeries (VTarget 18, VTracker 5): at least two vertices; two
/// are opposite corners of a latitude-longitude aligned box
/// (R-NESTED-ENCODE-114).
fn boundary_item(ctx: &mut Ctx<'_>, tag: u8, vertices: &[Location], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if vertices.len() < 2 {
        return Err(ctx.err(ErrorKind::Missing, "a BoundarySeries has at least two vertices (R-NESTED-ENCODE-114)"));
    }
    if let [a, b] = vertices {
        if let (Some((lat0, lon0)), Some((lat1, lon1))) = (a.lat_lon(), b.lat_lon()) {
            if lat0 == lat1 || lon0 == lon1 {
                let reason = "the two vertices of a BoundarySeries are opposite corners of a box (R-NESTED-ENCODE-114)";
                if ctx.strict() {
                    return Err(ctx.err(ErrorKind::OutOfRange, reason));
                }
                ctx.warn(reason);
            }
        }
    }
    series_item(ctx, tag, vertices, |l, ctx, e| l.write(ctx, e), out)
}

/// The groups of a Location or Velocity/Acceleration pack
/// (R-NESTED-ENCODE-110, -111): the triplet, then the standard deviations,
/// then the correlation coefficients, which need the standard deviations.
fn put_groups(
    ctx: &mut Ctx<'_>,
    table: &[PackField; 9],
    first: [Imap; 3],
    sigma: Option<[Imap; 3]>,
    rho: Option<[Imap; 3]>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if rho.is_some() && sigma.is_none() {
        return Err(ctx.err(
            ErrorKind::Missing,
            "correlation coefficients are only sent with the standard deviations (R-NESTED-ENCODE-110, -111)",
        ));
    }
    let values = first.iter().chain(sigma.iter().flatten()).chain(rho.iter().flatten());
    for (pf, &x) in table.iter().zip(values) {
        put_imap(ctx, pf.min, pf.max, pf.len, x, out)?;
    }
    Ok(())
}

/// An IMAPB item of `kind` from the decoder's table in `len` bytes.
fn imap_item(
    ctx: &mut Ctx<'_>,
    kind: Kind,
    tag: u8,
    x: Imap,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let Kind::Imapb { min, max, max_len } = kind else {
        return Err(ctx.err(ErrorKind::WrongType, "not an IMAPB item"));
    };
    if !(1..=max_len).contains(&len) {
        return Err(ctx.err(ErrorKind::OutOfRange, "IMAPB length outside the item's limits"));
    }
    let mut v = Vec::with_capacity(len);
    put_imap(ctx, min, max, len, x, &mut v)?;
    put_tlv(out, tag, &v);
    Ok(())
}

/// A text item of `kind` (its character limit from the decoder's table).
fn text_item(ctx: &mut Ctx<'_>, kind: Kind, tag: u8, s: &str, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let Kind::Text(limit) = kind else {
        return Err(ctx.err(ErrorKind::WrongType, "not a text item"));
    };
    let mut v = Vec::with_capacity(s.len().max(1));
    put_utf8(ctx, s, limit.map(|(n, _)| n), &mut v)?;
    put_tlv(out, tag, &v);
    Ok(())
}

/// A required text item: never empty (R-NESTED-ENCODE-017).
fn required_text(
    ctx: &mut Ctx<'_>,
    def: &SetDef,
    tag: u8,
    s: &str,
    why: &'static str,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if s.trim_matches(is_trimmed).is_empty() {
        return Err(ctx.err(ErrorKind::Missing, why));
    }
    text_field(ctx, def, tag, s, out)
}

/// An absolute IRI (RFC 3987): a scheme, `:`, something after it, and no
/// blanks or control characters (D-21). An error when strict, a warning
/// otherwise.
fn iri_check(ctx: &mut Ctx<'_>, s: &str, why: &'static str) -> Result<(), EncodeError> {
    let ok = match s.split_once(':') {
        Some((scheme, rest)) => {
            let mut c = scheme.chars();
            c.next().map_or(false, |f| f.is_ascii_alphabetic())
                && c.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
                && !rest.is_empty()
                && !s.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        }
        None => false,
    };
    if !ok {
        if ctx.strict() {
            return Err(ctx.err(ErrorKind::WrongType, why));
        }
        ctx.warn(why);
    }
    Ok(())
}

// ------------------------------------------------------------ leaf writers

/// Characters ST 0107 removes from text (R-NESTED-ENCODE-021).
fn is_removed(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}')
}

/// Characters ST 0107 trims from both ends of text (R-NESTED-ENCODE-020).
fn is_trimmed(c: char) -> bool {
    matches!(c, '\u{0}' | '\t' | '\n' | '\r' | ' ')
}

/// UTF-8 text per MISB ST 0107.4 section 6.3.3 (R-NESTED-ENCODE-019 to
/// -021, D-32): the empty string is the single byte `00` (a decoded `"\0"`
/// is that empty string, DECISIONS P-1); control characters and
/// surrounding blanks are an error when strict and removed with a warning
/// otherwise; at most `max_chars` characters (R-NESTED-ENCODE-057, -064).
fn put_utf8(ctx: &mut Ctx<'_>, s: &str, max_chars: Option<usize>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if s.is_empty() || s == "\0" {
        out.push(0);
        return Ok(());
    }
    let mut cleaned: std::borrow::Cow<'_, str> = s.into();
    if s.chars().any(is_removed) || s.starts_with(is_trimmed) || s.ends_with(is_trimmed) {
        let reason = "text has control characters or leading or trailing blanks (R-NESTED-ENCODE-020, -021, D-32)";
        if ctx.strict() {
            return Err(ctx.err(ErrorKind::WrongType, reason));
        }
        ctx.warn("control characters or surrounding blanks removed from text (D-32)");
        let kept: String = s.chars().filter(|&c| !is_removed(c)).collect();
        cleaned = kept.trim_matches(is_trimmed).to_string().into();
    }
    if ctx.opts.ascii_only && !cleaned.is_ascii() {
        return Err(ctx.err(ErrorKind::WrongType, "text is not ASCII and ascii_only is set"));
    }
    if let Some(max) = max_chars {
        if let Some((cut, _)) = cleaned.char_indices().nth(max) {
            if ctx.strict() {
                return Err(ctx.err(
                    ErrorKind::TooLong,
                    "text has more characters than the item allows (R-NESTED-ENCODE-014)",
                ));
            }
            ctx.warn("text cut to the item's maximum number of characters");
            cleaned = cleaned[..cut].to_string().into();
        }
    }
    if cleaned.is_empty() {
        out.push(0);
    } else {
        out.extend_from_slice(cleaned.as_bytes());
    }
    Ok(())
}

/// An ST 1201 special pattern: the first byte, the other L - 1 bytes `00`
/// (R-NESTED-ENCODE-145, -073).
fn pattern(out: &mut Vec<u8>, first: u8, len: usize) {
    out.push(first);
    out.extend(std::iter::repeat(0).take(len.saturating_sub(1)));
}

/// ST 1201 IMAPB(`min`, `max`) of `x` in `len` bytes (ST 1201.5 section
/// 7.2.1, R-NESTED-ENCODE-140 to -150; ST 0903.6 section 9.1.1 for the
/// signals; D-15, D-16).
fn put_imap(ctx: &mut Ctx<'_>, min: f64, max: f64, len: usize, x: Imap, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let map = Imapb::new(min, max, len).ok_or_else(|| ctx.err(ErrorKind::OutOfRange, "IMAPB length must be 1 to 8 bytes"))?;
    let x = match x {
        Imap::BelowMinimum => 0xE0,
        Imap::AboveMaximum => 0xE1,
        Imap::Invalid => 0xC1,
        Imap::Special(s) => return put_special(ctx, s, len, out),
        Imap::Value(x) => {
            return put_number(ctx, &map, x, out);
        }
    };
    pattern(out, x, len);
    Ok(())
}

/// [`put_imap`] for a number.
fn put_number(ctx: &mut Ctx<'_>, map: &Imapb, x: f64, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let (min, max, len) = (map.min(), map.max(), map.byte_len());
    if !x.is_finite() {
        // R-NESTED-ENCODE-144, D-15, D-16: +inf C8, -inf E8, any NaN D0.
        let reason = "NaN and infinity are only sent as their ST 1201 patterns under Policy::Clamp or with Imap::Special (D-15)";
        if ctx.strict() {
            return Err(ctx.err(ErrorKind::NotFinite, reason));
        }
        ctx.warn("NaN or infinity sent as its ST 1201 special pattern (D-15, D-16)");
        let first = if x.is_nan() {
            0xD0
        } else if x > 0.0 {
            0xC8
        } else {
            0xE8
        };
        pattern(out, first, len);
        return Ok(());
    }
    // R-NESTED-ENCODE-147: -0.0 is +0.0.
    let x = if x == 0.0 { 0.0 } else { x };
    // The value the code 0 stands for is a little below `min` when the
    // range spans zero (ST 1201.5 section 7.1.2 step 6); it is in range.
    let lowest = map.int_to_real(0).min(min);
    if x < lowest || x > max {
        // R-NESTED-ENCODE-072, -146, D-15: never clamped.
        if ctx.strict() {
            return Err(ctx.err(
                ErrorKind::OutOfRange,
                "value outside the item's IMAPB range: use Imap::BelowMinimum or Imap::AboveMaximum, or Policy::Clamp (D-15)",
            ));
        }
        ctx.warn("value outside the IMAPB range sent as IMAP_BELOW_MINIMUM or IMAP_ABOVE_MAXIMUM (R-NESTED-ENCODE-072)");
        pattern(out, if x < lowest { 0xE0 } else { 0xE1 }, len);
        return Ok(());
    }
    put_uint_n(out, forward(map, x), len);
    Ok(())
}

/// The ST 1201.5 forward mapping `floor(sF * (x - a) + Zoffset)` (section
/// 7.2.1, R-NESTED-ENCODE-140, -150, D-28) for `x` between the value of
/// code 0 and `max`, made exact against the decoder's reverse mapping: the
/// largest code whose value is not above `x`, so decode(encode(x)) is in
/// (x - 1 LSB, x] and every decoded value encodes back to its own code.
fn forward(map: &Imapb, x: f64) -> u64 {
    let top = map.real_to_int(map.max()).unwrap_or(0);
    let mut y = map.real_to_int(x.max(map.min()).min(map.max())).unwrap_or(0);
    // f64 rounding moves the formula by at most one code either way.
    for _ in 0..2 {
        if y > 0 && map.int_to_real(y) > x {
            y -= 1;
        }
    }
    for _ in 0..2 {
        if y < top && map.int_to_real(y + 1) <= x {
            y += 1;
        }
    }
    y
}

/// An explicit ST 1201.5 special pattern (Tables 2 and 3,
/// R-NESTED-ENCODE-144, -145): the kind bits in the first byte, the
/// identifier in the remaining 3 + 8 (L - 1) bits.
fn put_special(ctx: &Ctx<'_>, s: Special, len: usize, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let (first, id) = match s {
        Special::PositiveInfinity => (0xC8u8, 0u64),
        Special::NegativeInfinity => (0xE8, 0),
        Special::PositiveQuietNan(id) => (0xD0, id),
        Special::NegativeQuietNan(id) => (0xF0, id),
        Special::PositiveSignalingNan(id) => (0xD8, id),
        Special::NegativeSignalingNan(id) => (0xF8, id),
        Special::UserDefined(id) => (0xC0, id),
        Special::BelowMinimum => (0xE0, 0),
        Special::AboveMaximum => (0xE1, 0),
        _ => {
            return Err(ctx.err(
                ErrorKind::InvalidCode,
                "MISB-defined and reserved IMAPB patterns are never written (ST 1201.5 Table 2)",
            ))
        }
    };
    let bits = 3 + 8 * len.saturating_sub(1);
    if !(1..=8).contains(&len) || (bits < 64 && id >> bits != 0) {
        return Err(ctx.err(ErrorKind::OutOfRange, "IMAPB special value identifier does not fit the item's length"));
    }
    let v = (u128::from(first) << (8 * (len - 1))) | u128::from(id);
    out.extend_from_slice(&v.to_be_bytes()[16 - len..]);
    Ok(())
}

/// Nominal IMAPB length of an ST 0903 item, by its range (ST 0903.6
/// Tables 9, 10, 12 and 13; D-14): 3 bytes for the offsets, 2 for the
/// fields of view, the height and the confidence.
fn nominal_len(min: f64, max: f64) -> usize {
    if min == -19.2 && max == 19.2 {
        3
    } else {
        2
    }
}

// ------------------------------------------------------- decoded VMTI sets

/// Write the items of a decoded VMTI set (no key, length or checksum item,
/// R-NESTED-ENCODE-001, -052) into `out`.
///
/// Items are written in the set's order (D-33). An item whose recorded
/// bytes still decode to its value is copied; otherwise it is encoded from
/// its value, reusing the recorded bytes of every unchanged part
/// (DECISIONS P-2: IMAPB signals, which all decode to `OutOfRange`, survive
/// that way). Rules between items are not enforced here but reported as
/// warnings; the builder enforces them.
pub(crate) fn encode_set(set: &Packet, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if set.standard != Standard::St0903 {
        return Err(ctx.err(ErrorKind::WrongType, "not an ST 0903 set"));
    }
    if set.items.len() > max_entries() {
        return Err(ctx.err(ErrorKind::TooLarge, "more items than a decoder reads (D-26)"));
    }
    let cfg = Config::default();
    for (i, item) in set.items.iter().enumerate() {
        ctx.within(Standard::St0903, item.tag, |ctx| {
            match item.tag {
                // R-NESTED-ENCODE-002, -052: never inside tag 74.
                1 => {
                    ctx.warn("checksum item 1 left out of the nested VMTI set (R-NESTED-ENCODE-052)");
                    return Ok(());
                }
                2 if i > 0 => ctx.warn("item 2 is not the first item of the VMTI set (R-NESTED-ENCODE-054)"),
                _ => {}
            }
            // VMTI LS items sit at level 1, below ST 0601. Empty recorded
            // bytes count too: a zero-length item decodes to `Unknown`, or
            // to `Invalid` for a mandatory item, and is passed through.
            let raw_ok = same_value(&super::decode_item(item.tag, &item.raw, 1, &cfg).value, &item.value);
            if raw_ok {
                put_item_oid(out, item.tag, &item.raw);
                return Ok(());
            }
            encode_item(item.tag, &item.value, (!item.raw.is_empty()).then_some(&item.raw[..]), &cfg, ctx, out)
        })?;
    }
    ctx.within(Standard::St0903, 4, |ctx| {
        if set.get(Tag::VersionNumber).is_none() {
            ctx.warn("the VMTI set has no version number, item 4 (R-NESTED-ENCODE-058)");
        }
    });
    ctx.within(Standard::St0903, 6, |ctx| {
        if set.get(Tag::NumberOfReportedTargets).is_none() {
            ctx.warn("the VMTI set has no numTargetsReported, item 6 (R-NESTED-ENCODE-060)");
        }
    });
    Ok(())
}

/// An item of the VMTI LS: BER-OID tag, BER length, value.
fn put_item_oid(out: &mut Vec<u8>, tag: u64, value: &[u8]) {
    put_oid(out, tag);
    put_prefixed(out, value);
}

/// One VMTI LS item from its value, `hint` its recorded bytes.
fn encode_item(
    tag: u64,
    v: &Value,
    hint: Option<&[u8]>,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let Some(t) = Tag::from_u64(tag) else {
        // An unknown tag is kept as its bytes (ST 0107).
        return match v {
            Value::Bytes(b) => {
                put_item_oid(out, tag, b);
                Ok(())
            }
            Value::Unknown => {
                put_item_oid(out, tag, &[]);
                Ok(())
            }
            _ => Err(ctx.err(ErrorKind::WrongType, "an unknown tag is kept as bytes")),
        };
    };
    if let Value::Unknown = v {
        // A zero-length item, as received; never for the mandatory item 4
        // (R-NESTED-ENCODE-017).
        if !t.zero_length_allowed() {
            return Err(ctx.err(ErrorKind::NotAllowed, "a mandatory item is never zero length (R-NESTED-ENCODE-017)"));
        }
        put_item_oid(out, tag, &[]);
        return Ok(());
    }
    let mut b = Vec::new();
    write_value(t.kind(), v, hint, 1, cfg, ctx, &mut b)?;
    put_item_oid(out, tag, &b);
    Ok(())
}

/// Copy `hint` when `decode(hint)` is `v`.
fn reuse_with(v: &Value, hint: Option<&[u8]>, out: &mut Vec<u8>, decode: impl FnOnce(&[u8]) -> Value) -> bool {
    match hint {
        Some(h) if !h.is_empty() && same_value(&decode(h), v) => {
            out.extend_from_slice(h);
            true
        }
        _ => false,
    }
}

/// A value of `kind` in a set at `level`: its recorded bytes when they
/// still decode to it, else encoded from the value.
fn value_of(
    kind: Kind,
    v: &Value,
    hint: Option<&[u8]>,
    level: usize,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if reuse_with(v, hint, out, |h| decode_value(kind, h, level, cfg)) {
        return Ok(());
    }
    write_value(kind, v, hint, level, cfg, ctx, out)
}

/// A value of `kind` in a set at `level`, encoded from the value with the
/// decoder's table: every value the decoder produces as valid encodes to
/// bytes that decode to it again. `hint` holds the recorded bytes, used for
/// the parts that did not change.
fn write_value(
    kind: Kind,
    v: &Value,
    hint: Option<&[u8]>,
    level: usize,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let wrong = |ctx: &Ctx<'_>| match v {
        Value::Invalid(_) => ctx.err(ErrorKind::WrongType, "an invalid value without its recorded bytes cannot be encoded"),
        Value::Unknown => ctx.err(ErrorKind::WrongType, "an unknown value is only allowed as a whole item"),
        _ => ctx.err(ErrorKind::WrongType, "the value does not have the item's type (ST 0903.6 Tables 9 to 20)"),
    };
    match kind {
        Kind::UintV { .. } | Kind::Uint8 { .. } | Kind::Checksum => {
            if !matches!(v, Value::Uint(_) | Value::Enum { .. }) {
                return Err(wrong(ctx));
            }
            let n = ctx.integer(View::value(v))?;
            put_uint(ctx, kind, n, "integer outside the item's range (ST 0903.6 Tables 9 to 17)", out)
        }
        Kind::Time => match v {
            Value::Time(t) | Value::Uint(t) => {
                put_uint_n(out, *t, 8);
                Ok(())
            }
            _ => Err(wrong(ctx)),
        },
        Kind::Text(limit) => match v {
            Value::Text(s) => put_utf8(ctx, s, limit.map(|(n, _)| n), out),
            _ => Err(wrong(ctx)),
        },
        Kind::Bytes => match v {
            Value::Bytes(b) if !b.is_empty() => {
                out.extend_from_slice(b);
                Ok(())
            }
            _ => Err(wrong(ctx)),
        },
        Kind::Imapb { min, max, max_len } => {
            // The recorded length when there is one (ST 1201.5 section 7.4,
            // R-NESTED-ENCODE-149), else the nominal length (D-14).
            let len = match hint {
                Some(h) if (1..=max_len).contains(&h.len()) => h.len(),
                _ => nominal_len(min, max).min(max_len),
            };
            match v {
                Value::Float(x) => put_imap(ctx, min, max, len, Imap::Value(*x), out),
                Value::OutOfRange => Err(ctx.err(ErrorKind::WrongType, AMBIGUOUS)),
                _ => Err(wrong(ctx)),
            }
        }
        Kind::Enum(labels) => {
            let code = match v {
                Value::Enum { code, .. } | Value::Uint(code) => Some(*code),
                Value::Text(s) => labels.iter().position(|l| *l == s.as_str()).map(|i| i as u64),
                _ => return Err(wrong(ctx)),
            };
            match code {
                // R-NESTED-ENCODE-101: only the codes of the table.
                Some(c) if (c as usize) < labels.len() && c <= 0xFF => {
                    out.push(c as u8);
                    Ok(())
                }
                _ => Err(ctx.err(ErrorKind::InvalidCode, "code not defined by ST 0903.6 (Table 5)")),
            }
        }
        Kind::Color | Kind::Fpa => {
            let Value::Struct(fields) = v else { return Err(wrong(ctx)) };
            let names: &[&str] = if let Kind::Color = kind { &["Red", "Green", "Blue"] } else { &["Row", "Column"] };
            if fields.len() != names.len() {
                return Err(ctx.err(ErrorKind::Missing, "target color is Red, Green, Blue; FPA index is Row, Column"));
            }
            for name in names {
                let n = match field(fields, name) {
                    Some(x @ Value::Uint(_)) => ctx.integer(View::value(x))?,
                    _ => return Err(ctx.err(ErrorKind::Missing, "target color is Red, Green, Blue; FPA index is Row, Column")),
                };
                out.push(u8::try_from(n).map_err(|_| ctx.err(ErrorKind::OutOfRange, "a color or FPA component is 0 to 255"))?);
            }
            Ok(())
        }
        Kind::Uuid => {
            let id = match v {
                Value::Text(s) => parse_uuid(s),
                Value::Bytes(b) => <[u8; 16]>::try_from(b.as_slice()).ok(),
                _ => return Err(wrong(ctx)),
            };
            let id = id.ok_or_else(|| ctx.err(ErrorKind::WrongType, "track ID is a UUID: 32 hex digits or 16 bytes"))?;
            out.extend_from_slice(&id);
            Ok(())
        }
        Kind::Location => write_pack(&LOCATION, &[10, 16, 22], v, hint, level, cfg, ctx, out),
        Kind::Motion => write_pack(&MOTION, &[6, 12, 18], v, hint, level, cfg, ctx, out),
        Kind::LocationSeries => write_series(v, hint, cfg, ctx, out, |e, h, ctx, out| {
            value_of(Kind::Location, e, h, level, cfg, ctx, out)
        }),
        Kind::PixelContour => write_series(v, hint, cfg, ctx, out, |e, h, ctx, out| value_of(PIXEL, e, h, level, cfg, ctx, out)),
        Kind::BitMaskSeries => write_series(v, hint, cfg, ctx, out, |e, h, ctx, out| {
            if reuse_with(e, h, out, super::pixel_run) {
                return Ok(());
            }
            let why = "a pixel run is a struct of Pixel and Run Length";
            let Value::Struct(fields) = e else { return Err(ctx.err(ErrorKind::WrongType, why)) };
            let parts = (field(fields, "Pixel"), field(fields, "Run Length"), fields.len());
            let (Some(Value::Uint(p)), Some(Value::Uint(run)), 2) = parts else {
                return Err(ctx.err(ErrorKind::Missing, why));
            };
            // R-NESTED-ENCODE-121: [L][pixel][run as a BER length].
            let mut b = Vec::with_capacity(8);
            put_uint(ctx, PIXEL, *p, "a pixel number is 1 to 2^48 - 1", &mut b)?;
            put_prefixed(out, &b);
            put_len(out, usize::try_from(*run).map_err(|_| ctx.err(ErrorKind::OutOfRange, "pixel run too long"))?);
            Ok(())
        }),
        Kind::Miis => crate::st1204::encode::encode_value(View::value(v), ctx, out),
        Kind::Set(def) => match v {
            Value::Struct(fields) => write_set(def, fields, hint, level.saturating_add(1), cfg, ctx, out),
            _ => Err(wrong(ctx)),
        },
        // Each element decodes as `Kind::Set(def)` at this level.
        Kind::SetSeries(def) => write_series(v, hint, cfg, ctx, out, |e, h, ctx, out| {
            value_of(Kind::Set(def), e, h, level, cfg, ctx, out)
        }),
        Kind::VTargetSeries => write_series(v, hint, cfg, ctx, out, |e, h, ctx, out| {
            let at = level.saturating_add(1);
            if reuse_with(e, h, out, |h| vtarget(h, at, cfg)) {
                return Ok(());
            }
            match e {
                Value::Struct(fields) => write_vtarget(fields, h, at, cfg, ctx, out),
                _ => Err(ctx.err(ErrorKind::WrongType, "a VTarget Pack is a struct")),
            }
        }),
    }
}

/// A Series (R-NESTED-ENCODE-068) from a [`Value::List`]: each element with
/// its BER length; element `i` reuses element `i` of the recorded bytes.
fn write_series(
    v: &Value,
    hint: Option<&[u8]>,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
    mut element: impl FnMut(&Value, Option<&[u8]>, &mut Ctx<'_>, &mut Vec<u8>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    let Value::List(list) = v else {
        return Err(ctx.err(ErrorKind::WrongType, "a Series is a list"));
    };
    if list.is_empty() {
        return Err(ctx.err(ErrorKind::Missing, "a Series without elements is not written (D-23)"));
    }
    entries(ctx, list.len())?;
    let hints: Vec<&[u8]> = match hint {
        Some(h) => elements(h).into_iter().take(cfg.max_items).map_while(Result::ok).map(|e| e.value).collect(),
        None => Vec::new(),
    };
    let mut e = Vec::new();
    for (i, x) in list.iter().enumerate() {
        e.clear();
        element(x, hints.get(i).copied(), ctx, &mut e)?;
        if e.is_empty() {
            return Err(ctx.err(ErrorKind::Missing, "an empty Series element is not written (D-23)"));
        }
        put_prefixed(out, &e);
    }
    Ok(())
}

/// A Location or Velocity/Acceleration pack from its struct: whole groups
/// of three from the start (R-NESTED-ENCODE-110, -111), each field at its
/// table length; a field reuses its recorded bytes when unchanged.
#[allow(clippy::too_many_arguments)]
fn write_pack(
    table: &[PackField; 9],
    lengths: &[usize; 3],
    v: &Value,
    hint: Option<&[u8]>,
    level: usize,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let Value::Struct(fields) = v else {
        return Err(ctx.err(ErrorKind::WrongType, "a Location, Velocity or Acceleration pack is a struct"));
    };
    let values: Vec<Option<&Value>> = table.iter().map(|pf| field(fields, pf.name)).collect();
    let n = values.iter().take_while(|x| x.is_some()).count();
    if !matches!(n, 3 | 6 | 9) || values[n..].iter().any(Option::is_some) || fields.len() != n {
        return Err(ctx.err(
            ErrorKind::Missing,
            "a Location, Velocity or Acceleration pack sends whole groups of three from the start (R-NESTED-ENCODE-110, -111)",
        ));
    }
    let hint = hint.filter(|h| lengths.contains(&h.len()));
    let mut at = 0;
    for (pf, x) in table.iter().zip(&values).take(n) {
        let Some(x) = x else { break };
        let sub = hint.and_then(|h| h.get(at..at + pf.len));
        at += pf.len;
        let kind = Kind::Imapb { min: pf.min, max: pf.max, max_len: pf.len };
        if reuse_with(x, sub, out, |h| decode_value(kind, h, level, cfg)) {
            continue;
        }
        match x {
            Value::Float(f) => put_imap(ctx, pf.min, pf.max, pf.len, Imap::Value(*f), out)?,
            Value::OutOfRange => return Err(ctx.err(ErrorKind::WrongType, AMBIGUOUS)),
            _ => return Err(ctx.err(ErrorKind::WrongType, "a pack field is a number")),
        }
    }
    Ok(())
}

/// The recorded items of a set with one-byte tags, to find the bytes each
/// field was decoded from: the `n`-th field with a tag matches the `n`-th
/// recorded item with that tag.
struct ItemHints<'h> {
    /// (tag, position, value), sorted by tag then position.
    sorted: Vec<(u64, usize, &'h [u8])>,
}

impl<'h> ItemHints<'h> {
    fn new(hint: Option<&'h [u8]>, cfg: &Config) -> ItemHints<'h> {
        let mut sorted = Vec::new();
        if let Some(h) = hint {
            for (i, item) in set_items(h).iter().take(cfg.max_items).enumerate() {
                match item {
                    Ok(item) => sorted.push((item.tag, i, item.value)),
                    Err(_) => break,
                }
            }
        }
        // Stable, so equal tags keep their order.
        sorted.sort_by_key(|&(tag, _, _)| tag);
        ItemHints { sorted }
    }

    fn get(&self, tag: u64, n: usize) -> Option<&'h [u8]> {
        let first = self.sorted.partition_point(|&(t, _, _)| t < tag);
        self.sorted.get(first.checked_add(n)?).filter(|e| e.0 == tag).map(|e| e.2)
    }
}

/// The items of a nested set at `level` from its struct, in the struct's
/// order: defined fields by name with their table kind, `"Unknown"` fields
/// as their tag and bytes.
fn write_set(
    def: &SetDef,
    fields: &[Field],
    hint: Option<&[u8]>,
    level: usize,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if fields.is_empty() {
        return Err(ctx.err(ErrorKind::Missing, "an empty nested set is not written (D-23)"));
    }
    if fields.len() > max_entries() {
        return Err(ctx.err(ErrorKind::TooLarge, "more items than a decoder reads (D-26)"));
    }
    let hints = ItemHints::new(hint, cfg);
    let mut seen = [0usize; 256];
    let mut b = Vec::new();
    for f in fields {
        if f.name == "Unknown" {
            let Value::Struct(parts) = &f.value else {
                return Err(ctx.err(ErrorKind::WrongType, "an unknown item is a struct of Tag and Value"));
            };
            let (Some(Value::Uint(tag)), Some(Value::Bytes(bytes))) = (field(parts, "Tag"), field(parts, "Value")) else {
                return Err(ctx.err(ErrorKind::WrongType, "an unknown item is a struct of Tag and Value"));
            };
            let tag = u8::try_from(*tag).map_err(|_| ctx.err(ErrorKind::UnknownTag, "tags of nested ST 0903 sets are one byte"))?;
            seen[usize::from(tag)] += 1;
            put_tlv(out, tag, bytes);
            continue;
        }
        let fd = def
            .fields
            .iter()
            .find(|d| d.name == f.name)
            .ok_or_else(|| ctx.err(ErrorKind::UnknownTag, "field name not in the ST 0903.6 table of this set"))?;
        let n = seen[usize::from(fd.tag)];
        seen[usize::from(fd.tag)] += 1;
        if let Value::Unknown = f.value {
            // A zero-length item, as received (never for a mandatory one,
            // R-NESTED-ENCODE-017).
            if fd.required {
                return Err(ctx.err(ErrorKind::NotAllowed, "a mandatory item is never zero length (R-NESTED-ENCODE-017)"));
            }
            put_tlv(out, fd.tag, &[]);
            continue;
        }
        b.clear();
        value_of(fd.kind, &f.value, hints.get(u64::from(fd.tag), n), level, cfg, ctx, &mut b)?;
        put_tlv(out, fd.tag, &b);
    }
    Ok(())
}

/// A VTarget Pack at `level` from its struct: the target ID (BER-OID,
/// R-NESTED-ENCODE-080, -082), then its items.
fn write_vtarget(
    fields: &[Field],
    hint: Option<&[u8]>,
    level: usize,
    cfg: &Config,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let (id, rest) = match fields.split_first() {
        Some((Field { name: "Target ID", value: Value::Uint(id) }, rest)) if *id <= MAX_TARGET_ID => (*id, rest),
        _ => {
            return Err(ctx.err(
                ErrorKind::Missing,
                "a VTarget Pack starts with its Target ID, 0 to 2^63 - 1 (R-NESTED-ENCODE-080, -082)",
            ))
        }
    };
    put_oid(out, id);
    if rest.is_empty() {
        ctx.warn("a VTarget Pack without items after its targetId (R-NESTED-ENCODE-081)");
        return Ok(());
    }
    let items = hint.and_then(|h| {
        let (_, used) = smpte_klv::ber::decode_oid(h, crate::klv::OPTIONS.strict_oid).ok()?;
        h.get(used..)
    });
    write_set(&VTARGET, rest, items, level, cfg, ctx, out)
}

/// A UUID as 32 hex digits, dashes ignored (the decoder writes the RFC
/// 4122 form).
fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let digits: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (o, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let d = |c: u8| (c as char).to_digit(16);
        *o = (d(pair[0])? * 16 + d(pair[1])?) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::Policy;

    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    fn opts(policy: Policy) -> EncodeOptions {
        let mut o = EncodeOptions::default();
        o.policy = policy;
        o
    }

    /// IMAPB bytes of `x`, and the warnings.
    fn imap(min: f64, max: f64, len: usize, x: Imap, policy: Policy) -> Result<(Vec<u8>, usize), EncodeError> {
        let o = opts(policy);
        let mut w = Vec::new();
        let mut ctx = Ctx::new(&o, &mut w, Standard::St0903);
        let mut out = Vec::new();
        put_imap(&mut ctx, min, max, len, x, &mut out)?;
        Ok((out, w.len()))
    }

    fn strict(min: f64, max: f64, len: usize, x: f64) -> Vec<u8> {
        imap(min, max, len, Imap::Value(x), Policy::Strict).unwrap().0
    }

    /// nested-encode.md 3.12, IMAPB vectors: every ST 0903 mapping and the
    /// ST 1201.5 examples and tests, forward mapped and decoded back.
    #[test]
    fn imapb_vectors() {
        let vectors: &[(f64, f64, usize, f64, &str, f64)] = &[
            (0.0, 180.0, 2, 12.5, "0640", 12.5),
            (0.0, 180.0, 2, 10.0, "0500", 10.0),
            (0.0, 180.0, 2, 180.0, "5A00", 180.0),
            (-19.2, 19.2, 3, 10.0, "3A6667", 10.0),
            (-19.2, 19.2, 3, 12.0, "3E6667", 12.0),
            (-19.2, 19.2, 3, 0.0, "266667", 0.0),
            (-19.2, 19.2, 3, 19.2, "4CCCCD", 19.199996948242188),
            (-19.2, 19.2, 3, -19.2, "000000", -19.20000457763672),
            (-900.0, 19000.0, 2, 10000.0, "2A94", 10000.0),
            (-900.0, 19000.0, 2, 19000.0, "4DBC", 19000.0),
            (-90.0, 90.0, 4, 90.0, "5A000000", 90.0),
            (-90.0, 90.0, 4, 38.8, "40666666", 38.799999952316284),
            (-180.0, 180.0, 4, 180.0, "5A000000", 180.0),
            (-180.0, 180.0, 4, -77.0, "19C00000", -77.0),
            (0.0, 650.0, 2, 650.0, "5140", 650.0),
            (-1.0, 1.0, 2, 1.0, "8000", 1.0),
            (-1.0, 1.0, 2, 0.5, "6000", 0.5),
            (-900.0, 900.0, 2, 900.0, "7080", 900.0),
            (-900.0, 900.0, 2, 0.0, "3840", 0.0),
            (0.0, 100.0, 1, 100.0, "64", 100.0),
            (0.0, 100.0, 1, 37.5, "25", 37.0),
            (0.0, 100.0, 2, 100.0, "6400", 100.0),
            (0.0, 100.0, 2, 90.0, "5A00", 90.0),
            (0.0, 100.0, 3, 100.0, "640000", 100.0),
            (-900.0, 19000.0, 3, 10.0, "038E00", 10.0),
            (-900.0, 19000.0, 3, 0.0, "038400", 0.0),
            (0.1, 0.9, 2, 0.5, "3333", 0.499993896484375),
            (0.1, 0.9, 2, 0.9, "6666", 0.89998779296875),
            (0.0, 100.0, 4, 10.1, "0A199999", 10.099999964237213),
            (0.0, 100.0, 4, 100.0, "64000000", 100.0),
            (0.0, 100.0, 3, 20.2, "143333", 20.199996948242188),
            (-9.9, 110.0, 3, -9.9, "000000", -9.900009155273438),
            (-9.9, 110.0, 3, 0.0, "09E667", 0.0),
            (-9.9, 110.0, 3, 0.225, "0A2000", 0.2249908447265625),
            (-9.9, 110.0, 3, 101.475, "6F6000", 101.47499084472656),
            (-9.9, 110.0, 3, 110.0, "77E667", 110.0),
        ];
        for &(min, max, len, x, want, back) in vectors {
            let got = strict(min, max, len, x);
            assert_eq!(got, hex(want), "IMAPB({min}, {max}, {len}) {x}");
            assert_eq!(crate::imapb::decode(min, max, &got), Value::Float(back), "IMAPB({min}, {max}, {len}) {x}");
            // A decoded value encodes back to its own code.
            assert_eq!(strict(min, max, len, back), got, "IMAPB({min}, {max}, {len}) {back}");
        }
        // R-NESTED-ENCODE-147: -0.0 is +0.0.
        assert_eq!(strict(-19.2, 19.2, 3, -0.0), hex("266667"));
        assert_eq!(strict(0.0, 180.0, 2, -0.0), hex("0000"));
    }

    #[test]
    fn signals_and_special_patterns() {
        // nested-encode.md 3.10, L = 1 to 4.
        for len in 1..=4 {
            let zeros = vec![0u8; len - 1];
            let with = |first: u8| [vec![first], zeros.clone()].concat();
            let s = |x: Imap| imap(-19.2, 19.2, len, x, Policy::Strict).unwrap().0;
            assert_eq!(s(Imap::BelowMinimum), with(0xE0));
            assert_eq!(s(Imap::AboveMaximum), with(0xE1));
            assert_eq!(s(Imap::Invalid), with(0xC1));
            assert_eq!(s(Imap::Special(Special::PositiveInfinity)), with(0xC8));
            assert_eq!(s(Imap::Special(Special::NegativeInfinity)), with(0xE8));
            assert_eq!(s(Imap::Special(Special::PositiveQuietNan(0))), with(0xD0));
            assert_eq!(s(Imap::Special(Special::NegativeQuietNan(0))), with(0xF0));
            assert_eq!(s(Imap::Special(Special::PositiveSignalingNan(0))), with(0xD8));
            assert_eq!(s(Imap::Special(Special::NegativeSignalingNan(0))), with(0xF8));
            assert_eq!(s(Imap::Special(Special::BelowMinimum)), with(0xE0));
            assert_eq!(s(Imap::Special(Special::AboveMaximum)), with(0xE1));
            // The VMTI "Invalid" signal is the user-defined value whose
            // identifier is the lowest bit of the first byte.
            assert_eq!(s(Imap::Special(Special::UserDefined(1 << (8 * (len - 1))))), with(0xC1));
            assert_eq!(crate::imapb::special(&with(0xC1)), Some(Special::UserDefined(1 << (8 * (len - 1)))));
            // Every pattern is classified back as written.
            assert_eq!(crate::imapb::special(&s(Imap::Special(Special::PositiveQuietNan(5)))), Some(Special::PositiveQuietNan(5)));
            assert_eq!(super::super::imapb_0903(-19.2, 19.2, &s(Imap::Invalid)), Value::OutOfRange);
            // MISB-defined and reserved patterns are refused; an identifier
            // must fit.
            for bad in [Special::MisbDefined(3), Special::Reserved(1)] {
                assert_eq!(imap(0.0, 1.0, len, Imap::Special(bad), Policy::Strict).unwrap_err().kind, ErrorKind::InvalidCode);
            }
            let too_big = 1u64 << (3 + 8 * (len - 1));
            assert!(imap(0.0, 1.0, len, Imap::Special(Special::PositiveQuietNan(too_big)), Policy::Strict).is_err());
            assert!(imap(0.0, 1.0, len, Imap::Special(Special::PositiveQuietNan(too_big - 1)), Policy::Strict).is_ok());
        }
        // Out of range and not finite: errors when strict (D-15), signals and
        // patterns with a warning otherwise; never clamped.
        for (x, kind, first) in [
            (19.3, ErrorKind::OutOfRange, 0xE1),
            (-19.3, ErrorKind::OutOfRange, 0xE0),
            (f64::NAN, ErrorKind::NotFinite, 0xD0),
            (-f64::NAN, ErrorKind::NotFinite, 0xD0),
            (f64::INFINITY, ErrorKind::NotFinite, 0xC8),
            (f64::NEG_INFINITY, ErrorKind::NotFinite, 0xE8),
        ] {
            assert_eq!(imap(-19.2, 19.2, 3, Imap::Value(x), Policy::Strict).unwrap_err().kind, kind, "{x}");
            assert_eq!(imap(-19.2, 19.2, 3, Imap::Value(x), Policy::Clamp).unwrap(), (vec![first, 0, 0], 1), "{x}");
        }
        // One LSB below the minimum of a range spanning zero is code 0 (the
        // value code 0 decodes to), not below the range.
        assert_eq!(strict(-19.2, 19.2, 3, -19.200004), hex("000000"));
        assert!(imap(-19.2, 19.2, 3, Imap::Value(-19.20001), Policy::Strict).is_err());
    }

    #[test]
    fn offsets_from_the_quantised_frame_centre() {
        // D-18: tags 23 and 24 quantise the frame centre first.
        let (lat, lon) = offsets((38.8, -77.0), (38.9, -76.9)).unwrap();
        assert!((lat - 0.1).abs() < 1e-7 && (lon - 0.1).abs() < 1e-7, "{lat} {lon}");
        // Across the antimeridian, both ways.
        let (_, lon) = offsets((0.0, 179.95), (0.0, -179.95)).unwrap();
        assert!((lon - 0.1).abs() < 1e-6, "{lon}");
        let (_, lon) = offsets((0.0, -179.95), (0.0, 179.95)).unwrap();
        assert!((lon + 0.1).abs() < 1e-6, "{lon}");
        // A frame centre outside its range.
        assert!(offsets((91.0, 0.0), (0.0, 0.0)).is_err());
        assert!(offsets((f64::NAN, 0.0), (0.0, 0.0)).is_err());
    }

    #[test]
    fn imapa_lengths_of_nested_encode_3_10() {
        for (a, b, g, want) in [
            (-900.0, 19000.0, 0.5, 3),
            (0.0, 100.0, 1e-5, 4),
            (0.0, 1.0, 1e-5, 3),
            (0.0, 100.0, 0.1, 2),
            (0.0, 100.0, 1.0, 1),
            (0.0, 100.0, 0.001, 3),
            (-1.0, 1.0, 1e-4, 2),
            (0.0, 180.0, 0.01, 2),
            (0.0, 1e6, 1e-6, 6),
        ] {
            assert_eq!(imapa_len(a, b, g), Some(want), "IMAPA({a}, {b}, {g})");
        }
        assert_eq!(imapa_len(0.0, 100.0, 1000.0), Some(1));
        assert_eq!(imapa_len(0.0, 100.0, 0.0), None);
        assert_eq!(imapa_len(0.0, 100.0, f64::NAN), None);
        assert_eq!(floor_log2(f64::from_bits(1)), -1074);
        assert_eq!(ceil_log2(f64::from_bits(3)), -1072);
        assert_eq!((floor_log2(0.75), ceil_log2(0.75)), (-1, 0));
        assert_eq!((floor_log2(1024.0), ceil_log2(1024.0)), (10, 10));
    }

    fn ex_c() -> Vmti {
        let mut vmti = Vmti::new();
        vmti.frame_width = Some(1920);
        let mut t = VTarget::new(1);
        t.centroid = Some(409_600);
        t.status = Some(DetectionStatus::ActiveMoving);
        vmti.targets.push(t);
        vmti
    }

    /// nested-encode.md 3.12 examples C, E and G.
    #[test]
    fn short_examples() {
        assert_eq!(ex_c().encode().unwrap(), hex("04 01 06 06 01 01 08 02 07 80 65 0A 09 01 01 03 06 40 00 17 01 01"));
        assert_eq!(Vmti::new().encode().unwrap(), hex("04 01 06 06 01 00"));
        let mut vmti = Vmti::new();
        let mut t = VTarget::new(5);
        t.location_offset = Some((Imap::Invalid, Imap::AboveMaximum));
        t.location = Some(Location::new(Imap::Invalid, 1.0, 0.0));
        vmti.targets.push(t);
        assert_eq!(
            vmti.encode().unwrap(),
            hex("04 01 06 06 01 01 65 18 17 05 0A 03 C1 00 00 0B 03 E1 00 00 11 0A C1 00 00 00 2D 40 00 00 03 84")
        );
    }

    const MIIS: &str = "0170F592F02373364AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645";
    const TRACK: [u8; 16] = [0xF8, 0x1D, 0x4F, 0xAE, 0x7D, 0xEC, 0x11, 0xD0, 0xA7, 0x65, 0x00, 0xA0, 0xC9, 0x1E, 0x6B, 0xF6];

    /// nested-encode.md 3.12 example D (552 bytes).
    fn ex_d() -> Vmti {
        let mut vmti = Vmti::new();
        vmti.vmti_mi_is_user_mi = false;
        vmti.system_name = Some("DSTO_ADSS_VMTI".into());
        vmti.total_targets_detected = Some(28);
        vmti.frame_width = Some(1920);
        vmti.frame_height = Some(1080);
        vmti.source_sensor = Some("EO Nose".into());
        vmti.horizontal_fov = Some(12.5.into());
        vmti.vertical_fov = Some(10.0.into());
        vmti.miis_id = Some(CoreIdentifier::from_bytes(&hex(MIIS)).unwrap());
        let mut t1 = VTarget::new(1);
        t1.centroid = Some(409_600);
        t1.priority = Some(1);
        t1.confidence = Some(80);
        t1.color = Some([0xDA, 0xA5, 0x20]);
        t1.location_offset = Some((10.0.into(), 12.0.into()));
        t1.hae = Some(10_000.0.into());
        t1.algorithm_id = Some(9);
        t1.status = Some(DetectionStatus::ActiveMoving);
        let mut object = VObject::new(10, 90.0);
        object.features.push(VFeature::new(11, 80.0));
        t1.objects.push(object);
        let mut t2 = VTarget::new(1234);
        t2.location = Some(Location::new(38.8, -77.0, 30.0).with_sigma(10.0, 10.0, 20.0).with_rho(0.5, 0.0, 0.0));
        t2.centroid_row_col = Some((872, 1137));
        t2.status = Some(DetectionStatus::ActiveStopped);
        t2.mask = Some(VMask {
            contour: vec![14762, 14783, 15115],
            bit_mask: vec![PixelRun::new(74, 2), PixelRun::new(89, 4), PixelRun::new(106, 2)],
        });
        t2.tracker = Some(VTracker {
            track_id: Some(TRACK),
            first_observation: Some(MispTime::from_micros(987_654_321_000_000)),
            latest_observation: Some(MispTime::from_micros(0x0003_8244_3115_52C0)),
            confidence: Some(50),
            velocity: Some(Motion::new(10.0, -5.0, 0.0)),
            algorithm_id: Some(9),
            ..VTracker::default()
        });
        t2.chips.push(VChip::iri(ImageType::Png, "https://example.com/chips/1234.png"));
        // Given out of order: the series is sorted by targetId (D-02).
        vmti.targets = vec![t2, t1];
        let mut a = Algorithm::new(9, "k6_yolo_9000_tracker", "2.6a");
        a.class = Some("kalmann".into());
        a.frames = Some(10);
        vmti.algorithms.push(a);
        let mut car = Ontology::new(10, "http://purl.obolibrary.org/obo/envo.owl", "http://purl.obolibrary.org/obo/ENVO_01000604");
        car.label = Some("car".into());
        let mut antenna = Ontology::new(11, "https://example.com/features.owl", "https://example.com/features.owl#Antenna");
        antenna.label = Some("Antenna".into());
        vmti.ontologies = vec![antenna, car];
        vmti
    }

    #[test]
    fn example_d_up_to_the_ontology_series() {
        let got = ex_d().encode().unwrap();
        let want = hex(&format!(
            "03 0E 44 53 54 4F 5F 41 44 53 53 5F 56 4D 54 49  04 01 06  05 01 1C  06 01 02  08 02 07 80  09 02 04 38 \
             0A 07 45 4F 20 4E 6F 73 65  0B 02 06 40  0C 02 05 00  0D 22 {MIIS} \
             65 81 DD \
             39 01  01 03 06 40 00  04 01 01  05 01 50  08 03 DA A5 20  0A 03 3A 66 67  0B 03 3E 66 67  0C 02 2A 94 \
             16 01 09  17 01 01  6B 12 11 03 01 0A 04 02 5A 00 05 08 07 03 01 0B 04 02 50 00 \
             81 A1 89 52  11 16 40 66 66 66 19 C0 00 00 03 A2 01 40 01 40 02 80 60 00 40 00 40 00 \
             13 02 03 68  14 02 04 71  17 01 03 \
             65 19 01 09 02 39 AA 02 39 BF 02 3B 0B 02 0C 03 01 4A 02 03 01 59 04 03 01 6A 02 \
             68 34 01 10 F8 1D 4F AE 7D EC 11 D0 A7 65 00 A0 C9 1E 6B F6 03 08 00 03 82 44 30 F6 CE 40 \
             04 08 00 03 82 44 31 15 52 C0 07 01 32 0A 06 38 E0 37 F0 38 40 0C 01 09 \
             69 29 01 03 70 6E 67 02 22 {iri} \
             66 2C 2B 01 01 09 02 14 6B 36 5F 79 6F 6C 6F 5F 39 30 30 30 5F 74 72 61 63 6B 65 72 \
             03 04 32 2E 36 61 04 07 6B 61 6C 6D 61 6E 6E 05 01 0A",
            iri = "https://example.com/chips/1234.png".bytes().map(|b| format!("{b:02X}")).collect::<String>()
        ));
        assert_eq!(&got[..want.len()], &want[..]);
        // Then the ontology series, ascending ids.
        assert_eq!(got[want.len()], 0x67);
        let decoded = crate::registry::decode_set(Standard::St0903, &got, 1, &Config::default());
        assert!(decoded.is_ok());
        let ontologies = decoded.get(Tag::OntologySeries).and_then(Value::as_list).unwrap();
        let ids: Vec<_> = ontologies.iter().map(|o| o.field("Ontology ID").cloned()).collect();
        assert_eq!(ids, [Some(Value::Uint(10)), Some(Value::Uint(11))]);
    }

    /// Re-encode `bytes` (a VMTI LS) after decoding it with `cfg`.
    fn re_encode(set: &Packet) -> Result<(Vec<u8>, Vec<Warning>), EncodeError> {
        let o = EncodeOptions::default();
        let mut w = Vec::new();
        let mut ctx = Ctx::new(&o, &mut w, Standard::St0601);
        ctx.tag = Some(74);
        let mut out = Vec::new();
        encode_set(set, &mut ctx, &mut out)?;
        drop(ctx);
        Ok((out, w))
    }

    fn decoded(bytes: &[u8], keep_raw: bool) -> Packet {
        let mut cfg = Config::default();
        cfg.keep_raw = keep_raw;
        crate::registry::decode_set(Standard::St0903, bytes, 1, &cfg)
    }

    #[test]
    fn decoded_sets_re_encode_byte_for_byte() {
        for bytes in [ex_c().encode().unwrap(), ex_d().encode().unwrap(), Vmti::new().encode().unwrap()] {
            for keep_raw in [true, false] {
                let (out, w) = re_encode(&decoded(&bytes, keep_raw)).unwrap();
                assert_eq!(out, bytes, "keep_raw {keep_raw}");
                assert!(w.is_empty(), "{w:?}");
            }
        }
        // Example E: the signals need their recorded bytes (D-33).
        let mut vmti = Vmti::new();
        let mut t = VTarget::new(5);
        t.location_offset = Some((Imap::Invalid, Imap::AboveMaximum));
        vmti.targets.push(t);
        let bytes = vmti.encode().unwrap();
        assert_eq!(re_encode(&decoded(&bytes, true)).unwrap().0, bytes);
        assert_eq!(re_encode(&decoded(&bytes, false)).unwrap_err().reason, AMBIGUOUS);
    }

    /// DECISIONS P-2: in a changed item, unchanged parts keep their bytes,
    /// so an "Invalid" or above-maximum signal is not lost.
    #[test]
    fn changed_items_keep_their_unchanged_parts() {
        let mut vmti = ex_d();
        vmti.targets[0].location_offset = Some((Imap::Invalid, Imap::AboveMaximum));
        vmti.targets[0].hae = Some(Imap::BelowMinimum);
        vmti.horizontal_fov = Some(Imap::Invalid);
        let bytes = vmti.encode().unwrap();
        let mut set = decoded(&bytes, true);
        // Change the priority of target 1 (element 2 of the series, as
        // targets are sorted) and the confidence of the other target's
        // object.
        let series = set.items.iter_mut().find(|i| i.tag == 101).unwrap();
        let Value::List(targets) = &mut series.value else { panic!() };
        let Value::Struct(t1) = &mut targets[0] else { panic!() };
        for f in t1.iter_mut() {
            if f.name == "Target Priority" {
                f.value = Value::Uint(2);
            }
        }
        let (out, _) = re_encode(&set).unwrap();
        let mut expected = ex_d();
        expected.targets[0].location_offset = Some((Imap::Invalid, Imap::AboveMaximum));
        expected.targets[0].hae = Some(Imap::BelowMinimum);
        expected.horizontal_fov = Some(Imap::Invalid);
        expected.targets.iter_mut().find(|t| t.id == 1).unwrap().priority = Some(2);
        assert_eq!(out, expected.encode().unwrap());
    }

    #[test]
    fn deprecated_and_unknown_items_re_encode_from_values() {
        // VMTI item 7, VTarget 21, 102, 103, VTracker 2, 6, 8, VObject 1, 2,
        // VFeature 1, 2, an unknown VTarget tag 99 and VMTI tag 50.
        let vobject = hex("01 03 63 61 72  02 04 61 75 74 6F  03 01 0A  04 02 5A 00");
        let vfeature = hex("01 01 73  02 01 66  03 01 0B  04 02 50 00");
        let vtracker = hex("02 01 01  06 04 6B 61 6C 6D  08 01 05");
        let mut pack = hex("07  15 02 03 04");
        for (tag, v) in [(0x66u8, &vobject), (0x67, &vfeature), (0x68, &vtracker)] {
            pack.push(tag);
            pack.push(v.len() as u8);
            pack.extend_from_slice(v);
        }
        pack.extend(hex("63 02 AB CD"));
        let mut set = hex("04 01 05  06 01 01  07 01 2A  32 01 FF  65");
        set.push(pack.len() as u8 + 1);
        set.push(pack.len() as u8);
        set.extend(&pack);
        for keep_raw in [true, false] {
            let p = decoded(&set, keep_raw);
            assert!(p.is_ok());
            assert_eq!(re_encode(&p).unwrap().0, set, "keep_raw {keep_raw}");
        }
        // Lengths other than the canonical ones (a 1-byte confidence, a
        // padded integer, a long-form length) survive with the recorded
        // bytes; from values alone they are written canonically.
        let padded = hex("04 01 06  06 02 00 00  0B 03 06 40 00");
        assert_eq!(re_encode(&decoded(&padded, true)).unwrap().0, padded);
        assert_eq!(re_encode(&decoded(&padded, false)).unwrap().0, hex("04 01 06  06 01 00  0B 02 06 40"));
    }

    #[test]
    fn value_path_errors() {
        let ok = decoded(&ex_c().encode().unwrap(), false);
        let edit = |f: &dyn Fn(&mut Packet)| {
            let mut p = ok.clone();
            f(&mut p);
            re_encode(&p).map(|r| r.0)
        };
        // A frame width of 0 decodes as invalid: not written from a value.
        let e = edit(&|p| p.items[2].value = Value::Uint(0)).unwrap_err();
        assert_eq!((e.standard, e.tag, e.kind), (Standard::St0903, Some(8), ErrorKind::OutOfRange));
        // An unknown version is not allowed (item 4 is mandatory).
        assert_eq!(edit(&|p| p.items[0].value = Value::Unknown).unwrap_err().kind, ErrorKind::NotAllowed);
        // A detection status outside Table 5.
        let e = edit(&|p| {
            let Value::List(l) = &mut p.items[3].value else { panic!() };
            let Value::Struct(f) = &mut l[0] else { panic!() };
            f[2].value = Value::Enum { code: 9, label: None };
        });
        assert_eq!(e.unwrap_err().kind, ErrorKind::InvalidCode);
        // A Target ID beyond 63 bits, and an empty series.
        let e = edit(&|p| {
            let Value::List(l) = &mut p.items[3].value else { panic!() };
            let Value::Struct(f) = &mut l[0] else { panic!() };
            f[0].value = Value::Uint(1 << 63);
        });
        assert_eq!(e.unwrap_err().kind, ErrorKind::Missing);
        assert_eq!(edit(&|p| p.items[3].value = Value::List(vec![])).unwrap_err().kind, ErrorKind::Missing);
        // A checksum item is dropped with a warning (R-NESTED-ENCODE-052).
        let mut with_checksum = ok.clone();
        with_checksum.items.push(crate::Item::new(1, "Checksum", "", Value::Uint(7), vec![]));
        let (out, w) = re_encode(&with_checksum).unwrap();
        assert_eq!(out, ex_c().encode().unwrap());
        assert_eq!(w.len(), 1);
        // Missing items 4 and 6 are warnings.
        let mut bare = ok.clone();
        bare.items.retain(|i| i.tag != 4 && i.tag != 6);
        assert_eq!(re_encode(&bare).unwrap().1.len(), 2);
        // Not an ST 0903 set.
        assert_eq!(re_encode(&Packet::new(Standard::St0102)).unwrap_err().kind, ErrorKind::WrongType);
    }
}
