//! Keyframe tracks sampled at any time (feature `encode`).
//!
//! A track turns sparse keyframes (a flight log at a few hertz, an NDJSON
//! file with `interpolate` hints) into metadata at any MISP time, so a
//! muxer can sample it at every video frame whatever the frame rate
//! (MUXING_PLAN.md sections 2.1 and 6.3). Each item has its own series of
//! keyframes and its own [`Interpolation`]:
//!
//! - [`Interpolation::Hold`] keeps the last value: text, enumerations,
//!   codes and counts, times, sets and packs.
//! - [`Interpolation::Linear`] for continuous numbers (heights, ranges,
//!   speeds, fields of view, corner offsets).
//! - [`Interpolation::Angle`] goes the shorter way around the circle:
//!   items whose range is 0 to 360 degrees wrap at 360, items whose range is
//!   -180 to 180 degrees wrap at +/-180.
//! - [`Interpolation::Geodesic`] moves latitude and longitude pairs
//!   ([`GEODESIC_PAIRS`]) together along the great circle.
//!
//! [`default_interpolation`] picks one per item from the tag table;
//! [`TrackConfig::set_interpolation`] and the hints of each [`Keyframe`]
//! override it.
//!
//! # Sampling rules
//!
//! For an item at time `t`, let P be the last keyframe at or before `t`
//! that carries the item and N the first keyframe after `t` that does.
//!
//! - At P's own time the value is P's, as given.
//! - Between P and N the value is interpolated when the segment's
//!   interpolation is not [`Hold`](Interpolation::Hold), both values are
//!   plain numbers (never an unknown, a special value such as
//!   [`Input::OffEarth`], text or a code), and P and N are at most
//!   [`TrackConfig::max_gap`] apart. A geodesic pair is interpolated only
//!   when both items are geodesic, plain numbers and carried by the same
//!   two keyframes, and the points are not antipodal. An interpolated value
//!   is fresh.
//! - Otherwise P's value is held. A held value goes stale after its
//!   maximum age, counted from P ([`TrackConfig::staleness`], the same
//!   rules as [`MetadataState`](crate::state::MetadataState)), and is then
//!   left out or written as unknown.
//! - Before the item's first keyframe it is left out, or with
//!   [`TrackConfig::hold_before_first`] the first value is used (back to at
//!   most [`max_gap`](TrackConfig::max_gap) before it).
//!
//! A hint in a keyframe sets the interpolation of its item for segments
//! that start at that keyframe or later, until another hint changes it;
//! hints win over the configuration, which wins over the table default.
//!
//! # Streaming
//!
//! A [`Track`] is built incrementally, so a scheduler can stream a long
//! file: [`Track::push`] keyframes in time order, check [`Track::ready`]
//! before [`Track::sample`] at a time (it says whether the keyframes pushed
//! so far settle the values at that time), and [`Track::prune`] what is no
//! longer needed. With [`max_gap`](TrackConfig::max_gap) set, a track never
//! needs keyframes more than that ahead of the sampling time, so memory is
//! bounded by the keyframes in that window plus one value per item.
//!
//! ```
//! use misb::encode::EncodeOptions;
//! use misb::st0601::Tag;
//! use misb::track::{Keyframe, Track, TrackConfig};
//! use misb::MispTime;
//!
//! let t = |s: u64| MispTime::from_micros(1_700_000_000_000_000 + s * 1_000_000);
//! let mut track = Track::new(TrackConfig::new());
//! track.push(Keyframe::new(t(0)).set(Tag::PlatformHeadingAngle, 350.0).set(Tag::SlantRange, 1000.0)
//!     .set(Tag::SensorLatitude, 0.0).set(Tag::SensorLongitude, 10.0).set(Tag::MissionId, "M1"))?;
//! track.push(Keyframe::new(t(2)).set(Tag::PlatformHeadingAngle, 10.0).set(Tag::SlantRange, 2000.0)
//!     .set(Tag::SensorLatitude, 0.0).set(Tag::SensorLongitude, 20.0))?;
//! assert!(track.ready(t(1)));
//! let s = track.sample(t(1))?;
//! assert_eq!(s.get(Tag::SlantRange).and_then(|v| v.as_f64()), Some(1500.0));      // linear
//! assert_eq!(s.get(Tag::PlatformHeadingAngle).and_then(|v| v.as_f64()), Some(0.0)); // the short way
//! assert!((s.get(Tag::SensorLongitude).unwrap().as_f64().unwrap() - 15.0).abs() < 1e-9); // great circle
//! assert!(s.get(Tag::MissionId).is_some());                                         // held
//! let packet = s.encode_at(t(1), &EncodeOptions::default())?;
//! # let _ = packet;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::encode::{EncodeError, EncodeOptions, ErrorKind, Input, St0601Builder};
use crate::st0601::{self, Tag};
use crate::state::{Entry, Snapshot, StalePolicy, Staleness};
use crate::{MispTime, Standard, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Series indexed by tag number: ST 0601.19 defines tags 1 to 143.
const SLOTS: usize = 144;

/// How a track fills in an item between keyframes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Interpolation {
    /// Keep the last value.
    Hold,
    /// Linear between keyframes.
    Linear,
    /// Linear on the shorter way around the circle (items with a 0 to 360
    /// or -180 to 180 degree range).
    Angle,
    /// Along the great circle (latitude and longitude pairs).
    Geodesic,
}

impl Interpolation {
    /// The NDJSON name: `"hold"`, `"linear"`, `"angle"` or `"geodesic"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Interpolation::Hold => "hold",
            Interpolation::Linear => "linear",
            Interpolation::Angle => "angle",
            Interpolation::Geodesic => "geodesic",
        }
    }

    /// The interpolation with this NDJSON name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Interpolation> {
        Some(match name {
            "hold" => Interpolation::Hold,
            "linear" => Interpolation::Linear,
            "angle" => Interpolation::Angle,
            "geodesic" => Interpolation::Geodesic,
            _ => return None,
        })
    }
}

impl fmt::Display for Interpolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The latitude and longitude pairs of ST 0601.19 that are WGS84 points
/// (latitude first): sensor (13, 14), frame centre (23, 24), target
/// location (40, 41), alternate platform (67, 68) and the four full corner
/// points (82 to 89). The corner offsets (26 to 33) are differences, not
/// points, and interpolate linearly.
pub const GEODESIC_PAIRS: [(Tag, Tag); 8] = [
    (Tag::SensorLatitude, Tag::SensorLongitude),
    (Tag::FrameCenterLatitude, Tag::FrameCenterLongitude),
    (Tag::TargetLocationLatitude, Tag::TargetLocationLongitude),
    (Tag::AlternatePlatformLatitude, Tag::AlternatePlatformLongitude),
    (Tag::CornerLatitudePoint1Full, Tag::CornerLongitudePoint1Full),
    (Tag::CornerLatitudePoint2Full, Tag::CornerLongitudePoint2Full),
    (Tag::CornerLatitudePoint3Full, Tag::CornerLongitudePoint3Full),
    (Tag::CornerLatitudePoint4Full, Tag::CornerLongitudePoint4Full),
];

/// Integer items that are codes, counts or settings rather than measured
/// quantities: numbers, but held by default.
const HELD_NUMBERS: [Tag; 6] = [
    Tag::Checksum,
    Tag::UasDatalinkLsVersionNumber,
    Tag::NumberOfNavsatsInView,
    Tag::OnBoardMiStorageCapacity,
    Tag::LeapSeconds,
    Tag::CorrectionOffset,
];

/// What kind of value an item holds, as far as interpolation goes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Class {
    /// Not a plain number: only held.
    Discrete,
    /// A plain number.
    Number,
    /// An angle in degrees whose range spans a full circle from `lo`.
    Angle { lo: f64 },
    /// The latitude of a geodesic pair.
    Latitude,
    /// The longitude of a geodesic pair (also an angle from -180).
    Longitude,
}

fn class(tag: Tag) -> Class {
    for (lat, lon) in GEODESIC_PAIRS {
        if tag == lat {
            return Class::Latitude;
        }
        if tag == lon {
            return Class::Longitude;
        }
    }
    match st0601::encode::numeric_range(tag) {
        None => Class::Discrete,
        Some((lo, hi)) if tag.units() == "deg" && hi - lo == 360.0 => Class::Angle { lo },
        Some(_) => Class::Number,
    }
}

/// The interpolation an item gets unless configured otherwise, from the tag
/// table: [`Geodesic`](Interpolation::Geodesic) for the
/// [`GEODESIC_PAIRS`], [`Angle`](Interpolation::Angle) for angles with a
/// full-circle range (tags 5, 18, 19, 20, 35, 64, 71, 93, 112),
/// [`Linear`](Interpolation::Linear) for the other mapped, IMAPB and
/// integer measurements, and [`Hold`](Interpolation::Hold) for everything
/// else: text, enumerations, times, sets, packs, bytes, and the integers
/// that are codes or counts (tags 65, 123, 133, 136, 137).
#[must_use]
pub fn default_interpolation(tag: Tag) -> Interpolation {
    match class(tag) {
        Class::Latitude | Class::Longitude => Interpolation::Geodesic,
        Class::Angle { .. } => Interpolation::Angle,
        Class::Number if HELD_NUMBERS.contains(&tag) => Interpolation::Hold,
        Class::Number => Interpolation::Linear,
        Class::Discrete => Interpolation::Hold,
    }
}

/// Whether `how` can apply to `tag`: [`Hold`](Interpolation::Hold) to
/// any item, [`Linear`](Interpolation::Linear) to items that hold plain
/// numbers, [`Angle`](Interpolation::Angle) to angles with a full-circle
/// range (longitudes included), [`Geodesic`](Interpolation::Geodesic) to
/// the items of [`GEODESIC_PAIRS`].
pub fn check_interpolation(tag: Tag, how: Interpolation) -> Result<(), TrackError> {
    let reason = match (how, class(tag)) {
        (Interpolation::Hold, _) => return Ok(()),
        (Interpolation::Linear, Class::Discrete) => "linear interpolation needs an item that holds a number",
        (Interpolation::Linear, _) => return Ok(()),
        (Interpolation::Angle, Class::Angle { .. } | Class::Longitude) => return Ok(()),
        (Interpolation::Angle, _) => "angle interpolation needs an angle whose range is a full circle",
        (Interpolation::Geodesic, Class::Latitude | Class::Longitude) => return Ok(()),
        (Interpolation::Geodesic, _) => "geodesic interpolation applies to latitude and longitude pairs",
    };
    Err(TrackError::Interpolation { tag, interpolation: how, reason })
}

/// The lower end of the full circle an angle item wraps on.
fn angle_lo(tag: Tag) -> Option<f64> {
    match class(tag) {
        Class::Angle { lo } => Some(lo),
        Class::Longitude => Some(-180.0),
        _ => None,
    }
}

/// How a track samples: interpolation overrides, gaps and staleness, and
/// the encoder options keyframe values are checked with.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct TrackConfig {
    /// Options keyframe values are checked with when pushed (default
    /// strict).
    pub options: EncodeOptions,
    /// How long a held value stays valid after its keyframe, and what a
    /// stale value becomes (default: never stale).
    pub staleness: Staleness,
    /// Two keyframes further apart than this are not interpolated (the
    /// earlier value is held), and a first value is not held back further
    /// than this before its keyframe. `None` (default): no limit, but then
    /// [`Track::ready`] may need keyframes far ahead.
    pub max_gap: Option<Duration>,
    /// Before an item's first keyframe, use its first value instead of
    /// leaving it out (default false).
    pub hold_before_first: bool,
    interpolation: BTreeMap<Tag, Interpolation>,
}

impl TrackConfig {
    /// The defaults: table interpolation, no gap limit, never stale, items
    /// left out before their first keyframe.
    #[must_use]
    pub fn new() -> TrackConfig {
        TrackConfig::default()
    }

    /// Interpolate `tag` with `how` unless a keyframe hint says otherwise;
    /// refused when `how` cannot apply ([`check_interpolation`]). Set both
    /// items of a geodesic pair together.
    pub fn set_interpolation(&mut self, tag: Tag, how: Interpolation) -> Result<&mut Self, TrackError> {
        check_interpolation(tag, how)?;
        self.interpolation.insert(tag, how);
        Ok(self)
    }

    /// The interpolation of `tag` without keyframe hints: the configured
    /// one or [`default_interpolation`].
    #[must_use]
    pub fn interpolation(&self, tag: Tag) -> Interpolation {
        self.interpolation.get(&tag).copied().unwrap_or_else(|| default_interpolation(tag))
    }
}

/// One keyframe: values at a MISP time, with interpolation hints.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Keyframe {
    /// When the values hold.
    pub time: MispTime,
    /// Tag 65 override from this keyframe on.
    pub version: Option<u8>,
    /// The values; `Input::Value(Value::Unknown)` marks an item unknown.
    pub items: Vec<(Tag, Input)>,
    /// Interpolation hints for this keyframe's segments and later ones.
    pub interpolate: Vec<(Tag, Interpolation)>,
}

impl Keyframe {
    /// An empty keyframe at `time`.
    #[must_use]
    pub fn new(time: MispTime) -> Keyframe {
        Keyframe { time, version: None, items: Vec::new(), interpolate: Vec::new() }
    }

    /// Add a value.
    #[must_use]
    pub fn set(mut self, tag: Tag, value: impl Into<Input>) -> Keyframe {
        self.items.push((tag, value.into()));
        self
    }

    /// Mark an item unknown at this keyframe.
    #[must_use]
    pub fn unknown(mut self, tag: Tag) -> Keyframe {
        self.items.push((tag, Input::Value(Value::Unknown)));
        self
    }

    /// Add an interpolation hint.
    #[must_use]
    pub fn with_interpolation(mut self, tag: Tag, how: Interpolation) -> Keyframe {
        self.interpolate.push((tag, how));
        self
    }

    /// Set the tag 65 override.
    #[must_use]
    pub fn with_version(mut self, version: u8) -> Keyframe {
        self.version = Some(version);
        self
    }
}

/// Why a keyframe was refused or a time could not be sampled.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum TrackError {
    /// A keyframe earlier than the last one pushed. (One at the same time
    /// is merged into it.)
    OutOfOrder {
        /// The refused keyframe's time.
        time: MispTime,
        /// The last keyframe's time.
        last: MispTime,
    },
    /// An interpolation that cannot apply to the item.
    Interpolation {
        /// The item.
        tag: Tag,
        /// The interpolation asked for.
        interpolation: Interpolation,
        /// Why not.
        reason: &'static str,
    },
    /// A keyframe value the encoder refuses.
    Encode(EncodeError),
    /// A time before what [`Track::prune`] kept.
    Pruned {
        /// The time asked for.
        time: MispTime,
        /// The earliest time the track can still sample.
        earliest: MispTime,
    },
    /// A keyframe pushed after [`Track::finish`].
    Finished,
}

impl fmt::Display for TrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrackError::OutOfOrder { time, last } => write!(
                f,
                "keyframe at {} us is before the previous keyframe at {} us",
                time.as_micros(),
                last.as_micros()
            ),
            TrackError::Interpolation { tag, interpolation, reason } => {
                write!(f, "ST 0601 tag {} ({}): {interpolation}: {reason}", *tag as u64, tag.name())
            }
            TrackError::Encode(e) => e.fmt(f),
            TrackError::Pruned { time, earliest } => write!(
                f,
                "time {} us is before {} us, the earliest time the pruned track can sample",
                time.as_micros(),
                earliest.as_micros()
            ),
            TrackError::Finished => f.write_str("the track is finished: no more keyframes"),
        }
    }
}

impl std::error::Error for TrackError {}

impl From<EncodeError> for TrackError {
    fn from(e: EncodeError) -> TrackError {
        TrackError::Encode(e)
    }
}

/// One keyframe value of an item.
#[derive(Clone, Debug)]
struct Point {
    time: MispTime,
    value: Arc<Input>,
    /// The interpolation of the segment that starts here.
    how: Interpolation,
}

/// Keyframes sampled at any MISP time. See the [module
/// documentation](self) for the rules.
#[derive(Clone, Debug)]
pub struct Track {
    cfg: TrackConfig,
    /// `series[n]`: the keyframe values of tag `n`, strictly increasing in
    /// time.
    series: Vec<VecDeque<Point>>,
    /// Tag 65 overrides, strictly increasing in time.
    versions: VecDeque<(MispTime, u8)>,
    /// Sticky keyframe hints.
    hints: BTreeMap<Tag, Interpolation>,
    last: Option<MispTime>,
    earliest: Option<MispTime>,
    finished: bool,
    keyframes: u64,
    check: St0601Builder,
    unknown: Arc<Input>,
}

impl Track {
    /// An empty track.
    #[must_use]
    pub fn new(cfg: TrackConfig) -> Track {
        Track {
            check: St0601Builder::with_options(MispTime::EPOCH, cfg.options.clone()),
            cfg,
            series: vec![VecDeque::new(); SLOTS],
            versions: VecDeque::new(),
            hints: BTreeMap::new(),
            last: None,
            earliest: None,
            finished: false,
            keyframes: 0,
            unknown: Arc::new(Input::Value(Value::Unknown)),
        }
    }

    /// A finished track holding every keyframe of `keyframes` (in time
    /// order).
    pub fn from_keyframes(cfg: TrackConfig, keyframes: impl IntoIterator<Item = Keyframe>) -> Result<Track, TrackError> {
        let mut track = Track::new(cfg);
        for k in keyframes {
            track.push(k)?;
        }
        track.finish();
        Ok(track)
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &TrackConfig {
        &self.cfg
    }

    /// Add a keyframe. Keyframes come in time order: an earlier one is
    /// refused; one at the time of the last is merged into it (its values
    /// replace the earlier ones). Every value is checked with the encoder's
    /// rules for its item and every hint with [`check_interpolation`]
    /// before anything changes; an item twice in one keyframe is refused.
    /// Tag 65 among the items is the version override, like
    /// [`Keyframe::version`].
    pub fn push(&mut self, keyframe: Keyframe) -> Result<(), TrackError> {
        if self.finished {
            return Err(TrackError::Finished);
        }
        let time = keyframe.time;
        if let Some(last) = self.last {
            if time < last {
                return Err(TrackError::OutOfOrder { time, last });
            }
        }
        for &(tag, how) in &keyframe.interpolate {
            check_interpolation(tag, how)?;
        }
        let mut version = keyframe.version;
        let mut seen = [false; SLOTS];
        let mut values = Vec::with_capacity(keyframe.items.len());
        for (tag, input) in keyframe.items {
            let n = tag as usize;
            let duplicate = || {
                TrackError::Encode(EncodeError::new(
                    Standard::St0601,
                    Some(n as u64),
                    ErrorKind::Duplicate,
                    "item given twice in one keyframe",
                ))
            };
            if seen.get(n).copied().unwrap_or(true) {
                return Err(duplicate());
            }
            seen[n] = true;
            self.check.clear();
            if tag == Tag::UasDatalinkLsVersionNumber {
                if version.is_some() {
                    return Err(duplicate());
                }
                self.check.set_ref(tag, &input)?;
                version = self.check.version_override();
                continue;
            }
            self.check.set_ref(tag, &input)?;
            let value = match input {
                Input::Value(Value::Unknown) => Arc::clone(&self.unknown),
                other => Arc::new(other),
            };
            values.push((tag, value));
        }
        if seen[Tag::SensorEllipsoidHeight as usize] && seen[Tag::SensorEllipsoidHeightExtended as usize] {
            return Err(TrackError::Encode(EncodeError::new(
                Standard::St0601,
                Some(Tag::SensorEllipsoidHeightExtended as u64),
                ErrorKind::NotAllowed,
                "items 75 and 104 are exclusive",
            )));
        }
        // Checked: now apply.
        for (tag, how) in keyframe.interpolate {
            self.hints.insert(tag, how);
            if let Some(p) = self.series[tag as usize].back_mut().filter(|p| p.time == time) {
                p.how = how;
            }
        }
        for (tag, value) in values {
            let how = self.hints.get(&tag).copied().unwrap_or_else(|| self.cfg.interpolation(tag));
            let series = &mut self.series[tag as usize];
            let point = Point { time, value, how };
            match series.back_mut() {
                Some(last) if last.time == time => *last = point,
                _ => series.push_back(point),
            }
        }
        if let Some(v) = version {
            match self.versions.back_mut() {
                Some(last) if last.0 == time => last.1 = v,
                _ => self.versions.push_back((time, v)),
            }
        }
        self.last = Some(time);
        self.keyframes += 1;
        Ok(())
    }

    /// No more keyframes will come: values after the last keyframe are now
    /// settled, and [`Track::ready`] is true for every time.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// Whether [`Track::finish`] was called.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The time of the last keyframe pushed.
    #[must_use]
    pub fn last_time(&self) -> Option<MispTime> {
        self.last
    }

    /// The earliest time [`Track::sample`] accepts after [`Track::prune`];
    /// `None` before any pruning.
    #[must_use]
    pub fn earliest(&self) -> Option<MispTime> {
        self.earliest
    }

    /// Keyframes pushed so far (merged ones counted once each push).
    #[must_use]
    pub fn keyframes_pushed(&self) -> u64 {
        self.keyframes
    }

    /// Item values held in memory (one per item per keyframe kept), to
    /// watch memory use.
    #[must_use]
    pub fn values_held(&self) -> usize {
        self.series.iter().map(VecDeque::len).sum::<usize>() + self.versions.len()
    }

    /// Whether the keyframes pushed so far settle the values at `t`: no
    /// keyframe pushed later can change [`Track::sample`] at `t`. True once
    /// the track is finished; otherwise a keyframe after `t` is needed, and
    /// each item that may still be interpolated at `t` needs its next
    /// keyframe, unless the last keyframe is more than
    /// [`max_gap`](TrackConfig::max_gap) after `t`. With
    /// [`hold_before_first`](TrackConfig::hold_before_first) an item not yet
    /// seen could still appear, so only the gap or the end settle it.
    #[must_use]
    pub fn ready(&self, t: MispTime) -> bool {
        if self.finished {
            return true;
        }
        let Some(last) = self.last else { return false };
        if last <= t {
            return false;
        }
        // A later keyframe is at or after `last`.
        let beyond = |from: MispTime| self.cfg.max_gap.map_or(false, |g| exceeds(from, last, g));
        if beyond(t) {
            return true;
        }
        if self.cfg.hold_before_first {
            return false;
        }
        self.series.iter().all(|s| {
            let i = s.partition_point(|p| p.time <= t);
            if i < s.len() || i == 0 {
                // The next keyframe is known, or the item is not seen yet.
                return true;
            }
            let p = &s[i - 1];
            p.time == t || p.how == Interpolation::Hold || number(&p.value).is_none() || beyond(p.time)
        })
    }

    /// The values at `t` (rules in the [module documentation](self)), in
    /// ascending tag order. Fails only for a time before
    /// [`Track::earliest`]. Sampling before [`Track::ready`] gives the
    /// values the keyframes pushed so far imply.
    pub fn sample(&self, t: MispTime) -> Result<Snapshot, TrackError> {
        if let Some(earliest) = self.earliest {
            if t < earliest {
                return Err(TrackError::Pruned { time: t, earliest });
            }
        }
        let mut values: Vec<Option<Arc<Input>>> = vec![None; SLOTS];
        let mut done = [false; SLOTS];
        for (lat, lon) in GEODESIC_PAIRS {
            if let Some((a, b)) = self.geodesic(lat, lon, t) {
                values[lat as usize] = Some(Arc::new(Input::Float(a)));
                values[lon as usize] = Some(Arc::new(Input::Float(b)));
                done[lat as usize] = true;
                done[lon as usize] = true;
            }
        }
        let mut items = Vec::new();
        for (n, slot) in values.into_iter().enumerate() {
            let value = if done[n] { slot } else { self.value_at(n, t) };
            if let (Some(value), Some(tag)) = (value, Tag::from_u64(n as u64)) {
                items.push(Entry { tag, value });
            }
        }
        Ok(Snapshot::from_parts(t, self.version_at(t), items))
    }

    /// Drop what is no longer needed to sample times at or after `t`: for
    /// each item, the keyframe values before its last one at or before `t`.
    /// Sampling before `t` is then refused.
    pub fn prune(&mut self, t: MispTime) {
        for s in &mut self.series {
            let i = s.partition_point(|p| p.time <= t);
            if i > 1 {
                s.drain(..i - 1);
            }
        }
        let i = self.versions.partition_point(|v| v.0 <= t);
        if i > 1 {
            self.versions.drain(..i - 1);
        }
        self.earliest = Some(self.earliest.map_or(t, |e| e.max(t)));
    }

    /// The value of tag number `n` at `t`, without geodesic pairing.
    fn value_at(&self, n: usize, t: MispTime) -> Option<Arc<Input>> {
        let s = &self.series[n];
        let i = s.partition_point(|p| p.time <= t);
        let Some(p) = i.checked_sub(1).map(|j| &s[j]) else {
            // Before the first keyframe.
            let first = s.front()?;
            let near = self.cfg.max_gap.map_or(true, |g| !exceeds(t, first.time, g));
            return (self.cfg.hold_before_first && near).then(|| Arc::clone(&first.value));
        };
        if p.time == t {
            return Some(Arc::clone(&p.value));
        }
        let tag = Tag::from_u64(n as u64)?;
        if let Some(next) = s.get(i) {
            if let Some(x) = self.interpolate(tag, p, next, t) {
                return Some(Arc::new(Input::Float(x)));
            }
        }
        if !self.cfg.staleness.is_stale(tag, p.time, t) {
            Some(Arc::clone(&p.value))
        } else if self.cfg.staleness.policy == StalePolicy::Unknown {
            Some(Arc::clone(&self.unknown))
        } else {
            None
        }
    }

    /// Linear or angle interpolation between `p` and `n`, if it applies.
    fn interpolate(&self, tag: Tag, p: &Point, n: &Point, t: MispTime) -> Option<f64> {
        if self.cfg.max_gap.map_or(false, |g| exceeds(p.time, n.time, g)) {
            return None;
        }
        let (a, b) = (number(&p.value)?, number(&n.value)?);
        let f = fraction(p.time, n.time, t);
        match p.how {
            Interpolation::Linear => Some(a + (b - a) * f),
            Interpolation::Angle => Some(lerp_angle(a, b, f, angle_lo(tag)?)),
            // Hold, and a geodesic item whose pair cannot be interpolated.
            _ => None,
        }
    }

    /// The great-circle position of a pair at `t`, if both items qualify.
    fn geodesic(&self, lat: Tag, lon: Tag, t: MispTime) -> Option<(f64, f64)> {
        let around = |tag: Tag| {
            let s = &self.series[tag as usize];
            let i = s.partition_point(|p| p.time <= t);
            Some((s.get(i.checked_sub(1)?)?, s.get(i)?))
        };
        let (pa, na) = around(lat)?;
        let (po, no) = around(lon)?;
        let aligned = pa.time == po.time && na.time == no.time && pa.time != t;
        let geodesic = pa.how == Interpolation::Geodesic && po.how == Interpolation::Geodesic;
        if !aligned || !geodesic || self.cfg.max_gap.map_or(false, |g| exceeds(pa.time, na.time, g)) {
            return None;
        }
        let a = (number(&pa.value)?, number(&po.value)?);
        let b = (number(&na.value)?, number(&no.value)?);
        great_circle(a, b, fraction(pa.time, na.time, t))
    }

    fn version_at(&self, t: MispTime) -> Option<u8> {
        let i = self.versions.partition_point(|v| v.0 <= t);
        match i.checked_sub(1) {
            Some(j) => Some(self.versions[j].1),
            None => {
                let &(first, v) = self.versions.front()?;
                let near = self.cfg.max_gap.map_or(true, |g| !exceeds(t, first, g));
                (self.cfg.hold_before_first && near).then_some(v)
            }
        }
    }
}

/// Whether `to - from` (with `to >= from`) is longer than `gap`.
fn exceeds(from: MispTime, to: MispTime, gap: Duration) -> bool {
    u128::from(to.as_micros().saturating_sub(from.as_micros())) * 1000 > gap.as_nanos()
}

/// Where `t` lies between `p` and `n` (`p <= t < n`), 0 to 1.
fn fraction(p: MispTime, n: MispTime, t: MispTime) -> f64 {
    (t.as_micros() - p.as_micros()) as f64 / (n.as_micros() - p.as_micros()) as f64
}

/// A plain number: never an unknown, a special value, text or a code.
fn number(v: &Input) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

/// From angle `a` towards `b` the shorter way around a full circle starting
/// at `lo`, the fraction `f` of the way; the result is in `[lo, lo + 360)`.
/// Exactly opposite angles go the negative way.
fn lerp_angle(a: f64, b: f64, f: f64, lo: f64) -> f64 {
    let d = (b - a + 180.0).rem_euclid(360.0) - 180.0;
    lo + (a + d * f - lo).rem_euclid(360.0)
}

/// The point the fraction `f` of the way from `a` to `b` (latitude,
/// longitude in degrees) along the great circle through them (spherical
/// linear interpolation of the unit vectors); `None` for antipodal points,
/// which no single great circle joins.
fn great_circle(a: (f64, f64), b: (f64, f64), f: f64) -> Option<(f64, f64)> {
    let unit = |(lat, lon): (f64, f64)| {
        let (phi, lambda) = (lat.to_radians(), lon.to_radians());
        [phi.cos() * lambda.cos(), phi.cos() * lambda.sin(), phi.sin()]
    };
    let (u, v) = (unit(a), unit(b));
    let dot = u[0] * v[0] + u[1] * v[1] + u[2] * v[2];
    let cross = [u[1] * v[2] - u[2] * v[1], u[2] * v[0] - u[0] * v[2], u[0] * v[1] - u[1] * v[0]];
    let sin = (cross[0] * cross[0] + cross[1] * cross[1] + cross[2] * cross[2]).sqrt();
    let omega = sin.atan2(dot);
    if omega < 1e-12 {
        // The same point, to within a few nanometres.
        return Some((a.0 + (b.0 - a.0) * f, lerp_angle(a.1, b.1, f, -180.0)));
    }
    if std::f64::consts::PI - omega < 1e-9 {
        return None;
    }
    let (wa, wb) = (((1.0 - f) * omega).sin() / omega.sin(), (f * omega).sin() / omega.sin());
    let p = [wa * u[0] + wb * v[0], wa * u[1] + wb * v[1], wa * u[2] + wb * v[2]];
    let lat = p[2].atan2(p[0].hypot(p[1])).to_degrees();
    let lon = p[1].atan2(p[0]).to_degrees();
    Some((lat.clamp(-90.0, 90.0), lon.clamp(-180.0, 180.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angles_go_the_short_way() {
        assert_eq!(lerp_angle(350.0, 10.0, 0.5, 0.0), 0.0);
        assert_eq!(lerp_angle(10.0, 350.0, 0.5, 0.0), 0.0);
        assert_eq!(lerp_angle(350.0, 10.0, 0.25, 0.0), 355.0);
        assert_eq!(lerp_angle(-170.0, 170.0, 0.5, -180.0), -180.0);
        assert_eq!(lerp_angle(170.0, -170.0, 0.5, -180.0), -180.0);
        assert_eq!(lerp_angle(10.0, 20.0, 0.5, 0.0), 15.0);
        assert_eq!(lerp_angle(0.0, 180.0, 0.5, 0.0), 270.0);
    }

    #[test]
    fn classes() {
        assert_eq!(default_interpolation(Tag::PlatformHeadingAngle), Interpolation::Angle);
        assert_eq!(default_interpolation(Tag::PlatformSideslipAngleFull), Interpolation::Angle);
        assert_eq!(default_interpolation(Tag::PlatformCourseAngle), Interpolation::Angle);
        assert_eq!(default_interpolation(Tag::SensorRelativeElevationAngle), Interpolation::Angle);
        assert_eq!(default_interpolation(Tag::SensorLongitude), Interpolation::Geodesic);
        assert_eq!(default_interpolation(Tag::CornerLatitudePoint4Full), Interpolation::Geodesic);
        assert_eq!(default_interpolation(Tag::OffsetCornerLatitudePoint1), Interpolation::Linear);
        assert_eq!(default_interpolation(Tag::SensorHorizontalFieldOfView), Interpolation::Linear);
        assert_eq!(default_interpolation(Tag::PlatformTrueAirspeed), Interpolation::Linear);
        assert_eq!(default_interpolation(Tag::SensorEllipsoidHeightExtended), Interpolation::Linear);
        assert_eq!(default_interpolation(Tag::NumberOfNavsatsInView), Interpolation::Hold);
        assert_eq!(default_interpolation(Tag::MissionId), Interpolation::Hold);
        assert_eq!(default_interpolation(Tag::IcingDetected), Interpolation::Hold);
        assert_eq!(default_interpolation(Tag::EventStartTime), Interpolation::Hold);
        assert_eq!(default_interpolation(Tag::SecurityLocalSet), Interpolation::Hold);
        assert_eq!(default_interpolation(Tag::SensorFrameRatePack), Interpolation::Hold);
        let angles: Vec<u64> =
            (1..=143).filter_map(Tag::from_u64).filter(|&t| default_interpolation(t) == Interpolation::Angle).map(|t| t as u64).collect();
        assert_eq!(angles, [5, 18, 19, 20, 35, 64, 71, 93, 112]);
        assert!(check_interpolation(Tag::SensorLongitude, Interpolation::Angle).is_ok());
        assert!(check_interpolation(Tag::SensorLatitude, Interpolation::Angle).is_err());
        assert!(check_interpolation(Tag::SlantRange, Interpolation::Geodesic).is_err());
        assert!(check_interpolation(Tag::MissionId, Interpolation::Linear).is_err());
        assert!(check_interpolation(Tag::MissionId, Interpolation::Hold).is_ok());
        for i in [Interpolation::Hold, Interpolation::Linear, Interpolation::Angle, Interpolation::Geodesic] {
            assert_eq!(Interpolation::from_name(i.name()), Some(i));
        }
    }

    #[test]
    fn gap_arithmetic() {
        let t = MispTime::from_micros;
        assert!(!exceeds(t(0), t(1000), Duration::from_millis(1)));
        assert!(exceeds(t(0), t(1001), Duration::from_millis(1)));
        assert!(exceeds(t(0), t(1), Duration::from_nanos(999)));
        assert_eq!(fraction(t(10), t(20), t(15)), 0.5);
    }
}
