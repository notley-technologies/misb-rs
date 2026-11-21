//! Live metadata state with consistent snapshots (feature `encode`).
//!
//! [`MetadataState`] holds the current value of every ST 0601 item a live
//! source reports. Values change at any time, from any source (a control
//! channel, a sensor feed, a tracker); each is checked when it is set by the
//! encoder's rules for its item, so a value the standard does not allow is
//! refused at once rather than when the next packet is built. Each value
//! remembers the MISP time it was set at, and [`Staleness`] says how long it
//! stays valid, so a dead sensor feed does not keep reporting its last
//! position forever (MUXING_PLAN.md section 6.3).
//!
//! [`MetadataState::snapshot`] takes a [`Snapshot`]: an immutable copy at
//! one MISP time with staleness applied, cheap to take (values are shared,
//! not copied) and safe to hand to another thread. One snapshot encodes to
//! one ST 0601 packet with [`Snapshot::encode_at`], so a packet never mixes
//! values from two updates. [`MetadataState::revision`] counts changes, so
//! a scheduler with an on-change rate can tell whether anything changed
//! since its last snapshot, and [`MetadataState::next_expiry`] says when a
//! value will next go stale.
//!
//! ```
//! use misb::encode::EncodeOptions;
//! use misb::state::MetadataState;
//! use misb::{st0601::Tag, MispTime};
//! use std::time::Duration;
//!
//! let t0 = MispTime::from_micros(1_700_000_000_000_000);
//! let mut state = MetadataState::new();
//! state.staleness_mut().max_age = Some(Duration::from_secs(2));
//! state.staleness_mut().set_max_age(Tag::MissionId, None); // never stale
//! state.set(Tag::MissionId, "MISSION01", t0)?.set(Tag::SensorLatitude, 38.8895, t0)?.unknown(Tag::SlantRange, t0)?;
//!
//! // A value outside its item's range is refused when it is set.
//! let revision = state.revision();
//! assert!(state.set(Tag::SensorLatitude, 91.0, t0).is_err());
//! assert_eq!(state.revision(), revision);
//!
//! let packet = state.snapshot(t0).encode_at(t0, &EncodeOptions::default())?;
//! assert!(misb::decode(&packet).unwrap().is_ok());
//!
//! // Three seconds later the latitude is stale and left out.
//! let later = t0.checked_add_micros(3_000_000).unwrap();
//! let snapshot = state.snapshot(later);
//! assert!(snapshot.get(Tag::SensorLatitude).is_none());
//! assert!(snapshot.get(Tag::MissionId).is_some());
//! # Ok::<(), misb::encode::EncodeError>(())
//! ```

use crate::encode::{EncodeError, EncodeOptions, ErrorKind, Input, Security, St0601Builder, Vmti, ST0601_VERSION};
use crate::st0601::Tag;
use crate::{MispTime, Standard, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Slots indexed by tag number: ST 0601.19 defines tags 1 to 143.
const SLOTS: usize = 144;

/// What a snapshot does with a value older than its maximum age.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StalePolicy {
    /// Leave the item out of the packet (default): it is no longer reported.
    #[default]
    Omit,
    /// Write it as a zero-length item: the value is now unknown (ST 0601.19
    /// section 6.5).
    Unknown,
}

/// How long values stay valid: a maximum age for every item, overrides for
/// single items, and what happens to a value that is older.
///
/// A value set at MISP time `s` is stale at time `t` when `t - s` exceeds
/// its maximum age; a maximum age of `None` means never stale. The default
/// is never stale, with [`StalePolicy::Omit`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Staleness {
    /// The maximum age of items without an override (default `None`: never
    /// stale).
    pub max_age: Option<Duration>,
    /// What a snapshot does with a stale value (default
    /// [`StalePolicy::Omit`]).
    pub policy: StalePolicy,
    overrides: BTreeMap<Tag, Option<Duration>>,
}

impl Staleness {
    /// Never stale, with [`StalePolicy::Omit`].
    #[must_use]
    pub fn new() -> Staleness {
        Staleness::default()
    }

    /// Every item stale after `max_age`, with [`StalePolicy::Omit`].
    #[must_use]
    pub fn with_max_age(max_age: Duration) -> Staleness {
        Staleness { max_age: Some(max_age), ..Staleness::default() }
    }

    /// Give `tag` its own maximum age (`None`: never stale), whatever
    /// [`max_age`](Staleness::max_age) says.
    pub fn set_max_age(&mut self, tag: Tag, max_age: Option<Duration>) -> &mut Self {
        self.overrides.insert(tag, max_age);
        self
    }

    /// Remove the override of `tag`: it follows
    /// [`max_age`](Staleness::max_age) again.
    pub fn remove_override(&mut self, tag: Tag) -> &mut Self {
        self.overrides.remove(&tag);
        self
    }

    /// The maximum age of `tag`: its override, or the common one.
    #[must_use]
    pub fn max_age(&self, tag: Tag) -> Option<Duration> {
        match self.overrides.get(&tag) {
            Some(&age) => age,
            None => self.max_age,
        }
    }

    /// Whether a value of `tag` set at `at` is stale at `now`. A value set
    /// after `now` is not.
    #[must_use]
    pub fn is_stale(&self, tag: Tag, at: MispTime, now: MispTime) -> bool {
        match self.max_age(tag) {
            None => false,
            // The age is whole microseconds, so exceeding the maximum is
            // exceeding its whole microseconds.
            Some(max) => u128::from(now.as_micros().saturating_sub(at.as_micros())) > max.as_micros(),
        }
    }

    /// The first MISP time at which a value of `tag` set at `at` is stale,
    /// `None` if never (or past the range of [`MispTime`]).
    #[must_use]
    pub fn expiry(&self, tag: Tag, at: MispTime) -> Option<MispTime> {
        let max = u64::try_from(self.max_age(tag)?.as_micros()).ok()?;
        // Stale once the age in whole microseconds exceeds the maximum.
        at.as_micros().checked_add(max)?.checked_add(1).map(MispTime::from_micros)
    }
}

/// One value of the state.
#[derive(Clone, Debug)]
struct Slot {
    tag: Tag,
    value: Arc<Input>,
    at: MispTime,
}

/// The current ST 0601 values of a live source. See the [module
/// documentation](self).
///
/// Every value is keyed by its tag and holds the MISP time it was set at
/// (the library never reads a clock: callers pass the time in). Setting a
/// value checks it with the encoder's rules for that item under
/// [`options`](MetadataState::options), so [`MetadataState::set`] refuses
/// what [`St0601Builder::set`] would refuse and leaves the state unchanged.
/// A snapshot encoded with the same options then only fails for rules
/// between items that one value cannot break on its own (the frame centre a
/// VMTI set needs, DECISIONS D-31) or a packet larger than
/// [`EncodeOptions::max_packet_bytes`].
///
/// Tags 1 (checksum) and 2 (time) belong to each packet and cannot be set;
/// tag 65 is the version override ([`MetadataState::set_version`]).
#[derive(Clone, Debug)]
pub struct MetadataState {
    opts: EncodeOptions,
    staleness: Staleness,
    /// `slots[n]` holds tag `n`.
    slots: Vec<Option<Slot>>,
    count: usize,
    version: Option<u8>,
    revision: u64,
    /// Scratch builder that checks values as they are set.
    check: St0601Builder,
    /// The shared value of every unknown (zero-length) item.
    unknown: Arc<Input>,
}

impl Default for MetadataState {
    fn default() -> Self {
        MetadataState::new()
    }
}

impl MetadataState {
    /// An empty state checking values with the default
    /// [`EncodeOptions`] (strict), values never stale.
    #[must_use]
    pub fn new() -> MetadataState {
        MetadataState::with_options(EncodeOptions::default())
    }

    /// An empty state checking values under `opts` (for example
    /// [`crate::encode::Policy::Clamp`]).
    #[must_use]
    pub fn with_options(opts: EncodeOptions) -> MetadataState {
        MetadataState {
            check: St0601Builder::with_options(MispTime::EPOCH, opts.clone()),
            opts,
            staleness: Staleness::default(),
            slots: vec![None; SLOTS],
            count: 0,
            version: None,
            revision: 0,
            unknown: Arc::new(Input::Value(Value::Unknown)),
        }
    }

    /// The options values are checked with.
    #[must_use]
    pub fn options(&self) -> &EncodeOptions {
        &self.opts
    }

    /// The staleness rules.
    #[must_use]
    pub fn staleness(&self) -> &Staleness {
        &self.staleness
    }

    /// Change the staleness rules; they apply to the values already held
    /// too, from the next snapshot on.
    pub fn staleness_mut(&mut self) -> &mut Staleness {
        &mut self.staleness
    }

    /// Set item `tag` to `value`, valid from MISP time `at` (usually now),
    /// replacing any earlier value.
    ///
    /// The value is checked as [`St0601Builder::set`] checks it; an error
    /// leaves the state unchanged. `Input::Value(Value::Unknown)` marks the
    /// item unknown, as [`MetadataState::unknown`]. Tag 65 sets the version
    /// override. Items 75 and 104 are exclusive (R-ST0601-ENCODE-83):
    /// setting one while the other is held is refused, so clear the other
    /// first. Nested sets (tags 48, 73, 74) take what the builder takes:
    /// [`Input::Set`] with the encoded items, or a decoded
    /// [`Value::Set`].
    pub fn set(&mut self, tag: Tag, value: impl Into<Input>, at: MispTime) -> Result<&mut Self, EncodeError> {
        let input = value.into();
        if tag == Tag::UasDatalinkLsVersionNumber {
            self.check.clear();
            self.check.set_ref(tag, &input)?;
            let version = self.check.version_override();
            self.set_version(version);
            return Ok(self);
        }
        if matches!(input, Input::Value(Value::Unknown)) {
            return self.unknown(tag, at);
        }
        self.exclusive(tag)?;
        self.check.clear();
        self.check.set_ref(tag, &input)?;
        self.store(tag, Arc::new(input), at);
        Ok(self)
    }

    /// Mark item `tag` unknown from MISP time `at`: snapshots write it as a
    /// zero-length item (ST 0601.19 section 6.5) until it is set or cleared.
    /// Refused for the items that may not be zero length (1, 2, 65, 100,
    /// 101, 102, 115; R-ST0601-ENCODE-48, -49).
    pub fn unknown(&mut self, tag: Tag, at: MispTime) -> Result<&mut Self, EncodeError> {
        self.exclusive(tag)?;
        self.check.clear();
        self.check.unknown(tag)?;
        let value = Arc::clone(&self.unknown);
        self.store(tag, value, at);
        Ok(self)
    }

    /// Set the ST 0102 security set (tag 48), checked and encoded under the
    /// state's options.
    pub fn set_security(&mut self, security: &Security, at: MispTime) -> Result<&mut Self, EncodeError> {
        let items = security.encode_with(&self.opts, &mut Vec::new(), false)?;
        self.set(Tag::SecurityLocalSet, Input::Set(items), at)
    }

    /// Set the ST 0903 VMTI set (tag 74), checked and encoded under the
    /// state's options. A packet with VMTI also needs the frame centre
    /// (tags 23 and 24, DECISIONS D-31), checked when it is encoded.
    pub fn set_vmti(&mut self, vmti: &Vmti, at: MispTime) -> Result<&mut Self, EncodeError> {
        let items = vmti.encode_with(&self.opts, &mut Vec::new())?;
        self.set(Tag::VmtiLocalSet, Input::Set(items), at)
    }

    /// Stop reporting item `tag` (tag 65: drop the version override).
    /// Returns whether there was a value.
    pub fn clear(&mut self, tag: Tag) -> bool {
        if tag == Tag::UasDatalinkLsVersionNumber {
            let had = self.version.is_some();
            self.set_version(None);
            return had;
        }
        match self.slots.get_mut(tag as usize).and_then(Option::take) {
            Some(_) => {
                self.count -= 1;
                self.revision += 1;
                true
            }
            None => false,
        }
    }

    /// Stop reporting every item, and drop the version override.
    pub fn clear_all(&mut self) {
        if self.count == 0 && self.version.is_none() {
            return;
        }
        self.slots.iter_mut().for_each(|s| *s = None);
        self.count = 0;
        self.version = None;
        self.revision += 1;
    }

    /// Override tag 65 (`None`: the default, 19; DECISIONS D-05).
    pub fn set_version(&mut self, version: Option<u8>) -> &mut Self {
        if self.version != version {
            self.version = version;
            self.revision += 1;
        }
        self
    }

    /// The tag 65 override.
    #[must_use]
    pub fn version(&self) -> Option<u8> {
        self.version
    }

    /// The value of `tag`, stale or not (`Input::Value(Value::Unknown)`
    /// for an item marked unknown).
    #[must_use]
    pub fn get(&self, tag: Tag) -> Option<&Input> {
        self.slot(tag).map(|s| &*s.value)
    }

    /// When the value of `tag` was set.
    #[must_use]
    pub fn set_at(&self, tag: Tag) -> Option<MispTime> {
        self.slot(tag).map(|s| s.at)
    }

    /// Whether `tag` has a value.
    #[must_use]
    pub fn contains(&self, tag: Tag) -> bool {
        self.slot(tag).is_some()
    }

    /// How many items have a value (the version override not counted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// No item has a value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Every value, in ascending tag order, with the time it was set at.
    pub fn iter(&self) -> impl Iterator<Item = (Tag, &Input, MispTime)> + '_ {
        self.slots.iter().flatten().map(|s| (s.tag, &*s.value, s.at))
    }

    /// A counter that grows with every change (a value set or marked
    /// unknown, a value cleared, the version changed). Compare it with the
    /// value at the last snapshot to tell whether anything changed; values
    /// going stale do not change it (see [`MetadataState::next_expiry`]).
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The values at MISP time `now`, staleness applied: stale values are
    /// left out or written as unknown ([`Staleness::policy`]). Items come in
    /// ascending tag order. Taking a snapshot copies no value.
    #[must_use]
    pub fn snapshot(&self, now: MispTime) -> Snapshot {
        let mut items = Vec::with_capacity(self.count);
        for s in self.slots.iter().flatten() {
            if !self.staleness.is_stale(s.tag, s.at, now) {
                items.push(Entry { tag: s.tag, value: Arc::clone(&s.value) });
            } else if self.staleness.policy == StalePolicy::Unknown {
                items.push(Entry { tag: s.tag, value: Arc::clone(&self.unknown) });
            }
        }
        Snapshot::from_parts(now, self.version, items)
    }

    /// The earliest MISP time after `now` at which a value that is fresh at
    /// `now` goes stale, so that a snapshot taken then differs from one
    /// taken at `now` without any change to the state. `None` if no value
    /// will go stale.
    #[must_use]
    pub fn next_expiry(&self, now: MispTime) -> Option<MispTime> {
        self.slots.iter().flatten().filter_map(|s| self.staleness.expiry(s.tag, s.at)).filter(|&t| t > now).min()
    }

    fn slot(&self, tag: Tag) -> Option<&Slot> {
        self.slots.get(tag as usize).and_then(Option::as_ref)
    }

    fn store(&mut self, tag: Tag, value: Arc<Input>, at: MispTime) {
        if let Some(slot) = self.slots.get_mut(tag as usize) {
            if slot.is_none() {
                self.count += 1;
            }
            *slot = Some(Slot { tag, value, at });
            self.revision += 1;
        }
    }

    /// R-ST0601-ENCODE-83: items 75 and 104 are never in one packet.
    fn exclusive(&self, tag: Tag) -> Result<(), EncodeError> {
        let other = match tag {
            Tag::SensorEllipsoidHeight => Tag::SensorEllipsoidHeightExtended,
            Tag::SensorEllipsoidHeightExtended => Tag::SensorEllipsoidHeight,
            _ => return Ok(()),
        };
        if self.contains(other) {
            return Err(EncodeError::new(
                Standard::St0601,
                Some(tag as u64),
                ErrorKind::NotAllowed,
                "items 75 and 104 are exclusive: clear the other first",
            ));
        }
        Ok(())
    }
}

/// One item of a snapshot; values are shared with the state or track.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Entry {
    pub(crate) tag: Tag,
    pub(crate) value: Arc<Input>,
}

/// An immutable, consistent set of ST 0601 values at one MISP time, from a
/// [`MetadataState`] or a [`crate::track::Track`].
///
/// Cloning is cheap (the items are shared). It is `Send` and `Sync`, so it
/// can be taken under a lock and encoded elsewhere. Encode it with
/// [`Snapshot::encode_at`]; give its items to other code (for example a
/// `misb::mux::Sample`) with [`Snapshot::items`] or [`Snapshot::to_items`].
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    time: MispTime,
    version: Option<u8>,
    /// Ascending tag order, one entry per tag.
    items: Arc<[Entry]>,
}

impl Snapshot {
    pub(crate) fn from_parts(time: MispTime, version: Option<u8>, items: Vec<Entry>) -> Snapshot {
        Snapshot { time, version, items: items.into() }
    }

    /// The MISP time the snapshot was taken at (staleness and interpolation
    /// were evaluated at it). The packet's tag 2 is the time given to
    /// [`Snapshot::encode_at`].
    #[must_use]
    pub fn time(&self) -> MispTime {
        self.time
    }

    /// The tag 65 override, if any.
    #[must_use]
    pub fn version(&self) -> Option<u8> {
        self.version
    }

    /// How many items the snapshot holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// The snapshot holds no item (it still encodes to a packet with tags
    /// 2, 65 and 1).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The items in ascending tag order. `Input::Value(Value::Unknown)` is
    /// an item written with zero length (unknown).
    pub fn items(&self) -> impl ExactSizeIterator<Item = (Tag, &Input)> + '_ {
        self.items.iter().map(|e| (e.tag, &*e.value))
    }

    /// The value of `tag`, if the snapshot holds it.
    #[must_use]
    pub fn get(&self, tag: Tag) -> Option<&Input> {
        self.items.binary_search_by(|e| e.tag.cmp(&tag)).ok().map(|i| &*self.items[i].value)
    }

    /// The items copied out, in the form `misb::mux::Sample::items` and
    /// `misb::json::Record` use.
    #[must_use]
    pub fn to_items(&self) -> Vec<(Tag, Input)> {
        self.items.iter().map(|e| (e.tag, (*e.value).clone())).collect()
    }

    /// Whether two snapshots hold the same version and items, whatever
    /// their times (for on-change rates fed by a track, whose values change
    /// without a revision counter).
    #[must_use]
    pub fn same_items(&self, other: &Snapshot) -> bool {
        self.version == other.version && self.items == other.items
    }

    /// One ST 0601 packet with tag 2 = `time` and these items, encoded
    /// under `opts` (the item order of [`EncodeOptions::order`], tag 65 the
    /// override or 19).
    pub fn encode_at(&self, time: MispTime, opts: &EncodeOptions) -> Result<Vec<u8>, EncodeError> {
        self.to_builder(time, opts)?.finish()
    }

    /// A builder holding this snapshot's packet with tag 2 = `time`, for
    /// its [`warnings`](St0601Builder::warnings) or to add items.
    pub fn to_builder(&self, time: MispTime, opts: &EncodeOptions) -> Result<St0601Builder, EncodeError> {
        let mut b = St0601Builder::with_options(time, opts.clone());
        self.fill(time, &mut b)?;
        Ok(b)
    }

    /// Load this snapshot into a reused builder (its options are kept):
    /// clear it, set tag 2 = `time`, the version and every item. Follow
    /// with [`St0601Builder::finish_into`] to encode without allocating
    /// once the buffers have grown. On an error the builder holds the items
    /// before the failing one.
    pub fn fill<'b>(&self, time: MispTime, builder: &'b mut St0601Builder) -> Result<&'b mut St0601Builder, EncodeError> {
        builder.clear().time(time).version(self.version.unwrap_or(ST0601_VERSION));
        for e in self.items.iter() {
            builder.set_ref(e.tag, &e.value)?;
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: MispTime = MispTime::from_micros(1_000_000_000);

    fn at(us: u64) -> MispTime {
        MispTime::from_micros(T0.as_micros() + us)
    }

    #[test]
    fn staleness_boundaries() {
        let mut s = Staleness::with_max_age(Duration::from_micros(10));
        s.set_max_age(Tag::MissionId, None);
        assert!(!s.is_stale(Tag::SensorLatitude, T0, at(10)));
        assert!(s.is_stale(Tag::SensorLatitude, T0, at(11)));
        assert!(!s.is_stale(Tag::SensorLatitude, at(5), T0));
        assert!(!s.is_stale(Tag::MissionId, T0, at(1 << 40)));
        assert_eq!(s.expiry(Tag::SensorLatitude, T0), Some(at(11)));
        assert_eq!(s.expiry(Tag::MissionId, T0), None);
        // Sub-microsecond parts of a maximum age never make a value stale
        // earlier than its whole microseconds allow.
        let s = Staleness::with_max_age(Duration::from_nanos(10_500));
        assert!(!s.is_stale(Tag::SensorLatitude, T0, at(10)));
        assert!(s.is_stale(Tag::SensorLatitude, T0, at(11)));
        assert_eq!(s.expiry(Tag::SensorLatitude, T0), Some(at(11)));
        let mut s = Staleness::with_max_age(Duration::from_secs(1));
        s.set_max_age(Tag::MissionId, None).remove_override(Tag::MissionId);
        assert_eq!(s.max_age(Tag::MissionId), Some(Duration::from_secs(1)));
    }

    #[test]
    fn revision_counts_changes_only() {
        let mut s = MetadataState::new();
        assert_eq!(s.revision(), 0);
        s.set(Tag::SensorLatitude, 1.0, T0).unwrap();
        assert_eq!(s.revision(), 1);
        assert!(!s.clear(Tag::SensorLongitude));
        assert_eq!(s.revision(), 1);
        s.set_version(None);
        assert_eq!(s.revision(), 1);
        s.set_version(Some(17));
        assert_eq!(s.revision(), 2);
        assert!(s.clear(Tag::SensorLatitude));
        assert_eq!(s.revision(), 3);
        s.clear_all();
        assert_eq!(s.revision(), 4);
        s.clear_all();
        assert_eq!(s.revision(), 4);
    }
}
