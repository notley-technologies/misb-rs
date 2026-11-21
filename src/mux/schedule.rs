//! Turning a metadata source into timed units for an injector.

use super::anchor::{wrap_pts, Anchor, PtsUnwrapper};
use super::rate::{Rate, RateError, RateLimiter};
use super::source::{Sample, SampleData, SampleError};
use crate::encode::EncodeOptions;
use crate::MispTime;
use std::collections::{BinaryHeap, VecDeque};
use std::cmp::Reverse;
use std::fmt;
use std::iter::Peekable;

/// 90 kHz ticks per millisecond.
const TICKS_PER_MS: i64 = 90;
/// A recorded packet waiting to be snapped goes out unsnapped when no
/// frame came within this much (on top of the minimum lead) of its PTS.
const SNAP_FALLBACK_MS: i64 = 20;

/// How the metadata is carried, which decides whether units get a PTS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Carriage {
    /// Synchronous KLV (stream_type 0x15): every unit has the PTS of the
    /// moment it describes.
    Sync,
    /// Asynchronous KLV (stream_type 0x06): no PTS; a unit goes out just
    /// before the video frame it describes (st1402-time.md D-7).
    Async,
}

/// Where the MISP time line meets the program clock (MUXING_PLAN.md
/// section 5). The input's own ST 0604 timestamps (the best anchor) and the
/// live wall clock come in later phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnchorSpec {
    /// The first video frame (in presentation order) is at this MISP time.
    /// Convert a UTC instant with [`MispTime::from_utc`].
    FirstFrame(MispTime),
    /// The first video frame is at the time of the first sample: the
    /// metadata is aligned to the start of the video, keeping its own
    /// times (recorded packets are not changed).
    SourceStart,
    /// The 33-bit PTS `pts` is MISP time `misp`.
    Pts {
        /// A PTS on the program's clock.
        pts: u64,
        /// The MISP time at that PTS.
        misp: MispTime,
    },
}

/// What a [`Scheduler`] does.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ScheduleConfig {
    /// Sync or async units.
    pub carriage: Carriage,
    /// Where MISP time meets the program clock.
    pub anchor: AnchorSpec,
    /// Which frames get metadata; [`Rate::Explicit`] sends each sample at
    /// its own time.
    pub rate: Rate,
    /// Options for the packets built from items.
    pub encode: EncodeOptions,
    /// How far ahead of the input's program clock samples are turned into
    /// units. It must exceed the injector's largest lead (990 ms by
    /// default) so units are queued before their window opens. Default
    /// 1500 ms.
    pub horizon_ms: u32,
    /// A unit whose PTS is closer than this to the input's clock would be
    /// late (D-ISO13818-14) and is skipped. Default 1 ms.
    pub min_lead_ms: u32,
    /// When sampling at frames, how long a sample's values stay valid
    /// after its time; frames later than that get no metadata until the
    /// next sample, so a source that stopped is not repeated forever.
    /// `None`: until the next sample. Default 3000 ms.
    pub max_hold_ms: Option<u32>,
    /// Move each recorded packet's PTS to the nearest video frame's PTS
    /// (D-6 option; mirrors the receiver rule of ISO/IEC 13818-1 2.12.2).
    /// Tag 2 is not changed. Default false.
    pub snap_to_frames: bool,
    /// Frames held to put B-frames back in presentation order. Default 16
    /// (the H.264 and H.265 limit on reordering).
    pub reorder_depth: usize,
}

impl ScheduleConfig {
    /// Defaults for a carriage: the anchor at the source start, every
    /// sample at its own time.
    #[must_use]
    pub fn new(carriage: Carriage) -> ScheduleConfig {
        ScheduleConfig {
            carriage,
            anchor: AnchorSpec::SourceStart,
            rate: Rate::Explicit,
            encode: EncodeOptions::default(),
            horizon_ms: 1500,
            min_lead_ms: 1,
            max_hold_ms: Some(3000),
            snap_to_frames: false,
            reorder_depth: 16,
        }
    }

    /// Check the settings.
    pub fn validate(&self) -> Result<(), ScheduleError> {
        self.rate.validate().map_err(ScheduleError::Rate)?;
        if self.horizon_ms < 100 || self.horizon_ms > 60_000 {
            return Err(ScheduleError::Config("horizon_ms must be between 100 and 60000"));
        }
        if self.min_lead_ms > 1000 {
            return Err(ScheduleError::Config("min_lead_ms must be at most 1000"));
        }
        if self.reorder_depth == 0 || self.reorder_depth > 64 {
            return Err(ScheduleError::Config("reorder_depth must be between 1 and 64"));
        }
        Ok(())
    }
}

/// A video frame as the injector sees it, in decode order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTime {
    /// PTS, 33 bits.
    pub pts: u64,
    /// DTS when coded (B-frame video).
    pub dts: Option<u64>,
    /// The program clock time base changed before this frame.
    pub discontinuity: bool,
}

/// A unit for the injector: an ST 0601 packet and, for synchronous
/// carriage, its PTS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledUnit {
    /// The 33-bit PTS, `None` for asynchronous carriage.
    pub pts: Option<u64>,
    /// One complete ST 0601 packet.
    pub data: Vec<u8>,
}

/// Counters of a [`Scheduler`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScheduleStats {
    /// Units handed to the injector.
    pub units: u64,
    /// Samples read from the source.
    pub samples: u64,
    /// Samples skipped because their time goes back.
    pub out_of_order: u64,
    /// Units skipped because they would arrive too late (before the video
    /// started, or the source is behind the input).
    pub late: u64,
    /// Recorded packets whose PTS was moved to a frame's.
    pub snapped: u64,
    /// Frames that got no metadata because the last sample was too old.
    pub stale: u64,
    /// Samples left when the input ended.
    pub unused: u64,
    /// Program clock discontinuities the time line was carried across.
    pub discontinuities: u64,
}

/// Why scheduling stopped.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ScheduleError {
    /// A setting is out of range.
    Config(&'static str),
    /// The rate is invalid.
    Rate(RateError),
    /// A recorded packet can only go out at its own time; sampling at
    /// frames needs items (D-6).
    RecordedNeedsExplicit,
    /// A sample did not encode.
    Sample(SampleError),
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScheduleError::Config(m) => f.write_str(m),
            ScheduleError::Rate(e) => e.fmt(f),
            ScheduleError::RecordedNeedsExplicit => {
                f.write_str("recorded packets keep their own tag 2 and need Rate::Explicit; sample items instead")
            }
            ScheduleError::Sample(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ScheduleError {}

impl From<SampleError> for ScheduleError {
    fn from(e: SampleError) -> ScheduleError {
        ScheduleError::Sample(e)
    }
}

/// Turns a stream of [`Sample`]s into [`ScheduledUnit`]s for an injector,
/// from the video frames and program clock of the stream being injected
/// into. Pure logic: no I/O, no clock; the caller passes in what the
/// injector saw.
///
/// - With [`Rate::Explicit`], every sample goes out at its own time: its
///   PTS is the anchor applied to its tag 2 (rounded to the nearest 90 kHz
///   tick, or snapped to a frame), handed over once it is within
///   [`horizon_ms`](ScheduleConfig::horizon_ms) of the input's clock.
///   Recorded packets go out byte for byte.
/// - With a frame rate, frames are put back in presentation order and each
///   frame the [`RateLimiter`] admits gets the latest sample at or before
///   its time, encoded with tag 2 = the frame's MISP time and PTS = the
///   frame's PTS, so time and PTS agree exactly (D-6).
///
/// The anchor is set on the first frame in presentation order. A program
/// clock discontinuity carries the time line across: the first frame after
/// it continues one frame period after the last frame before it.
pub struct Scheduler<S: Iterator<Item = Sample>> {
    cfg: ScheduleConfig,
    source: Peekable<S>,
    rate: RateLimiter,
    unwrap: PtsUnwrapper,
    /// How the next anchor is set: the configured one, or after a
    /// discontinuity the continued time line.
    anchor_spec: AnchorSpec,
    anchor: Option<Anchor>,
    /// Decode-order frames waiting for presentation order: unwrapped PTS.
    reorder: BinaryHeap<Reverse<i64>>,
    /// Highest unwrapped DTS seen.
    dts: Option<i64>,
    /// The last two frames released, unwrapped PTS (period estimate,
    /// carrying the time line across a discontinuity).
    released: (Option<i64>, Option<i64>),
    /// Recorded samples waiting for the frames around them (snap) or, for
    /// async carriage, for their frame: (unwrapped PTS, sample).
    waiting: VecDeque<(i64, Sample)>,
    /// The sample whose values hold at the current frame (sampling).
    current: Option<Sample>,
    last_time: Option<MispTime>,
    stats: ScheduleStats,
}

impl<S: Iterator<Item = Sample>> fmt::Debug for Scheduler<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheduler").field("cfg", &self.cfg).field("anchor", &self.anchor).field("stats", &self.stats).finish()
    }
}

impl<S: Iterator<Item = Sample>> Scheduler<S> {
    /// A scheduler reading `source`.
    pub fn new(cfg: ScheduleConfig, source: S) -> Result<Self, ScheduleError> {
        cfg.validate()?;
        Ok(Scheduler {
            rate: RateLimiter::new(cfg.rate).map_err(ScheduleError::Rate)?,
            anchor_spec: cfg.anchor,
            cfg,
            source: source.peekable(),
            unwrap: PtsUnwrapper::new(),
            anchor: None,
            reorder: BinaryHeap::new(),
            dts: None,
            released: (None, None),
            waiting: VecDeque::new(),
            current: None,
            last_time: None,
            stats: ScheduleStats::default(),
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &ScheduleConfig {
        &self.cfg
    }

    /// The anchor, once set.
    #[must_use]
    pub fn anchor(&self) -> Option<Anchor> {
        self.anchor
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> ScheduleStats {
        self.stats
    }

    fn explicit(&self) -> bool {
        self.cfg.rate == Rate::Explicit
    }

    /// A video frame, in decode order, seen at program clock `clock` (27
    /// MHz). Units for this frame and earlier ones go to `out`.
    pub fn frame<E>(
        &mut self,
        frame: &FrameTime,
        clock: Option<u64>,
        out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>,
    ) -> Result<(), Flow<E>> {
        if frame.discontinuity && self.unwrap_seeded() {
            self.discontinuity(out)?;
        }
        let pts = self.unwrap.unwrap(frame.pts);
        let dts = frame.dts.map_or(pts, |d| self.unwrap.peek(d));
        self.dts = Some(self.dts.map_or(dts, |d| d.max(dts)));
        self.reorder.push(Reverse(pts));
        let now = self.now(clock);
        // Async samples go out just before the first frame (decode order)
        // that shows their time (D-7).
        if self.cfg.carriage == Carriage::Async && self.explicit() {
            self.release_waiting(|p| p <= pts, now, out)?;
        }
        while let Some(&Reverse(p)) = self.reorder.peek() {
            let safe = self.dts.map_or(false, |d| p <= d);
            if !safe && self.reorder.len() <= self.cfg.reorder_depth {
                break;
            }
            self.reorder.pop();
            self.presented(p, now, out)?;
        }
        self.tick(clock, out)
    }

    /// The input reached program clock `clock`: hand over the samples now
    /// within the horizon. Call it after every input chunk; [`frame`]
    /// calls it too.
    ///
    /// [`frame`]: Scheduler::frame
    pub fn tick<E>(&mut self, clock: Option<u64>, out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>) -> Result<(), Flow<E>> {
        let Some(now) = self.now(clock) else { return Ok(()) };
        if self.anchor.is_none() {
            if let AnchorSpec::Pts { pts, misp } = self.anchor_spec {
                self.anchor = Some(Anchor::new(self.unwrap.peek(pts), misp));
            }
        }
        if !self.explicit() {
            return Ok(());
        }
        let Some(anchor) = self.anchor else { return Ok(()) };
        let horizon = now + i64::from(self.cfg.horizon_ms) * TICKS_PER_MS;
        while let Some(s) = self.source.peek() {
            let pts = anchor.pts_at(s.time);
            if pts > horizon {
                break;
            }
            let Some(s) = self.next_sample() else { continue };
            if self.cfg.snap_to_frames || self.cfg.carriage == Carriage::Async {
                self.waiting.push_back((pts, s));
            } else {
                self.emit(pts, Some(pts), &s, s.time, Some(now), out)?;
            }
        }
        // Without frames to snap to or to wait for, waiting samples go out
        // once they are close: async at their time, sync just before the
        // last moment they can still be placed.
        let cutoff = match self.cfg.carriage {
            Carriage::Async => now,
            Carriage::Sync => now + (i64::from(self.cfg.min_lead_ms) + SNAP_FALLBACK_MS) * TICKS_PER_MS,
        };
        self.release_waiting(|p| p <= cutoff, Some(now), out)
    }

    /// The input ended: flush the frames still held and count the samples
    /// left over.
    pub fn finish<E>(&mut self, clock: Option<u64>, out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>) -> Result<ScheduleStats, Flow<E>> {
        let now = self.now(clock);
        while let Some(Reverse(p)) = self.reorder.pop() {
            self.presented(p, now, out)?;
        }
        self.tick(clock, out)?;
        self.stats.unused += self.waiting.len() as u64;
        self.waiting.clear();
        while self.next_sample().is_some() {
            self.stats.unused += 1;
        }
        Ok(self.stats)
    }

    fn unwrap_seeded(&self) -> bool {
        self.unwrap != PtsUnwrapper::new()
    }

    /// The input clock as unwrapped 90 kHz ticks.
    fn now(&self, clock: Option<u64>) -> Option<i64> {
        clock.map(|c| self.unwrap.peek(c / 300))
    }

    /// The next sample in time order, skipping ones that go back.
    fn next_sample(&mut self) -> Option<Sample> {
        loop {
            let s = self.source.next()?;
            self.stats.samples += 1;
            if self.last_time.map_or(false, |t| s.time < t) {
                self.stats.out_of_order += 1;
                continue;
            }
            self.last_time = Some(s.time);
            return Some(s);
        }
    }

    /// A frame in presentation order (unwrapped PTS `pts`).
    fn presented<E>(&mut self, pts: i64, now: Option<i64>, out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>) -> Result<(), Flow<E>> {
        if self.released.1.map_or(false, |last| pts <= last) {
            return Ok(());
        }
        self.released = (self.released.1, Some(pts));
        if self.anchor.is_none() {
            self.anchor = match self.anchor_spec {
                AnchorSpec::FirstFrame(t) => Some(Anchor::new(pts, t)),
                AnchorSpec::SourceStart => self.source.peek().map(|s| Anchor::new(pts, s.time)),
                AnchorSpec::Pts { pts: p, misp } => Some(Anchor::new(self.unwrap.peek(p), misp)),
            };
        }
        let Some(anchor) = self.anchor else { return Ok(()) };
        if self.explicit() {
            if self.cfg.snap_to_frames && self.cfg.carriage == Carriage::Sync {
                self.snap(pts, now, out)?;
            }
            return Ok(());
        }
        let Some(time) = anchor.misp_at(pts) else { return Ok(()) };
        while self.source.peek().map_or(false, |s| s.time <= time) {
            if let Some(s) = self.next_sample() {
                if matches!(s.data, SampleData::Packet(_)) {
                    return Err(Flow::Schedule(ScheduleError::RecordedNeedsExplicit));
                }
                self.current = Some(s);
            }
        }
        let Some(current) = self.current.take() else { return Ok(()) };
        let age_ms = (time.as_micros() - current.time.as_micros()) / 1000;
        let fresh = self.cfg.max_hold_ms.map_or(true, |hold| age_ms <= u64::from(hold));
        let result = if !fresh {
            self.stats.stale += 1;
            Ok(())
        } else if self.rate.admit(pts) {
            let unit_pts = (self.cfg.carriage == Carriage::Sync).then_some(pts);
            self.emit(pts, unit_pts, &current, time, now, out)
        } else {
            Ok(())
        };
        self.current = Some(current);
        result
    }

    /// Move waiting recorded samples to the nearest frame once the frames
    /// on both sides of them are known.
    fn snap<E>(&mut self, frame: i64, now: Option<i64>, out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>) -> Result<(), Flow<E>> {
        while let Some(&(pts, _)) = self.waiting.front() {
            if pts > frame {
                break;
            }
            let (pts, s) = self.waiting.pop_front().expect("front exists");
            let before = self.released.0.filter(|&b| b <= pts);
            let snapped = match before {
                Some(b) if pts - b < frame - pts => b,
                _ => frame,
            };
            if snapped != pts {
                self.stats.snapped += 1;
            }
            self.emit(snapped, Some(snapped), &s, s.time, now, out)?;
        }
        Ok(())
    }

    fn release_waiting<E>(
        &mut self,
        due: impl Fn(i64) -> bool,
        now: Option<i64>,
        out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>,
    ) -> Result<(), Flow<E>> {
        while let Some(&(pts, _)) = self.waiting.front() {
            if !due(pts) {
                break;
            }
            let (pts, s) = self.waiting.pop_front().expect("front exists");
            let unit_pts = (self.cfg.carriage == Carriage::Sync).then_some(pts);
            self.emit(pts, unit_pts, &s, s.time, now, out)?;
        }
        Ok(())
    }

    /// Build the unit for sample `s` at MISP time `time` and hand it over,
    /// unless a synchronous unit would be late.
    fn emit<E>(
        &mut self,
        pts: i64,
        unit_pts: Option<i64>,
        s: &Sample,
        time: MispTime,
        now: Option<i64>,
        out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>,
    ) -> Result<(), Flow<E>> {
        if unit_pts.is_some() {
            let min_lead = i64::from(self.cfg.min_lead_ms) * TICKS_PER_MS;
            if now.map_or(false, |now| pts - now < min_lead) {
                self.stats.late += 1;
                return Ok(());
            }
        }
        let data = s.encode_at(time, &self.cfg.encode).map_err(|e| Flow::Schedule(e.into()))?;
        out(ScheduledUnit { pts: unit_pts.map(wrap_pts), data }).map_err(Flow::Out)?;
        self.stats.units += 1;
        Ok(())
    }

    /// The program clock jumped: present the frames held under the old
    /// time line, then continue it one frame period after the last frame.
    fn discontinuity<E>(&mut self, out: &mut dyn FnMut(ScheduledUnit) -> Result<(), E>) -> Result<(), Flow<E>> {
        while let Some(Reverse(p)) = self.reorder.pop() {
            self.presented(p, None, out)?;
        }
        self.stats.discontinuities += 1;
        let next_time = match (self.anchor, self.released) {
            (Some(a), (Some(prev), Some(last))) => a.misp_at(last + (last - prev).clamp(1, 90_000)),
            (Some(a), (None, Some(last))) => a.misp_at(last),
            _ => None,
        };
        self.unwrap.reset();
        self.dts = None;
        self.released = (None, None);
        self.rate.reset();
        // Samples already turned into PTS on the old clock cannot be
        // placed on the new one.
        self.stats.late += self.waiting.len() as u64;
        self.waiting.clear();
        self.anchor = None;
        if let Some(t) = next_time {
            self.anchor_spec = AnchorSpec::FirstFrame(t);
        }
        Ok(())
    }
}

/// Why a [`Scheduler`] call stopped: its own error, or the error the
/// output callback returned.
#[derive(Clone, Debug, PartialEq)]
pub enum Flow<E> {
    /// The scheduler failed.
    Schedule(ScheduleError),
    /// The output callback failed (for example the injector's queue is
    /// full).
    Out(E),
}

impl<E: fmt::Display> fmt::Display for Flow<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flow::Schedule(e) => e.fmt(f),
            Flow::Out(e) => e.fmt(f),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for Flow<E> {}
