//! Live injection (MUXING_PLAN.md section 6.7): metadata from a
//! [`MetadataState`] that changes at any time, put into a live transport
//! stream as its video frames pass.

use super::anchor::{wrap_pts, Anchor, PtsUnwrapper};
use super::rate::{Rate, RateError, RateLimiter};
use super::schedule::Carriage;
use super::video::{frame_timestamp, TimestampWriter, VideoTimestampOptions, VideoTimestampStats, VideoTimestamps};
use crate::encode::{EncodeError, EncodeOptions};
use crate::st0604::{Jump, Timestamp};
use crate::state::MetadataState;
use crate::MispTime;
use mpegts::mux::{
    Frame, FrameReorder, InjectConfig, InjectError, InjectEvent, InjectStats, Injector, InsertUnit, KlvCarriage,
    PacketSink, Units, VideoSei,
};
use mpegts::ClockMode;
use std::collections::VecDeque;
use std::fmt;

/// Where the MISP time line of a live stream meets its program clock
/// (MUXING_PLAN.md section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum LiveAnchor {
    /// The first video frame is at the wall-clock time its first packet
    /// arrived (the `now` passed to [`LiveMux::push`]), and again after
    /// each program clock discontinuity. The default.
    #[default]
    WallClock,
    /// The first video frame is at this MISP time; the time line is
    /// carried across discontinuities.
    FirstFrame(MispTime),
    /// The 33-bit PTS `pts` is MISP time `misp`.
    Pts {
        /// A PTS on the program's clock.
        pts: u64,
        /// The MISP time at that PTS.
        misp: MispTime,
    },
}

/// Settings of a [`LiveMux`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct LiveMuxConfig {
    /// Where and how the KLV goes into the stream. [`LiveMuxConfig::new`]
    /// sets the extrapolating program clock ([`ClockMode::Extrapolate`]),
    /// so no input packet waits for the next PCR; the video SEI mode is
    /// set from the options below.
    pub inject: InjectConfig,
    /// Which frames get metadata: [`Rate::EveryFrame`],
    /// [`Rate::EveryNthFrame`] or [`Rate::Hz`]. Defaults:
    /// [`Rate::SYNC_DEFAULT`] and [`Rate::ASYNC_DEFAULT`].
    pub rate: Rate,
    /// Where MISP time meets the program clock.
    pub anchor: LiveAnchor,
    /// Take MISP time from the video's ST 0604 timestamps when it carries
    /// them, ahead of `anchor` (st1402-time.md D-15): a frame's own
    /// timestamp is its metadata's tag 2, and the anchor follows the
    /// timestamps (see [`ScheduleConfig::video_anchor`]). Default false.
    ///
    /// [`ScheduleConfig::video_anchor`]: super::ScheduleConfig::video_anchor
    pub video_anchor: bool,
    /// Re-anchor on a frame whose ST 0604 time strays from the anchor's
    /// prediction by more than this, in microseconds. Default 1000.
    pub video_anchor_tolerance_us: u32,
    /// Writing ST 0604 timestamps into the video. Default off.
    pub video_timestamps: VideoTimestampOptions,
    /// Options for the packets built from the state.
    pub encode: EncodeOptions,
    /// Frames held to put B-frames back in presentation order. Default 16.
    /// Only the metadata waits; video packets are never held for it.
    pub reorder_depth: usize,
}

impl LiveMuxConfig {
    /// Defaults for a carriage: the wall-clock anchor, the carriage's
    /// default rate, no video timestamps.
    #[must_use]
    pub fn new(carriage: Carriage) -> LiveMuxConfig {
        let (klv, rate) = match carriage {
            Carriage::Sync => (KlvCarriage::Sync, Rate::SYNC_DEFAULT),
            Carriage::Async => (KlvCarriage::Async, Rate::ASYNC_DEFAULT),
        };
        LiveMuxConfig {
            inject: InjectConfig::default().with_carriage(klv).with_clock(ClockMode::Extrapolate),
            rate,
            anchor: LiveAnchor::WallClock,
            video_anchor: false,
            video_anchor_tolerance_us: 1000,
            video_timestamps: VideoTimestampOptions::default(),
            encode: EncodeOptions::default(),
            reorder_depth: 16,
        }
    }

    /// The carriage, from the injector settings.
    #[must_use]
    pub fn carriage(&self) -> Carriage {
        match self.inject.carriage {
            KlvCarriage::Async => Carriage::Async,
            _ => Carriage::Sync,
        }
    }

    /// Check the settings.
    pub fn validate(&self) -> Result<(), LiveMuxError> {
        self.rate.validate().map_err(LiveMuxError::Rate)?;
        if self.rate == Rate::Explicit {
            return Err(LiveMuxError::Config("live metadata is sampled at video frames: use a frame rate, not Explicit"));
        }
        if self.reorder_depth == 0 || self.reorder_depth > 64 {
            return Err(LiveMuxError::Config("reorder_depth must be between 1 and 64"));
        }
        self.encode.validate().map_err(LiveMuxError::Encode)
    }
}

/// Why a [`LiveMux`] stopped.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum LiveMuxError {
    /// A setting is out of range.
    Config(&'static str),
    /// The rate is invalid.
    Rate(RateError),
    /// The encoder options are invalid.
    Encode(EncodeError),
    /// The injector failed.
    Inject(InjectError),
}

impl fmt::Display for LiveMuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveMuxError::Config(m) => f.write_str(m),
            LiveMuxError::Rate(e) => e.fmt(f),
            LiveMuxError::Encode(e) => e.fmt(f),
            LiveMuxError::Inject(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LiveMuxError {}

impl From<InjectError> for LiveMuxError {
    fn from(e: InjectError) -> LiveMuxError {
        LiveMuxError::Inject(e)
    }
}

/// Counters of a [`LiveMux`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LiveMuxStats {
    /// The injector's counters.
    pub inject: InjectStats,
    /// Video frames seen.
    pub frames: u64,
    /// Metadata units handed to the injector.
    pub units: u64,
    /// Of those, units sent because of [`LiveMux::emit`] (or a control
    /// line's `emit`) that the rate alone would not have sent.
    pub emitted: u64,
    /// Frames due for metadata while the state held nothing to send.
    pub empty: u64,
    /// Units not sent because their PTS would have gone back (after the
    /// anchor moved back).
    pub late: u64,
    /// Units the injector refused (its queue was full).
    pub refused: u64,
    /// Snapshots that did not encode (see [`LiveMux::last_encode_error`]).
    pub encode_errors: u64,
    /// Program clock discontinuities.
    pub discontinuities: u64,
    /// Times the anchor moved to the video's ST 0604 time after it was
    /// set.
    pub reanchors: u64,
    /// ST 0604 timestamps found in and written to the video.
    pub video: VideoTimestampStats,
}

/// Everything the frame callback changes, apart from the injector.
#[derive(Debug)]
struct Core {
    cfg: LiveMuxConfig,
    state: MetadataState,
    rate: RateLimiter,
    reorder: FrameReorder,
    unwrap: PtsUnwrapper,
    anchor: Option<Anchor>,
    /// After a discontinuity with a carried time line: the next frame's
    /// time.
    carried: Option<MispTime>,
    /// The last two frames presented, unwrapped PTS.
    released: (Option<i64>, Option<i64>),
    /// ST 0604 times of frames not yet presented.
    video_times: VecDeque<(i64, MispTime)>,
    jump: Option<Jump>,
    last_unit: Option<i64>,
    /// The time of the current push.
    now: MispTime,
    emit: bool,
    writer: TimestampWriter,
    scanning: bool,
    failed: Option<LiveMuxError>,
    last_encode_error: Option<EncodeError>,
    stats: LiveMuxStats,
}

/// Live KLV injection: a live transport stream goes through, and each
/// video frame the rate admits gets one ST 0601 packet built from a
/// snapshot of the current [`MetadataState`], with tag 2 = the frame's
/// MISP time and (synchronous carriage) PTS = the frame's PTS, inserted
/// right before the frame (MUXING_PLAN.md section 6.7).
///
/// Caller-driven, no threads and no clock inside: the caller pushes input
/// as it arrives, with the wall-clock MISP time of its arrival, and changes
/// the state between pushes, so a packet never mixes two updates and a
/// change shows on the next frame. Output is written to the sink during
/// the call: with the default extrapolating clock and video timestamps off,
/// every input packet is written before `push` returns (zero added
/// latency). Writing ST 0604 timestamps holds the packets of a frame until
/// its first slice has been read (see the `mpegts` injector).
///
/// ```
/// use misb::mux::{Carriage, LiveMux, LiveMuxConfig};
/// use misb::st0601::Tag;
/// use misb::MispTime;
///
/// # fn input() -> Vec<u8> { Vec::new() }
/// let mut live = LiveMux::new(LiveMuxConfig::new(Carriage::Sync))?;
/// let now = MispTime::from_micros(1_700_000_000_000_000);
/// live.state_mut().set(Tag::SensorLatitude, 38.8977, now)?;
/// let mut out = Vec::new();
/// live.push(&input(), now, &mut out)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct LiveMux {
    inj: Injector,
    core: Core,
}

impl LiveMux {
    /// A live muxer with an empty state.
    pub fn new(cfg: LiveMuxConfig) -> Result<LiveMux, LiveMuxError> {
        cfg.validate()?;
        let mut inject = cfg.inject.clone();
        let writing = cfg.video_timestamps.mode != VideoTimestamps::Off;
        if writing {
            inject = inject.with_video_sei(VideoSei::Write);
        } else if cfg.video_anchor && inject.video_sei == VideoSei::Off {
            inject = inject.with_video_sei(VideoSei::Scan);
        }
        let scanning = inject.video_sei != VideoSei::Off;
        let inj = Injector::new(inject)?;
        Ok(LiveMux {
            inj,
            core: Core {
                state: MetadataState::with_options(cfg.encode.clone()),
                rate: RateLimiter::new(cfg.rate).map_err(LiveMuxError::Rate)?,
                reorder: FrameReorder::new(cfg.reorder_depth),
                unwrap: PtsUnwrapper::new(),
                anchor: None,
                carried: None,
                released: (None, None),
                video_times: VecDeque::new(),
                jump: None,
                last_unit: None,
                now: MispTime::EPOCH,
                emit: false,
                writer: TimestampWriter::new(cfg.video_timestamps),
                scanning,
                failed: None,
                last_encode_error: None,
                stats: LiveMuxStats::default(),
                cfg,
            },
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &LiveMuxConfig {
        &self.core.cfg
    }

    fn usable(&self) -> Result<(), LiveMuxError> {
        match &self.core.failed {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn outcome(&mut self, r: Result<(), LiveMuxError>) -> Result<(), LiveMuxError> {
        if let Err(e) = r {
            self.core.failed.get_or_insert(e);
        }
        self.usable()
    }

    /// Input bytes as they arrived, in any chunking, at wall-clock MISP
    /// time `now` (for example [`MispTime::from_system_time`]). Output goes
    /// to `sink` during the call.
    pub fn push<S: PacketSink + ?Sized>(&mut self, data: &[u8], now: MispTime, sink: &mut S) -> Result<(), LiveMuxError> {
        self.usable()?;
        self.core.now = now;
        if self.core.emit && self.core.cfg.carriage() == Carriage::Async {
            let r = self.emit_async();
            self.outcome(r)?;
        }
        let core = &mut self.core;
        let r = self.inj.push_with(data, sink, &mut |f: &Frame, u: &mut Units<'_>| core.frame(f, u));
        self.outcome(r.map_err(LiveMuxError::from))
    }

    /// An asynchronous unit right away (an `emit` request), timed by the
    /// anchor at the input's current clock, or by the wall clock.
    fn emit_async(&mut self) -> Result<(), LiveMuxError> {
        let core = &mut self.core;
        let clock_time = match (core.anchor, self.inj.clock()) {
            (Some(a), Some(c)) => a.misp_at(core.unwrap.peek(c / 300)),
            _ => None,
        };
        let time = clock_time.unwrap_or(core.now);
        let snap = core.state.snapshot(time);
        core.emit = false;
        if snap.is_empty() {
            core.stats.empty += 1;
            return Ok(());
        }
        let data = match snap.encode_at(time, &core.cfg.encode) {
            Ok(d) => d,
            Err(e) => {
                core.stats.encode_errors += 1;
                core.last_encode_error = Some(e);
                return Ok(());
            }
        };
        match self.inj.insert(InsertUnit::asynchronous(data)) {
            Ok(()) => {
                core.stats.units += 1;
                core.stats.emitted += 1;
                Ok(())
            }
            Err(InjectError::QueueFull { .. }) => {
                core.stats.refused += 1;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> &MetadataState {
        &self.core.state
    }

    /// The state, to change between pushes. Values are stamped with the
    /// MISP time the caller passes, which is what staleness counts from.
    pub fn state_mut(&mut self) -> &mut MetadataState {
        &mut self.core.state
    }

    /// Send a packet at the next opportunity whatever the rate says: the
    /// next frame (synchronous), or before the next input packet
    /// (asynchronous, timed now).
    pub fn emit(&mut self) {
        self.core.emit = true;
    }

    /// Apply one control line (`misb::json` commands, for example
    /// `{"set": {"SensorLatitude": 38.8}}`) at MISP time `at`: all of it
    /// or nothing. An `emit` command calls [`emit`](Self::emit).
    #[cfg(feature = "json")]
    pub fn apply_line(&mut self, line: &str, at: MispTime) -> Result<crate::json::Applied, crate::json::JsonError> {
        let applied = crate::json::apply_line(line, &mut self.core.state, at, crate::LeapSeconds::builtin())?;
        if applied.emit {
            self.emit();
        }
        Ok(applied)
    }

    /// The input has ended: process what is held, give the last frames
    /// their metadata and place what can still be placed.
    pub fn finish<S: PacketSink + ?Sized>(&mut self, sink: &mut S) -> Result<LiveMuxStats, LiveMuxError> {
        self.usable()?;
        let core = &mut self.core;
        let r = self.inj.end_input_with(sink, &mut |f: &Frame, u: &mut Units<'_>| core.frame(f, u));
        self.outcome(r.map_err(LiveMuxError::from))?;
        // Frames still waiting for presentation order: their units can
        // only be queued now; the injector places what it still can.
        let frames: Vec<Frame> = self.core.reorder.flush().collect();
        for f in frames {
            let core = &mut self.core;
            if let Some((p, data)) = core.unit_for(&f) {
                let unit = match core.cfg.carriage() {
                    Carriage::Sync => InsertUnit::sync(wrap_pts(p), data),
                    Carriage::Async => InsertUnit::asynchronous(data),
                };
                match self.inj.insert(unit) {
                    Ok(()) => core.sent(p),
                    Err(InjectError::QueueFull { .. } | InjectError::OutOfOrder { .. }) => core.stats.refused += 1,
                    Err(e) => return self.outcome(Err(e.into())).map(|()| self.stats()),
                }
            }
        }
        let r = self.inj.finish(sink).map(|_| ()).map_err(LiveMuxError::from);
        self.outcome(r)?;
        Ok(self.stats())
    }

    /// The counters so far.
    #[must_use]
    pub fn stats(&self) -> LiveMuxStats {
        let mut s = self.core.stats;
        s.inject = self.inj.stats();
        s.video = self.core.writer.stats;
        s
    }

    /// The anchor, once the first frame set it.
    #[must_use]
    pub fn anchor(&self) -> Option<Anchor> {
        self.core.anchor
    }

    /// The injector, for its target and settings.
    #[must_use]
    pub fn injector(&self) -> &Injector {
        &self.inj
    }

    /// The oldest injector event.
    pub fn pop_event(&mut self) -> Option<InjectEvent> {
        self.inj.pop_event()
    }

    /// Why the latest snapshot that failed to encode failed (the state
    /// checks each value when it is set, but a few rules between items are
    /// only checked when a packet is built).
    #[must_use]
    pub fn last_encode_error(&self) -> Option<&EncodeError> {
        self.core.last_encode_error.as_ref()
    }
}

impl Core {
    /// A frame in decode order, from the injector's callback.
    fn frame(&mut self, f: &Frame, units: &mut Units<'_>) {
        if self.failed.is_some() {
            return;
        }
        self.stats.frames += 1;
        if f.discontinuity && self.unwrap != PtsUnwrapper::new() {
            self.discontinuity();
        }
        let pts = self.unwrap.unwrap(f.pts);
        let found = if self.scanning { frame_timestamp(units) } else { None };
        self.writer.saw(found.as_ref());
        if let (true, Some(ts)) = (self.cfg.video_anchor, found.as_ref()) {
            self.video_time(pts, ts);
        }
        if self.anchor.is_none() {
            self.anchor = Some(match (self.carried.take(), self.cfg.anchor) {
                (Some(t), _) => Anchor::new(pts, t),
                (None, LiveAnchor::WallClock) => Anchor::new(pts, self.now),
                (None, LiveAnchor::FirstFrame(t)) => Anchor::new(pts, t),
                (None, LiveAnchor::Pts { pts: p, misp }) => Anchor::new(self.unwrap.peek(p), misp),
            });
        }
        if self.writer.enabled() {
            let time = self.anchor.and_then(|a| a.misp_at(pts));
            let jump = self.jump.take();
            if let Err(e) = self.writer.write(units, found.as_ref(), time, jump) {
                self.failed = Some(e.into());
                return;
            }
        }
        self.reorder.push(*f);
        while let Some(r) = self.reorder.pop() {
            let Some((p, data)) = self.unit_for(&r) else { continue };
            let unit = match self.cfg.carriage() {
                Carriage::Sync => InsertUnit::sync(wrap_pts(p), data),
                Carriage::Async => InsertUnit::asynchronous(data),
            };
            match units.insert(unit) {
                Ok(()) => self.sent(p),
                Err(InjectError::QueueFull { .. } | InjectError::OutOfOrder { .. }) => self.stats.refused += 1,
                Err(e) => {
                    self.failed = Some(e.into());
                    return;
                }
            }
        }
    }

    /// The unit for a frame in presentation order, if it gets one:
    /// (unwrapped PTS, ST 0601 packet).
    fn unit_for(&mut self, f: &Frame) -> Option<(i64, Vec<u8>)> {
        let p = self.unwrap.peek(f.pts);
        if self.released.1.map_or(false, |l| p <= l) {
            return None;
        }
        self.released = (self.released.1, Some(p));
        let mut own = None;
        while let Some(&(vp, t)) = self.video_times.front() {
            if vp > p {
                break;
            }
            self.video_times.pop_front();
            if vp == p {
                own = Some(t);
            }
        }
        let time = own.or_else(|| self.anchor.and_then(|a| a.misp_at(p)))?;
        let admitted = self.rate.admit(p);
        if !admitted && !self.emit {
            return None;
        }
        if self.cfg.carriage() == Carriage::Sync && self.last_unit.map_or(false, |l| p < l) {
            self.stats.late += 1;
            return None;
        }
        let snap = self.state.snapshot(time);
        if snap.is_empty() {
            self.stats.empty += 1;
            return None;
        }
        if self.emit && !admitted {
            self.stats.emitted += 1;
        }
        self.emit = false;
        match snap.encode_at(time, &self.cfg.encode) {
            Ok(data) => Some((p, data)),
            Err(e) => {
                self.stats.encode_errors += 1;
                self.last_encode_error = Some(e);
                None
            }
        }
    }

    /// A unit for unwrapped PTS `p` was queued.
    fn sent(&mut self, p: i64) {
        self.stats.units += 1;
        if self.cfg.carriage() == Carriage::Sync {
            self.last_unit = Some(p);
        }
    }

    /// A frame (unwrapped PTS) with an ST 0604 timestamp (D-15).
    fn video_time(&mut self, pts: i64, ts: &Timestamp) {
        let time = ts.misp_time();
        if self.video_times.len() >= 4 * self.cfg.reorder_depth + 4 {
            self.video_times.pop_front();
        }
        let at = self.video_times.partition_point(|&(p, _)| p < pts);
        self.video_times.insert(at, (pts, time));
        match self.anchor {
            None => self.anchor = Some(Anchor::new(pts, time)),
            Some(a) => {
                let predicted = a.misp_at(pts);
                let off = predicted.map_or(u64::MAX, |p| p.as_micros().abs_diff(time.as_micros()));
                if ts.status.is_discontinuity() || off > u64::from(self.cfg.video_anchor_tolerance_us) {
                    self.anchor = Some(Anchor::new(pts, time));
                    self.stats.reanchors += 1;
                    self.jump = Some(match predicted {
                        Some(p) if time < p => Jump::Backward,
                        _ => Jump::Forward,
                    });
                }
            }
        }
    }

    /// The program clock jumped: the next frame starts a new time base.
    fn discontinuity(&mut self) {
        self.stats.discontinuities += 1;
        let continued = match (self.anchor, self.released) {
            (Some(a), (Some(prev), Some(last))) => a.misp_at(last + (last - prev).clamp(1, 90_000)),
            (Some(a), (None, Some(last))) => a.misp_at(last),
            _ => None,
        };
        self.unwrap.reset();
        self.video_times.clear();
        self.last_unit = None;
        self.released = (None, None);
        self.rate.reset();
        self.anchor = None;
        match self.cfg.anchor {
            LiveAnchor::WallClock => {
                // The wall clock re-anchors; signal a jump when the new
                // time is not where the old time line would have been.
                if let Some(c) = continued {
                    let off = c.as_micros().abs_diff(self.now.as_micros());
                    if off > u64::from(self.cfg.video_anchor_tolerance_us) {
                        self.jump = Some(if self.now < c { Jump::Backward } else { Jump::Forward });
                    }
                }
            }
            _ => self.carried = continued,
        }
    }
}
