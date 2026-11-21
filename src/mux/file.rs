//! A metadata source injected into a transport stream.

use super::schedule::{Carriage, Flow, FrameTime, ScheduleConfig, ScheduleError, ScheduleStats, ScheduledUnit, Scheduler};
use super::source::Sample;
use super::video::{frame_timestamp, TimestampWriter, VideoTimestampOptions, VideoTimestampStats, VideoTimestamps};
use super::Anchor;
use mpegts::mux::{
    Frame, InjectConfig, InjectError, InjectEvent, InjectStats, Injector, InsertUnit, KlvCarriage, Packet, PacketSink,
    Units, VideoSei,
};
use std::fmt;

/// Input is handed to the injector in pieces of this many bytes, with the
/// scheduler run between them, so samples are queued well ahead of their
/// window however large the caller's chunks are.
const PIECE: usize = 64 * 188;
/// With pre-timed packets, the scheduler runs every this many packets
/// (and at every video frame).
const TICK_PACKETS: u32 = 32;

/// Settings of a [`FileMux`]: the injector's and the scheduler's.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct FileMuxConfig {
    /// Where and how the KLV goes into the stream. Its carriage must match
    /// [`schedule`](Self::schedule)'s.
    pub inject: InjectConfig,
    /// When the samples go in.
    pub schedule: ScheduleConfig,
    /// Writing MISB ST 0604 timestamps into the video (MUXING_PLAN.md
    /// section 6.8): each access unit's MISP time is the anchor applied to
    /// its PTS. Default off. Turning it on (or
    /// [`ScheduleConfig::video_anchor`]) sets the injector's
    /// [`video_sei`](InjectConfig::video_sei) mode.
    pub video_timestamps: VideoTimestampOptions,
}

impl FileMuxConfig {
    /// Defaults for a carriage: the injector's defaults (VBR, the first
    /// program with video, an existing sync stream joined as a new
    /// service) and every sample at its own time, the source's first
    /// sample aligned with the first video frame.
    #[must_use]
    pub fn new(carriage: Carriage) -> FileMuxConfig {
        let klv = match carriage {
            Carriage::Sync => KlvCarriage::Sync,
            Carriage::Async => KlvCarriage::Async,
        };
        let inject = InjectConfig::default().with_carriage(klv);
        let mut schedule = ScheduleConfig::new(carriage);
        schedule.min_lead_ms = inject.min_lead_ms;
        FileMuxConfig { inject, schedule, video_timestamps: VideoTimestampOptions::default() }
    }

    /// Check that the two halves agree.
    pub fn validate(&self) -> Result<(), FileMuxError> {
        self.schedule.validate().map_err(FileMuxError::Schedule)?;
        let same = matches!(
            (self.inject.carriage, self.schedule.carriage),
            (KlvCarriage::Sync, Carriage::Sync) | (KlvCarriage::Async, Carriage::Async)
        );
        if !same {
            return Err(FileMuxError::Config("the injector and the scheduler must use the same carriage"));
        }
        if self.schedule.horizon_ms <= self.inject.max_lead_ms + 100 {
            return Err(FileMuxError::Config(
                "schedule.horizon_ms must exceed inject.max_lead_ms by more than 100 ms, so units are queued before their window opens",
            ));
        }
        Ok(())
    }
}

/// Why a [`FileMux`] stopped.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum FileMuxError {
    /// The settings do not fit together.
    Config(&'static str),
    /// The injector refused the input, a unit or a setting.
    Inject(InjectError),
    /// The scheduler failed (a sample did not encode, a recorded packet
    /// with a frame rate).
    Schedule(ScheduleError),
}

impl fmt::Display for FileMuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileMuxError::Config(m) => f.write_str(m),
            FileMuxError::Inject(e) => write!(f, "injector: {e}"),
            FileMuxError::Schedule(e) => write!(f, "metadata: {e}"),
        }
    }
}

impl std::error::Error for FileMuxError {}

impl From<InjectError> for FileMuxError {
    fn from(e: InjectError) -> FileMuxError {
        FileMuxError::Inject(e)
    }
}

impl From<Flow<InjectError>> for FileMuxError {
    fn from(e: Flow<InjectError>) -> FileMuxError {
        match e {
            Flow::Schedule(e) => FileMuxError::Schedule(e),
            Flow::Out(e) => FileMuxError::Inject(e),
        }
    }
}

/// Counters of a [`FileMux`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileMuxStats {
    /// The injector's.
    pub inject: InjectStats,
    /// The scheduler's.
    pub schedule: ScheduleStats,
    /// ST 0604 timestamps found in and written to the video.
    pub video: VideoTimestampStats,
}

/// Injects a metadata source into a transport stream: the
/// [`Scheduler`] decides which samples go in and with which PTS, the
/// `mpegts` [`Injector`] puts them into the stream (MUXING_PLAN.md
/// section 6.7, phase 3).
///
/// The caller does the I/O: it pushes the input stream in and writes what
/// comes out to the sink. Every input packet goes out unchanged except the
/// PAT, the target PMT and the KLV PID (see [`Injector`]).
///
/// ```
/// use misb::encode::St0601Builder;
/// use misb::mux::{AnchorSpec, Carriage, FileMux, FileMuxConfig, Sample};
/// use misb::MispTime;
///
/// # fn input_ts() -> Vec<u8> { Vec::new() }
/// // Recorded packets, here built in place.
/// let samples = (0..10u64).map(|k| {
///     let t = MispTime::from_micros(1_700_000_000_000_000 + k * 100_000);
///     Sample::packet(t, St0601Builder::new(t).finish().unwrap())
/// });
/// let mut cfg = FileMuxConfig::new(Carriage::Sync);
/// cfg.schedule.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(1_700_000_000_000_000));
/// let mut mux = FileMux::new(cfg, samples)?;
/// let mut out = Vec::new();
/// mux.push(&input_ts(), &mut out)?;
/// # if false {
/// let stats = mux.finish(&mut out)?;
/// println!("{} KLV units inserted", stats.inject.units_inserted);
/// # }
/// # Ok::<(), misb::mux::FileMuxError>(())
/// ```
pub struct FileMux<S: Iterator<Item = Sample>> {
    inj: Injector,
    sched: Scheduler<S>,
    video: Video,
    failed: Option<FileMuxError>,
    since_tick: u32,
}

/// The video timestamp side of the frame callback.
#[derive(Debug)]
struct Video {
    writer: TimestampWriter,
    /// The injector reads the video's SEI user data.
    scanning: bool,
}

impl<S: Iterator<Item = Sample>> fmt::Debug for FileMux<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileMux").field("injector", &self.inj).field("scheduler", &self.sched).finish()
    }
}

fn to_unit(u: ScheduledUnit) -> InsertUnit {
    match u.pts {
        Some(pts) => InsertUnit::sync(pts, u.data),
        None => InsertUnit::asynchronous(u.data),
    }
}

/// The frame callback: the scheduler sees the frame and inserts what is
/// due before it.
fn on_frame<S: Iterator<Item = Sample>>(
    sched: &mut Scheduler<S>,
    video: &mut Video,
    failed: &mut Option<FileMuxError>,
    frame: &Frame,
    units: &mut Units<'_>,
) {
    if failed.is_some() {
        return;
    }
    let time = FrameTime { pts: frame.pts, dts: frame.dts, discontinuity: frame.discontinuity };
    let clock = frame.clock.or_else(|| units.clock());
    let found = if video.scanning { frame_timestamp(units) } else { None };
    video.writer.saw(found.as_ref());
    if let Err(e) = sched.frame_with_video(&time, found.as_ref(), clock, &mut |u| units.insert(to_unit(u))) {
        *failed = Some(e.into());
        return;
    }
    if video.writer.enabled() {
        let misp = sched.frame_time(&time);
        let jump = sched.take_jump();
        if let Err(e) = video.writer.write(units, found.as_ref(), misp, jump) {
            *failed = Some(e.into());
        }
    }
}

impl<S: Iterator<Item = Sample>> FileMux<S> {
    /// A muxer reading `source`.
    pub fn new(cfg: FileMuxConfig, source: S) -> Result<Self, FileMuxError> {
        cfg.validate()?;
        let mut inject = cfg.inject;
        if cfg.video_timestamps.mode != VideoTimestamps::Off {
            inject = inject.with_video_sei(VideoSei::Write);
        } else if cfg.schedule.video_anchor && inject.video_sei == VideoSei::Off {
            inject = inject.with_video_sei(VideoSei::Scan);
        }
        let video = Video { writer: TimestampWriter::new(cfg.video_timestamps), scanning: inject.video_sei != VideoSei::Off };
        Ok(FileMux {
            inj: Injector::new(inject)?,
            sched: Scheduler::new(cfg.schedule, source).map_err(FileMuxError::Schedule)?,
            video,
            failed: None,
            since_tick: 0,
        })
    }

    fn usable(&self) -> Result<(), FileMuxError> {
        match &self.failed {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    /// Record the outcome of a step; errors are final.
    fn outcome(&mut self, r: Result<(), FileMuxError>) -> Result<(), FileMuxError> {
        if let Err(e) = r {
            self.failed.get_or_insert(e);
        }
        self.usable()
    }

    fn tick(&mut self) -> Result<(), FileMuxError> {
        self.since_tick = 0;
        let clock = self.inj.clock();
        let inj = &mut self.inj;
        let r = self.sched.tick(clock, &mut |u| inj.insert(to_unit(u))).map_err(FileMuxError::from);
        self.outcome(r)
    }

    /// Input bytes in any chunking. Output goes to `sink` as it is ready.
    pub fn push<P: PacketSink + ?Sized>(&mut self, data: &[u8], sink: &mut P) -> Result<(), FileMuxError> {
        self.usable()?;
        for piece in data.chunks(PIECE) {
            let (sched, video, failed) = (&mut self.sched, &mut self.video, &mut self.failed);
            let r = self
                .inj
                .push_with(piece, sink, &mut |f: &Frame, u: &mut Units<'_>| on_frame(sched, video, failed, f, u));
            self.outcome(r.map_err(FileMuxError::from))?;
            self.tick()?;
        }
        Ok(())
    }

    /// One packet with its program clock time (27 MHz), from the caller's
    /// own [`PcrTimeline`](mpegts::PcrTimeline), for tools that pace the
    /// output and need the time of every packet. Everything written to
    /// `sink` during the call goes out at that time. Use either `push` or
    /// `push_packet` on one muxer.
    pub fn push_packet<P: PacketSink + ?Sized>(
        &mut self,
        packet: &Packet,
        clock: Option<u64>,
        sink: &mut P,
    ) -> Result<(), FileMuxError> {
        self.usable()?;
        let (sched, video, failed) = (&mut self.sched, &mut self.video, &mut self.failed);
        let r = self.inj.push_packet_with(packet, clock, sink, &mut |f: &Frame, u: &mut Units<'_>| {
            on_frame(sched, video, failed, f, u);
        });
        self.outcome(r.map_err(FileMuxError::from))?;
        self.since_tick += 1;
        if self.since_tick >= TICK_PACKETS {
            self.tick()?;
        }
        Ok(())
    }

    /// The input has ended: process what is still held, insert the
    /// metadata of the last frames, place what can still be placed, and
    /// return the counters.
    pub fn finish<P: PacketSink + ?Sized>(&mut self, sink: &mut P) -> Result<FileMuxStats, FileMuxError> {
        self.usable()?;
        let (sched, video, failed) = (&mut self.sched, &mut self.video, &mut self.failed);
        let r = self
            .inj
            .end_input_with(sink, &mut |f: &Frame, u: &mut Units<'_>| on_frame(sched, video, failed, f, u));
        self.outcome(r.map_err(FileMuxError::from))?;
        let clock = self.inj.clock();
        let inj = &mut self.inj;
        let r = self.sched.finish(clock, &mut |u| inj.insert(to_unit(u))).map(|_| ()).map_err(FileMuxError::from);
        self.outcome(r)?;
        let r = self.inj.finish(sink).map(|_| ()).map_err(FileMuxError::from);
        self.outcome(r)?;
        Ok(self.stats())
    }

    /// The counters so far.
    #[must_use]
    pub fn stats(&self) -> FileMuxStats {
        FileMuxStats { inject: self.inj.stats(), schedule: self.sched.stats(), video: self.video.writer.stats }
    }

    /// The anchor, once the first video frame set it.
    #[must_use]
    pub fn anchor(&self) -> Option<Anchor> {
        self.sched.anchor()
    }

    /// The injector, for its target and settings.
    #[must_use]
    pub fn injector(&self) -> &Injector {
        &self.inj
    }

    /// The oldest injector event (target found, drops, warnings).
    pub fn pop_event(&mut self) -> Option<InjectEvent> {
        self.inj.pop_event()
    }
}
