//! MISB ST 0604 timestamps in the video (MUXING_PLAN.md section 6.8): read
//! from the input's SEI user data to anchor MISP time, and written into it.
//!
//! The `mpegts` injector finds and rewrites the SEI user_data_unregistered
//! messages of each access unit; this module decides what they hold
//! (st1402-time.md D-12): one ST 0604 message per access unit, in every
//! access unit, with the time of that frame.

use crate::st0604::{self, Identifier, Jump, TimeStatus, Timestamp};
use crate::MispTime;
use mpegts::mux::{InjectError, Units};
use mpegts::nal::VideoCodec;

/// Whether ST 0604 timestamps are written into the input video.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum VideoTimestamps {
    /// The video is never changed (the default).
    #[default]
    Off,
    /// Access units without an ST 0604 timestamp get one; those that have
    /// one keep it. Video and metadata then share one clock even when the
    /// input had none.
    AddWhenMissing,
    /// Every access unit gets the muxer's time: existing timestamps are
    /// replaced in place (keeping their identifier), missing ones added.
    /// For re-timed outputs.
    Rewrite,
}

/// How ST 0604 timestamps are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct VideoTimestampOptions {
    /// Off, add when missing, or rewrite.
    pub mode: VideoTimestamps,
    /// Time Status bit 7 (ST 0603.5): `Some(true)` asserts that the time
    /// is locked to an absolute reference, `Some(false)` says the lock is
    /// unknown. `None` (the default): unknown, unless the input's own
    /// timestamps say otherwise, whose lock bit is then copied (D-12).
    pub locked: Option<bool>,
    /// H.265 only: write the nanosecond identifier instead of the
    /// microsecond one. One stream uses one representation (R-ST1402TIME-53),
    /// so an input that already carries nanosecond timestamps gets them
    /// whatever this says.
    pub nanoseconds: bool,
}

impl VideoTimestampOptions {
    /// Options with this mode and the other defaults.
    #[must_use]
    pub fn new(mode: VideoTimestamps) -> VideoTimestampOptions {
        VideoTimestampOptions { mode, ..VideoTimestampOptions::default() }
    }
}

const ALL_IDENTIFIERS: [[u8; 16]; 3] =
    [st0604::MISP_MICROSECTIME, st0604::HEVC_MICROSECONDS_UUID, st0604::HEVC_NANOSECONDS_UUID];

/// The ST 0604 timestamp of the access unit `units` describes, if its
/// video carries one (the first readable message; D-14 tolerances apply).
#[must_use]
pub fn frame_timestamp(units: &Units<'_>) -> Option<Timestamp> {
    units.user_data().iter().find_map(|ud| {
        let id = Identifier::from_bytes(&ud.uuid)?;
        st0604::decode_payload(id, &ud.payload).ok().map(|d| d.timestamp)
    })
}

/// Counters of the timestamps written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VideoTimestampStats {
    /// Access units whose video carried an ST 0604 timestamp.
    pub found: u64,
    /// Timestamps written (added or rewritten).
    pub written: u64,
    /// Access units left without a new timestamp: no time for them yet
    /// (before the anchor), a codec that cannot carry one, or the
    /// injector could not fit it (see its counters).
    pub skipped: u64,
}

/// Writes one timestamp per access unit from the frame callback.
#[derive(Clone, Debug, Default)]
pub(crate) struct TimestampWriter {
    opts: VideoTimestampOptions,
    /// The input has used the nanosecond identifier.
    input_nanos: bool,
    /// The lock bit of the input's latest timestamp.
    input_locked: Option<bool>,
    pub stats: VideoTimestampStats,
}

impl TimestampWriter {
    pub fn new(opts: VideoTimestampOptions) -> TimestampWriter {
        TimestampWriter { opts, ..TimestampWriter::default() }
    }

    pub fn enabled(&self) -> bool {
        self.opts.mode != VideoTimestamps::Off
    }

    /// Note the input's own timestamp of an access unit.
    pub fn saw(&mut self, found: Option<&Timestamp>) {
        if let Some(ts) = found {
            self.stats.found += 1;
            self.input_nanos |= ts.identifier.is_nanoseconds();
            self.input_locked = Some(ts.status.is_locked());
        }
    }

    /// Write the timestamp of the access unit `units` describes: `time`
    /// is its MISP time (`None` when not known yet), `found` its own
    /// timestamp, `jump` an anchor discontinuity to signal. Errors are the
    /// injector's refusals of the write; the caller decides whether they
    /// are fatal.
    pub fn write(
        &mut self,
        units: &mut Units<'_>,
        found: Option<&Timestamp>,
        time: Option<MispTime>,
        jump: Option<Jump>,
    ) -> Result<(), InjectError> {
        if !self.enabled() || (found.is_some() && self.opts.mode == VideoTimestamps::AddWhenMissing) {
            return Ok(());
        }
        let codec = units.video_prefix().map(|p| p.codec);
        let identifier = match (found, codec) {
            (Some(ts), _) => ts.identifier,
            (None, Some(VideoCodec::H264)) => Identifier::MispMicrosectime,
            (None, Some(VideoCodec::H265)) if self.opts.nanoseconds || self.input_nanos => Identifier::HevcNanoseconds,
            (None, Some(VideoCodec::H265)) => Identifier::HevcMicroseconds,
            _ => {
                self.stats.skipped += 1;
                return Ok(());
            }
        };
        let Some(time) = time else {
            self.stats.skipped += 1;
            return Ok(());
        };
        let locked = self.opts.locked.or(self.input_locked).unwrap_or(false);
        let status = TimeStatus::default().with_locked(locked).with_jump(jump);
        let payload = Timestamp::from_misp(identifier, status, time).and_then(|ts| ts.payload().ok());
        let Some(payload) = payload else {
            self.stats.skipped += 1;
            return Ok(());
        };
        units.write_user_data(identifier.bytes(), &payload, &ALL_IDENTIFIERS)?;
        self.stats.written += 1;
        Ok(())
    }
}
