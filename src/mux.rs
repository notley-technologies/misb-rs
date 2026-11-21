//! Inserting ST 0601 metadata into MPEG transport streams (feature `mux`).
//!
//! The pieces between a metadata source and the [`mpegts`] injector:
//!
//! - [`Anchor`] maps MISP time to the program clock and back
//!   (st1402-time.md D-11), with [`PtsUnwrapper`] counting across the 2^33
//!   PTS wrap-around.
//! - [`Sample`] is one piece of metadata at a time: a recorded packet
//!   (written unchanged, D-6) or items to encode. [`KlvSamples`] splits a
//!   recorded `.klv` byte stream into samples; NDJSON authoring records
//!   convert with `From` (feature `json`).
//! - [`Rate`] and [`RateLimiter`] decide which video frames get metadata.
//! - [`Scheduler`] turns samples into timed units from the frames and
//!   program clock of the stream being injected into: each sample at its
//!   own time, or sampled at video frames.
//! - [`FileMux`] puts it together: a source scheduled into an input
//!   transport stream by the `mpegts` injector. With
//!   [`ScheduleConfig::interpolate`] items are interpolated between
//!   samples through a [`crate::track::Track`].
//! - [`LiveMux`] injects into a live stream: each frame gets a snapshot of
//!   a [`crate::state::MetadataState`] the caller changes at any time.
//! - MISB ST 0604 timestamps in the video ([`VideoTimestamps`]) anchor MISP
//!   time ([`ScheduleConfig::video_anchor`]) and can be written into the
//!   video.
//!
//! Like the rest of the crate this does no I/O and never reads the clock:
//! tools such as `tsflow` read files and sockets and push bytes in.
//!
//! The `mpegts` crate is re-exported as [`misb::mpegts`](crate::mpegts),
//! so a program that uses both gets one consistent version.

mod anchor;
mod file;
mod live;
mod rate;
mod schedule;
mod source;
mod video;

pub use anchor::{wrap_pts, Anchor, PtsUnwrapper};
pub use file::{FileMux, FileMuxConfig, FileMuxError, FileMuxStats};
pub use live::{LiveAnchor, LiveMux, LiveMuxConfig, LiveMuxError, LiveMuxStats};
pub use rate::{Rate, RateError, RateLimiter};
pub use schedule::{
    AnchorSpec, Carriage, Flow, FrameTime, ScheduleConfig, ScheduleError, ScheduleStats, ScheduledUnit, Scheduler,
};
pub use source::{KlvSampleStats, KlvSamples, Sample, SampleData, SampleError};
pub use video::{frame_timestamp, VideoTimestampOptions, VideoTimestampStats, VideoTimestamps};
