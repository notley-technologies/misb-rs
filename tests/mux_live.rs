//! LiveMux: a live stream with metadata from a changing state. Time is
//! simulated: each push carries the MISP time the caller says it arrived.
#![forbid(unsafe_code)]

mod mux_synth;

use misb::mpegts::mux::KlvCarriage;
use misb::mpegts::nal::VideoCodec;
use misb::mpegts::Codec;
use misb::mux::{Carriage, LiveAnchor, LiveMux, LiveMuxConfig, Rate, VideoTimestampOptions, VideoTimestamps};
use misb::st0601::Tag;
use misb::st0604::{Identifier, TimeStatus, Timestamp};
use misb::{MispTime, Value};
use mux_synth::*;
use std::time::Duration;

/// Wall-clock MISP time of the first push.
const N0: u64 = 1_765_000_000_000_000;

fn at(us: u64) -> MispTime {
    MispTime::from_micros(us)
}

/// Latitude to the precision of tag 13 (about 4e-8 degrees).
fn lat_of(p: &misb::Packet) -> Option<f64> {
    p.get(Tag::SensorLatitude).and_then(Value::as_f64).map(|v| (v * 1e6).round() / 1e6)
}

/// Push frame by frame, the wall clock advancing one frame period per
/// frame; `before(k, live)` runs before frame `k` is pushed.
fn run_frames(live: &mut LiveMux, made: &Made, mut before: impl FnMut(usize, &mut LiveMux)) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, chunk) in made.frames().into_iter().enumerate() {
        before(k, live);
        live.push(chunk, at(N0 + k as u64 * 33_367), &mut out).unwrap();
    }
    live.finish(&mut out).unwrap();
    out
}

fn sync(rate: Rate) -> LiveMuxConfig {
    let mut cfg = LiveMuxConfig::new(Carriage::Sync);
    cfg.rate = rate;
    cfg
}

#[test]
fn every_input_packet_leaves_during_its_push() {
    let made = VideoSynth { frames: 60, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::EveryFrame)).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 38.5, at(N0)).unwrap();
    let mut out = Vec::new();
    let mut pushed = 0u64;
    let mut found = false;
    for (k, chunk) in made.ts.chunks(7 * 188).enumerate() {
        live.push(chunk, at(N0 + k as u64 * 4000), &mut out).unwrap();
        pushed += (chunk.len() / 188) as u64;
        let s = live.stats();
        found |= live.injector().target().is_some();
        if found {
            assert_eq!(s.inject.packets_in, pushed);
            // Nothing waits for a PCR or for the metadata: zero added
            // latency once the program's tables have been read.
            assert_eq!(s.inject.held_packets, 0, "after push {k}");
            assert_eq!(out.len() / 188, (s.inject.packets_out) as usize);
        }
    }
    assert!(found);
    let stats = live.finish(&mut out).unwrap();
    assert_eq!(stats.units, 60);
    assert_eq!(klv_units(&out, Codec::KlvSync).len(), 60);
}

#[test]
fn the_wall_clock_anchors_the_first_frame() {
    let made = VideoSynth { frames: 30, b_frames: true, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::EveryFrame)).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 1.0, at(N0)).unwrap();
    let out = run_frames(&mut live, &made, |_, _| {});
    let klv = klv_units(&out, Codec::KlvSync);
    assert_eq!(klv.len(), 30);
    let mut last = 0;
    for (pts, t, _) in &klv {
        let pts = pts.unwrap();
        assert!(pts > last, "presentation order");
        last = pts;
        // The first frame arrived at N0; later frames are timed by their
        // PTS, not by when they arrived.
        assert_eq!(*t, misp_of(pts, BASE, N0));
    }
    assert_eq!(live.anchor().map(|a| a.misp), Some(at(N0)));
}

#[test]
fn a_change_shows_on_the_next_frame() {
    let made = VideoSynth { frames: 40, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::EveryFrame)).unwrap();
    let out = run_frames(&mut live, &made, |k, live| {
        let now = at(N0 + k as u64 * 33_367);
        if k == 0 {
            live.state_mut().set(Tag::SensorLatitude, 1.0, now).unwrap();
        }
        if k == 17 {
            live.state_mut().set(Tag::SensorLatitude, 2.0, now).unwrap().set(Tag::MissionId, "CHANGED", now).unwrap();
        }
    });
    for (pts, _, p) in klv_units(&out, Codec::KlvSync) {
        let k = (pts.unwrap() - BASE) / FRAME;
        let changed = k >= 17;
        assert_eq!(lat_of(&p), Some(if changed { 2.0 } else { 1.0 }), "frame {k}");
        assert_eq!(p.get(Tag::MissionId).is_some(), changed, "frame {k}: one snapshot per packet");
    }
}

#[test]
fn emit_sends_a_packet_the_rate_would_skip() {
    let made = VideoSynth { frames: 60, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::Hz(1.0))).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 1.0, at(N0)).unwrap();
    let out = run_frames(&mut live, &made, |k, live| {
        if k == 10 {
            live.emit();
        }
    });
    let frames: Vec<u64> = klv_units(&out, Codec::KlvSync).iter().map(|(p, _, _)| (p.unwrap() - BASE) / FRAME).collect();
    // 1 Hz: frames 0 and 30 (29.97 fps), and frame 10 on request.
    assert_eq!(frames, [0, 10, 30]);
    assert_eq!(live.stats().emitted, 1);
}

#[test]
fn stale_values_are_left_out() {
    let made = VideoSynth { frames: 45, ..VideoSynth::default() }.make();
    let mut cfg = sync(Rate::EveryFrame);
    cfg.encode = misb::encode::EncodeOptions::default();
    let mut live = LiveMux::new(cfg).unwrap();
    live.state_mut().staleness_mut().max_age = Some(Duration::from_millis(500));
    let out = run_frames(&mut live, &made, |k, live| {
        let now = at(N0 + k as u64 * 33_367);
        if k == 0 {
            live.state_mut().set(Tag::SensorLatitude, 1.0, now).unwrap();
        }
        // The heading is fresh at every frame.
        live.state_mut().set(Tag::PlatformHeadingAngle, 90.0, now).unwrap();
    });
    for (_, t, p) in klv_units(&out, Codec::KlvSync) {
        let age = t - N0;
        assert_eq!(lat_of(&p).is_some(), age <= 500_000, "age {age} us");
        assert!(p.get(Tag::PlatformHeadingAngle).is_some());
    }
}

#[test]
fn an_empty_state_sends_nothing() {
    let made = VideoSynth { frames: 10, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::EveryFrame)).unwrap();
    let out = run_frames(&mut live, &made, |_, _| {});
    assert!(klv_units(&out, Codec::KlvSync).is_empty());
    assert_eq!(live.stats().empty, 10);
}

#[test]
fn asynchronous_carriage_and_immediate_events() {
    let made = VideoSynth { frames: 90, ..VideoSynth::default() }.make();
    let cfg = LiveMuxConfig::new(Carriage::Async);
    assert_eq!(cfg.inject.carriage, KlvCarriage::Async);
    let mut live = LiveMux::new(cfg).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 1.0, at(N0)).unwrap();
    let out = run_frames(&mut live, &made, |k, live| {
        if k == 45 {
            live.emit();
        }
    });
    let klv = klv_units(&out, Codec::KlvAsync);
    // 10 Hz on 3 s of video, plus the event.
    assert_eq!(klv.len(), 31);
    assert!(klv.iter().all(|(pts, _, _)| pts.is_none()));
    assert_eq!(live.stats().emitted, 1);
}

#[cfg(feature = "json")]
#[test]
fn control_lines_change_the_state() {
    let made = VideoSynth { frames: 20, ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::Hz(2.0))).unwrap();
    let out = run_frames(&mut live, &made, |k, live| {
        let now = at(N0 + k as u64 * 33_367);
        if k == 0 {
            live.apply_line(r#"{"set": {"SensorLatitude": 12.5, "MissionId": "LIVE"}}"#, now).unwrap();
        }
        if k == 5 {
            let applied = live.apply_line(r#"{"set": {"SensorLatitude": 13.5}, "emit": true}"#, now).unwrap();
            assert!(applied.emit && applied.changed);
            assert!(live.apply_line(r#"{"set": {"SensorLatitude": 1000}}"#, now).is_err(), "checked when set");
        }
        if k == 8 {
            live.apply_line(r#"{"clear": ["MissionId"], "unknown": ["SlantRange"]}"#, now).unwrap();
            live.emit();
        }
    });
    let units = klv_units(&out, Codec::KlvSync);
    let frames: Vec<u64> = units.iter().map(|(p, _, _)| (p.unwrap() - BASE) / FRAME).collect();
    assert_eq!(frames, [0, 5, 8, 15]);
    assert_eq!(lat_of(&units[0].2), Some(12.5));
    assert_eq!(lat_of(&units[1].2), Some(13.5));
    let last = &units[2].2;
    assert!(last.get(Tag::MissionId).is_none());
    assert_eq!(last.get(Tag::SlantRange), Some(&Value::Unknown));
}

#[test]
fn st0604_timestamps_are_written_and_followed() {
    // The input carries timestamps in its first 10 frames only; the live
    // muxer anchors on them and fills in the rest from the same clock.
    const V0: u64 = 1_760_000_000_000_000;
    let made = VideoSynth {
        codec: VideoCodec::H265,
        frames: 40,
        st0604: Some(Box::new(|n| {
            (n < 10).then(|| Timestamp::new(Identifier::HevcMicroseconds, TimeStatus::LOCKED, misp_of(BASE + n * FRAME, BASE, V0)))
        })),
        ..VideoSynth::default()
    }
    .make();
    let mut cfg = sync(Rate::EveryFrame);
    cfg.video_anchor = true;
    cfg.video_timestamps = VideoTimestampOptions::new(VideoTimestamps::AddWhenMissing);
    let mut live = LiveMux::new(cfg).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 1.0, at(N0)).unwrap();
    let out = run_frames(&mut live, &made, |_, _| {});
    let aus = video_timestamps(&out, VideoCodec::H265);
    assert_eq!(aus.len(), 40);
    for (pts, stamps) in &aus {
        assert_eq!(stamps.len(), 1);
        assert_eq!(stamps[0].value, misp_of(*pts, BASE, V0));
    }
    for (pts, t, _) in klv_units(&out, Codec::KlvSync) {
        assert_eq!(t, misp_of(pts.unwrap(), BASE, V0), "tag 2 on the video's clock, not the wall clock");
    }
    let s = live.stats();
    assert_eq!((s.video.found, s.video.written), (10, 30));
}

#[test]
fn a_discontinuity_re_anchors_to_the_wall_clock() {
    // At frame 20 the program clock jumps 100 s ahead.
    let made = VideoSynth { frames: 40, jump: Some((20, 9_000_000)), ..VideoSynth::default() }.make();
    let mut live = LiveMux::new(sync(Rate::EveryFrame)).unwrap();
    live.state_mut().set(Tag::SensorLatitude, 1.0, at(N0)).unwrap();
    let out = run_frames(&mut live, &made, |_, _| {});
    let klv = klv_units(&out, Codec::KlvSync);
    assert_eq!(live.stats().discontinuities, 1);
    let after: Vec<_> = klv.iter().filter(|(p, _, _)| p.unwrap() >= BASE + 9_000_000).collect();
    assert!(!after.is_empty());
    // The first frame after the jump is at the wall time it arrived.
    let first_after = after.iter().map(|(p, _, _)| p.unwrap()).min().unwrap();
    let (_, t, _) = after.iter().find(|(p, _, _)| p.unwrap() == first_after).unwrap();
    assert_eq!(*t, N0 + 20 * 33_367);
}

#[test]
fn explicit_rate_is_refused() {
    let mut cfg = LiveMuxConfig::new(Carriage::Sync);
    cfg.rate = Rate::Explicit;
    assert!(LiveMux::new(cfg).is_err());
    let mut cfg = LiveMuxConfig::new(Carriage::Sync);
    cfg.anchor = LiveAnchor::FirstFrame(at(N0));
    assert!(LiveMux::new(cfg).is_ok());
}
