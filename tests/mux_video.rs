//! MISB ST 0604 timestamps in the video with FileMux: written into every
//! access unit, read from the input to anchor MISP time, rewritten.
#![forbid(unsafe_code)]

mod mux_synth;

use misb::encode::Input;
use misb::mpegts::nal::VideoCodec;
use misb::mpegts::Codec;
use misb::mux::{AnchorSpec, Carriage, FileMux, FileMuxConfig, Rate, Sample, VideoTimestampOptions, VideoTimestamps};
use misb::st0601::Tag;
use misb::st0604::{Identifier, TimeStatus, Timestamp};
use misb::MispTime;
use mux_synth::*;

/// Items every 100 ms for 10 s from `t0`.
fn items(t0: u64) -> impl Iterator<Item = Sample> {
    (0..100u64).map(move |k| {
        Sample::items(MispTime::from_micros(t0 + k * 100_000), vec![(Tag::SensorLatitude, Input::Float(k as f64 / 10.0))])
    })
}

fn run(cfg: FileMuxConfig, source: impl Iterator<Item = Sample>, ts: &[u8]) -> (Vec<u8>, misb::mux::FileMuxStats) {
    let mut mux = FileMux::new(cfg, source).unwrap();
    let mut out = Vec::new();
    for chunk in ts.chunks(1316) {
        mux.push(chunk, &mut out).unwrap();
    }
    let stats = mux.finish(&mut out).unwrap();
    (out, stats)
}

fn sampled(mode: VideoTimestamps) -> FileMuxConfig {
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::EveryFrame;
    cfg.schedule.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    cfg.video_timestamps = VideoTimestampOptions::new(mode);
    cfg
}

/// TSDuck, when configured: continuity on every PID.
fn tsduck(ts: &[u8], name: &str) {
    let Ok(bin) = std::env::var("MPEGTS_TSDUCK") else { return };
    let dir = std::env::temp_dir().join(format!("misb-video-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.ts");
    std::fs::write(&path, ts).unwrap();
    let tsp = std::path::Path::new(&bin).join("tsp");
    let out = std::process::Command::new(&tsp)
        .args(["-I", "file"])
        .arg(&path)
        .args(["-P", "continuity", "-O", "drop"])
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", tsp.display()));
    let report = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && report.trim().is_empty(), "TSDuck: {report}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn check_added(codec: VideoCodec, b_frames: bool) {
    let made = VideoSynth { codec, b_frames, ..VideoSynth::default() }.make();
    let (out, stats) = run(sampled(VideoTimestamps::AddWhenMissing), items(T0), &made.ts);
    let aus = video_timestamps(&out, codec);
    assert_eq!(aus.len(), made.pts.len());
    let want_id = match codec {
        VideoCodec::H264 => Identifier::MispMicrosectime,
        _ => Identifier::HevcMicroseconds,
    };
    for (pts, stamps) in &aus {
        assert_eq!(stamps.len(), 1, "one timestamp per access unit");
        let ts = &stamps[0];
        assert_eq!(ts.identifier, want_id);
        assert_eq!(ts.status, TimeStatus::LOCK_UNKNOWN, "an anchor cannot assert lock (D-12)");
        assert_eq!(ts.value, misp_of(*pts, BASE, T0), "the frame's MISP time");
    }
    // The metadata of each frame has the time its video carries (D-6).
    let klv = klv_units(&out, Codec::KlvSync);
    assert_eq!(klv.len(), made.pts.len());
    for (pts, t, _) in &klv {
        let au = aus.iter().find(|(p, _)| Some(*p) == *pts).expect("a frame with the unit's PTS");
        assert_eq!(*t, au.1[0].value);
    }
    assert_eq!((stats.video.written, stats.video.found, stats.video.skipped), (made.pts.len() as u64, 0, 0));
    assert_eq!(stats.inject.user_data_inserted, made.pts.len() as u64);
    tsduck(&out, &format!("{codec:?}-{b_frames}"));
}

#[test]
fn h264_access_units_get_st0604_timestamps() {
    check_added(VideoCodec::H264, false);
}

#[test]
fn h265_access_units_get_st0604_timestamps_with_b_frames() {
    check_added(VideoCodec::H265, true);
}

/// The input's own clock: V0 at the first frame shown.
const V0: u64 = 1_760_000_000_000_000;

fn input_st0604(pts: u64, id: Identifier) -> Timestamp {
    Timestamp::new(id, TimeStatus::LOCKED, misp_of(pts, BASE, V0))
}

#[test]
fn the_input_timestamps_anchor_the_metadata_and_are_kept() {
    let made = VideoSynth {
        frames: 60,
        st0604: Some(Box::new(|n| Some(input_st0604(BASE + n * FRAME, Identifier::MispMicrosectime)))),
        ..VideoSynth::default()
    }
    .make();
    let mut cfg = sampled(VideoTimestamps::AddWhenMissing);
    cfg.schedule.video_anchor = true;
    let (out, stats) = run(cfg, items(V0), &made.ts);
    // Nothing to add: the video is unchanged.
    // (The input's tables follow its first frame, so a demuxer reading
    // the input misses that one; compare the others.)
    let (a, b) = (pes_of(&out, Codec::H264), pes_of(&made.ts, Codec::H264));
    assert_eq!(a.len(), 60);
    assert!(b.len() >= 59);
    for unit in &b {
        assert!(a.contains(unit), "access unit at PTS {:?} unchanged", unit.0);
    }
    assert_eq!((stats.video.found, stats.video.written), (60, 0));
    assert_eq!((stats.schedule.video_times, stats.schedule.reanchors), (60, 0));
    // Tag 2 follows the video's clock, not the configured anchor.
    let klv = klv_units(&out, Codec::KlvSync);
    assert_eq!(klv.len(), 60);
    for (pts, t, p) in &klv {
        assert_eq!(*t, misp_of(pts.unwrap(), BASE, V0));
        let lat = p.get(Tag::SensorLatitude).and_then(misb::Value::as_f64).unwrap();
        assert!((lat - ((*t - V0) / 100_000) as f64 / 10.0).abs() < 1e-6);
    }
}

#[test]
fn missing_timestamps_are_filled_from_the_video_clock() {
    // Every other access unit carries a timestamp.
    let made = VideoSynth {
        frames: 60,
        st0604: Some(Box::new(|n| (n % 2 == 0).then(|| input_st0604(BASE + n * FRAME, Identifier::MispMicrosectime)))),
        ..VideoSynth::default()
    }
    .make();
    let mut cfg = sampled(VideoTimestamps::AddWhenMissing);
    cfg.schedule.video_anchor = true;
    let (out, stats) = run(cfg, items(V0), &made.ts);
    for (pts, stamps) in video_timestamps(&out, VideoCodec::H264) {
        assert_eq!(stamps.len(), 1);
        assert_eq!(stamps[0].value, misp_of(pts, BASE, V0));
        // The input's lock bit is copied to the added ones (D-12).
        assert!(stamps[0].status.is_locked());
    }
    assert_eq!((stats.video.found, stats.video.written), (30, 30));
}

#[test]
fn rewrite_replaces_the_input_timestamps_in_place() {
    let made = VideoSynth {
        codec: VideoCodec::H265,
        frames: 60,
        st0604: Some(Box::new(|n| Some(input_st0604(BASE + n * FRAME, Identifier::HevcNanoseconds)))),
        ..VideoSynth::default()
    }
    .make();
    let (out, stats) = run(sampled(VideoTimestamps::Rewrite), items(T0), &made.ts);
    for (pts, stamps) in video_timestamps(&out, VideoCodec::H265) {
        assert_eq!(stamps.len(), 1);
        // The identifier (nanoseconds) is kept; the time is the anchor's.
        assert_eq!(stamps[0].identifier, Identifier::HevcNanoseconds);
        assert_eq!(stamps[0].value, misp_of(pts, BASE, T0) * 1000);
    }
    assert_eq!((stats.video.found, stats.video.written), (60, 60));
    assert_eq!(stats.inject.user_data_rewritten, 60);
    tsduck(&out, "rewrite");
}

#[test]
fn a_jump_in_the_input_clock_moves_the_anchor() {
    // The video's clock jumps 3 s forward at frame 30, flagged as a
    // discontinuity; the program clock runs on.
    let made = VideoSynth {
        frames: 60,
        st0604: Some(Box::new(|n| {
            let mut ts = input_st0604(BASE + n * FRAME, Identifier::MispMicrosectime);
            if n >= 30 {
                ts.value += 3_000_000;
            }
            if n == 30 {
                ts.status = TimeStatus::LOCKED_FORWARD_JUMP;
            }
            Some(ts)
        })),
        ..VideoSynth::default()
    }
    .make();
    let mut cfg = sampled(VideoTimestamps::Off);
    cfg.schedule.video_anchor = true;
    let (out, stats) = run(cfg, items(V0), &made.ts);
    assert_eq!(stats.schedule.reanchors, 1);
    for (pts, t, _) in klv_units(&out, Codec::KlvSync) {
        let n = (pts.unwrap() - BASE) / FRAME;
        let jump = if n >= 30 { 3_000_000 } else { 0 };
        assert_eq!(t, misp_of(pts.unwrap(), BASE, V0) + jump);
    }
}

#[test]
fn a_minute_across_the_pts_wrap_with_a_track_and_timestamps() {
    // 60 s of video whose PTS wraps from 2^33 back to 0 after 5 s; a sparse
    // track (a keyframe every 2 s) sampled at every frame, and ST 0604
    // timestamps written into the video.
    const FRAMES: u64 = 1800;
    let base = misb::mpegts::PTS_WRAP - 150 * FRAME;
    let made = VideoSynth { frames: FRAMES, base, pad_to: 16, ..VideoSynth::default() }.make();
    let keyframes = (0..=31u64).map(|k| {
        Sample::items(
            MispTime::from_micros(T0 + k * 2_000_000),
            vec![
                (Tag::SensorLatitude, Input::Float(k as f64 * 0.01)),
                (Tag::SensorLongitude, Input::Float(10.0)),
                (Tag::SensorTrueAltitude, Input::Float(1000.0 + k as f64 * 20.0)),
            ],
        )
    });
    let mut cfg = sampled(VideoTimestamps::AddWhenMissing);
    cfg.schedule.interpolate = Some(misb::track::TrackConfig::new());
    let (out, stats) = run(cfg, keyframes, &made.ts);
    let klv = klv_units(&out, Codec::KlvSync);
    assert_eq!(klv.len() as u64, FRAMES);
    assert!(klv.iter().any(|(p, _, _)| p.unwrap() < 150 * FRAME), "the PTS wrapped");
    let mut last = None;
    for (n, (pts, t, p)) in klv.iter().enumerate() {
        // Tag 2 runs on across the wrap: the frame's time from the anchor.
        assert_eq!(*t, T0 + (n as u64 * FRAME * 100) / 9, "frame {n}");
        assert_eq!(*pts, Some((base + n as u64 * FRAME) % misb::mpegts::PTS_WRAP));
        if let Some(l) = last {
            assert!(*t > l);
        }
        last = Some(*t);
        // Altitude is interpolated linearly between keyframes 2 s apart.
        let secs = (*t - T0) as f64 / 1e6;
        let alt = p.get(Tag::SensorTrueAltitude).and_then(misb::Value::as_f64).unwrap();
        assert!((alt - (1000.0 + 10.0 * secs)).abs() < 0.2, "frame {n}: altitude {alt} at {secs} s");
    }
    for (pts, stamps) in video_timestamps(&out, VideoCodec::H264) {
        assert_eq!(stamps.len(), 1);
        let n = (pts + misb::mpegts::PTS_WRAP - base) % misb::mpegts::PTS_WRAP / FRAME;
        assert_eq!(stamps[0].value, T0 + (n * FRAME * 100) / 9);
    }
    assert_eq!(stats.video.written, FRAMES);
    assert_eq!(stats.schedule.stale, 0);
    tsduck(&out, "wrap");
}

#[test]
fn m2ts_records_in_and_out() {
    // 192-byte records: a 4-byte TP_extra_header (arrival time stamp) before
    // each packet. The output keeps the input's headers and stamps the
    // inserted packets between their neighbours'.
    let made = VideoSynth { frames: 60, ..VideoSynth::default() }.make();
    let mut m2ts = Vec::new();
    for (i, p) in made.ts.chunks(188).enumerate() {
        m2ts.extend_from_slice(&((i as u32 * 13_500) & 0x3FFF_FFFF).to_be_bytes());
        m2ts.extend_from_slice(p);
    }
    let mut cfg = sampled(VideoTimestamps::Off);
    cfg.inject = cfg.inject.with_record_format(misb::mpegts::mux::RecordFormat::M2ts);
    let (out, stats) = run(cfg, items(T0), &m2ts);
    assert_eq!(out.len() % 192, 0);
    let ts: Vec<u8> = out.chunks(192).flat_map(|r| r[4..].to_vec()).collect();
    assert_eq!(klv_units(&ts, Codec::KlvSync).len(), 60);
    assert_eq!(stats.inject.units_inserted, 60);
    // Arrival stamps never go back (30-bit, no wrap in 60 frames).
    let stamps: Vec<u32> = out.chunks(192).map(|r| u32::from_be_bytes([r[0], r[1], r[2], r[3]]) & 0x3FFF_FFFF).collect();
    assert!(stamps.windows(2).all(|w| w[1] >= w[0]), "stamps in order");
    // Every input record is in the output unchanged, or is a PAT/PMT
    // record (resent, rewritten) .
    let input: std::collections::HashSet<&[u8]> = m2ts.chunks(192).collect();
    let kept = out.chunks(192).filter(|r| input.contains(r)).count();
    let psi = m2ts.chunks(192).filter(|r| matches!(((r[5] & 0x1F) as u16) << 8 | r[6] as u16, 0 | PMT)).count();
    assert!(kept >= m2ts.len() / 192 - psi, "{kept} of {} input records kept", m2ts.len() / 192);
}
