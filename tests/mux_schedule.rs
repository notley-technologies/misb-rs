//! The metadata scheduler: samples to timed units, from synthetic frames.
#![forbid(unsafe_code)]

use misb::encode::{Input, St0601Builder};
use misb::mux::{
    wrap_pts, Anchor, AnchorSpec, Carriage, Flow, FrameTime, Rate, Sample, ScheduleConfig, ScheduleError,
    ScheduledUnit, Scheduler,
};
use misb::st0601::Tag;
use misb::{MispTime, Value};
use std::convert::Infallible;

const T0: u64 = 1_700_000_000_000_000;
const P0: u64 = 1_000_000;
const FRAME: u64 = 3003;
/// Video arrives 700 ms before it is shown.
const LEAD: u64 = 63_000;
const WRAP: u64 = 1 << 33;

fn recorded(t: u64) -> Sample {
    let mut b = St0601Builder::new(MispTime::from_micros(t));
    b.set(Tag::SensorLatitude, 38.5).unwrap();
    Sample::packet(MispTime::from_micros(t), b.finish().unwrap())
}

fn items(t: u64, lat: f64) -> Sample {
    Sample::items(MispTime::from_micros(t), vec![(Tag::SensorLatitude, Input::Float(lat))])
}

/// A frame of 29.97 fps video in decode order: index `n`, shown at
/// position `shown`, arriving `LEAD` before its PTS (or before its DTS).
struct F {
    frame: FrameTime,
    clock: u64,
}

/// `count` frames without B-frames from PTS `base`.
fn plain(base: u64, count: u64) -> Vec<F> {
    (0..count)
        .map(|n| {
            let pts = (base + n * FRAME) % WRAP;
            F { frame: FrameTime { pts, dts: None, discontinuity: false }, clock: (pts + WRAP - LEAD) % WRAP * 300 }
        })
        .collect()
}

/// `count` frames I P B B P B B ... in decode order.
fn with_b_frames(base: u64, count: u64) -> Vec<F> {
    (0..count)
        .map(|n| {
            let shown = if n == 0 { 0 } else if n % 3 == 1 { n + 2 } else { n - 1 };
            let pts = base + shown * FRAME;
            let dts = base + n * FRAME - 2 * FRAME;
            F { frame: FrameTime { pts, dts: Some(dts), discontinuity: false }, clock: (dts - LEAD) * 300 }
        })
        .collect()
}

/// Run the frames through a scheduler; units with the index of the frame
/// call that produced them.
fn run<S: Iterator<Item = Sample>>(s: &mut Scheduler<S>, frames: &[F]) -> Vec<(usize, ScheduledUnit)> {
    let mut units = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let mut out = |u: ScheduledUnit| -> Result<(), Infallible> {
            units.push((i, u));
            Ok(())
        };
        s.frame(&f.frame, Some(f.clock), &mut out).unwrap();
    }
    let last = frames.last().map(|f| f.clock);
    let mut out = |u: ScheduledUnit| -> Result<(), Infallible> {
        units.push((frames.len(), u));
        Ok(())
    };
    s.finish(last, &mut out).unwrap();
    units
}

fn time_of(u: &ScheduledUnit) -> u64 {
    misb::decode(&u.data).unwrap().get(Tag::PrecisionTimeStamp).and_then(Value::as_time).unwrap()
}

#[test]
fn recorded_packets_go_out_unchanged_at_their_own_time() {
    let samples: Vec<Sample> = (0..100).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let mut s = Scheduler::new(cfg, samples.clone().into_iter()).unwrap();
    let units = run(&mut s, &plain(P0, 300));
    assert_eq!(units.len(), 100);
    for (k, (_, u)) in units.iter().enumerate() {
        let misb::mux::SampleData::Packet(bytes) = &samples[k].data else { unreachable!() };
        assert_eq!(&u.data, bytes, "recorded bytes unchanged");
        // 100 ms = 9000 ticks exactly.
        assert_eq!(u.pts, Some(P0 + 9000 * k as u64));
    }
    let st = s.stats();
    assert_eq!((st.units, st.late, st.unused, st.out_of_order), (100, 0, 0, 0));
    assert_eq!(s.anchor(), Some(Anchor::new(P0 as i64, MispTime::from_micros(T0))));
}

#[test]
fn units_are_handed_over_within_the_horizon() {
    let samples: Vec<Sample> = (0..100).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let frames = plain(P0, 300);
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    for (i, u) in run(&mut s, &frames) {
        let now = frames[i.min(frames.len() - 1)].clock / 300;
        let lead = u.pts.unwrap() as i64 - now as i64;
        assert!((90..=135_000).contains(&lead), "lead {lead}");
    }
}

#[test]
fn sampling_at_frames_follows_presentation_order() {
    // Items once a second for 5 s; video with B-frames for 10 s.
    let samples: Vec<Sample> = (0..5).map(|k| items(T0 + k * 1_000_000, k as f64)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.rate = Rate::EveryFrame;
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &with_b_frames(P0, 300));
    // Frames up to 4 s + 3 s of hold get metadata: 7 s at 29.97 fps.
    assert_eq!(units.len(), 210);
    assert_eq!(s.stats().stale, 90);
    let mut last = 0;
    for (n, (_, u)) in units.iter().enumerate() {
        let pts = u.pts.unwrap();
        assert_eq!(pts, P0 + n as u64 * FRAME, "every frame in PTS order");
        assert!(pts > last);
        last = pts;
        let p = misb::decode(&u.data).unwrap();
        assert!(p.is_ok());
        // Tag 2 is the frame's MISP time (D-11 floor), the values those of
        // the latest sample.
        let t = time_of(u);
        assert_eq!(t, T0 + (n as u64 * FRAME * 100) / 9);
        let lat = p.get(Tag::SensorLatitude).unwrap().as_f64().unwrap();
        let latest = ((t - T0) / 1_000_000).min(4);
        assert!((lat - latest as f64).abs() < 1e-6, "frame {n}: {lat}");
    }
}

#[test]
fn hz_rate_thins_frames() {
    let samples: Vec<Sample> = (0..11).map(|k| items(T0 + k * 1_000_000, 1.0)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.rate = Rate::Hz(10.0);
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &plain(P0, 300));
    assert_eq!(units.len(), 100);
    for w in units.windows(2) {
        assert_eq!(w[1].1.pts.unwrap() - w[0].1.pts.unwrap(), 3 * FRAME);
    }
}

#[test]
fn snapping_moves_pts_to_the_nearest_frame_only() {
    // Recorded 4 ms after every third frame's time.
    let samples: Vec<Sample> = (0..50).map(|k| recorded(T0 + (k * 3 * FRAME * 100) / 9 + 4_000)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    cfg.snap_to_frames = true;
    let mut s = Scheduler::new(cfg, samples.clone().into_iter()).unwrap();
    let units = run(&mut s, &plain(P0, 200));
    assert_eq!(units.len(), 50);
    for (k, (_, u)) in units.iter().enumerate() {
        assert_eq!(u.pts, Some(P0 + 3 * FRAME * k as u64));
        assert_eq!(time_of(u), samples[k].time.as_micros(), "tag 2 untouched");
    }
    assert_eq!(s.stats().snapped, 50);
}

#[test]
fn async_units_go_before_the_frame_they_describe() {
    let samples: Vec<Sample> = (0..30).map(|k| recorded(T0 + k * 100_000 + 50)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Async);
    cfg.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let frames = plain(P0, 120);
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &frames);
    assert_eq!(units.len(), 30);
    for (i, u) in &units {
        assert_eq!(u.pts, None);
        let want = Anchor::new(P0 as i64, MispTime::from_micros(T0)).pts_at(MispTime::from_micros(time_of(u)));
        // Handed over at the first frame showing a time at or after it.
        let first = frames.iter().position(|f| f.frame.pts as i64 >= want).unwrap();
        assert_eq!(*i, first);
    }
}

#[test]
fn recorded_packets_cannot_be_sampled() {
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.rate = Rate::EveryFrame;
    let mut s = Scheduler::new(cfg, vec![recorded(T0)].into_iter()).unwrap();
    let f = &plain(P0, 1)[0];
    let mut out = |_u: ScheduledUnit| -> Result<(), Infallible> { Ok(()) };
    let e = s.frame(&f.frame, Some(f.clock), &mut out).unwrap_err();
    assert_eq!(e, Flow::Schedule(ScheduleError::RecordedNeedsExplicit));
}

#[test]
fn late_and_out_of_order_samples_are_counted() {
    // A sample before the video (its PTS has passed when the first frame
    // arrives), then one going back in time.
    let samples = vec![recorded(T0 - 900_000), recorded(T0), recorded(T0 + 100_000), recorded(T0 + 50_000)];
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &plain(P0, 30));
    assert_eq!(units.len(), 2);
    let st = s.stats();
    assert_eq!((st.late, st.out_of_order, st.samples), (1, 1, 4));
}

#[test]
fn pts_wraps() {
    let base = WRAP - 90_000;
    let samples: Vec<Sample> = (0..30).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.anchor = AnchorSpec::Pts { pts: base, misp: MispTime::from_micros(T0) };
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &plain(base, 100));
    assert_eq!(units.len(), 30);
    for (k, (_, u)) in units.iter().enumerate() {
        assert_eq!(u.pts, Some((base + 9000 * k as u64) % WRAP));
    }
    assert_eq!(wrap_pts(WRAP as i64 + 5), 5);
}

#[test]
fn a_clock_discontinuity_carries_the_time_line() {
    let samples: Vec<Sample> = (0..10).map(|k| items(T0 + k * 1_000_000, 2.0)).collect();
    let mut cfg = ScheduleConfig::new(Carriage::Sync);
    cfg.rate = Rate::EveryFrame;
    cfg.max_hold_ms = None;
    let mut frames = plain(P0, 60);
    let mut after = plain(5_000_000_000, 60);
    after[0].frame.discontinuity = true;
    frames.extend(after);
    let mut s = Scheduler::new(cfg, samples.into_iter()).unwrap();
    let units = run(&mut s, &frames);
    assert_eq!(units.len(), 120);
    assert_eq!(s.stats().discontinuities, 1);
    // Tag 2 keeps advancing one frame at a time across the jump.
    let times: Vec<u64> = units.iter().map(|(_, u)| time_of(u)).collect();
    for w in times.windows(2) {
        let step = w[1] - w[0];
        assert!((33_366..=33_367).contains(&step), "{step}");
    }
    assert_eq!(units[60].1.pts, Some(5_000_000_000));
}
