//! FileMux end to end: a metadata source injected into synthetic transport
//! streams, read back with the mpegts demuxer and the misb decoder.
#![forbid(unsafe_code)]

use misb::encode::{Input, St0601Builder};
use misb::mpegts::mux::{OnOverflow, PesUnit, PesWriter, ProgramTables, RateMode, StreamSpec, NULL_PACKET};
use misb::mpegts::{Codec, Demuxer, PacketHeader, Select, Subscription, Unit, PTS_WRAP};
use misb::mux::{
    AnchorSpec, Carriage, FileMux, FileMuxConfig, FileMuxError, KlvSamples, Rate, Sample, SampleData, ScheduleError,
};
use misb::st0601::Tag;
use misb::{MispTime, Value};

const T0: u64 = 1_700_000_000_000_000;
const BASE: u64 = 900_000;
const FRAME: u64 = 3003;
const VIDEO: u16 = 0x100;
const PMT: u16 = 0x1000;

/// A synthetic program: H.264-like video on 0x100 carrying the PCR, PAT
/// and PMT every third frame, video arriving 700 ms before its decode
/// time, optionally B-frames, and each frame period padded with null
/// packets to a fixed count (a constant bitrate stream).
struct Synth {
    frames: u64,
    b_frames: bool,
    /// Packets per frame period, padded with null packets (0: no padding,
    /// a variable bitrate stream).
    pad_to: usize,
    /// PTS of the first frame shown.
    base: u64,
}

impl Default for Synth {
    fn default() -> Self {
        Synth { frames: 90, b_frames: false, pad_to: 16, base: BASE }
    }
}

struct Made {
    ts: Vec<u8>,
    /// Frame PTS in decode order.
    pts: Vec<u64>,
}

impl Synth {
    fn make(&self) -> Made {
        let mut tables = ProgramTables::new(1);
        tables.add_program(1, PMT, Some(VIDEO)).unwrap();
        tables.add_stream(1, VIDEO, &StreamSpec::h264()).unwrap();
        let mut video = PesWriter::new(VIDEO, &StreamSpec::h264()).unwrap();
        let mut ts = Vec::new();
        let mut pts_list = Vec::new();
        let mut payload = vec![0, 0, 0, 1, 0x09, 0xF0];
        payload.resize(1500, 0xAB);
        for n in 0..self.frames {
            let (pts, dts) = if self.b_frames {
                let shown = if n == 0 { 0 } else if n % 3 == 1 { n + 2 } else { n - 1 };
                (self.base + shown * FRAME, self.base + n * FRAME - 2 * FRAME)
            } else {
                (self.base + n * FRAME, self.base + n * FRAME)
            };
            let (pts, dts) = (pts % PTS_WRAP, dts % PTS_WRAP);
            pts_list.push(pts);
            let start = ts.len();
            let mut unit = PesUnit::new(&payload).with_pts(pts).with_pcr((dts + PTS_WRAP - 63_000) % PTS_WRAP * 300);
            if self.b_frames {
                unit = unit.with_dts(dts);
            }
            if n % 30 == 0 {
                unit = unit.with_random_access();
            }
            video.write(&unit, &mut ts).unwrap();
            // Tables after the frame, so the PCR packet starts every
            // frame period and a padded stream has an exact constant rate.
            if n % 3 == 0 {
                tables.write_all(&mut ts).unwrap();
            }
            while (ts.len() - start) / 188 < self.pad_to {
                ts.extend_from_slice(&NULL_PACKET);
            }
        }
        Made { ts, pts: pts_list }
    }
}

fn recorded(t: u64) -> Sample {
    let mut b = St0601Builder::new(MispTime::from_micros(t));
    b.set(Tag::SensorLatitude, 38.5).unwrap();
    b.set(Tag::MissionId, "SYNTHETIC").unwrap();
    Sample::packet(MispTime::from_micros(t), b.finish().unwrap())
}

fn bytes_of(s: &Sample) -> Vec<u8> {
    match &s.data {
        SampleData::Packet(b) => b.clone(),
        _ => unreachable!(),
    }
}

fn run<S: Iterator<Item = Sample>>(cfg: FileMuxConfig, source: S, ts: &[u8]) -> (Vec<u8>, misb::mux::FileMuxStats) {
    let mut mux = FileMux::new(cfg, source).unwrap();
    let mut out = Vec::new();
    for chunk in ts.chunks(1316) {
        mux.push(chunk, &mut out).unwrap();
    }
    let stats = mux.finish(&mut out).unwrap();
    (out, stats)
}

/// KLV access units on the output: (PTS, payload), in stream order.
fn read_back(ts: &[u8], codec: Codec) -> Vec<(Option<u64>, Vec<u8>)> {
    let mut d = Demuxer::new();
    let mut sub = Subscription::new(Select::Codec(codec), Unit::Pes);
    if codec == Codec::KlvSync {
        sub = sub.strip_metadata_au();
    }
    d.subscribe(sub).unwrap();
    d.push(ts);
    d.finish();
    let mut units = Vec::new();
    while let Some(o) = d.pop_output() {
        units.push((o.pts, o.payload().to_vec()));
        d.recycle(o);
    }
    units
}

fn time_of(bytes: &[u8]) -> u64 {
    let p = misb::decode(bytes).unwrap();
    assert!(p.is_ok(), "{p:?}");
    p.get(Tag::PrecisionTimeStamp).and_then(Value::as_time).unwrap()
}

/// The patched ffprobe and TSDuck, when configured (as in the mpegts
/// tests); a wrong path fails rather than skips. TSDuck's pcrverify
/// measures PCRs against a constant bitrate, so it runs on constant
/// bitrate output only (VBR insertion raises the rate of a PCR interval,
/// which is conformant, D-ISO13818-15).
fn oracles(ts: &[u8], units: usize, name: &str, cbr: bool) {
    let dir = std::env::temp_dir().join(format!("misb-filemux-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.ts");
    std::fs::write(&path, ts).unwrap();
    if let Ok(ffprobe) = std::env::var("MPEGTS_FFPROBE") {
        let out = std::process::Command::new(&ffprobe)
            .args(["-v", "error", "-select_streams", "d", "-show_entries", "packet=pts", "-of", "csv=p=0"])
            .arg(&path)
            .output()
            .unwrap_or_else(|e| panic!("{ffprobe}: {e}"));
        // The synthetic video has no real pictures, so the H.264 decoder
        // complains while probing; any other message fails.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let other: Vec<&str> = stderr.lines().filter(|l| !l.starts_with("[h264 @")).collect();
        assert!(out.status.success() && other.is_empty(), "{stderr}");
        let packets = String::from_utf8(out.stdout).unwrap().lines().filter(|l| !l.is_empty()).count();
        assert_eq!(packets, units, "ffprobe sees every KLV unit");
    }
    if let Ok(bin) = std::env::var("MPEGTS_TSDUCK") {
        let tsp = std::path::Path::new(&bin).join("tsp");
        let mut tsp_cmd = std::process::Command::new(&tsp);
        tsp_cmd.args(["-I", "file"]).arg(&path).args(["-P", "continuity"]);
        if cbr {
            tsp_cmd.args(["-P", "pcrverify"]);
        }
        let out = tsp_cmd.args(["-O", "drop"]).output().unwrap_or_else(|e| panic!("{}: {e}", tsp.display()));
        let report = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{report}");
        for line in report.lines() {
            assert!(line.contains("pcrverify:") && line.contains(" 0 with jitter"), "TSDuck: {line}");
        }
        assert_eq!(report.lines().count(), usize::from(cbr), "TSDuck: {report}");
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn a_recorded_klv_file_goes_in_unchanged() {
    let made = Synth { frames: 150, b_frames: false, ..Synth::default() }.make();
    // A .klv file: 40 packets at 10 Hz, split back into samples.
    let packets: Vec<Sample> = (0..40).map(|k| recorded(T0 + k * 100_000)).collect();
    let file: Vec<u8> = packets.iter().flat_map(bytes_of).collect();
    let mut samples = KlvSamples::new();
    samples.push(&file);
    samples.finish();
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let (out, stats) = run(cfg, std::iter::from_fn(move || samples.next_sample()), &made.ts);

    let units = read_back(&out, Codec::KlvSync);
    assert_eq!(units.len(), 40);
    for (k, (pts, data)) in units.iter().enumerate() {
        assert_eq!(*data, bytes_of(&packets[k]), "packet {k} byte for byte");
        assert_eq!(*pts, Some(BASE + 9000 * k as u64), "PTS from tag 2 through the anchor");
    }
    assert_eq!(stats.inject.units_inserted, 40);
    assert_eq!(stats.inject.dropped_late, 0);
    assert_eq!(stats.schedule.unused, 0);
    oracles(&out, 40, "recorded", false);
}

#[test]
fn items_sampled_at_every_frame_with_b_frames() {
    let made = Synth { frames: 90, b_frames: true, ..Synth::default() }.make();
    let samples = (0..4u64).map(|k| {
        Sample::items(MispTime::from_micros(T0 + k * 1_000_000), vec![(Tag::SensorLatitude, Input::Float(k as f64))])
    });
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::EveryFrame;
    let (out, stats) = run(cfg, samples, &made.ts);

    let units = read_back(&out, Codec::KlvSync);
    let mut want: Vec<u64> = made.pts.clone();
    want.sort_unstable();
    let got: Vec<u64> = units.iter().map(|(p, _)| p.unwrap()).collect();
    assert_eq!(got, want, "one unit per frame, in presentation order");
    for (pts, data) in &units {
        // SourceStart: the first frame is at the first sample's time.
        assert_eq!(time_of(data), T0 + (pts.unwrap() - BASE) * 100 / 9);
    }
    assert_eq!(stats.inject.dropped_late, 0);
    oracles(&out, 90, "frames", false);
}

#[cfg(feature = "json")]
#[test]
fn ndjson_records_drive_the_metadata() {
    let made = Synth { frames: 60, b_frames: false, ..Synth::default() }.make();
    let lines = [
        r#"{"time": "2023-11-14T22:13:20Z", "time_scale": "misp", "items": {"SensorLatitude": 38.0, "SensorLongitude": -77.0}}"#,
        r#"{"time": "2023-11-14T22:13:21Z", "time_scale": "misp", "items": {"SensorLatitude": 38.1, "SensorLongitude": -77.1}}"#,
    ];
    let samples = lines.iter().map(|l| Sample::from(misb::json::parse_record(l, misb::LeapSeconds::builtin()).unwrap()));
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::Hz(10.0);
    let (out, _) = run(cfg, samples, &made.ts);
    let units = read_back(&out, Codec::KlvSync);
    assert_eq!(units.len(), 20, "60 frames at 10 Hz");
    let lat = |d: &[u8]| misb::decode(d).unwrap().get(Tag::SensorLatitude).unwrap().as_f64().unwrap();
    assert!((lat(&units[0].1) - 38.0).abs() < 1e-6);
    assert!((lat(&units[19].1) - 38.1).abs() < 1e-6);
}

#[test]
fn async_carriage() {
    let made = Synth { frames: 90, b_frames: false, ..Synth::default() }.make();
    let packets: Vec<Sample> = (0..25).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = FileMuxConfig::new(Carriage::Async);
    cfg.schedule.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let (out, stats) = run(cfg, packets.clone().into_iter(), &made.ts);
    let units = read_back(&out, Codec::KlvAsync);
    assert_eq!(units.len(), 25);
    for (k, (pts, data)) in units.iter().enumerate() {
        assert_eq!(*pts, None);
        assert_eq!(*data, bytes_of(&packets[k]));
    }
    assert_eq!(stats.inject.units_inserted, 25);
    oracles(&out, 25, "async", false);
}

#[test]
fn cbr_keeps_every_packet_in_place() {
    let made = Synth { frames: 120, b_frames: false, pad_to: 18, ..Synth::default() }.make();
    let samples = (0..4u64).map(|k| Sample::items(MispTime::from_micros(T0 + k * 1_000_000), vec![]));
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::EveryFrame;
    cfg.inject = cfg.inject.with_rate(RateMode::Cbr { on_overflow: OnOverflow::Fail });
    let (out, stats) = run(cfg, samples, &made.ts);
    assert_eq!(out.len(), made.ts.len(), "same packet count");
    let pcrs = |ts: &[u8]| -> Vec<(usize, u64)> {
        ts.chunks(188)
            .enumerate()
            .filter_map(|(i, p)| PacketHeader::parse(p.try_into().unwrap()).unwrap().pcr().map(|c| (i, c)))
            .collect()
    };
    assert_eq!(pcrs(&out), pcrs(&made.ts), "every PCR at the same position");
    assert_eq!(read_back(&out, Codec::KlvSync).len(), 120);
    assert_eq!(stats.inject.dropped_overflow, 0);
    oracles(&out, 120, "cbr", true);
}

#[test]
fn other_packets_pass_through_unchanged() {
    let made = Synth { frames: 60, b_frames: true, ..Synth::default() }.make();
    let samples = (0..3u64).map(|k| Sample::items(MispTime::from_micros(T0 + k * 1_000_000), vec![]));
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::EveryFrame;
    let mut mux = FileMux::new(cfg, samples).unwrap();
    let mut out = Vec::new();
    mux.push(&made.ts, &mut out).unwrap();
    mux.finish(&mut out).unwrap();
    let klv = mux.injector().target().unwrap().klv_pid;
    let keep = |ts: &[u8], drop: &[u16]| -> Vec<Vec<u8>> {
        ts.chunks(188)
            .filter(|p| {
                let pid = PacketHeader::parse((*p).try_into().unwrap()).unwrap().pid;
                !drop.contains(&pid)
            })
            .map(<[u8]>::to_vec)
            .collect()
    };
    assert_eq!(keep(&out, &[0, PMT, klv]), keep(&made.ts, &[0, PMT]));
}

#[test]
fn recorded_packets_with_a_frame_rate_stop_with_an_error() {
    let made = Synth { frames: 30, b_frames: false, ..Synth::default() }.make();
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.rate = Rate::EveryFrame;
    let mut mux = FileMux::new(cfg, vec![recorded(T0)].into_iter()).unwrap();
    let mut out = Vec::new();
    let e = mux.push(&made.ts, &mut out).and_then(|()| mux.finish(&mut out).map(|_| ())).unwrap_err();
    assert_eq!(e, FileMuxError::Schedule(ScheduleError::RecordedNeedsExplicit));
    // Errors are final.
    assert_eq!(mux.push(&made.ts[..188], &mut out).unwrap_err(), e);
}

#[test]
fn settings_must_agree() {
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.carriage = Carriage::Async;
    assert!(matches!(cfg.validate(), Err(FileMuxError::Config(_))));
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.horizon_ms = 1000;
    assert!(matches!(cfg.validate(), Err(FileMuxError::Config(_))));
}

#[test]
fn pts_wrap_inside_the_stream() {
    // The video starts 1 s before the 2^33 wrap and runs 2 s.
    let base = PTS_WRAP - 90_000;
    let made = Synth { frames: 60, base, ..Synth::default() }.make();
    let packets: Vec<Sample> = (0..20).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.anchor = AnchorSpec::FirstFrame(MispTime::from_micros(T0));
    let (out, stats) = run(cfg, packets.clone().into_iter(), &made.ts);
    let units = read_back(&out, Codec::KlvSync);
    assert_eq!(units.len(), 20);
    for (k, (pts, data)) in units.iter().enumerate() {
        assert_eq!(*pts, Some((base + 9000 * k as u64) % PTS_WRAP));
        assert_eq!(*data, bytes_of(&packets[k]));
    }
    assert_eq!(stats.inject.dropped_late, 0);
    oracles(&out, 20, "wrap", false);
}

#[test]
fn samples_before_the_video_are_skipped() {
    // PTS BASE is T0 + 1 s, so the first packets' times have passed when
    // the video starts arriving 700 ms ahead of it; the ones inside the
    // window go right before the first frame.
    let made = Synth { frames: 60, ..Synth::default() }.make();
    let packets: Vec<Sample> = (0..15).map(|k| recorded(T0 + k * 100_000)).collect();
    let mut cfg = FileMuxConfig::new(Carriage::Sync);
    cfg.schedule.anchor = AnchorSpec::Pts { pts: BASE - 90_000, misp: MispTime::from_micros(T0) };
    let (out, stats) = run(cfg, packets.into_iter(), &made.ts);
    let units = read_back(&out, Codec::KlvSync);
    // Packets 0 to 3 are at or before the first packet's clock (BASE - 63000).
    assert_eq!(stats.schedule.late, 4);
    assert_eq!(units.len(), 11);
    assert_eq!(units[0].0, Some(BASE - 90_000 + 4 * 9000));
    assert_eq!(stats.inject.dropped_late, 0);
}
