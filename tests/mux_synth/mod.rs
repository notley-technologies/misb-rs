//! Synthetic H.264 and H.265 transport streams for the mux tests: access
//! units with the NAL unit structure the injector looks at (access unit
//! delimiter, parameter sets, optional SEI, a slice), and readers for what
//! comes out.
#![allow(dead_code)]

use misb::mpegts::mux::{PesUnit, PesWriter, ProgramTables, StreamSpec, NULL_PACKET};
use misb::mpegts::nal::{find_user_data, user_data_sei, UserData, VideoCodec};
use misb::mpegts::{Codec, Demuxer, Select, Subscription, Unit, PTS_WRAP};
use misb::st0601::Tag;
use misb::st0604::Timestamp;
use misb::Value;

pub const T0: u64 = 1_700_000_000_000_000;
pub const BASE: u64 = 900_000;
pub const FRAME: u64 = 3003;
pub const VIDEO: u16 = 0x100;
pub const PMT: u16 = 0x1000;

/// A synthetic program: video on 0x100 carrying the PCR, PAT and PMT every
/// third frame, video arriving 700 ms before its decode time, each frame
/// period padded with null packets to `pad_to` packets.
pub struct VideoSynth {
    pub codec: VideoCodec,
    pub frames: u64,
    pub b_frames: bool,
    pub pad_to: usize,
    /// PTS of the first frame shown.
    pub base: u64,
    /// The ST 0604 timestamp the input carries in frame `n` (decode order).
    pub st0604: Option<Box<dyn Fn(u64) -> Option<Timestamp>>>,
    /// From this frame on, every timestamp moves by this many 90 kHz
    /// ticks, and its PCR packet sets discontinuity_indicator.
    pub jump: Option<(u64, u64)>,
}

impl Default for VideoSynth {
    fn default() -> Self {
        VideoSynth {
            codec: VideoCodec::H264,
            frames: 90,
            b_frames: false,
            pad_to: 20,
            base: BASE,
            st0604: None,
            jump: None,
        }
    }
}

pub struct Made {
    pub ts: Vec<u8>,
    /// Frame PTS in decode order.
    pub pts: Vec<u64>,
    /// Byte offset of each frame's first packet.
    pub starts: Vec<usize>,
}

impl Made {
    /// The stream cut at frame starts: chunk `k` holds frame `k` (and
    /// what follows it up to the next frame).
    pub fn frames(&self) -> Vec<&[u8]> {
        let mut cuts = self.starts.clone();
        cuts.push(self.ts.len());
        cuts.windows(2).map(|w| &self.ts[w[0]..w[1]]).collect()
    }
}

/// One access unit in byte stream form.
pub fn access_unit(codec: VideoCodec, idr: bool, st0604: Option<&Timestamp>) -> Vec<u8> {
    let mut au = Vec::new();
    match codec {
        VideoCodec::H264 => {
            au.extend_from_slice(&[0, 0, 0, 1, 0x09, 0xF0]);
            if idr {
                au.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E, 0x8D, 0x68, 0x0B, 0x04]);
                au.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
            }
        }
        _ => {
            au.extend_from_slice(&[0, 0, 0, 1, 0x46, 0x01, 0x50]);
            if idr {
                au.extend_from_slice(&[0, 0, 0, 1, 0x40, 0x01, 0x0C, 0x01, 0xFF, 0xFF]);
                au.extend_from_slice(&[0, 0, 0, 1, 0x42, 0x01, 0x01, 0x01, 0x60, 0x00]);
                au.extend_from_slice(&[0, 0, 0, 1, 0x44, 0x01, 0xC1, 0x72, 0xB4]);
            }
        }
    }
    if let Some(ts) = st0604 {
        let bytes = ts.to_bytes().unwrap();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[..16]);
        assert!(user_data_sei(codec, 1, &uuid, &bytes[16..], &mut au));
    }
    match codec {
        VideoCodec::H264 => au.extend_from_slice(&[0, 0, 0, 1, if idr { 0x65 } else { 0x41 }, 0x88, 0x84]),
        _ => au.extend_from_slice(&[0, 0, 0, 1, if idr { 0x26 } else { 0x02 }, 0x01, 0xAF]),
    }
    au.resize(au.len() + 1400, 0xAB);
    au
}

impl VideoSynth {
    pub fn make(&self) -> Made {
        let spec = match self.codec {
            VideoCodec::H264 => StreamSpec::h264(),
            _ => StreamSpec::h265(),
        };
        let mut tables = ProgramTables::new(1);
        tables.add_program(1, PMT, Some(VIDEO)).unwrap();
        tables.add_stream(1, VIDEO, &spec).unwrap();
        let mut video = PesWriter::new(VIDEO, &spec).unwrap();
        let mut ts = Vec::new();
        let mut pts_list = Vec::new();
        let mut starts = Vec::new();
        for n in 0..self.frames {
            let (pts, dts) = if self.b_frames {
                let shown = if n == 0 { 0 } else if n % 3 == 1 { n + 2 } else { n - 1 };
                (self.base + shown * FRAME, self.base + n * FRAME - 2 * FRAME)
            } else {
                (self.base + n * FRAME, self.base + n * FRAME)
            };
            let shift = match self.jump {
                Some((k, d)) if n >= k => d,
                _ => 0,
            };
            let (pts, dts) = ((pts + shift) % PTS_WRAP, (dts + shift) % PTS_WRAP);
            pts_list.push(pts);
            let st0604 = self.st0604.as_ref().and_then(|f| f(n));
            let payload = access_unit(self.codec, n % 30 == 0, st0604.as_ref());
            let start = ts.len();
            let mut unit = PesUnit::new(&payload).with_pts(pts).with_pcr((dts + PTS_WRAP - 63_000) % PTS_WRAP * 300);
            if self.b_frames {
                unit = unit.with_dts(dts);
            }
            if n % 30 == 0 {
                unit = unit.with_random_access();
            }
            video.write(&unit, &mut ts).unwrap();
            if self.jump.map_or(false, |(k, _)| k == n) {
                // discontinuity_indicator in the PCR packet's adaptation field.
                assert!(ts[start + 3] & 0x20 != 0 && ts[start + 4] > 0);
                ts[start + 5] |= 0x80;
            }
            starts.push(start);
            if n % 3 == 0 {
                tables.write_all(&mut ts).unwrap();
            }
            while (ts.len() - start) / 188 < self.pad_to {
                ts.extend_from_slice(&NULL_PACKET);
            }
        }
        Made { ts, pts: pts_list, starts }
    }
}

/// PES payloads of one codec on the output: (PTS, payload), in stream
/// order. KLV is stripped of its access unit cells.
pub fn pes_of(ts: &[u8], codec: Codec) -> Vec<(Option<u64>, Vec<u8>)> {
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

/// Each video access unit's PTS and ST 0604 timestamps.
pub fn video_timestamps(ts: &[u8], codec: VideoCodec) -> Vec<(u64, Vec<Timestamp>)> {
    let c = match codec {
        VideoCodec::H264 => Codec::H264,
        _ => Codec::H265,
    };
    pes_of(ts, c)
        .into_iter()
        .map(|(pts, es)| {
            let mut found: Vec<UserData> = Vec::new();
            find_user_data(codec, &es, &mut found);
            let stamps = found
                .iter()
                .filter_map(|u| {
                    let id = misb::st0604::Identifier::from_bytes(&u.uuid)?;
                    misb::st0604::decode_payload(id, &u.payload).ok().map(|d| d.timestamp)
                })
                .collect();
            (pts.unwrap(), stamps)
        })
        .collect()
}

/// The KLV units on the output: (PTS, tag 2, packet).
pub fn klv_units(ts: &[u8], codec: Codec) -> Vec<(Option<u64>, u64, misb::Packet)> {
    pes_of(ts, codec)
        .into_iter()
        .map(|(pts, bytes)| {
            let p = misb::decode(&bytes).unwrap();
            assert!(p.is_ok(), "{p:?}");
            let t = p.get(Tag::PrecisionTimeStamp).and_then(Value::as_time).unwrap();
            (pts, t, p)
        })
        .collect()
}

/// The MISP time of a PTS `pts` when `base` is at `t0` (D-11 floor).
pub fn misp_of(pts: u64, base: u64, t0: u64) -> u64 {
    let d = (pts + PTS_WRAP - base) % PTS_WRAP;
    t0 + d * 100 / 9
}
