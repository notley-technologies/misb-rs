//! Fuzz harnesses, shared by the coverage-guided targets in `fuzz/` and the
//! stable-toolchain fuzz test `tests/fuzz.rs`.
//!
//! Each harness accepts any bytes, must never panic, and checks properties
//! that hold for every input:
//!
//! - the packets and counters do not depend on how the input is split into
//!   pushes (when nothing is dropped to the queue limit), and the stream
//!   decoder, `decode_all_with`, `decode_iter_with` and `decode_prefix`
//!   agree;
//! - every decoded packet stays within its `Config` limits, and every input
//!   byte is counted once;
//! - pushing slices no larger than the rule in `include/misb.h`, draining
//!   after each, never drops a packet;
//! - the C API returns only documented status codes, never reports an
//!   internal error, and shows the same tree as the Rust API.
#![allow(dead_code)]

#[path = "../common/mod.rs"]
pub mod common;

use common::*;
use misb::capi::*;
use misb::{Checksum, Config, Decoder, Packet, Received, Value};
use std::ffi::CStr;
use std::hint::black_box;
use std::os::raw::c_char;
use std::ptr;
use std::mem;

/// Largest stream the generator builds, to keep each run fast.
const MAX_STREAM: usize = 12 * 1024;
/// Most nodes of one packet's tree the C API walk visits.
const MAX_NODES: usize = 3000;

// ---------------------------------------------------------------- targets

/// Raw bytes: the first byte picks the settings, the rest is the stream.
pub fn decode(data: &[u8]) {
    let (control, bytes) = data.split_first().map_or((0, &[][..]), |(c, rest)| (*c, rest));
    let cfg = config_from_control(control);
    check_stream(bytes, &cfg, hash(data));
}

/// Structured: the bytes are a program that builds a stream of ST 0601
/// packets with nested sets, other keys and damage, so mutations explore
/// packet structure instead of mostly failing to find a key.
pub fn stream(data: &[u8]) {
    let mut input = Input::new(data);
    let cfg = config_from(&mut input);
    let s = generate(&mut input);
    check_stream(&s, &cfg, hash(data));
}

/// The C API: the first part of the input is a sequence of API calls, the
/// rest builds the stream they push.
pub fn capi(data: &[u8]) {
    let mut input = Input::new(data);
    let ops_len = usize::from(input.u8()) * 2;
    let mut ops = Input::new(input.bytes(ops_len));
    let s = generate(&mut input);
    // SAFETY: every pointer handed to the API points at live, correctly
    // sized memory owned by this function, or at what the API returned.
    unsafe { capi_session(&mut ops, &s) }
}

// ---------------------------------------------------------------- input

/// Reads values from fuzz input; reads past the end return zeros.
pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Input { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn u8(&mut self) -> u8 {
        match self.data.split_first() {
            Some((b, rest)) => {
                self.data = rest;
                *b
            }
            None => 0,
        }
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    pub fn u64(&mut self) -> u64 {
        (u64::from(self.u32()) << 32) | u64::from(self.u32())
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 != 0
    }

    /// Up to `n` bytes.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.data.split_at(n.min(self.data.len()));
        self.data = b;
        a
    }

    /// `n` bytes: as many as the input has (at most 64), then a repeating
    /// pattern.
    pub fn filled(&mut self, n: usize) -> Vec<u8> {
        let mut v = self.bytes(n.min(64)).to_vec();
        let fill = v.last().copied().unwrap_or(0xA5);
        v.resize(n, fill);
        v
    }

    /// Usually `nominal`, sometimes any length up to 24.
    fn len(&mut self, nominal: usize) -> usize {
        match self.u8() {
            b if b < 200 => nominal,
            b if b < 230 => usize::from(b % 25),
            _ => 0,
        }
    }
}

/// FNV-1a, to derive push sizes from the input deterministically.
pub fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xCBF2_9CE4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01B3)) | 1
}

// ---------------------------------------------------------------- settings

/// Settings from one byte: the flags, and presets of tight limits.
pub fn config_from_control(b: u8) -> Config {
    let mut c = Config::default();
    c.verify_checksum = b & 1 == 0;
    c.reject_bad_checksum = b & 2 != 0;
    c.keep_raw = b & 4 == 0;
    if b & 8 != 0 {
        c.max_depth = usize::from(b >> 5);
        c.max_items = 3;
        c.max_total_items = 20;
    }
    if b & 0x10 != 0 {
        c.max_packet_bytes = 256;
        c.max_skip_bytes = 512;
        c.max_buffer_bytes = 2048;
    }
    c.validate().expect("harness built an invalid config");
    c
}

pub fn config_from(input: &mut Input<'_>) -> Config {
    let b = input.u8();
    let mut c = config_from_control(b & 7);
    if b & 0x08 != 0 {
        c.max_depth = usize::from(input.u8()) % (Config::MAX_DEPTH_LIMIT + 1);
    }
    if b & 0x10 != 0 {
        c.max_items = 1 + usize::from(input.u8() % 64);
        c.max_total_items = 1 + usize::from(input.u16() % 600);
    }
    if b & 0x20 != 0 {
        // Tight byte limits, so oversized, unskippable and dropped packets
        // happen.
        c.max_packet_bytes = 1 + usize::from(input.u16() % 4096);
        c.max_skip_bytes = 1 + usize::from(input.u16());
        c.max_buffer_bytes = 1 + usize::from(input.u16()) * 2;
    }
    c.validate().expect("harness built an invalid config");
    c
}

// ---------------------------------------------------------------- generator

/// ST 0601 tags and their nominal lengths (ST 0601.19 section 8), 0 for
/// text and other variable-length values; sets and packs are built apart.
const ST0601_LENGTHS: [(u8, u8); 87] = [
    (2, 8), (3, 0), (4, 0), (5, 2), (6, 2), (7, 2), (8, 1), (9, 1), (10, 0), (11, 0), (12, 0), (13, 4), (14, 4),
    (15, 2), (16, 2), (17, 2), (18, 4), (19, 4), (20, 4), (21, 4), (22, 2), (23, 4), (24, 4), (25, 2), (26, 2),
    (27, 2), (28, 2), (29, 2), (30, 2), (31, 2), (32, 2), (33, 2), (34, 1), (35, 2), (36, 1), (37, 2), (38, 2),
    (39, 1), (40, 4), (41, 4), (42, 2), (43, 1), (44, 1), (45, 2), (46, 2), (47, 1), (49, 2), (50, 2), (51, 2),
    (52, 2), (53, 2), (54, 2), (55, 1), (56, 1), (57, 4), (58, 2), (59, 0), (60, 2), (61, 1), (62, 2), (63, 1),
    (64, 2), (65, 1), (66, 0), (67, 4), (68, 4), (69, 2), (70, 0), (71, 2), (72, 8), (75, 2), (76, 2), (77, 1),
    (78, 2), (79, 2), (80, 2), (82, 4), (83, 4), (90, 4), (93, 4), (96, 3), (103, 3), (110, 2), (113, 3),
    (117, 2), (131, 8), (136, 1),
];

/// The ST 0601.19 examples of the packs, to mutate.
const PACKS: [(u8, &str); 15] = [
    (81, "00243800"),
    (94, "0170F592F02373364AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645"),
    (115, "0511466C7920746F20576179706F696E742031"),
    (116, "0307"),
    (121, "0103"),
    (122, "010E0343414E0003465241"),
    (127, "83D4608769"),
    (128, "0D15000007D000000FA04E4E4952"),
    (130, "0B406BC20919BDA554070E000B40783CB819A2927407C600"),
    (138, "031200000F564953204E6F73652043616D6572611501001241434D4520564953204D6F64656C203132331402001141434D45204952204D6F64656C20343536"),
    (139, "0B"),
    (140, "0E01010103820307486172706F6F6E0F010102029E040848656C6C666972650C0102010103064742552D3135"),
    (141, "0F000001034071D89419BDBFE70898000F010002024071D38819BCCE2408FC000F027FFF014071E30819BF2C1B07D0000F03FFFE004071E5AF19BF5AA7096000"),
    (142, "063480004B0000061A40000C8000"),
    (143, "008DC4F4623EA25A859C5D0AF0C95E8C39"),
];

struct Gen<'a, 'b> {
    input: &'b mut Input<'a>,
    out: Vec<u8>,
    time: u64,
}

/// Build a KLV stream from fuzz input.
pub fn generate(input: &mut Input<'_>) -> Vec<u8> {
    let mut g = Gen { input, out: Vec::new(), time: 1_224_807_209_913_000 };
    while !g.input.is_empty() && g.out.len() < MAX_STREAM {
        match g.input.u8() % 16 {
            0..=5 => g.packet(),
            6 => g.known(),
            7 => g.other_key(),
            8 => g.garbage(),
            9 | 10 => g.corrupt(),
            11 => g.oversized(),
            12 => g.deep(),
            13 => g.cut(),
            14 => g.duplicate(),
            _ => g.key_prefix(),
        }
    }
    g.out
}

impl Gen<'_, '_> {
    fn packet(&mut self) {
        let opts = self.input.u8();
        let mut b = St0601::new();
        if opts & 1 == 0 {
            self.time += 33_367;
            b = b.time(self.time);
        }
        let mut body = Set::new();
        for _ in 0..self.input.u8() % 12 {
            body = self.item(body, 0);
        }
        b = b.raw(body.bytes());
        if opts & 2 != 0 {
            b = b.long_length(1 + usize::from(self.input.u8() % 9));
        }
        if opts & 4 != 0 {
            b = b.version_byte(self.input.u8());
        }
        if opts & 0x38 == 0x38 {
            b = b.no_checksum();
        }
        let mut bytes = b.build();
        if opts & 0xC0 == 0xC0 {
            corrupt_checksum(&mut bytes);
        }
        self.out.extend(bytes);
    }

    /// One item of an ST 0601 set at nesting level `depth`.
    fn item(&mut self, set: Set, depth: usize) -> Set {
        match self.input.u8() % 16 {
            0..=6 => {
                let (tag, nominal) = ST0601_LENGTHS[usize::from(self.input.u8()) % ST0601_LENGTHS.len()];
                let n = if nominal == 0 { usize::from(self.input.u8() % 40) } else { self.input.len(usize::from(nominal)) };
                let v = self.input.filled(n);
                set.item(u64::from(tag), &v)
            }
            7 => {
                let (tag, example) = PACKS[usize::from(self.input.u8()) % PACKS.len()];
                let mut v = hex(example);
                self.mutate(&mut v);
                // Tag 143 belongs in Segment and Amend sets.
                set.item(u64::from(tag), &v)
            }
            8 => {
                let s = self.st0102();
                set.set(48, s)
            }
            9 => {
                let s = self.st0806();
                set.set(73, s)
            }
            10 | 11 => {
                let s = self.st0903();
                set.set(74, s)
            }
            12 if depth < 6 => {
                let mut inner = Set::new();
                for _ in 0..self.input.u8() % 6 {
                    inner = self.item(inner, depth + 1);
                }
                set.set(100 + u64::from(self.input.u8() & 1), inner)
            }
            13 => {
                let v = self.sdcc();
                set.item(102, &v)
            }
            14 => {
                // Any tag, including multi-byte BER-OID tags.
                let tag = match self.input.u8() % 4 {
                    0 => u64::from(self.input.u8()),
                    1 => u64::from(self.input.u16()),
                    2 => 128 + u64::from(self.input.u8() % 20),
                    _ => self.input.u64() >> (self.input.u8() % 64),
                };
                let n = usize::from(self.input.u8() % 32);
                let v = self.input.filled(n);
                set.item(tag, &v)
            }
            _ => {
                // A malformed item: raw tag and length bytes.
                let n = usize::from(self.input.u8() % 6);
                let raw = self.input.filled(n);
                set.raw(&raw)
            }
        }
    }

    /// A few byte-level changes to `v`.
    fn mutate(&mut self, v: &mut Vec<u8>) {
        match self.input.u8() % 8 {
            0 if !v.is_empty() => {
                let at = usize::from(self.input.u8()) % v.len();
                v[at] ^= 1 << (self.input.u8() % 8);
            }
            1 => v.truncate(usize::from(self.input.u8()) % (v.len() + 1)),
            2 => {
                let n = usize::from(self.input.u8() % 8);
                let extra = self.input.filled(n);
                v.extend(extra);
            }
            _ => {}
        }
    }

    fn st0102(&mut self) -> Set {
        let mut s = Set::new();
        for _ in 0..self.input.u8() % 10 {
            let tag = 1 + u64::from(self.input.u8() % 26);
            let v = match tag {
                1 | 2 | 12 => vec![self.input.u8() % 20],
                3 => b"//USA".to_vec(),
                10 => b"20251231".to_vec(),
                13 => utf16be("USA;CAN"),
                15..=18 => self.input.filled(32),
                21 => self.input.filled(16),
                22 => vec![0, self.input.u8() % 16],
                23 | 24 => b"2017-06-22".to_vec(),
                _ => {
                    let n = usize::from(self.input.u8() % 20);
                    self.input.filled(n)
                }
            };
            let n = self.input.len(v.len());
            let mut v = v;
            v.resize(n, b'x');
            s = s.item(tag, &v);
        }
        s
    }

    fn st0806(&mut self) -> Set {
        let mut s = Set::new();
        for _ in 0..self.input.u8() % 10 {
            let tag = 1 + u64::from(self.input.u8() % 22);
            s = match tag {
                11 => {
                    let ud = Set::new().item(1, &[self.input.u8()]);
                    let n = 1 + usize::from(self.input.u8() % 8);
                    let data = self.input.filled(n);
                    s.set(11, ud.item(2, &data))
                }
                12 | 13 => {
                    let mut sub = Set::new();
                    for _ in 0..self.input.u8() % 8 {
                        let t = 1 + u64::from(self.input.u8() % 11);
                        let nominal = match (tag, t) {
                            (_, 1) | (12, 4) => 2,
                            (12, 2 | 3) | (13, 2..=5) => 4,
                            (12, 5) | (13, 6) => 1,
                            _ => 6,
                        };
                        let n = self.input.len(nominal);
                        let v = self.input.filled(n);
                        sub = sub.item(t, &v);
                    }
                    s.set(tag, sub)
                }
                _ => {
                    let nominal = match tag {
                        1 | 7 | 9 => 4,
                        2 => 8,
                        3 | 4 | 6 => 2,
                        16 | 17 | 20 | 21 => 3,
                        15 | 19 => 3,
                        10 => 5,
                        _ => 1,
                    };
                    let n = self.input.len(nominal);
                    let v = self.input.filled(n);
                    s.item(tag, &v)
                }
            };
        }
        s
    }

    fn st0903(&mut self) -> Set {
        let mut s = Set::new();
        if self.input.u8() < 200 {
            s = s.item(4, &[if self.input.u8() < 230 { 6 } else { self.input.u8() }]);
        }
        for _ in 0..self.input.u8() % 8 {
            let tag = match self.input.u8() % 20 {
                n @ 0..=13 => u64::from(n),
                14..=16 => 101,
                17 => 102,
                18 => 103,
                _ => u64::from(self.input.u8()),
            };
            s = match tag {
                101 => {
                    let targets: Vec<Vec<u8>> = (0..1 + self.input.u8() % 4).map(|_| self.vtarget()).collect();
                    s.item(101, &series(&targets))
                }
                102 | 103 => {
                    let mut el = Set::new();
                    for _ in 0..self.input.u8() % 6 {
                        let t = 1 + u64::from(self.input.u8() % 7);
                        let n = self.input.len(if t <= 2 { 1 } else { 6 });
                        let v = self.input.filled(n);
                        el = el.item(t, &v);
                    }
                    s.item(tag, &series(&[el.0]))
                }
                13 => s.item(13, &hex("0170F592F02373364AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645")),
                _ => {
                    let nominal = match tag {
                        2 => 8,
                        3 | 10 => 6,
                        8 | 9 | 11 | 12 => 2,
                        _ => 1,
                    };
                    let n = self.input.len(nominal);
                    let v = self.input.filled(n);
                    s.item(tag, &v)
                }
            };
        }
        s
    }

    fn vtarget(&mut self) -> Vec<u8> {
        let id = u64::from(self.input.u16()) + 1;
        let mut s = Set::new();
        for _ in 0..self.input.u8() % 8 {
            let tag = match self.input.u8() % 32 {
                n @ 0..=23 => u64::from(n),
                n @ 24..=30 => 101 + u64::from(n - 24),
                _ => u64::from(self.input.u8()),
            };
            s = match tag {
                17 => {
                    let loc = self.location();
                    s.item(17, &loc)
                }
                18 => {
                    let locs = vec![self.location(), self.location()];
                    s.item(18, &series(&locs))
                }
                101 => {
                    let mask = Set::new()
                        .item(1, &series(&[vec![0x39, 0xAA], vec![0x39, 0xBF], self.input.filled(2)]))
                        .item(2, &series(&[vec![1, self.input.u8(), self.input.u8()]]));
                    s.set(101, mask)
                }
                102 | 107 => {
                    let feature = Set::new().item(3, &[self.input.u8()]).item(4, &self.input.filled(2));
                    let object = Set::new().item(3, &[1]).item(4, &[0x40, 0]).item(5, &series(&[feature.0]));
                    if tag == 102 {
                        s.set(102, object)
                    } else {
                        s.item(107, &series(&[object.0]))
                    }
                }
                103 => s.set(103, Set::new().item(3, &[2]).item(4, &self.input.filled(2))),
                104 => {
                    let tracker = Set::new()
                        .item(1, &self.input.filled(16))
                        .item(3, &self.input.filled(8))
                        .item(5, &series(&[self.location()]))
                        .item(10, &self.input.filled(6))
                        .item(12, &[self.input.u8()]);
                    s.set(104, tracker)
                }
                105 | 106 => {
                    let n = usize::from(self.input.u8() % 16);
                    let chip = Set::new().item(1, b"jpeg").item(3, &self.input.filled(n));
                    if tag == 105 {
                        s.set(105, chip)
                    } else {
                        s.item(106, &series(&[chip.0]))
                    }
                }
                _ => {
                    let nominal = match tag {
                        1..=3 => 3,
                        8 | 9 | 10 | 11 | 13..=16 => 3,
                        12 | 21 => 2,
                        19 | 20 => 2,
                        _ => 1,
                    };
                    let n = self.input.len(nominal);
                    let v = self.input.filled(n);
                    s.item(tag, &v)
                }
            };
        }
        vtarget(id, s)
    }

    /// An ST 0903 location pack: 10, 16 or 22 bytes, sometimes other.
    fn location(&mut self) -> Vec<u8> {
        let n = [10, 16, 22, 10, 16, 22, 9, 0][usize::from(self.input.u8() % 8)];
        self.input.filled(n)
    }

    /// An ST 1010 SDCC-FLP, usually with the lengths its parse control
    /// implies.
    fn sdcc(&mut self) -> Vec<u8> {
        let n = 1 + usize::from(self.input.u8() % 6);
        let b = self.input.u8();
        let mode2 = b & 1 == 0;
        let sparse = b & 2 != 0;
        let (slen, clen) = (usize::from(self.input.u8() % 9), usize::from(self.input.u8() % 5));
        let mut v = ber_oid(n as u64);
        if mode2 {
            v.push(0x80 | (u8::from(sparse) << 5) | ((b & 4) << 2) | clen as u8);
            v.push(((b & 8) << 1) | slen as u8);
        } else {
            v.push(((slen as u8 & 7) << 4) | (u8::from(sparse) << 3) | (clen as u8 & 7));
        }
        let pairs = n * (n - 1) / 2;
        let mut count = pairs;
        if sparse && clen > 0 {
            let bits = self.input.filled((pairs + 7) / 8);
            count = bits.iter().map(|x| x.count_ones() as usize).sum::<usize>().min(pairs);
            v.extend(bits);
        }
        let body = n * slen + count * clen;
        let len = if self.input.u8() < 220 { body } else { usize::from(self.input.u8() % 40) };
        v.extend(self.input.filled(len));
        v
    }

    fn known(&mut self) {
        let i = u64::from(self.input.u8());
        let p = match i % 5 {
            0 => sample(i),
            1 => rich(i),
            2 => spec_packet_a(),
            3 => spec_packet_b(),
            _ => St0601::new().time(i).build(),
        };
        self.out.extend(p);
    }

    fn other_key(&mut self) {
        let n = usize::from(self.input.u16() % 600);
        let v = self.input.filled(n);
        let key = match self.input.u8() % 4 {
            0 => ST0102_KEY,
            1 => ST0903_KEY,
            2 => {
                let mut k = KEY;
                k[12] = self.input.u8();
                k
            }
            _ => {
                let mut k = KEY;
                for b in &mut k[4..] {
                    *b = self.input.u8();
                }
                k
            }
        };
        self.out.extend(triplet(key, &v));
    }

    fn garbage(&mut self) {
        let n = usize::from(self.input.u8());
        let junk = self.input.filled(n);
        self.out.extend(junk);
    }

    /// Damage what has been produced so far.
    fn corrupt(&mut self) {
        let len = self.out.len();
        match self.input.u8() % 6 {
            0 if len > 0 => {
                let at = self.input.u32() as usize % len;
                self.out[at] ^= 1 << (self.input.u8() % 8);
            }
            1 => {
                let n = usize::from(self.input.u8()).min(len);
                self.out.truncate(len - n);
            }
            2 if len > 0 => {
                // A length byte made long form or huge.
                let at = self.input.u32() as usize % len;
                self.out[at] = [0x80, 0x81, 0x84, 0x88, 0xFF, 0x7F][usize::from(self.input.u8() % 6)];
            }
            3 if len > 0 => {
                let at = self.input.u32() as usize % len;
                let n = usize::from(self.input.u8() % 32).min(len - at);
                self.out.drain(at..at + n);
            }
            4 if len > 0 => {
                let at = self.input.u32() as usize % len;
                let n = usize::from(self.input.u8() % 16);
                let junk = self.input.filled(n);
                self.out.splice(at..at, junk);
            }
            _ => {}
        }
    }

    /// An ST 0601 key with a declared length far beyond any limit.
    fn oversized(&mut self) {
        self.out.extend(KEY);
        let len = match self.input.u8() % 4 {
            0 => ber_len(5000 + usize::from(self.input.u16())),
            1 => vec![0x84, 0x7F, 0xFF, 0xFF, 0xFF],
            2 => vec![0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            _ => ber_len_long(usize::from(self.input.u16()), 1 + usize::from(self.input.u8() % 16)),
        };
        self.out.extend(len);
        let n = usize::from(self.input.u16() % 2000);
        let v = self.input.filled(n);
        self.out.extend(v);
    }

    fn deep(&mut self) {
        let levels = usize::from(self.input.u8() % 48);
        let mut inner = Set::new();
        for _ in 0..self.input.u8() % 4 {
            inner = self.item(inner, 6);
        }
        let tags: [&[u64]; 3] = [&[100], &[101], &[100, 101]];
        let chain = nest(levels, tags[usize::from(self.input.u8() % 3)], inner);
        self.out.extend(St0601::new().time(self.time).set(100, chain).build());
    }

    /// A packet cut short, as after lost input.
    fn cut(&mut self) {
        let p = rich(u64::from(self.input.u8()));
        let n = usize::from(self.input.u16()) % p.len();
        self.out.extend(&p[..n]);
    }

    fn duplicate(&mut self) {
        let len = self.out.len();
        let n = usize::from(self.input.u16() % 1024).min(len);
        let tail = self.out[len - n..].to_vec();
        self.out.extend(tail);
    }

    /// The first bytes of a key, then whatever comes next.
    fn key_prefix(&mut self) {
        let n = 1 + usize::from(self.input.u8() % 16);
        self.out.extend(&KEY[..n]);
    }
}

// ---------------------------------------------------------------- checks

/// The largest slice that `include/misb.h` says never drops a packet when
/// the queue is drained after each push: `(max_buffer_bytes -
/// max_packet_bytes - 1024) / 8`, or nothing.
fn safe_slice(cfg: &Config) -> usize {
    cfg.max_buffer_bytes.saturating_sub(cfg.max_packet_bytes.saturating_add(1024)) / 8
}

/// Decode `s` every way and check that the ways agree and stay in bounds.
pub fn check_stream(s: &[u8], cfg: &Config, seed: u64) {
    let (reference, ref_stats) = misb::decode_all_with(s, cfg).unwrap();
    assert_eq!(ref_stats.dropped, 0, "decode_all_with dropped packets");
    assert_eq!(ref_stats.bytes, s.len() as u64);
    assert_eq!(ref_stats.bytes, ref_stats.packet_bytes + ref_stats.bytes_skipped, "bytes not accounted for");
    assert_eq!(ref_stats.packets, reference.len() as u64);
    let lazy: Vec<Packet> = misb::decode_iter_with(s, cfg).unwrap().collect();
    assert!(lazy == reference, "decode_iter differs from decode_all");

    // In random chunks, draining after each push.
    let mut rng = Rng(seed);
    let safe = safe_slice(cfg);
    let mut within_rule = safe > 0;
    let (chunked, stats) = run(s, cfg, |_| {
        let n = if rng.below(4) == 0 { 1 + rng.below(8) } else { 1 + rng.below(700) };
        within_rule &= n <= safe;
        n
    });
    if within_rule {
        assert_eq!(stats.dropped, 0, "dropped a packet although every push was at most {safe} bytes");
    }
    agrees(&chunked, &stats, &reference, &ref_stats, "in chunks");
    check_received(s, cfg, &chunked);

    // One byte at a time.
    if s.len() <= 3000 {
        let (single, stats) = run(s, cfg, |_| 1);
        agrees(&single, &stats, &reference, &ref_stats, "byte at a time");
    }

    // decode_prefix agrees with the decoder on a packet at offset 0.
    match misb::decode_prefix(s, cfg) {
        Ok((p, used)) => {
            assert!(used <= s.len());
            check_packet(&p, cfg, used);
            if let Some(first) = chunked.first().filter(|r| r.offset == 0) {
                assert_eq!((&p, used), (&first.packet, first.bytes.len()));
            }
        }
        Err(e) => {
            let _ = e.kind();
            black_box(e.to_string());
            assert!(chunked.first().map_or(true, |r| r.offset != 0), "decode_prefix failed on a packet the decoder found: {e}");
        }
    }

    // Access unit cells over the same bytes.
    let mut d = Decoder::with_config(cfg.clone()).unwrap();
    let mut covered = 0;
    for cell in misb::au_cells(s) {
        match cell {
            Ok(c) => {
                covered += 5 + c.data.len();
                assert!(c.fragment <= 3);
                d.push(c.data);
                while let Some(p) = d.next_packet() {
                    check_packet(&p, cfg, s.len());
                }
            }
            Err(e) => {
                assert!(matches!(e, misb::Error::Truncated { .. }));
                break;
            }
        }
    }
    assert!(covered <= s.len());
}

/// A run of the stream decoder gives the reference packets and counters,
/// unless it dropped packets to the queue limit (one push can complete more
/// than `max_buffer_bytes` of packets): then the packets it kept are some of
/// the reference's, in order, and the framing counters still agree, as
/// dropping happens after framing.
fn agrees(got: &[Received], stats: &misb::Stats, reference: &[Packet], ref_stats: &misb::Stats, how: &str) {
    let packets: Vec<Packet> = got.iter().map(|r| r.packet.clone()).collect();
    if stats.dropped == 0 {
        assert!(packets == reference, "packets depend on how the input was split ({how})");
        assert_eq!(stats, ref_stats, "counters depend on how the input was split ({how})");
        return;
    }
    let mut rest = reference.iter();
    for p in &packets {
        assert!(rest.any(|q| q == p), "a packet the reference does not have ({how})");
    }
    assert!(got.len() as u64 + stats.dropped >= reference.len() as u64);
    let framing = |s: &misb::Stats| (s.bytes, s.resyncs, s.skipped_keys, s.oversized, s.bad_lengths, s.truncated_at_finish);
    assert_eq!(framing(stats), framing(ref_stats), "framing depends on the queue ({how})");
}

/// Push in chunks of the sizes `next` gives, draining after every push and
/// sometimes finishing early.
fn run(s: &[u8], cfg: &Config, mut next: impl FnMut(usize) -> usize) -> (Vec<Received>, misb::Stats) {
    let mut d = Decoder::with_config(cfg.clone()).unwrap();
    let mut out: Vec<Received> = Vec::new();
    let mut pushed = 0;
    let mut last = misb::Stats::default();
    while pushed < s.len() {
        let n = next(pushed).clamp(1, s.len() - pushed);
        d.push(&s[pushed..pushed + n]);
        pushed += n;
        while let Some(r) = d.next_received() {
            out.push(r);
        }
        let st = d.stats().clone();
        assert_eq!(st.bytes, pushed as u64);
        assert!(st.packet_bytes + st.bytes_skipped <= st.bytes, "more bytes counted than pushed");
        assert_eq!(st.packets, out.len() as u64);
        for (now, before) in [
            (st.bytes_skipped, last.bytes_skipped),
            (st.resyncs, last.resyncs),
            (st.skipped_keys, last.skipped_keys),
            (st.oversized, last.oversized),
            (st.dropped, last.dropped),
            (st.bad_lengths, last.bad_lengths),
            (st.checksum_errors, last.checksum_errors),
        ] {
            assert!(now >= before, "a counter went backwards");
        }
        last = st;
    }
    d.finish();
    while let Some(r) = d.next_received() {
        out.push(r);
    }
    let st = d.stats().clone();
    assert_eq!(st.bytes, st.packet_bytes + st.bytes_skipped, "bytes not accounted for after finish");
    check_counts(&st, cfg, &out);
    // Finishing again changes nothing.
    d.finish();
    assert!(d.next_packet().is_none());
    assert_eq!(d.stats(), &st);
    (out, st)
}

fn check_counts(st: &misb::Stats, cfg: &Config, out: &[Received]) {
    let count = |f: &dyn Fn(&Packet) -> bool| out.iter().filter(|r| f(&r.packet)).count() as u64;
    assert_eq!(st.packets, out.len() as u64);
    assert_eq!(st.packet_bytes, out.iter().map(|r| r.bytes.len() as u64).sum::<u64>());
    assert_eq!(st.malformed, count(&|p| p.error.is_some()));
    assert_eq!(st.nested_errors, count(&|p| p.error.is_none() && p.items.iter().any(|i| nested_error(&i.value))));
    if cfg.reject_bad_checksum {
        assert_eq!(count(&|p| p.checksum != Checksum::Valid), 0, "a packet with a bad checksum was delivered");
    } else {
        assert_eq!(st.checksum_errors, count(&|p| matches!(p.checksum, Checksum::Mismatch { .. })));
        assert_eq!(st.checksum_missing, count(&|p| p.checksum == Checksum::Missing));
        if !cfg.verify_checksum {
            assert_eq!(count(&|p| p.checksum != Checksum::NotApplicable), 0);
        }
    }
}

/// True when `v` holds a set, at any depth, that stopped with an error.
fn nested_error(v: &Value) -> bool {
    match v {
        Value::Set(p) => p.error.is_some() || p.items.iter().any(|i| nested_error(&i.value)),
        Value::List(l) => l.iter().any(nested_error),
        Value::Struct(f) => f.iter().any(|x| nested_error(&x.value)),
        _ => false,
    }
}

fn check_received(s: &[u8], cfg: &Config, out: &[Received]) {
    let mut end = 0u64;
    for r in out {
        assert!(r.offset >= end, "packets overlap");
        let at = usize::try_from(r.offset).unwrap();
        assert_eq!(&s[at..at + r.bytes.len()], &r.bytes[..], "bytes are not the input's");
        assert_eq!(&r.key()[..4], &KEY[..4]);
        let (p, used) = misb::decode_prefix(&r.bytes, cfg).expect("a delivered packet decodes again");
        assert_eq!(used, r.bytes.len());
        assert!(p == r.packet, "decode_prefix and the decoder differ");
        check_packet(&r.packet, cfg, r.bytes.len());
        check_options(&r.bytes, cfg, &r.packet);
        check_display(&r.packet);
        check_checksum(&r.bytes, &r.packet);
        check_names(&r.packet);
        #[cfg(feature = "serde")]
        black_box(serde_json::to_string(&r.packet).unwrap());
        end = r.offset + r.bytes.len() as u64;
    }
}

/// The checksum outcome, recomputed from the bytes (ST 0601.19 section
/// 8.1): a running sum of big-endian 16-bit words over everything before
/// the final two checksum bytes. The length can use long-form BER.
fn check_checksum(bytes: &[u8], p: &Packet) {
    let n = bytes.len();
    let sum = |b: &[u8]| b.iter().enumerate().fold(0u16, |sum, (i, &byte)| {
        sum.wrapping_add(u16::from(byte) << (if i % 2 == 0 { 8 } else { 0 }))
    });
    match p.checksum {
        Checksum::Valid => {
            assert_eq!(sum(&bytes[..n - 2]), u16::from_be_bytes([bytes[n - 2], bytes[n - 1]]));
            // The checksum covers the bytes; decoding may still have stopped
            // early at an item limit.
            if p.error.is_none() {
                assert_eq!(p.items.last().map(|i| i.tag), Some(1), "valid checksum not in the last item");
            } else {
                assert!(matches!(p.error, Some(misb::Error::TooManyItems { .. })), "{:?}", p.error);
            }
        }
        Checksum::Mismatch { expected, computed } => {
            assert_eq!(expected, u16::from_be_bytes([bytes[n - 2], bytes[n - 1]]));
            assert_eq!(computed, sum(&bytes[..n - 2]));
            assert_ne!(expected, computed);
        }
        _ => {}
    }
}

/// Every item carries its standard's name for its tag, "Unknown" for tags
/// the standard does not define.
fn check_names(p: &Packet) {
    for item in &p.items {
        let name = match p.standard {
            misb::Standard::St0601 => misb::st0601::Tag::from_u64(item.tag).map(|t| t.name()),
            misb::Standard::St0102 => misb::st0102::Tag::from_u64(item.tag).map(|t| t.name()),
            misb::Standard::St0806 => misb::st0806::Tag::from_u64(item.tag).map(|t| t.name()),
            misb::Standard::St0903 => misb::st0903::Tag::from_u64(item.tag).map(|t| t.name()),
            _ => panic!("a Standard the harness does not know"),
        };
        assert_eq!(item.name, name.unwrap_or("Unknown"), "tag {}", item.tag);
        if let Value::Set(s) = &item.value {
            check_names(s);
        }
    }
}

/// `keep_raw` only changes `raw`, and `verify_checksum` only the checksum.
fn check_options(bytes: &[u8], cfg: &Config, p: &Packet) {
    let mut other = cfg.clone();
    other.keep_raw = !cfg.keep_raw;
    let (q, _) = misb::decode_prefix(bytes, &other).unwrap();
    assert!(without_raw(p.clone()) == without_raw(q), "keep_raw changed a value");
    if !cfg.reject_bad_checksum {
        let mut other = cfg.clone();
        other.verify_checksum = !cfg.verify_checksum;
        let (mut q, _) = misb::decode_prefix(bytes, &other).unwrap();
        if other.verify_checksum {
            assert_ne!(q.checksum, Checksum::NotApplicable, "checksum not checked");
        }
        q.checksum = p.checksum;
        assert!(&q == p, "verify_checksum changed more than the checksum");
    }
}

fn without_raw(mut p: Packet) -> Packet {
    for item in &mut p.items {
        item.raw.clear();
        strip(&mut item.value);
    }
    p
}

fn strip(v: &mut Value) {
    match v {
        Value::Set(p) => {
            let standard = p.standard;
            let inner = std::mem::replace(&mut **p, Packet::new(standard));
            **p = without_raw(inner);
        }
        Value::List(l) => l.iter_mut().for_each(strip),
        Value::Struct(f) => f.iter_mut().for_each(|x| strip(&mut x.value)),
        _ => {}
    }
}

/// A packet prints as one line, one line per item and one for its error:
/// no value can start a line of its own (control characters are escaped).
fn check_display(p: &Packet) {
    let text = p.to_string();
    let want = 1 + p.items.len() + usize::from(p.error.is_some());
    assert_eq!(text.lines().count(), want, "a value printed a line break");
    assert!(!text.contains('\u{1b}'), "an escape character was printed");
}

// ---------------------------------------------------------------- C API

fn expect(status: misb_status, allowed: &[misb_status], call: &str) {
    assert!(allowed.contains(&status), "{call} returned {status}");
}

/// Read every byte, so a bad pointer is caught (by a sanitizer, or a crash).
unsafe fn touch(data: *const u8, len: u64) {
    if len > 0 {
        assert!(!data.is_null(), "null data with length {len}");
        let s = std::slice::from_raw_parts(data, usize::try_from(len).unwrap());
        black_box(s.iter().fold(0u8, |a, &b| a ^ b));
    }
}

/// A string the library returned: not NULL, NUL-terminated.
unsafe fn cstr<'a>(p: *const c_char, what: &str) -> &'a [u8] {
    assert!(!p.is_null(), "{what} is NULL");
    CStr::from_ptr(p).to_bytes()
}

/// A `struct_size` for `T`: usually exact (always, once the input runs
/// out), sometimes an older (shorter) or newer (longer) struct, sometimes
/// invalid.
fn struct_size<T>(ops: &mut Input<'_>) -> u32 {
    let full = mem::size_of::<T>() as u32;
    match ops.u8() % 8 {
        1 => u32::from(ops.u8()) % full,
        2 => full + u32::from(ops.u8()),
        _ => full,
    }
}

const fn full<T>() -> u32 {
    mem::size_of::<T>() as u32
}

/// Bytes of `misb_item` up to and including `id`, which navigation needs.
fn item_ref_size() -> u32 {
    let v = mem::MaybeUninit::<misb_item>::uninit();
    let base = v.as_ptr();
    // SAFETY: only the address is computed; nothing is read.
    let at = unsafe { ptr::addr_of!((*base).id) } as usize - base as usize;
    (at + mem::size_of::<u64>()) as u32
}

fn kind_of(v: &Value) -> u32 {
    match v {
        Value::Uint(_) => MISB_VALUE_UINT,
        Value::Int(_) => MISB_VALUE_INT,
        Value::Float(_) => MISB_VALUE_FLOAT,
        Value::Text(_) => MISB_VALUE_TEXT,
        Value::Bytes(_) => MISB_VALUE_BYTES,
        Value::Time(_) => MISB_VALUE_TIME,
        Value::Enum { .. } => MISB_VALUE_ENUM,
        Value::OutOfRange => MISB_VALUE_OUT_OF_RANGE,
        Value::Set(_) => MISB_VALUE_SET,
        Value::List(_) => MISB_VALUE_LIST,
        Value::Struct(_) => MISB_VALUE_STRUCT,
        Value::Invalid(_) => MISB_VALUE_INVALID,
        Value::Unknown => MISB_VALUE_UNKNOWN,
        _ => panic!("a Value variant the harness does not know"),
    }
}

/// The C view of a config the library would build from `c`: the bytes up
/// to `struct_size` over the defaults, then the documented rules.
fn config_accepted(c: &misb_config) -> bool {
    let size = c.struct_size as usize;
    if size < 4 {
        return false;
    }
    let mut v = misb_config_defaults();
    let n = size.min(mem::size_of::<misb_config>());
    // SAFETY: both are plain repr(C) structs of the same type; n bytes fit.
    unsafe { ptr::copy_nonoverlapping(c as *const misb_config as *const u8, &mut v as *mut misb_config as *mut u8, n) };
    let flags_ok = [v.verify_checksum, v.reject_bad_checksum, v.keep_raw].iter().all(|&f| f <= 1);
    let limits_ok = [v.max_packet_bytes, v.max_buffer_bytes, v.max_skip_bytes, v.max_items, v.max_total_items]
        .iter()
        .all(|&l| l != 0 && usize::try_from(l).is_ok());
    flags_ok && limits_ok && v.max_depth <= Config::MAX_DEPTH_LIMIT as u64
}

fn misb_config_defaults() -> misb_config {
    // SAFETY: zeroed is a valid misb_config; the library fills it.
    let mut c: misb_config = unsafe { std::mem::zeroed() };
    c.struct_size = full::<misb_config>();
    // SAFETY: c is a live, correctly sized struct.
    assert_eq!(unsafe { misb_config_default(&mut c) }, MISB_OK);
    c
}

unsafe fn capi_session(ops: &mut Input<'_>, s: &[u8]) {
    const OK: &[i32] = &[MISB_OK];
    const NULL: &[i32] = &[MISB_ERR_NULL];

    let mut config = misb_config_defaults();
    match ops.u8() % 4 {
        0 => {}
        1 => {
            config.verify_checksum = u32::from(ops.bool());
            config.reject_bad_checksum = u32::from(ops.bool());
            config.keep_raw = u32::from(ops.bool());
            config.max_depth = u64::from(ops.u8() % 33);
            config.max_items = 1 + u64::from(ops.u8());
            config.max_total_items = 1 + u64::from(ops.u16());
            config.max_packet_bytes = 1 + u64::from(ops.u16());
            config.max_buffer_bytes = 1 + u64::from(ops.u16()) * 4;
            config.max_skip_bytes = 1 + u64::from(ops.u16());
        }
        2 => {
            // Anything, valid or not.
            config.verify_checksum = u32::from(ops.u8() % 3);
            config.reject_bad_checksum = u32::from(ops.u8() % 3);
            config.keep_raw = u32::from(ops.u8() % 3);
            config.reserved = ops.u32();
            config.max_depth = u64::from(ops.u8() % 40);
            config.max_items = u64::from(ops.u16() % 300);
            config.max_total_items = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_packet_bytes = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_buffer_bytes = [0, 1, u64::from(ops.u32() % (1 << 22)), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_skip_bytes = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
        }
        _ => config.struct_size = struct_size::<misb_config>(ops),
    }
    let mut d: *mut misb_decoder = ptr::null_mut();
    let use_config = ops.u8() >= 32;
    let config_ptr: *const misb_config = if use_config { &config } else { ptr::null() };
    let status = misb_decoder_new(config_ptr, &mut d);
    expect(status, &[MISB_OK, MISB_ERR_INVALID], "decoder_new");
    assert_eq!(status == MISB_OK, !use_config || config_accepted(&config), "decoder_new accepted the wrong configs");
    if status != MISB_OK {
        assert!(d.is_null(), "failed decoder_new left a handle");
        expect(misb_decoder_new(ptr::null(), &mut d), OK, "decoder_new(defaults)");
    }
    assert!(!d.is_null());
    expect(misb_decoder_new(ptr::null(), ptr::null_mut()), NULL, "decoder_new(out=NULL)");

    let mut pos = 0usize;
    let mut kept: Vec<*mut misb_packet> = Vec::new();
    while !ops.is_empty() {
        match ops.u8() % 10 {
            0 => {
                let n = (1 + usize::from(ops.u16() % 4096)).min(s.len() - pos);
                expect(misb_decoder_push(d, s[pos..].as_ptr(), n), OK, "push");
                pos += n;
            }
            1 => {
                expect(misb_decoder_push(d, ptr::null(), 0), OK, "push(NULL, 0)");
                expect(misb_decoder_push(d, ptr::null(), 1), NULL, "push(NULL, 1)");
                expect(misb_decoder_push(ptr::null_mut(), s.as_ptr(), 0), NULL, "push(decoder=NULL)");
            }
            2 => expect(misb_decoder_finish(d), OK, "finish"),
            3 => {
                let mut p = ptr::null_mut();
                let status = misb_decoder_next(d, &mut p);
                expect(status, &[MISB_OK, MISB_EMPTY], "next");
                assert_eq!(status == MISB_OK, !p.is_null());
                if status == MISB_OK {
                    walk_packet(p, ops, None);
                    // Some packets outlive the decoder.
                    if ops.bool() {
                        kept.push(p);
                    } else {
                        misb_packet_free(p);
                    }
                }
            }
            4 => {
                let mut st: misb_stats = misb_stats::default();
                st.struct_size = struct_size::<misb_stats>(ops);
                let size = st.struct_size;
                let status = misb_decoder_stats(d, &mut st);
                expect(status, &[MISB_OK, MISB_ERR_INVALID], "stats");
                assert_eq!(status == MISB_ERR_INVALID, size < 4);
                if status == MISB_OK {
                    assert_eq!(st.struct_size, size.min(full::<misb_stats>()));
                    if st.struct_size == full::<misb_stats>() {
                        assert!(st.packet_bytes + st.bytes_skipped <= st.bytes);
                        assert!(st.bytes <= pos as u64);
                    }
                }
            }
            5 => {
                if ops.u8() < 40 {
                    expect(misb_decoder_reset(d), OK, "reset");
                }
            }
            6 => decode_ex_call(ops, s),
            7 => au_cell_calls(ops, s),
            8 => names(ops),
            _ => null_calls(ops, d, s),
        }
    }

    // Finish the stream and drain everything.
    if pos < s.len() {
        expect(misb_decoder_push(d, s[pos..].as_ptr(), s.len() - pos), OK, "push(rest)");
    }
    expect(misb_decoder_finish(d), OK, "finish");
    loop {
        let mut p = ptr::null_mut();
        let status = misb_decoder_next(d, &mut p);
        expect(status, &[MISB_OK, MISB_EMPTY], "next");
        if status != MISB_OK {
            assert!(p.is_null());
            break;
        }
        walk_packet(p, &mut Input::new(&[]), None);
        misb_packet_free(p);
    }
    let mut st = misb_stats::default();
    st.struct_size = full::<misb_stats>();
    expect(misb_decoder_stats(d, &mut st), OK, "stats");
    assert_eq!(st.bytes, st.packet_bytes + st.bytes_skipped, "bytes not accounted for after finish");
    misb_decoder_free(d);
    misb_decoder_free(ptr::null_mut());
    // A packet does not depend on its decoder.
    for p in kept {
        walk_packet(p, &mut Input::new(&[]), None);
        misb_packet_free(p);
    }
    misb_packet_free(ptr::null_mut());
}

/// misb_decode and misb_decode_ex on a slice of the stream, against
/// `decode_prefix`.
unsafe fn decode_ex_call(ops: &mut Input<'_>, s: &[u8]) {
    let at = if s.is_empty() { 0 } else { usize::from(ops.u16()) % s.len() };
    let n = usize::from(ops.u16()).min(s.len() - at);
    let data = &s[at..at + n];
    let mut config = misb_config_defaults();
    if ops.bool() {
        config.max_packet_bytes = 1 + u64::from(ops.u16());
        config.max_depth = u64::from(ops.u8() % 40);
        config.keep_raw = u32::from(ops.u8() % 3);
    }
    let use_config = ops.bool();
    let config_ptr: *const misb_config = if use_config { &config } else { ptr::null() };
    let (mut p, mut consumed, mut error) = (ptr::null_mut(), usize::MAX, u32::MAX);
    let with_outs = ops.bool();
    let status = misb_decode_ex(
        data.as_ptr(),
        data.len(),
        config_ptr,
        &mut p,
        if with_outs { &mut consumed } else { ptr::null_mut() },
        if with_outs { &mut error } else { ptr::null_mut() },
    );
    expect(status, &[MISB_OK, MISB_ERR_PARSE, MISB_ERR_INVALID], "decode_ex");
    assert_eq!(status == MISB_OK, !p.is_null());
    if use_config && !config_accepted(&config) {
        assert_eq!(status, MISB_ERR_INVALID);
        return;
    }
    let cfg = if use_config { rust_config(&config) } else { Config::default() };
    match misb::decode_prefix(data, &cfg) {
        Ok((packet, used)) => {
            assert_eq!(status, MISB_OK);
            if with_outs {
                assert_eq!((consumed, error), (used, MISB_ERROR_NONE));
            }
            walk_packet(p, ops, Some(&packet));
            misb_packet_free(p);
        }
        Err(e) => {
            assert_eq!(status, MISB_ERR_PARSE);
            if with_outs {
                assert_eq!(consumed, 0);
                let name = cstr(misb_error_name(error), "error name");
                assert!(!name.is_empty());
                assert_ne!(error, MISB_ERROR_NONE, "{e}");
            }
        }
    }
    // misb_decode is misb_decode_ex with the defaults.
    let mut q = ptr::null_mut();
    let status = misb_decode(data.as_ptr(), data.len(), &mut q);
    expect(status, &[MISB_OK, MISB_ERR_PARSE], "decode");
    assert_eq!(status == MISB_OK, misb::decode(data).is_ok());
    misb_packet_free(q);
}

/// The Rust config the C config stands for (already accepted).
fn rust_config(c: &misb_config) -> Config {
    let mut r = Config::default();
    r.verify_checksum = c.verify_checksum == 1;
    r.reject_bad_checksum = c.reject_bad_checksum == 1;
    r.keep_raw = c.keep_raw == 1;
    r.max_packet_bytes = c.max_packet_bytes as usize;
    r.max_buffer_bytes = c.max_buffer_bytes as usize;
    r.max_skip_bytes = c.max_skip_bytes as usize;
    r.max_depth = c.max_depth as usize;
    r.max_items = c.max_items as usize;
    r.max_total_items = c.max_total_items as usize;
    r
}

unsafe fn au_cell_calls(ops: &mut Input<'_>, s: &[u8]) {
    let at = if s.is_empty() { 0 } else { usize::from(ops.u16()) % s.len() };
    let data = &s[at..];
    let mut offset = 0usize;
    let mut steps = 0;
    loop {
        let mut cell: misb_au_cell = std::mem::zeroed();
        cell.struct_size = struct_size::<misb_au_cell>(ops);
        let size = cell.struct_size;
        let before = offset;
        let status = misb_au_cell_next(data.as_ptr(), data.len(), &mut offset, &mut cell);
        expect(status, &[MISB_OK, MISB_EMPTY, MISB_ERR_PARSE, MISB_ERR_INVALID], "au_cell_next");
        assert_eq!(status == MISB_ERR_INVALID, size < 4);
        steps += 1;
        if status != MISB_OK {
            assert_eq!(offset, before, "offset moved on {status}");
            if status == MISB_ERR_INVALID && steps < 1000 {
                continue;
            }
            break;
        }
        assert!(offset > before && offset <= data.len());
        if cell.struct_size == full::<misb_au_cell>() {
            assert_eq!(cell.data_len as usize + 5, offset - before);
            assert!(!cell.data.is_null());
            touch(cell.data, cell.data_len);
            assert!(cell.fragment <= 3 && cell.decoder_config <= 1 && cell.random_access <= 1);
        }
        if steps > 1000 {
            break;
        }
    }
    let mut cell: misb_au_cell = std::mem::zeroed();
    cell.struct_size = full::<misb_au_cell>();
    let mut past = data.len() + 1;
    expect(misb_au_cell_next(data.as_ptr(), data.len(), &mut past, &mut cell), &[MISB_ERR_RANGE], "au_cell_next(past end)");
    expect(misb_au_cell_next(data.as_ptr(), data.len(), ptr::null_mut(), &mut cell), &[MISB_ERR_NULL], "au_cell_next(offset=NULL)");
    let mut zero = 0usize;
    expect(misb_au_cell_next(ptr::null(), 0, &mut zero, &mut cell), &[MISB_EMPTY], "au_cell_next(NULL, 0)");
}

unsafe fn names(ops: &mut Input<'_>) {
    assert_eq!(misb_abi_version(), MISB_ABI_VERSION);
    assert_eq!(cstr(misb_version(), "version"), misb::VERSION.as_bytes());
    let kind = u32::from(ops.u8() % 20);
    assert_eq!(misb_value_kind_name(kind).is_null(), !(1..=13).contains(&kind), "kind {kind}");
    let standard = u32::from(ops.u8() % 8);
    assert_eq!(misb_standard_name(standard).is_null(), !(1..=4).contains(&standard), "standard {standard}");
    let error = u32::from(ops.u8() % 12);
    assert_eq!(misb_error_name(error).is_null(), error > 8, "error {error}");
    assert!(!cstr(misb_status_string(ops.u32() as i32), "status string").is_empty());
}

unsafe fn null_calls(ops: &mut Input<'_>, d: *mut misb_decoder, s: &[u8]) {
    const NULL: &[i32] = &[MISB_ERR_NULL];
    let mut p = 1 as *mut misb_packet;
    expect(misb_decoder_next(ptr::null_mut(), &mut p), NULL, "next(decoder=NULL)");
    assert!(p.is_null(), "next did not clear *out");
    expect(misb_decoder_next(d, ptr::null_mut()), NULL, "next(out=NULL)");
    let mut st = misb_stats::default();
    st.struct_size = full::<misb_stats>();
    expect(misb_decoder_stats(ptr::null(), &mut st), NULL, "stats(decoder=NULL)");
    expect(misb_decoder_stats(d, ptr::null_mut()), NULL, "stats(out=NULL)");
    expect(misb_decoder_finish(ptr::null_mut()), NULL, "finish(NULL)");
    expect(misb_decoder_reset(ptr::null_mut()), NULL, "reset(NULL)");
    expect(misb_config_default(ptr::null_mut()), NULL, "config_default(NULL)");
    let mut c: misb_config = std::mem::zeroed();
    expect(misb_config_default(&mut c), &[MISB_ERR_INVALID], "config_default(struct_size 0)");
    let mut q = 1 as *mut misb_packet;
    expect(misb_decode(ptr::null(), 5, &mut q), NULL, "decode(NULL, 5)");
    assert!(q.is_null());
    expect(misb_decode(s.as_ptr(), s.len(), ptr::null_mut()), NULL, "decode(out=NULL)");
    expect(misb_decode_ex(ptr::null(), 1, ptr::null(), &mut q, ptr::null_mut(), ptr::null_mut()), NULL, "decode_ex(NULL, 1)");
    let mut info: misb_packet_info = std::mem::zeroed();
    info.struct_size = full::<misb_packet_info>();
    expect(misb_packet_info_get(ptr::null(), &mut info), NULL, "packet_info_get(NULL)");
    let mut item: misb_item = std::mem::zeroed();
    item.struct_size = full::<misb_item>();
    expect(misb_packet_root(ptr::null(), &mut item), NULL, "packet_root(NULL)");
    expect(misb_packet_item(ptr::null(), 0, &mut item), NULL, "packet_item(NULL)");
    expect(misb_packet_find(ptr::null(), 1, &mut item), NULL, "packet_find(NULL)");
    expect(misb_item_child(ptr::null(), 0, &mut item), NULL, "item_child(NULL)");
    expect(misb_item_find(ptr::null(), 0, &mut item), NULL, "item_find(NULL)");
    expect(misb_item_field(ptr::null(), b"x\0".as_ptr() as *const c_char, &mut item), NULL, "item_field(NULL)");
    expect(misb_set_info_get(ptr::null(), &mut info), NULL, "set_info_get(NULL)");
    // An item the library did not fill in: no packet behind it.
    let mut blank: misb_item = std::mem::zeroed();
    blank.struct_size = full::<misb_item>();
    expect(misb_item_child(&blank, 0, &mut item), &[MISB_ERR_INVALID], "item_child(blank)");
    blank.struct_size = u32::from(ops.u8() % 4);
    expect(misb_item_child(&blank, 0, &mut item), &[MISB_ERR_INVALID], "item_child(struct_size < 4)");
}

/// Walk a packet's tree through the C API, checking every node and, when
/// `rust` is given, that it shows the same values as the Rust packet.
unsafe fn walk_packet(p: *const misb_packet, ops: &mut Input<'_>, rust: Option<&Packet>) {
    let mut info: misb_packet_info = std::mem::zeroed();
    info.struct_size = struct_size::<misb_packet_info>(ops);
    let size = info.struct_size;
    let status = misb_packet_info_get(p, &mut info);
    expect(status, &[MISB_OK, MISB_ERR_INVALID], "packet_info_get");
    assert_eq!(status == MISB_ERR_INVALID, size < 4);
    info.struct_size = full::<misb_packet_info>();
    expect(misb_packet_info_get(p, &mut info), &[MISB_OK], "packet_info_get");
    check_info(&info, rust);
    assert_eq!(info.standard, MISB_STANDARD_ST0601);
    assert!(info.checksum <= MISB_CHECKSUM_MISSING);

    let mut root: misb_item = std::mem::zeroed();
    root.struct_size = full::<misb_item>();
    expect(misb_packet_root(p, &mut root), &[MISB_OK], "packet_root");
    assert_eq!((root.kind, root.tag, root.child_count), (MISB_VALUE_SET, 0, info.item_count));
    assert!(root.raw.is_null() && root.raw_len == 0);
    assert!(!cstr(root.name, "root name").is_empty());
    let mut budget = MAX_NODES;
    let items: Option<Vec<&Value>> = rust.map(|r| r.items.iter().map(|i| &i.value).collect());
    walk_children(&root, ops, items.as_deref(), &mut budget);

    // misb_packet_item and misb_packet_find agree with the root's children.
    let mut a: misb_item = std::mem::zeroed();
    a.struct_size = full::<misb_item>();
    let index = usize::from(ops.u8());
    let status = misb_packet_item(p, index, &mut a);
    expect(status, &[MISB_OK, MISB_ERR_RANGE], "packet_item");
    assert_eq!(status == MISB_OK, (index as u64) < info.item_count);
    if status == MISB_OK {
        let mut b: misb_item = std::mem::zeroed();
        b.struct_size = full::<misb_item>();
        expect(misb_item_child(&root, index, &mut b), &[MISB_OK], "item_child(root)");
        assert_eq!((a.id, a.tag, a.kind), (b.id, b.tag, b.kind));
        let mut f: misb_item = std::mem::zeroed();
        f.struct_size = full::<misb_item>();
        expect(misb_packet_find(p, a.tag, &mut f), &[MISB_OK], "packet_find");
        assert_eq!(f.tag, a.tag);
        assert!(f.id <= a.id, "find returned a later item than the first");
    }
    let tag = u64::from(ops.u16());
    expect(misb_packet_find(p, tag, &mut a), &[MISB_OK, MISB_EMPTY], "packet_find");
}

unsafe fn check_info(info: &misb_packet_info, rust: Option<&Packet>) {
    assert!(info.error <= MISB_ERROR_INVALID_CONFIG);
    assert_eq!(info.error == MISB_ERROR_NONE, info.error_message.is_null());
    if !info.error_message.is_null() {
        assert!(!cstr(info.error_message, "error message").is_empty());
    }
    if info.checksum != MISB_CHECKSUM_MISMATCH {
        assert_eq!((info.checksum_expected, info.checksum_computed), (0, 0));
    }
    if let Some(r) = rust {
        assert_eq!(info.item_count, r.items.len() as u64);
        assert_eq!(info.error == MISB_ERROR_NONE, r.error.is_none());
        let code = match r.checksum {
            Checksum::NotApplicable => MISB_CHECKSUM_NOT_APPLICABLE,
            Checksum::Valid => MISB_CHECKSUM_VALID,
            Checksum::Mismatch { .. } => MISB_CHECKSUM_MISMATCH,
            Checksum::Missing => MISB_CHECKSUM_MISSING,
            _ => panic!("a Checksum variant the harness does not know"),
        };
        assert_eq!(info.checksum, code);
        if let Some(e) = &r.error {
            assert_eq!(cstr(info.error_message, "error message"), e.to_string().as_bytes());
        }
    }
}

/// Check the children of `parent` (filled in by the library), recursively
/// while the budget lasts. `rust` holds the values the children show.
unsafe fn walk_children(parent: &misb_item, ops: &mut Input<'_>, rust: Option<&[&Value]>, budget: &mut usize) {
    if let Some(r) = rust {
        assert_eq!(parent.child_count, r.len() as u64, "child count differs from the Rust value");
    }
    for i in 0..parent.child_count as usize {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let mut c: misb_item = std::mem::zeroed();
        // Sometimes an older, shorter struct.
        c.struct_size = if ops.u8() >= 240 { item_ref_size() + u32::from(ops.u8() % 16) } else { full::<misb_item>() };
        let size = c.struct_size;
        expect(misb_item_child(parent, i, &mut c), &[MISB_OK], "item_child");
        assert_eq!(c.struct_size, size.min(full::<misb_item>()));
        if c.struct_size < full::<misb_item>() {
            // Fill in the rest through the same item, as `out` may be the
            // same struct as `parent`.
            let mut whole = c;
            whole.struct_size = full::<misb_item>();
            let mut again: misb_item = whole;
            expect(misb_item_child(parent, i, &mut again), &[MISB_OK], "item_child");
            // Only the fields the short struct had room for were written.
            assert_eq!(again.id, c.id);
            c = again;
        }
        let value = rust.map(|r| r[i]);
        check_item(&c, parent.kind == MISB_VALUE_SET, value);
        // Out of range, and lookups.
        let mut x: misb_item = std::mem::zeroed();
        x.struct_size = full::<misb_item>();
        expect(misb_item_child(&c, c.child_count as usize, &mut x), &[MISB_ERR_RANGE], "item_child(past end)");
        expect(misb_item_find(parent, c.tag, &mut x), &[MISB_OK], "item_find(own tag)");
        assert_eq!(x.tag, c.tag);
        let name = cstr(c.name, "name").to_vec();
        let mut name_z = name.clone();
        name_z.push(0);
        expect(misb_item_field(parent, name_z.as_ptr() as *const c_char, &mut x), &[MISB_OK], "item_field(own name)");
        assert_eq!(cstr(x.name, "name"), &name[..]);
        let mut info: misb_packet_info = std::mem::zeroed();
        info.struct_size = full::<misb_packet_info>();
        let status = misb_set_info_get(&c, &mut info);
        if c.kind == MISB_VALUE_SET {
            expect(status, &[MISB_OK], "set_info_get");
            assert_eq!(info.item_count, c.child_count);
            assert_eq!(info.standard, c.standard);
            assert_eq!(info.checksum, MISB_CHECKSUM_NOT_APPLICABLE);
            check_info(&info, value.and_then(Value::as_set));
        } else {
            expect(status, &[MISB_ERR_INVALID], "set_info_get(not a set)");
        }
        let children: Option<Vec<&Value>> = value.map(|v| match v {
            Value::Set(p) => p.items.iter().map(|i| &i.value).collect(),
            Value::List(l) => l.iter().collect(),
            Value::Struct(f) => f.iter().map(|x| &x.value).collect(),
            _ => Vec::new(),
        });
        if c.child_count > 0 {
            // Navigate from a copy, then from the same struct as the output.
            walk_children(&c, ops, children.as_deref(), budget);
            let mut same = c;
            let both: *mut misb_item = &mut same;
            expect(misb_item_child(both, 0, both), &[MISB_OK], "item_child(out == parent)");
        }
    }
}

unsafe fn check_item(c: &misb_item, in_set: bool, rust: Option<&Value>) {
    assert!((MISB_VALUE_UINT..=MISB_VALUE_UNKNOWN).contains(&c.kind), "kind {}", c.kind);
    assert!(!misb_value_kind_name(c.kind).is_null());
    cstr(c.name, "name");
    cstr(c.units, "units");
    if in_set {
        assert!(!c.raw.is_null(), "a set item without raw");
        touch(c.raw, c.raw_len);
    } else {
        assert!(c.raw.is_null() && c.raw_len == 0);
    }
    match c.kind {
        MISB_VALUE_TEXT => {
            assert!(!c.data.is_null());
            touch(c.data, c.data_len + 1);
            assert_eq!(*c.data.add(c.data_len as usize), 0, "text not NUL-terminated");
        }
        MISB_VALUE_BYTES => {
            assert!(!c.data.is_null());
            touch(c.data, c.data_len);
        }
        MISB_VALUE_INVALID => {
            cstr(c.invalid_reason, "invalid reason");
        }
        MISB_VALUE_ENUM => {
            if !c.enum_label.is_null() {
                cstr(c.enum_label, "enum label");
            }
        }
        MISB_VALUE_SET => assert!((MISB_STANDARD_ST0601..=MISB_STANDARD_ST0903).contains(&c.standard)),
        MISB_VALUE_UNKNOWN => assert_eq!(c.raw_len, 0),
        _ => {}
    }
    if !matches!(c.kind, MISB_VALUE_SET | MISB_VALUE_LIST | MISB_VALUE_STRUCT) {
        assert_eq!(c.child_count, 0);
    }
    let Some(v) = rust else { return };
    assert_eq!(c.kind, kind_of(v), "kind differs from {v:?}");
    match v {
        Value::Uint(u) => assert_eq!(c.uint_value, *u),
        Value::Int(i) => assert_eq!(c.int_value, *i),
        Value::Float(f) => assert!(c.float_value == *f || (c.float_value.is_nan() && f.is_nan())),
        Value::Time(t) => assert_eq!(c.time_us, *t),
        Value::Text(t) => assert_eq!(std::slice::from_raw_parts(c.data, c.data_len as usize), t.as_bytes()),
        Value::Bytes(b) => assert_eq!(std::slice::from_raw_parts(c.data, c.data_len as usize), &b[..]),
        Value::Enum { code, label } => {
            assert_eq!(c.enum_code, *code);
            assert_eq!(c.enum_label.is_null(), label.is_none());
            if let Some(l) = label {
                assert_eq!(cstr(c.enum_label, "label"), l.as_bytes());
            }
        }
        Value::Invalid(why) => assert_eq!(cstr(c.invalid_reason, "reason"), why.as_bytes()),
        _ => {}
    }
}
