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

#[cfg(feature = "capi")]
pub mod capi;

#[path = "../common/mod.rs"]
pub mod common;

use common::*;
use misb::{Checksum, Config, Decoder, Packet, Received, Value};
use std::hint::black_box;

/// Largest stream the generator builds, to keep each run fast.
const MAX_STREAM: usize = 12 * 1024;

// ---------------------------------------------------------------- targets

/// Raw bytes: the first byte picks the settings, the rest is the stream.
pub fn decode(data: &[u8]) {
    let (control, bytes) = data.split_first().map_or((0, &[][..]), |(c, rest)| (*c, rest));
    let cfg = config_from_control(control);
    check_stream(bytes, &cfg, hash(data));
    check_st0604(control, bytes);
}

/// The ST 0604 reader on the same bytes, also behind a real identifier
/// (picked by the control byte) so mutations reach the payload: it never
/// panics, and a message it reads without warnings encodes back to the
/// same 28 bytes.
fn check_st0604(control: u8, bytes: &[u8]) {
    use misb::st0604::{self, Identifier};
    let mut framed = Identifier::ALL[usize::from(control) % 3].bytes().to_vec();
    framed.extend_from_slice(bytes);
    for input in [bytes, &framed[..]] {
        let Ok(d) = st0604::decode(input) else { continue };
        assert_eq!(d.warnings.trailing_bytes, input.len() - st0604::TIMESTAMP_LEN);
        let _ = black_box(d.timestamp.misp_time());
        // `capi` implies misb's `encode`, and is a feature of the fuzz
        // crate too (which has no `encode` of its own).
        #[cfg(feature = "capi")]
        if d.warnings.is_empty() && d.timestamp.status.is_valid() {
            assert_eq!(&d.timestamp.to_bytes().unwrap()[..], &input[..st0604::TIMESTAMP_LEN]);
        }
    }
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
