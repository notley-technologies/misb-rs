//! Builders for synthetic MISB KLV, shared by the integration tests, the
//! fuzz harnesses (`tests/harness`) and the cargo-fuzz targets.
//!
//! [`St0601`] builds an ST 0601 packet item by item, with nested sets,
//! long-form lengths and a correct checksum (ST 0601.19 section 8.1);
//! [`Set`] builds the bare local sets nested inside one. The rest are
//! encoders for the pieces those are made of, sample packets that use every
//! nested standard, ways to damage a stream, and a check that a decoded
//! packet stays within its [`Config`] limits.
#![allow(dead_code)]

use misb::{Checksum, Config, Error, Packet, Standard, Value};

pub use misb::st0601::KEY;

/// The ST 0102 Security Metadata Local Set key (ST 0102.12 section 6.7):
/// a valid key, but not one the decoder decodes at top level.
pub const ST0102_KEY: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 2, 3, 1, 1, 0x0E, 1, 3, 3, 2, 0, 0, 0];

/// The ST 0903 VMTI Local Set key (ST 0903.6 section 10.1).
pub const ST0903_KEY: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 3, 6, 0, 0, 0];

// ---------------------------------------------------------------- encoders

/// BER length in its shortest form (SMPTE ST 336 section 5.3).
pub fn ber_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes = (n as u64).to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = vec![0x80 | (8 - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// BER long-form length with exactly `width` length bytes (1 to 127), padded
/// with leading zeros: legal, if not minimal.
pub fn ber_len_long(n: usize, width: usize) -> Vec<u8> {
    assert!((1..=127).contains(&width));
    let mut out = vec![0x80 | width as u8];
    for i in (0..width).rev() {
        out.push(if i < 8 { ((n as u64) >> (8 * i)) as u8 } else { 0 });
    }
    out
}

/// BER-OID integer (ISO/IEC 8825-1 section 8.19): seven bits per byte, most
/// significant first, the top bit set on all but the last byte.
pub fn ber_oid(n: u64) -> Vec<u8> {
    let mut out = vec![(n & 0x7F) as u8];
    let mut rest = n >> 7;
    while rest > 0 {
        out.push(0x80 | (rest & 0x7F) as u8);
        rest >>= 7;
    }
    out.reverse();
    out
}

/// One local set item: BER-OID tag, BER length, value.
pub fn item(tag: u64, value: &[u8]) -> Vec<u8> {
    let mut out = ber_oid(tag);
    out.extend(ber_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// A Series (ST 0903.6 section 9.2.2, ST 0601 lists): each element
/// preceded by its BER length.
pub fn series(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in elements {
        out.extend(ber_len(e.len()));
        out.extend_from_slice(e);
    }
    out
}

/// Parse hex digits, ignoring whitespace (for the published examples).
pub fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len() % 2 == 0, "odd number of hex digits");
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("not hex"))
        .collect()
}

/// UTF-16BE without a byte order mark (RFC 2781), as ST 0102 tag 13 uses.
pub fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

// ---------------------------------------------------------------- builders

/// A bare local set: the value of a nested set item (ST 0601 tags 48, 73,
/// 74, 100 and 101, ST 0806 subordinate sets, ST 0903 sets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Set(pub Vec<u8>);

impl Set {
    pub fn new() -> Set {
        Set(Vec::new())
    }

    /// Append an item with a short or minimal long-form length.
    pub fn item(mut self, tag: u64, value: &[u8]) -> Set {
        self.0.extend(item(tag, value));
        self
    }

    /// Append an item whose length is long form with `width` bytes.
    pub fn item_long(mut self, tag: u64, value: &[u8], width: usize) -> Set {
        self.0.extend(ber_oid(tag));
        self.0.extend(ber_len_long(value.len(), width));
        self.0.extend_from_slice(value);
        self
    }

    /// Append a nested set as the value of `tag`.
    pub fn set(self, tag: u64, nested: Set) -> Set {
        self.item(tag, &nested.0)
    }

    /// Append bytes as they are, for malformed items.
    pub fn raw(mut self, bytes: &[u8]) -> Set {
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An ST 0601 packet under construction. [`St0601::build`] appends the
/// checksum item (tag 1, ST 0601.19 section 8.1) as the last item, computed
/// over the key, the length and every item up to its own length byte.
#[derive(Clone, Debug)]
pub struct St0601 {
    key: [u8; 16],
    body: Set,
    length_width: Option<usize>,
    checksum: bool,
}

impl Default for St0601 {
    fn default() -> Self {
        St0601::new()
    }
}

impl St0601 {
    /// An empty packet with the ST 0601 key and a checksum.
    pub fn new() -> St0601 {
        St0601 { key: KEY, body: Set::new(), length_width: None, checksum: true }
    }

    /// Tag 2, Precision Time Stamp, which ST 0601 puts first.
    pub fn time(self, us: u64) -> St0601 {
        self.item(2, &us.to_be_bytes())
    }

    pub fn item(mut self, tag: u64, value: &[u8]) -> St0601 {
        self.body = self.body.item(tag, value);
        self
    }

    pub fn item_long(mut self, tag: u64, value: &[u8], width: usize) -> St0601 {
        self.body = self.body.item_long(tag, value, width);
        self
    }

    pub fn set(mut self, tag: u64, nested: Set) -> St0601 {
        self.body = self.body.set(tag, nested);
        self
    }

    pub fn raw(mut self, bytes: &[u8]) -> St0601 {
        self.body = self.body.raw(bytes);
        self
    }

    /// Use another key, for example another standard's.
    pub fn key(mut self, key: [u8; 16]) -> St0601 {
        self.key = key;
        self
    }

    /// Change the registry version byte (byte 8), which decoders ignore.
    pub fn version_byte(mut self, v: u8) -> St0601 {
        self.key[7] = v;
        self
    }

    /// Write the packet length in long form with `width` bytes.
    pub fn long_length(mut self, width: usize) -> St0601 {
        self.length_width = Some(width);
        self
    }

    /// Leave out the checksum item.
    pub fn no_checksum(mut self) -> St0601 {
        self.checksum = false;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let tail = if self.checksum { 4 } else { 0 };
        let len = self.body.len() + tail;
        let mut out = self.key.to_vec();
        out.extend(match self.length_width {
            Some(w) => ber_len_long(len, w),
            None => ber_len(len),
        });
        out.extend_from_slice(self.body.bytes());
        if self.checksum {
            out.extend([1, 2]);
            let sum = misb::checksum::st0601_checksum(&out);
            out.extend(sum.to_be_bytes());
        }
        out
    }
}

/// A KLV triplet with any key and value, for packets of other standards.
pub fn triplet(key: [u8; 16], value: &[u8]) -> Vec<u8> {
    let mut out = key.to_vec();
    out.extend(ber_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// A standalone ST 0102 packet: skipped by the decoder and counted.
pub fn other_key(value: &[u8]) -> Vec<u8> {
    triplet(ST0102_KEY, value)
}

/// One VTarget Pack (ST 0903.6 section 10.2): the Target ID as a BER-OID,
/// then the pack's items.
pub fn vtarget(id: u64, items: Set) -> Vec<u8> {
    let mut out = ber_oid(id);
    out.extend(items.0);
    out
}

/// One metadata access unit cell (ISO/IEC 13818-1 section 2.12.4):
/// service id, sequence number, flags (fragment indication in the top two
/// bits, random access set), 16-bit length, data.
pub fn au_cell(service: u8, sequence: u8, fragment: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![service, sequence, (fragment << 6) | 0x10];
    out.extend((data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

// ---------------------------------------------------------------- samples

/// ST 0902.8 Annex C Table 10, "Dynamic & Constant": 228 bytes with a
/// nested ST 0102 set (tag 48), an ST 1204 identifier (tag 94) and a
/// two-byte long-form length; checksum 0x3E1E.
pub fn spec_packet_a() -> Vec<u8> {
    hex("06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00
         81 D2 02 08 00 04 60 50 58 4E 01 80 03 0A 4D 69
         73 73 69 6F 6E 20 31 32 05 02 71 C2 06 02 FD 3D
         07 02 08 B8 0A 08 50 72 65 64 61 74 6F 72 0B 07
         45 4F 20 4E 6F 73 65 0C 0E 47 65 6F 64 65 74 69
         63 20 57 47 53 38 34 0D 04 55 95 B6 6D 0E 04 5B
         53 60 C4 0F 02 C2 21 10 02 CD 9C 11 02 D9 17 12
         04 72 4A 0A 20 13 04 87 F8 4B 86 14 04 7D C5 5E
         CE 15 04 03 83 09 26 16 02 12 81 17 04 F1 01 A2
         29 18 04 14 BC 08 2B 19 02 34 F3 30 1C 01 01 01
         02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00
         55 00 53 00 41 16 02 00 0A 41 01 06 5E 22 01 70
         F5 92 F0 23 73 36 4A F8 AA 91 62 C0 0F 2E B2 DA
         16 B7 43 41 00 08 41 A0 BE 36 5B 5A B9 6A 36 45
         01 02 3E 1E")
}

/// ST 0902.8 Annex C Table 11, "Dynamic Only": 114 bytes, short-form
/// length; checksum 0x5C2B.
pub fn spec_packet_b() -> Vec<u8> {
    hex("06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00
         61 02 08 00 04 60 50 58 4E 01 80 05 02 71 C2 06
         02 FD 3D 07 02 08 B8 0D 04 55 95 B6 6D 0E 04 5B
         53 60 C4 0F 02 C2 21 10 02 CD 9C 11 02 D9 17 12
         04 72 4A 0A 20 13 04 87 F8 4B 86 14 04 7D C5 5E
         CE 15 04 03 83 09 26 16 02 12 81 17 04 F1 01 A2
         29 18 04 14 BC 08 2B 19 02 34 F3 41 01 06 01 02
         5C 2B")
}

/// A typical small packet: time stamp, mission, platform attitude and
/// sensor position, version 19.
pub fn sample(i: u64) -> Vec<u8> {
    St0601::new()
        .time(1_224_807_209_913_000 + i * 33_367)
        .item(3, b"MISSION01")
        .item(5, &(i as u16).wrapping_mul(97).to_be_bytes())
        .item(6, &[0xFD, 0x3D])
        .item(13, &[0x55, 0x95, 0xB6, 0x6D])
        .item(14, &[0x5B, 0x53, 0x60, 0xC4])
        .item(15, &[0xC2, 0x21])
        .item(65, &[19])
        .build()
}

/// ST 0102 security set (ST 0601 tag 48) with the Required items.
pub fn security_set() -> Set {
    Set::new()
        .item(1, &[1])
        .item(2, &[7])
        .item(3, b"//USA")
        .item(12, &[7])
        .item(13, &utf16be("USA"))
        .item(22, &[0, 12])
}

/// ST 0806 RVT set (ST 0601 tag 73) with a point and an area of interest
/// and a user defined item.
pub fn rvt_set() -> Set {
    let poi = Set::new()
        .item(1, &[0, 7])
        .item(2, &0x2000_0000u32.to_be_bytes())
        .item(3, &0xE000_0000u32.to_be_bytes())
        .item(4, &[0x10, 0x00])
        .item(5, &[2])
        .item(9, b"TGT-7");
    let aoi = Set::new()
        .item(1, &[0, 8])
        .item(2, &0x1000_0000u32.to_be_bytes())
        .item(3, &0x1000_0000u32.to_be_bytes())
        .item(4, &0x0F00_0000u32.to_be_bytes())
        .item(5, &0x1100_0000u32.to_be_bytes())
        .item(6, &[1]);
    let user = Set::new().item(1, &[0x85]).item(2, &[0x01, 0x00]);
    Set::new()
        .item(2, &1_224_807_209_913_000u64.to_be_bytes())
        .item(3, &[0, 147])
        .item(8, &[4])
        .item(10, b"H.264")
        .set(12, poi)
        .set(13, aoi)
        .set(11, user)
        .item(14, &[33])
        .item(15, b"UVG")
}

/// ST 0903 VMTI set (ST 0601 tag 74) with two targets, a VMask, a VTracker,
/// a VObject Series with a VFeature, and an Algorithm Series.
pub fn vmti_set() -> Set {
    let mask = Set::new().item(1, &series(&[vec![0x39, 0xAA], vec![0x39, 0xBF], vec![0x3B, 0x0B]]));
    let tracker = Set::new()
        .item(1, &hex("F81D4FAE7DEC11D0A76500A0C91E6BF6"))
        .item(3, &987_654_321_000_000u64.to_be_bytes())
        .item(7, &[50])
        .item(12, &[3]);
    let feature = Set::new().item(3, &[2]).item(4, &[0x40, 0x00]);
    let object = Set::new().item(3, &[1]).item(4, &[0x40, 0x00]).item(5, &series(&[feature.0]));
    let first = Set::new()
        .item(1, &[0x06, 0x40, 0x00])
        .item(4, &[27])
        .item(5, &[80])
        .item(10, &[0x3A, 0x66, 0x67])
        .item(11, &[0x3E, 0x66, 0x67])
        .item(12, &[0x2A, 0x94])
        .set(101, mask)
        .set(104, tracker)
        .item(107, &series(&[object.0]));
    let second = Set::new().item(1, &[0x01, 0x00]).item(23, &[1]);
    let algorithm = Set::new().item(1, &[9]).item(2, b"k6_yolo_9000_tracker").item(3, b"2.6a").item(5, &[10]);
    Set::new()
        .item(2, &987_654_321_000_000u64.to_be_bytes())
        .item(3, b"DSTO_ADSS_VMTI")
        .item(4, &[6])
        .item(5, &[28])
        .item(6, &[2])
        .item(8, &[0x07, 0x80])
        .item(9, &[0x04, 0x38])
        .item(11, &[0x06, 0x40])
        .item(101, &series(&[vtarget(1234, first), vtarget(2, second)]))
        .item(102, &series(&[algorithm.0]))
}

/// An ST 1010 SDCC-FLP for three items: Mode 2 parse control (0x93 0x04:
/// not sparse, IMAPB correlations of 3 bytes, IEEE standard deviations of
/// 4 bytes), as ST 0601 requires (ST 1010.3 section 7, Table 2).
pub fn sdcc() -> Vec<u8> {
    let mut v = vec![3, 0x93, 0x04];
    for s in [1.5f32, 2.0, 0.25] {
        v.extend(s.to_be_bytes());
    }
    v.extend([0x40, 0x00, 0x00, 0x60, 0x00, 0x00, 0x20, 0x00, 0x00]);
    v
}

/// A packet that uses every nested standard: ST 0102 (tag 48), ST 0806
/// (73), ST 0903 (74), an ST 1204 identifier (94), ST 1607 Segment and
/// Amend sets (100, 101) and an ST 1010 SDCC-FLP (102).
pub fn rich(i: u64) -> Vec<u8> {
    let segment = Set::new()
        .item(143, &[1])
        .item(13, &[0x55, 0x95, 0xB6, 0x6D])
        .item(14, &[0x5B, 0x53, 0x60, 0xC4])
        .item(102, &sdcc());
    let amend = Set::new().item(143, &[2]).item(3, b"AMENDED");
    St0601::new()
        .time(1_224_807_209_913_000 + i * 33_367)
        .item(3, b"MISSION01")
        .item(13, &[0x55, 0x95, 0xB6, 0x6D])
        .item(14, &[0x5B, 0x53, 0x60, 0xC4])
        .item(15, &[0xC2, 0x21])
        .item(102, &sdcc())
        .item(65, &[19])
        .set(48, security_set())
        .set(73, rvt_set())
        .set(74, vmti_set())
        .item(94, &hex("0170F592F02373364AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645"))
        .set(100, segment)
        .set(101, amend)
        .item(122, &hex("010E0343414E0003465241"))
        .item(130, &hex("0B406BC20919BDA554070E000B40783CB819A2927407C600"))
        .build()
}

/// A chain of `levels` nested sets, each the value of the next tag of
/// `tags` (cycled) in its parent, around `inner`.
pub fn nest(levels: usize, tags: &[u64], inner: Set) -> Set {
    let mut s = inner;
    for i in 0..levels {
        s = Set::new().item(3, b"level").set(tags[i % tags.len()], s);
    }
    s
}

/// A stream with garbage, other keys, an oversized declared length, a
/// corrupt checksum, a missing checksum, damage inside a packet and a
/// truncated tail between valid packets.
pub fn mixed_stream() -> Vec<u8> {
    let mut s = vec![0x00, 0x06, 0x0E, 0x2B];
    s.extend(sample(0));
    s.extend(rich(1));
    s.extend([0x06, 0x0E, 0x2B, 0x34, 0x99]);
    s.extend(other_key(b"standalone security set"));
    s.extend(spec_packet_a());
    let mut bad = sample(2);
    corrupt_checksum(&mut bad);
    s.extend(bad);
    s.extend(St0601::new().time(3).item(3, b"no checksum").no_checksum().build());
    // A declared length far larger than any limit.
    s.extend(KEY);
    s.extend([0x84, 0x7F, 0xFF, 0xFF, 0xFF, 1, 2, 3]);
    s.extend(spec_packet_b());
    // An item whose length runs past the end of the packet.
    s.extend(St0601::new().time(4).raw(&[3, 0x7F, b'x']).build());
    s.extend(sample(5).repeat(3));
    let cut = rich(6);
    s.extend(&cut[..cut.len() - 7]);
    s
}

// ---------------------------------------------------------------- damage

/// Flip the low bit of the last checksum byte.
pub fn corrupt_checksum(packet: &mut [u8]) {
    let n = packet.len();
    packet[n - 1] ^= 1;
}

/// Flip one bit.
pub fn flip(v: &mut [u8], at: usize, bit: u8) {
    v[at] ^= 1 << (bit % 8);
}

// ---------------------------------------------------------------- random

/// Small deterministic PRNG (xorshift64*).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

// ---------------------------------------------------------------- checks

/// Assert what holds for every decoded packet: nesting within
/// [`Config::max_depth`], items within [`Config::max_items`] per set and
/// [`Config::max_total_items`] in all, list and pack sizes bounded (see
/// [`MAX_FIXED`]), `raw` kept as [`Config::keep_raw`] says, a top-level
/// checksum only on ST 0601, and Display working. `size` is the packet's
/// value length.
/// Lists and packs whose size the data chooses hold at most
/// [`Config::max_items`] entries, plus a VTarget Pack's Target ID and an
/// end marker (ST 0903 "Error" field or element). Packs with a layout fixed
/// by the standard (ST 0601 tag 47's six flags, ST 0903 location packs, ST
/// 1204's fields) and ST 0601 tag 124 (one entry per bit of up to 8 bytes)
/// have at most this many, whatever `max_items` says.
pub const MAX_FIXED: usize = 64;

/// Most entries a list or pack may hold under `cfg`.
fn max_entries(cfg: &Config) -> usize {
    cfg.max_items.max(MAX_FIXED).saturating_add(2)
}

pub fn check_packet(p: &Packet, cfg: &Config, size: usize) {
    assert_eq!(p.standard, Standard::St0601, "top-level packet of another standard");
    let mut total = 0usize;
    check_set(p, cfg, size, 0, &mut total);
    assert!(total <= cfg.max_total_items, "{total} items exceed max_total_items {}", cfg.max_total_items);
    if let Some(Error::TooLarge { .. }) = p.error {
        assert!(p.items.is_empty());
    }
    // Display and Debug must not panic, whatever the values.
    std::hint::black_box(format!("{p}"));
    std::hint::black_box(format!("{p:?}"));
    let _ = p.is_ok();
}

fn check_set(p: &Packet, cfg: &Config, size: usize, depth: usize, total: &mut usize) {
    let limit = cfg.max_depth.min(Config::MAX_DEPTH_LIMIT);
    if depth > limit {
        assert_eq!(p.error, Some(Error::TooDeep), "set at depth {depth} beyond max_depth {limit}");
        assert!(p.items.is_empty(), "too-deep set holds items");
        return;
    }
    if depth > 0 {
        assert_eq!(p.checksum, Checksum::NotApplicable, "nested set with a checksum");
    }
    assert!(p.items.len() <= cfg.max_items, "{} items exceed max_items {}", p.items.len(), cfg.max_items);
    *total += p.items.len();
    if let Some(Error::TooManyItems { count, limit, .. }) = &p.error {
        assert!(*count > *limit);
    }
    for item in &p.items {
        assert!(item.raw.len() <= size, "raw longer than the packet");
        let keeps = match &item.value {
            Value::Set(s) => s.error.is_some(),
            v => !v.is_valid(),
        };
        if !cfg.keep_raw && !keeps {
            assert!(item.raw.is_empty(), "raw kept with keep_raw off for tag {}", item.tag);
        }
        if matches!(item.value, Value::Unknown) {
            assert!(item.raw.is_empty(), "unknown item with raw bytes");
        }
        std::hint::black_box(format!("{item}"));
        check_value(&item.value, cfg, size, depth, total);
    }
}

fn check_value(v: &Value, cfg: &Config, size: usize, depth: usize, total: &mut usize) {
    match v {
        Value::Set(s) => check_set(s, cfg, size, depth + 1, total),
        Value::List(l) => {
            assert!(l.len() <= max_entries(cfg), "list of {} entries", l.len());
            for e in l {
                check_value(e, cfg, size, depth, total);
            }
        }
        Value::Struct(fields) => {
            assert!(fields.len() <= max_entries(cfg), "pack of {} fields", fields.len());
            for f in fields {
                assert!(!f.name.is_empty());
                check_value(&f.value, cfg, size, depth, total);
            }
        }
        Value::Text(t) => assert!(t.len() <= size.saturating_mul(3), "text longer than its bytes allow"),
        Value::Bytes(b) => assert!(b.len() <= size),
        Value::Invalid(why) => assert!(!why.is_empty()),
        _ => {}
    }
    let _ = (v.as_f64(), v.as_u64(), v.as_i64(), v.as_str(), v.as_time(), v.is_valid());
}
