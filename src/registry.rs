//! Dispatch from ST 0601 packets and nested set tags to standard decoders.
//!
//! # Contract for standards modules
//!
//! Every local set module (`st0601`, and `st0102`, `st0806`, `st0903` which
//! only appear nested inside ST 0601) provides:
//!
//! ```text
//! pub enum Tag { .. }                     // with From<Tag> for u64
//! pub(crate) fn decode_item(tag: u64, value: &[u8], depth: usize, cfg: &Config) -> Item;
//! ```
//!
//! and `st0601` also has `pub const KEY: [u8; 16]`, the only key the crate
//! decodes at top level.
//!
//! `decode_item` turns one local set item into an [`Item`] and must never
//! panic. `depth` is the nesting level of the set the item belongs to (0 for
//! a top-level packet). An item that holds a nested local set decodes it with
//! [`decode_set`]`(standard, value, depth + 1, cfg)`, which enforces
//! [`Config::max_depth`] (capped at [`Config::MAX_DEPTH_LIMIT`]),
//! [`Config::max_items`] and [`Config::max_total_items`]; nesting a module
//! walks itself is compared with `cfg.depth_limit()`. Items are built with
//! [`item`], which keeps [`Item::raw`] as [`Config::keep_raw`] asks, and an
//! empty value that the standard allows to be empty decodes to
//! [`Value::Unknown`] (a zero-length item, MISB ST 0107).
//!
//! The registry owns everything around the items: the set walk, item limits
//! and the ST 0601 checksum.

use crate::klv::{local_set, Triplet, UniversalLabel};
use crate::{checksum, st0102, st0601, st0806, st0903};
use crate::{Checksum, Config, Error, Item, Packet, Standard, Value};
use std::cell::Cell;

thread_local! {
    /// Items the ST 0601 packet being decoded on this thread may still
    /// decode ([`Config::max_total_items`]). `usize::MAX`, no limit, outside
    /// [`decode_st0601`].
    static BUDGET: Cell<usize> = const { Cell::new(usize::MAX) };
    // Sparse ST 1010 lists can expand well beyond their encoded length.
    static MATRIX_VALUES: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Sets the item budget for one packet and restores the previous one when
/// dropped, also on unwind.
struct Budget {
    previous_items: usize,
    previous_matrix_values: Option<usize>,
}

impl Budget {
    fn start(items: usize) -> Budget {
        Budget {
            previous_items: BUDGET.with(|b| b.replace(items)),
            previous_matrix_values: MATRIX_VALUES.with(|b| b.replace(Some(items))),
        }
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        BUDGET.with(|b| b.set(self.previous_items));
        MATRIX_VALUES.with(|b| b.set(self.previous_matrix_values));
    }
}

// Most packets fit in one allocation. Larger sets grow as the shared
// budget is consumed by their children.
const INITIAL_ITEMS: usize = 64;

fn remaining_items() -> usize {
    BUDGET.try_with(Cell::get).unwrap_or(usize::MAX)
}

/// Take one item from the budget; false when it is used up.
fn take_item() -> bool {
    BUDGET
        .try_with(|b| match b.get() {
            0 => false,
            n => {
                b.set(n - 1);
                true
            }
        })
        .unwrap_or(true)
}

/// Reserve space for one matrix before expanding its lists. A rejected
/// matrix leaves the allowance available for smaller ones in the packet.
pub(crate) fn take_matrix_values(count: usize) -> bool {
    MATRIX_VALUES.with(|budget| match budget.get() {
        None => true,
        Some(left) if count <= left => {
            budget.set(Some(left - count));
            true
        }
        Some(_) => false,
    })
}

/// True when `key` is the ST 0601 UAS Datalink Local Set key. Byte 8, the
/// registry version (SMPTE ST 336 section 6.2.3), is ignored because encoders
/// in the field stamp different versions into the same key.
pub(crate) fn is_st0601_key(key: &UniversalLabel) -> bool {
    key.eq_ignoring_version(&UniversalLabel::from_bytes(st0601::KEY))
}

/// What a header-only walk of a local set found.
struct Shape<'a> {
    /// Items parsed before the end or the first malformed item.
    count: usize,
    /// The last item parsed: tag and value.
    last: Option<(u64, &'a [u8])>,
    /// The walk reached the end of the set without a malformed item.
    complete: bool,
}

/// Walk the item headers of a set without decoding values: linear, and
/// bounded by the set's length.
fn shape(value: &[u8]) -> Shape<'_> {
    let mut s = Shape { count: 0, last: None, complete: true };
    for item in local_set(value) {
        match item {
            Ok(i) => {
                s.count += 1;
                s.last = Some((i.tag, i.value));
            }
            Err(_) => {
                s.complete = false;
                break;
            }
        }
    }
    s
}

/// Decode one ST 0601 packet; the caller has checked the key with
/// [`is_st0601_key`]. A value longer than [`Config::max_packet_bytes`] gives
/// an empty packet with [`Error::TooLarge`]. The checksum is verified when
/// [`Config::verify_checksum`] or [`Config::reject_bad_checksum`] is set.
pub(crate) fn decode_st0601(t: &Triplet<'_>, cfg: &Config) -> Packet {
    if t.value().len() > cfg.max_packet_bytes {
        let mut p = Packet::new(Standard::St0601);
        p.error = Some(Error::TooLarge { size: t.value().len(), limit: cfg.max_packet_bytes });
        return p;
    }
    let _budget = Budget::start(cfg.max_total_items);
    // One header walk sizes the item list and finds the last item for the
    // checksum.
    let shape = shape(t.value());
    let mut p = decode_items(Standard::St0601, t.value(), 0, cfg, shape.count);
    // Asking to reject bad checksums implies checking them.
    if cfg.verify_checksum || cfg.reject_bad_checksum {
        p.checksum = st0601_checksum(t, &shape);
    }
    p
}

/// Verify the ST 0601 checksum (tag 1). ST 0601 requires it to be the last
/// item of the set (ST 0601.8-11), 2 bytes long, covering every byte from
/// the start of the universal key to its own length byte.
///
/// When the set does not end with that item, a damaged length may have
/// moved the item boundaries: an item swallowing the checksum item, or a
/// malformed item before it. If the triplet still ends with `01 02 hi lo`
/// and those bytes do not sum to `hi lo`, the packet is damaged and reported
/// as a mismatch. Otherwise it is `Missing`, never `Valid`: matching bytes
/// do not prove that tag 1 is the last item.
fn st0601_checksum(t: &Triplet<'_>, shape: &Shape<'_>) -> Checksum {
    let bytes = t.as_bytes();
    let n = bytes.len();
    let compare = || {
        // The carried value is the final two bytes of the triplet;
        // everything before is covered.
        let computed = checksum::st0601_checksum(&bytes[..n - 2]);
        let expected = u16::from_be_bytes([bytes[n - 2], bytes[n - 1]]);
        (expected, computed)
    };
    let last_is_checksum =
        matches!(shape.last, Some((tag, v)) if tag == u64::from(st0601::Tag::Checksum) && v.len() == 2);
    if shape.complete && last_is_checksum {
        let (expected, computed) = compare();
        return if computed == expected { Checksum::Valid } else { Checksum::Mismatch { expected, computed } };
    }
    if t.value().len() >= 4 && bytes[n - 4..n - 2] == [0x01, 0x02] {
        let (expected, computed) = compare();
        if computed != expected {
            return Checksum::Mismatch { expected, computed };
        }
    }
    Checksum::Missing
}

/// Decode a local set value of `standard` found at nesting level `depth`.
///
/// Returns a packet with [`Checksum::NotApplicable`]; [`decode_st0601`]
/// fills in the checksum of top-level packets. Nesting beyond
/// [`Config::max_depth`] (capped at [`Config::MAX_DEPTH_LIMIT`]) gives an
/// empty packet with [`Error::TooDeep`]; more than [`Config::max_items`]
/// items, or running out of [`Config::max_total_items`], stops with
/// [`Error::TooManyItems`]. Malformed items stop the walk and set
/// [`Packet::error`], keeping the items before them.
pub(crate) fn decode_set(standard: Standard, value: &[u8], depth: usize, cfg: &Config) -> Packet {
    if depth > cfg.depth_limit() {
        let mut p = Packet::new(standard);
        p.error = Some(Error::TooDeep);
        return p;
    }
    let limit = remaining_items().min(cfg.max_items).min(INITIAL_ITEMS);
    let count = local_set(value).take(limit).count();
    decode_items(standard, value, depth, cfg, count)
}

/// The item walk of [`decode_set`], with the item list sized for `count`
/// items.
fn decode_items(standard: Standard, value: &[u8], depth: usize, cfg: &Config, count: usize) -> Packet {
    let mut p = Packet::new(standard);
    let decode: fn(u64, &[u8], usize, &Config) -> Item = match standard {
        Standard::St0601 => st0601::decode_item,
        Standard::St0102 => st0102::decode_item,
        Standard::St0806 => st0806::decode_item,
        Standard::St0903 => st0903::decode_item,
    };
    p.items.reserve_exact(count.min(cfg.max_items).min(remaining_items()).min(INITIAL_ITEMS));
    for item in local_set(value) {
        match item {
            Ok(i) => {
                if p.items.len() >= cfg.max_items {
                    let count = p.items.len().saturating_add(1);
                    p.error = Some(Error::TooManyItems { count, limit: cfg.max_items });
                    break;
                }
                if !take_item() {
                    let limit = cfg.max_total_items;
                    p.error = Some(Error::TooManyItems { count: limit.saturating_add(1), limit });
                    break;
                }
                p.items.push(decode(i.tag, i.value, depth, cfg));
            }
            Err(e) => {
                p.error = Some(e);
                break;
            }
        }
    }
    p
}

/// Build an item from its decoded value and its bytes. [`Item::raw`] gets a
/// copy of the bytes unless [`Config::keep_raw`] is off and the value
/// decoded validly: [`Value::Invalid`] and [`Value::OutOfRange`] values and
/// nested sets that stopped with an error keep their bytes either way.
pub(crate) fn item(tag: u64, name: &'static str, units: &'static str, value: Value, bytes: &[u8], cfg: &Config) -> Item {
    let keep = cfg.keep_raw
        || match &value {
            Value::Set(p) => p.error.is_some(),
            v => !v.is_valid(),
        };
    let raw = if keep { bytes.to_vec() } else { Vec::new() };
    Item { tag, name, units, value, raw }
}

/// An item whose tag the standard does not define: kept as raw bytes.
pub(crate) fn unknown_item(tag: u64, value: &[u8], _depth: usize, cfg: &Config) -> Item {
    item(tag, "Unknown", "", Value::Bytes(value.to_vec()), value, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klv::triplet;

    /// Build an ST 0601 packet from (tag, value) items, appending a correct
    /// checksum.
    fn st0601_packet(items: &[(u8, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, v) in items {
            body.push(*tag);
            body.push(v.len() as u8);
            body.extend_from_slice(v);
        }
        body.extend([1, 2]);
        let mut out = st0601::KEY.to_vec();
        out.push((body.len() + 2) as u8);
        out.extend(&body);
        let sum = checksum::st0601_checksum(&out);
        out.extend(sum.to_be_bytes());
        out
    }

    fn decode(buf: &[u8], cfg: &Config) -> Packet {
        decode_st0601(&triplet(buf).unwrap(), cfg)
    }

    #[test]
    fn key_match_ignores_version() {
        let mut k = st0601::KEY;
        assert!(is_st0601_key(&UniversalLabel::from_bytes(k)));
        k[7] = 0x02;
        assert!(is_st0601_key(&UniversalLabel::from_bytes(k)));
        k[15] = 0x01;
        assert!(!is_st0601_key(&UniversalLabel::from_bytes(k)));
    }

    #[test]
    fn valid_checksum() {
        let buf = st0601_packet(&[(2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8])]);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.standard, Standard::St0601);
        assert_eq!(p.checksum, Checksum::Valid);
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.items[1].tag, 1);
        assert!(p.is_ok());
    }

    #[test]
    fn checksum_mismatch_missing_and_off() {
        let mut buf = st0601_packet(&[(3, b"ABC")]);
        let n = buf.len();
        let good = u16::from_be_bytes([buf[n - 2], buf[n - 1]]);
        buf[n - 1] ^= 0x01;
        let p = decode(&buf, &Config::default());
        assert_eq!(p.checksum, Checksum::Mismatch { expected: good ^ 1, computed: good });
        assert!(!p.is_ok());

        let mut off = Config::default();
        off.verify_checksum = false;
        let p = decode(&buf, &off);
        assert_eq!(p.checksum, Checksum::NotApplicable);

        // No checksum item.
        let mut buf = st0601::KEY.to_vec();
        buf.extend([3, 3, 1, b'A', b'B']);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.checksum, Checksum::Missing);

        // Checksum present but not last.
        let mut buf = st0601::KEY.to_vec();
        buf.extend([7, 1, 2, 0, 0, 3, 1, b'A']);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.checksum, Checksum::Missing);

        // Empty set.
        let mut buf = st0601::KEY.to_vec();
        buf.push(0);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.checksum, Checksum::Missing);
        assert!(p.items.is_empty());
    }

    #[test]
    fn checksum_with_long_form_length() {
        let v = [b'x'; 200];
        let buf = st0601_packet_long(&v);
        let t = triplet(&buf).unwrap();
        assert_eq!(t.header_len(), 18);
        assert_eq!(decode_st0601(&t, &Config::default()).checksum, Checksum::Valid);
    }

    fn st0601_packet_long(v: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 0x81, v.len() as u8];
        body.extend_from_slice(v);
        body.extend([1, 2]);
        let mut out = st0601::KEY.to_vec();
        out.extend([0x81, (body.len() + 2) as u8]);
        out.extend(&body);
        let sum = checksum::st0601_checksum(&out);
        out.extend(sum.to_be_bytes());
        out
    }

    #[test]
    fn malformed_set_keeps_earlier_items() {
        let mut buf = st0601::KEY.to_vec();
        buf.extend([5, 3, 1, 0xAA, 3, 9]);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.error, Some(Error::Truncated { needed: 11, available: 2 }));
        assert_eq!(p.checksum, Checksum::Missing);
    }

    #[test]
    fn limits() {
        let mut cfg = Config::default();
        cfg.max_items = 2;
        let p = decode_set(Standard::St0102, &[1, 1, 1, 2, 1, 1, 3, 0], 0, &cfg);
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.error, Some(Error::TooManyItems { count: 3, limit: 2 }));

        cfg.max_depth = 1;
        assert_eq!(decode_set(Standard::St0102, &[1, 0], 1, &cfg).error, None);
        let deep = decode_set(Standard::St0102, &[1, 0], 2, &cfg);
        assert_eq!(deep.error, Some(Error::TooDeep));
        assert!(deep.items.is_empty());

        cfg.max_packet_bytes = 1;
        let buf = st0601_packet(&[]);
        let p = decode(&buf, &cfg);
        assert_eq!(p.error, Some(Error::TooLarge { size: 4, limit: 1 }));
        assert!(p.items.is_empty());
    }

    /// [(2, 8 bytes), (13, 4 bytes), (14, 4 bytes)] and a checksum.
    fn three_items() -> Vec<u8> {
        st0601_packet(&[(2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]), (13, &[1, 2, 3, 4]), (14, &[5, 6, 7, 8])])
    }

    fn carried_and_computed(buf: &[u8]) -> (u16, u16) {
        let n = buf.len();
        (u16::from_be_bytes([buf[n - 2], buf[n - 1]]), checksum::st0601_checksum(&buf[..n - 2]))
    }

    #[test]
    fn length_damage_that_swallows_the_checksum_is_a_mismatch() {
        // Tag 14's length 04 -> 08: tag 14 now ends with the checksum item,
        // so the set walks cleanly but tag 1 is not last. The bytes still
        // end in 01 02 hi lo, and they no longer sum to it (ST 0601.8-08).
        let mut buf = three_items();
        assert_eq!(buf[34], 4);
        buf[34] = 8;
        let p = decode(&buf, &Config::default());
        assert_eq!(p.error, None);
        let (expected, computed) = carried_and_computed(&buf);
        assert_ne!(expected, computed);
        assert_eq!(p.checksum, Checksum::Mismatch { expected, computed });
        assert!(!p.is_ok());

        // Tag 65 length 01 -> 05 swallows exactly 01 02 hi lo.
        let mut buf = st0601_packet(&[(2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]), (65, &[19])]);
        let at = buf.len() - 6;
        assert_eq!(&buf[at - 1..at + 1], &[65, 1]);
        buf[at] = 5;
        let p = decode(&buf, &Config::default());
        assert!(matches!(p.checksum, Checksum::Mismatch { .. }), "{:?}", p.checksum);
        assert!(!p.is_ok());
    }

    #[test]
    fn checksum_found_by_bytes_when_the_set_is_malformed() {
        // A malformed item before a checksum item that does not match.
        let mut buf = st0601::KEY.to_vec();
        buf.extend([6, 3, 0xFF, 1, 2, 0, 0]);
        let p = decode(&buf, &Config::default());
        assert_eq!(p.error, Some(Error::BadLength));
        let (expected, computed) = carried_and_computed(&buf);
        assert_eq!(p.checksum, Checksum::Mismatch { expected, computed });
        // When the bytes do sum to it, tag 1 is still not provably the last
        // item: missing, never valid.
        let n = buf.len();
        buf[n - 2..].copy_from_slice(&computed.to_be_bytes());
        let p = decode(&buf, &Config::default());
        assert_eq!(p.checksum, Checksum::Missing);
        assert!(!p.is_ok());
    }

    #[test]
    fn missing_checksum_is_not_ok() {
        let mut buf = st0601::KEY.to_vec();
        buf.extend([5, 3, 3, b'A', b'B', b'C']);
        let p = decode(&buf, &Config::default());
        assert_eq!((p.checksum, &p.error), (Checksum::Missing, &None));
        assert!(!p.is_ok());
        // Nested sets carry no checksum and stay ok.
        assert!(decode_set(Standard::St0601, &[3, 1, b'A'], 1, &Config::default()).is_ok());
        let mut off = Config::default();
        off.verify_checksum = false;
        assert!(decode(&buf, &off).is_ok());
    }

    #[test]
    fn rejecting_implies_verifying() {
        let mut buf = st0601_packet(&[(3, b"ABC")]);
        let n = buf.len();
        buf[n - 1] ^= 1;
        let mut c = Config::default();
        c.verify_checksum = false;
        c.reject_bad_checksum = true;
        assert!(matches!(decode(&buf, &c).checksum, Checksum::Mismatch { .. }));
    }

    #[test]
    fn depth_has_a_hard_ceiling() {
        let mut cfg = Config::default();
        cfg.max_depth = usize::MAX;
        assert_eq!(decode_set(Standard::St0102, &[1, 0], 32, &cfg).error, None);
        assert_eq!(decode_set(Standard::St0102, &[1, 0], 33, &cfg).error, Some(Error::TooDeep));
    }

    /// Segment Local Sets (tag 100, the ST 0601 table) nested `levels` deep
    /// around a tag 65 item, built without quadratic copying.
    fn nested_segments(levels: usize) -> Vec<u8> {
        fn ber(n: usize, out: &mut Vec<u8>) {
            if n < 0x80 {
                out.push(n as u8);
            } else {
                let b = (n as u64).to_be_bytes();
                let skip = b.iter().take_while(|&&x| x == 0).count();
                out.push(0x80 | (8 - skip) as u8);
                out.extend(&b[skip..]);
            }
        }
        let inner = [65u8, 1, 19];
        let mut lens = vec![inner.len()];
        for i in 0..levels {
            let mut h = vec![100];
            ber(lens[i], &mut h);
            lens.push(h.len() + lens[i]);
        }
        let mut out = Vec::with_capacity(lens[levels]);
        for i in (0..levels).rev() {
            out.push(100);
            ber(lens[i], &mut out);
        }
        out.extend(inner);
        assert_eq!(out.len(), lens[levels]);
        out
    }

    #[test]
    fn hostile_nesting_is_bounded_even_without_a_depth_limit() {
        // 100,000 levels of self-nested tag 100 on a small stack.
        let v = nested_segments(100_000);
        let deepest = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                let mut cfg = Config::default();
                cfg.max_depth = usize::MAX;
                cfg.max_packet_bytes = usize::MAX;
                let p = decode_set(Standard::St0601, &v, 0, &cfg);
                let mut level = &p;
                let mut depth = 0;
                while let Some(next) = level.items.first().and_then(|i| i.value.as_set()) {
                    level = next;
                    depth += 1;
                }
                (depth, level.error.clone())
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(deepest, (Config::MAX_DEPTH_LIMIT + 1, Some(Error::TooDeep)));
    }

    #[test]
    fn items_are_allocated_once() {
        let buf = three_items();
        let p = decode(&buf, &Config::default());
        assert_eq!(p.items.len(), 4);
        assert_eq!(p.items.capacity(), p.items.len());
        // The checksum still covers the whole set when max_items stops the
        // item walk early.
        let mut c = Config::default();
        c.max_items = 2;
        let p = decode(&buf, &c);
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.checksum, Checksum::Valid);
    }

    /// Count the items of a packet and every set nested in it.
    fn total_items(p: &Packet) -> usize {
        p.items.iter().map(|i| 1 + i.value.as_set().map_or(0, total_items)).sum()
    }

    #[test]
    fn item_budget_spans_the_whole_packet() {
        // 16 Security Local Sets of 32,000 empty items each, inside 1 MiB:
        // max_items holds per set, so only the packet budget limits them.
        let mut body = Vec::new();
        for _ in 0..16 {
            body.extend([48, 0x83, 0x00, 0xFA, 0x00]);
            body.extend([9u8, 0].repeat(32_000));
        }
        body.extend([1, 2]);
        let mut buf = st0601::KEY.to_vec();
        let len = (body.len() + 2) as u32;
        buf.push(0x83);
        buf.extend(&len.to_be_bytes()[1..]);
        buf.extend(&body);
        let sum = checksum::st0601_checksum(&buf);
        buf.extend(sum.to_be_bytes());
        let cfg = Config::default();
        assert!(buf.len() <= cfg.max_packet_bytes);
        let p = decode(&buf, &cfg);
        assert_eq!(total_items(&p), cfg.max_total_items);
        let mut limited = cfg.clone();
        limited.max_total_items = 2;
        let partial = decode(&buf, &limited);
        assert_eq!(partial.items.capacity(), 2);
        let security = partial.items[0].value.as_set().unwrap();
        assert_eq!(security.items.capacity(), 1);
        assert!(matches!(security.error, Some(Error::TooManyItems { limit: 2, .. })));
        assert_eq!(partial.checksum, Checksum::Valid);
        assert_eq!(p.error, Some(Error::TooManyItems { count: 65_537, limit: 65_536 }));
        assert_eq!(p.checksum, Checksum::Valid);
        // The budget belongs to one packet: the next one starts afresh, and
        // sets decoded on their own are not limited.
        let small = three_items();
        assert!(decode(&small, &cfg).is_ok());
        let mut c = Config::default();
        c.max_total_items = 3;
        let p = decode(&small, &c);
        assert_eq!((p.items.len(), p.error.clone()), (3, Some(Error::TooManyItems { count: 4, limit: 3 })));
        assert_eq!(decode_set(Standard::St0102, &[9, 0].repeat(10), 1, &c).items.len(), 10);
    }

    #[test]
    fn matrix_values_share_a_packet_limit_across_nested_sets() {
        let pack = [3, 0x09, 0]; // Three implicit zero coefficients.
        let nested = [102, 3, 3, 0x09, 0];
        let data = st0601_packet(&[(102, &pack), (100, &nested)]);
        for limit in [5, 6, 5] {
            let mut cfg = Config::default();
            cfg.max_total_items = limit;
            let packet = decode(&data, &cfg);
            let coefficients = |value: &Value| {
                value.field("Correlation Coefficient Values").and_then(Value::as_list).map(|list| list.len())
            };
            assert_eq!(coefficients(&packet.items[0].value), Some(3));
            let child = &packet.items[1].value.as_set().unwrap().items[0];
            if limit == 6 {
                assert_eq!(coefficients(&child.value), Some(3));
            } else {
                assert!(matches!(child.value, Value::Invalid(_)));
            }
            assert_eq!(packet.checksum, Checksum::Valid);
            assert_eq!(packet.items.last().unwrap().tag, 1);
        }
    }

    #[test]
    fn keep_raw_off_empties_raw_of_valid_values() {
        // Tag 2 valid, tag 13 wrong length (invalid), tag 48 a nested set.
        let buf = st0601_packet(&[
            (2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]),
            (13, &[1, 2, 3]),
            (48, &[1, 1, 1, 2, 1, 7]),
        ]);
        let full = decode(&buf, &Config::default());
        let mut c = Config::default();
        c.keep_raw = false;
        let lean = decode(&buf, &c);
        assert_eq!(full.items.len(), lean.items.len());
        for (a, b) in full.items.iter().zip(&lean.items) {
            assert_eq!(a.value.as_set().map(|p| p.items.len()), b.value.as_set().map(|p| p.items.len()));
            if a.value.as_set().is_none() {
                assert_eq!(a.value, b.value);
            }
            assert!(!a.raw.is_empty());
            assert_eq!(b.raw.is_empty(), a.value.is_valid(), "tag {}", a.tag);
        }
        let nested = lean.get(48u8).and_then(Value::as_set).unwrap();
        assert!(nested.items.iter().all(|i| i.raw.is_empty() == i.value.is_valid()));
        // Every module builds its items the same way, unknown tags included.
        let rvt = [8u8, 1, 4, 99, 1, 7, 12, 3, 9, 1, 0].to_vec();
        let vmti = [4u8, 1, 6, 2, 3, 0, 0, 0].to_vec();
        let buf = st0601_packet(&[(73, &rvt), (74, &vmti), (0, &[1]), (72, &[1]), (65, &[19])]);
        let lean = decode(&buf, &c);
        let full = decode(&buf, &Config::default());
        fn walk(p: &Packet, f: &mut dyn FnMut(&Item)) {
            for i in &p.items {
                f(i);
                if let Some(s) = i.value.as_set() {
                    walk(s, f);
                }
            }
        }
        let mut n = 0;
        walk(&lean, &mut |i| {
            n += 1;
            assert_eq!(i.raw.is_empty(), i.value.is_valid(), "tag {} {:?}", i.tag, i.value);
        });
        walk(&full, &mut |i| assert!(!i.raw.is_empty(), "tag {}", i.tag));
        assert!(n >= 8, "{n}");
    }

    #[test]
    fn unknown_item_is_raw() {
        let got = unknown_item(9, &[7], 0, &Config::default());
        let want =
            Item { tag: 9, name: "Unknown", units: "", value: Value::Bytes(vec![7]), raw: vec![7] };
        assert_eq!(got, want);
        let mut lean = Config::default();
        lean.keep_raw = false;
        assert!(unknown_item(9, &[7], 0, &lean).raw.is_empty());
    }
}
