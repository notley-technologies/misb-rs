//! MISB ST 0601 UAS Datalink Local Set decoder.
//!
//! The crate decodes the metadata that unmanned aircraft embed in motion
//! imagery: platform position and attitude, sensor pointing, frame corners,
//! time stamps and the rest of the ST 0601 tag table. Values arrive in
//! engineering units ([`Value::Float`] in degrees, metres, ...), and the
//! packet checksum (tag 1) is verified (see [`Checksum`]). It only parses:
//! no encoder, no I/O, no panics on hostile input, and every buffer, loop
//! and nesting level is bounded by [`Config`].
//!
//! # Scope
//!
//! Only ST 0601 packets are decoded at top level; packets with any other
//! universal key are skipped and counted in [`Stats::skipped_keys`]. The
//! sets ST 0601 embeds are decoded where it embeds them: [`st0102`]
//! security metadata (tag 48), [`st0806`] remote video terminal (tag 73),
//! [`st0903`] VMTI (tag 74), [`st1204`] MIIS identifiers (tag 94), MISB ST
//! 1607 Segment and Amend sets (tags 100 and 101, with the ST 0601 table)
//! and [`st1010`] SDCC-FLP packs (tag 102). Values follow MISB ST 1201
//! ([`imapb`]), ST 0603 ([`Value::Time`], which is MISP time, not UTC) and ST
//! 0107 (a zero-length item is [`Value::Unknown`]). The ST 1206, ST 1002, ST
//! 1601 and ST 1602 sets (tags 95, 97, 98, 99) stay [`Value::Bytes`].
//! [`Standard::revision`] and [`imapb::REVISION`] name the revisions the
//! tables follow.
//!
//! The SMPTE ST 336 framing (universal keys, BER lengths, BER-OID tags,
//! local sets and stream resynchronisation) comes from the `smpte-klv`
//! crate; this crate holds what MISB defines.
//!
//! # Features and the C ABI
//!
//! - `capi` (default) exports the C ABI. Disable default features for a
//!   Rust-only library compiled with `#![forbid(unsafe_code)]`.
//! - `serde`: `Serialize` for [`Packet`], [`Item`], [`Value`], [`Field`],
//!   [`Checksum`], [`Standard`], [`Error`], [`Stats`], [`Received`] and
//!   [`Config`], and `Deserialize` for [`Config`]. The JSON format is
//!   described at [`Value`]. Needs Rust 1.71; the library itself needs 1.70.
//!
//! A stable C ABI, built with `make` and installed with `make install`, is
//! described in `include/misb.h`.
//!
//! # Usage
//!
//! Decode one packet from a buffer:
//!
//! ```
//! use misb::st0601;
//!
//! // Build a tiny ST 0601 packet: tag 2 (Precision Time Stamp) and tag 1.
//! let mut pkt = st0601::KEY.to_vec();
//! pkt.push(14);
//! pkt.extend([2, 8, 0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]);
//! pkt.extend([1, 2]);
//! let sum = misb::checksum::st0601_checksum(&pkt);
//! pkt.extend(sum.to_be_bytes());
//!
//! let packet = misb::decode(&pkt).unwrap();
//! assert_eq!(packet.checksum, misb::Checksum::Valid);
//! assert!(packet.is_ok());
//! assert!(packet.get(st0601::Tag::PrecisionTimeStamp).is_some());
//! for item in &packet {
//!     println!("{item}");
//! }
//! ```
//!
//! or push a stream in chunks as it arrives and collect packets as they
//! complete, draining after every push:
//!
//! ```no_run
//! # fn recv() -> Vec<u8> { vec![] }
//! let mut decoder = misb::Decoder::new();
//! loop {
//!     decoder.push(&recv());
//!     for packet in decoder.packets() {
//!         println!("{packet}");
//!     }
//! }
//! ```
//!
//! A whole file already in memory is best decoded lazily with
//! [`decode_iter`], which holds one packet at a time; [`decode_all`] collects
//! them all.
//!
//! Synchronous KLV in MPEG transport streams arrives wrapped in metadata
//! access unit cells; [`au_cells`] unwraps them, and pushing every cell's
//! data in order into one [`Decoder`] joins fragmented access units.

// The README's Rust snippets compile as doctests.
#![cfg_attr(doctest, doc = include_str!("../README.md"))]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "capi"), forbid(unsafe_code))]
#![cfg_attr(feature = "capi", deny(unsafe_code))]

#[cfg(feature = "capi")]
#[doc(hidden)]
pub mod capi;
pub mod checksum;
mod config;
#[cfg(feature = "encode")]
#[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
pub mod encode;
#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub mod json;
mod error;
pub mod imapb;
mod klv;
#[cfg(feature = "mux")]
#[cfg_attr(docsrs, doc(cfg(feature = "mux")))]
pub mod mux;
mod registry;
pub mod st0102;
pub mod st0601;
pub mod st0806;
pub mod st0903;
pub mod st1010;
pub mod st1204;
mod stream;
mod time;
mod value;

pub use config::Config;
/// The transport stream crate the [`mux`] module builds on (feature
/// `mux`), re-exported so users get the same version.
#[cfg(feature = "mux")]
#[cfg_attr(docsrs, doc(cfg(feature = "mux")))]
pub use mpegts;
pub use error::Error;
pub use stream::{au_cells, AuCell, AuCells, Decoder, Received, Stats};
pub use time::{LeapSeconds, LeapSecondsError, MispTime, ParseUtcError, UtcDateTime};
pub use value::{Checksum, Field, Item, Packet, Standard, TagKey, Value};

/// The version of this crate, for audit records. The revisions of the MISB
/// documents its tables follow are given by [`Standard::revision`] and
/// [`imapb::REVISION`].
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Auto traits are part of the public API: fail the build if a change here
// or in a dependency takes one away.
const _: () = {
    use std::panic::{RefUnwindSafe, UnwindSafe};
    const fn send<T: Send>() {}
    const fn data<T: Send + Sync + UnwindSafe + RefUnwindSafe>() {}
    send::<Decoder>();
    send::<DecodeIter<'static>>();
    data::<Packet>();
    data::<Item>();
    data::<Value>();
    data::<Field>();
    data::<Checksum>();
    data::<Standard>();
    data::<Error>();
    data::<Config>();
    data::<Stats>();
    data::<Received>();
    data::<AuCell<'static>>();
    data::<AuCells<'static>>();
    data::<imapb::Imapb>();
};

/// Decode exactly one ST 0601 packet at the start of `buf` with the default
/// [`Config`]; trailing bytes are ignored. See [`decode_with`].
pub fn decode(buf: &[u8]) -> Result<Packet, Error> {
    decode_with(buf, &Config::default())
}

/// Decode exactly one ST 0601 packet at the start of `buf`; trailing bytes
/// are ignored.
///
/// Fails with [`Error::InvalidConfig`] if [`Config::validate`] refuses
/// `cfg` (before `buf` is looked at), [`Error::NotSt0601`] if `buf` does
/// not start with
/// [`st0601::KEY`], [`Error::TooLarge`] if the length field declares a value
/// over [`Config::max_packet_bytes`] (checked before the value is needed, so
/// a caller that reads more input on [`Error::Truncated`] is never asked for
/// more than the limit), [`Error::Truncated`] if the packet is cut short
/// (`needed` is a lower bound while the length field itself is incomplete)
/// and [`Error::BadLength`] for a malformed length. Problems inside the set
/// are reported in [`Packet::error`] and [`Packet::checksum`] instead.
pub fn decode_with(buf: &[u8], cfg: &Config) -> Result<Packet, Error> {
    decode_prefix(buf, cfg).map(|(p, _)| p)
}

/// Like [`decode_with`], with the same errors, also returning the number of
/// bytes the packet occupies (key, length and value), to step through a
/// buffer of packets with an error for each.
///
/// ```
/// # let mut buf = misb::st0601::KEY.to_vec();
/// # buf.extend([4, 1, 2, 0, 0]);
/// let mut rest = &buf[..];
/// while !rest.is_empty() {
///     match misb::decode_prefix(rest, &misb::Config::default()) {
///         Ok((packet, used)) => {
///             println!("{packet}");
///             rest = &rest[used..];
///         }
///         Err(e) => {
///             eprintln!("stopped: {e}");
///             break;
///         }
///     }
/// }
/// ```
pub fn decode_prefix(buf: &[u8], cfg: &Config) -> Result<(Packet, usize), Error> {
    cfg.validate()?;
    // Check the key before the length so another standard's packet is
    // reported as such even when it is cut short.
    let n = buf.len().min(16);
    let mut key = st0601::KEY;
    key[..n].copy_from_slice(&buf[..n]);
    if !registry::is_st0601_key(&klv::UniversalLabel::from_bytes(key)) {
        return Err(Error::NotSt0601);
    }
    // Then the declared length, before the value is needed.
    if let Some(len) = klv::header(buf)?.length().definite() {
        if len > cfg.max_packet_bytes as u64 {
            let size = usize::try_from(len).unwrap_or(usize::MAX);
            return Err(Error::TooLarge { size, limit: cfg.max_packet_bytes });
        }
    }
    let t = klv::triplet(buf)?;
    Ok((registry::decode_st0601(&t, cfg), t.encoded_len()))
}

/// Decode every ST 0601 packet in a complete buffer (for example a whole
/// `.klv` file) with the default [`Config`], skipping damaged bytes and other
/// keys like [`Decoder`]. See [`decode_all_with`].
#[must_use]
pub fn decode_all(buf: &[u8]) -> Vec<Packet> {
    collect_all(buf, Decoder::for_buffer(Config::default())).0
}

/// Decode every ST 0601 packet in a complete buffer like a [`Decoder`] with
/// this configuration, returning the packets and the decoder's [`Stats`]
/// (packets skipped as oversized, damaged or with other keys are counted
/// there). No packet is dropped to [`Config::max_buffer_bytes`]. Fails only
/// with [`Error::InvalidConfig`], for a config [`Config::validate`]
/// refuses.
///
/// Every decoded packet is held at once. The memory required depends on
/// its item values, nesting and [`Config::keep_raw`]. For large
/// files use [`decode_iter`], which holds one packet at a time.
///
/// ```
/// # let file: Vec<u8> = Vec::new();
/// let mut config = misb::Config::default();
/// config.keep_raw = false;
/// let (packets, stats) = misb::decode_all_with(&file, &config)?;
/// println!("{} packets, {} bytes skipped", packets.len(), stats.bytes_skipped);
/// # Ok::<(), misb::Error>(())
/// ```
pub fn decode_all_with(buf: &[u8], cfg: &Config) -> Result<(Vec<Packet>, Stats), Error> {
    cfg.validate()?;
    Ok(collect_all(buf, Decoder::for_buffer(cfg.clone())))
}

/// Every packet of `buf` through `d`, with its counters.
fn collect_all(buf: &[u8], mut d: Decoder) -> (Vec<Packet>, Stats) {
    let mut out = Vec::new();
    d.push_with(buf, |p| out.push(p));
    d.finish();
    out.extend(d.packets());
    (out, d.stats().clone())
}

/// Iterate over the ST 0601 packets of a complete buffer, decoding each only
/// when it is asked for, with the default [`Config`]. Gives the same packets
/// as [`decode_all`] with memory bounded however large the buffer is.
///
/// ```
/// # let file: Vec<u8> = Vec::new();
/// let mut packets = misb::decode_iter(&file);
/// for packet in &mut packets {
///     println!("{packet}");
/// }
/// println!("{} bytes skipped", packets.stats().bytes_skipped);
/// ```
pub fn decode_iter(buf: &[u8]) -> DecodeIter<'_> {
    DecodeIter::new(buf, Decoder::for_buffer(Config::default()))
}

/// [`decode_iter`] with this configuration; fails only with
/// [`Error::InvalidConfig`], for a config [`Config::validate`] refuses.
pub fn decode_iter_with<'a>(buf: &'a [u8], cfg: &Config) -> Result<DecodeIter<'a>, Error> {
    cfg.validate()?;
    Ok(DecodeIter::new(buf, Decoder::for_buffer(cfg.clone())))
}

/// Iterator returned by [`decode_iter`].
#[derive(Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct DecodeIter<'a> {
    rest: &'a [u8],
    decoder: Decoder,
    step: usize,
    finished: bool,
}

impl<'a> DecodeIter<'a> {
    fn new(buf: &'a [u8], decoder: Decoder) -> Self {
        let step = decoder.feed_step();
        DecodeIter { rest: buf, decoder, step, finished: false }
    }

    /// The decoder's counters so far.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        self.decoder.stats()
    }
}

impl Iterator for DecodeIter<'_> {
    type Item = Packet;

    fn next(&mut self) -> Option<Packet> {
        loop {
            if let Some(p) = self.decoder.next_packet() {
                return Some(p);
            }
            if !self.rest.is_empty() {
                // Only when the queue is empty, and in slices that cannot
                // overfill it.
                let n = self.step.min(self.rest.len());
                self.decoder.push(&self.rest[..n]);
                self.rest = &self.rest[n..];
            } else if !self.finished {
                self.decoder.finish();
                self.finished = true;
            } else {
                return None;
            }
        }
    }
}

impl std::iter::FusedIterator for DecodeIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut out = st0601::KEY.to_vec();
        out.push((payload.len() + 6) as u8);
        out.extend([3, payload.len() as u8]);
        out.extend_from_slice(payload);
        out.extend([1, 2]);
        let sum = checksum::st0601_checksum(&out);
        out.extend(sum.to_be_bytes());
        out
    }

    #[test]
    fn decode_one() {
        let mut buf = packet(b"abc");
        buf.extend([0xFF; 3]); // trailing bytes ignored
        let p = decode(&buf).unwrap();
        assert_eq!(p.standard, Standard::St0601);
        assert_eq!(p.checksum, Checksum::Valid);
        assert_eq!(p.items.len(), 2);
        assert!(p.is_ok());
    }

    #[test]
    fn decode_errors() {
        assert_eq!(decode(&[]), Err(Error::Truncated { needed: 17, available: 0 }));
        assert_eq!(decode(&[0x00]), Err(Error::NotSt0601));
        let buf = packet(b"abc");
        assert_eq!(
            decode(&buf[..buf.len() - 1]),
            Err(Error::Truncated { needed: buf.len(), available: buf.len() - 1 })
        );
        let mut other = buf.clone();
        other[12] = 0x03; // ST 0102 standalone key: not decoded
        assert_eq!(decode(&other), Err(Error::NotSt0601));
        assert_eq!(decode(&other[..14]), Err(Error::NotSt0601));
        let mut version = buf.clone();
        version[7] = 0x0A;
        assert!(decode(&version).is_ok());
        let mut huge = st0601::KEY.to_vec();
        huge.extend([0x83, 0x20, 0x00, 0x00]);
        huge.resize(huge.len() + 0x200000, 0);
        assert_eq!(decode(&huge), Err(Error::TooLarge { size: 0x200000, limit: 1 << 20 }));
    }

    #[test]
    fn declared_length_over_the_limit_is_too_large_even_when_cut_short() {
        // A caller that reads `needed` bytes and retries must not be asked
        // for gigabytes.
        let mut buf = st0601::KEY.to_vec();
        buf.extend([0x84, 0x7F, 0xFF, 0xFF, 0xFF]);
        buf.extend([0; 10]);
        assert_eq!(decode(&buf), Err(Error::TooLarge { size: 0x7FFF_FFFF, limit: 1 << 20 }));
        let mut buf = st0601::KEY.to_vec();
        buf.extend([0x88, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(decode(&buf), Err(Error::TooLarge { .. })));
        let mut huge = st0601::KEY.to_vec();
        huge.extend([0x83, 0x20, 0x00, 0x00]);
        huge.resize(30, 0);
        assert_eq!(decode(&huge), Err(Error::TooLarge { size: 0x200000, limit: 1 << 20 }));
        assert_eq!(decode(&[]), Err(Error::Truncated { needed: 17, available: 0 }));
    }

    #[test]
    fn decode_with_a_config_and_step_through_a_buffer() {
        let mut big = st0601::KEY.to_vec();
        big.extend([0x83, 0x20, 0x00, 0x09]);
        big.extend([3, 0x83, 0x20, 0x00, 0x00]);
        big.resize(big.len() + 0x20_0000, b'x');
        big.extend([1, 2]);
        let sum = checksum::st0601_checksum(&big);
        big.extend(sum.to_be_bytes());
        assert!(matches!(decode(&big), Err(Error::TooLarge { .. })));
        let mut cfg = Config::default();
        cfg.max_packet_bytes = 4 << 20;
        let p = decode_with(&big, &cfg).unwrap();
        assert_eq!((p.checksum, p.items.len()), (Checksum::Valid, 2));

        let one = packet(b"abc");
        let buf = one.repeat(3);
        let mut rest = &buf[..];
        let mut n = 0;
        while !rest.is_empty() {
            let (p, used) = decode_prefix(rest, &Config::default()).unwrap();
            assert_eq!(used, one.len());
            assert!(p.is_ok());
            rest = &rest[used..];
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[test]
    fn decode_all_with_never_drops_to_the_queue_limit() {
        let one = packet(&[7; 20]);
        let buf = one.repeat(20_000);
        for (queue, max) in [(200, 1000), (1, 1000), (1000, 1000), (5000, 1000), (4 << 20, 1 << 20)] {
            let mut cfg = Config::default();
            cfg.max_buffer_bytes = queue;
            cfg.max_packet_bytes = max;
            let (all, stats) = decode_all_with(&buf, &cfg).unwrap();
            assert_eq!((all.len(), stats.dropped), (20_000, 0), "queue {queue}, max {max}");
            assert_eq!(decode_iter_with(&buf, &cfg).unwrap().count(), 20_000);
        }
    }

    #[test]
    fn decode_iter_matches_decode_all() {
        let mut s = vec![0x00, 0x06, 0x0E];
        for i in 0..200u8 {
            s.extend(packet(&[i; 9]));
            if i % 7 == 0 {
                s.extend([0x06, 0x0E, 0x2B, 0x34, 0x99]);
            }
        }
        let cut = packet(b"cut short");
        s.extend(&cut[..cut.len() - 2]);
        let all = decode_all(&s);
        assert_eq!(all.len(), 200);
        let mut it = decode_iter(&s);
        assert!(it.by_ref().eq(all.into_iter()));
        assert_eq!(it.next(), None);
        assert_eq!(it.stats().truncated_at_finish, 1);
        assert_eq!(it.stats().packets, 200);
    }

    #[test]
    fn every_entry_point_validates_its_config() {
        let buf = packet(b"abc");
        let mut bad = Config::default();
        bad.max_items = 0;
        let refused = Some(Error::InvalidConfig("max_items is 0"));
        assert_eq!(decode_with(&buf, &bad).err(), refused);
        assert_eq!(decode_prefix(&buf, &bad).err(), refused);
        // The config is checked before the bytes.
        assert_eq!(decode_with(&[], &bad).err(), refused);
        assert_eq!(decode_all_with(&buf, &bad).err(), refused);
        assert_eq!(decode_iter_with(&buf, &bad).err(), refused);
        assert_eq!(Decoder::with_config(bad).err(), refused);
        // The defaults are valid, so the default entry points cannot fail
        // on the config.
        assert_eq!(Config::default().validate(), Ok(()));
        assert!(decode(&buf).is_ok());
        assert_eq!(decode_all(&buf).len(), 1);
        assert_eq!(decode_iter(&buf).count(), 1);
    }

    #[test]
    fn version_and_revisions() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(Standard::St0601.revision(), "ST 0601.19");
        assert_eq!(imapb::REVISION, "ST 1201.5");
    }

    #[test]
    fn decode_all_large_buffer() {
        let one = packet(&[7; 100]);
        let buf = one.repeat(50_000); // about 6 MB, larger than the queue limit
        let all = decode_all(&buf);
        assert_eq!(all.len(), 50_000);
        assert!(all.iter().all(|p| p.checksum == Checksum::Valid));
        assert!(decode_all(&[]).is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes() {
        let p = decode(&packet(b"ab")).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.starts_with(r#"{"standard":"st0601","items":[{"tag":3"#), "{json}");
        assert!(json.ends_with(r#""checksum":{"type":"valid"},"error":null}"#), "{json}");
        let stats = serde_json::to_value(Decoder::new().stats()).unwrap();
        assert_eq!(stats["skipped_keys"], 0);
        let mut d = Decoder::new();
        d.push(&packet(b"a"));
        let r = serde_json::to_value(d.next_received().unwrap()).unwrap();
        assert!(r["bytes"].as_str().unwrap().starts_with("060e2b34020b01010e01030101000000"));
        assert_eq!(r["offset"], 0);
    }

    /// The JSON wire format, byte for byte: every kind of value, a nested
    /// set that stopped with an error, a checksum mismatch and an error.
    #[cfg(feature = "serde")]
    #[test]
    fn json_golden() {
        let mut nested = Packet::new(Standard::St0102);
        let class = Value::Enum { code: 1, label: Some("UNCLASSIFIED//") };
        nested.items.push(Item::new(1, "Security Classification", "", class, vec![1]));
        nested.error = Some(Error::Truncated { needed: 5, available: 2 });
        let mut p = Packet::new(Standard::St0601);
        p.checksum = Checksum::Mismatch { expected: 0x1234, computed: 0xABCD };
        p.error = Some(Error::TooManyItems { count: 3, limit: 2 });
        let time = vec![0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8];
        let floats = vec![Value::Float(f64::NAN), Value::Float(f64::INFINITY), Value::Float(f64::NEG_INFINITY)];
        let rate = vec![Field::new("Numerator", Value::Uint(60_000)), Field::new("Denominator", Value::Uint(1001))];
        p.items = vec![
            Item::new(2, "Precision Time Stamp", "us", Value::Time(1_224_807_209_913_000), time),
            Item::new(3, "Mission ID", "", Value::Text("MISSION01".into()), b"MISSION01".to_vec()),
            Item::new(5, "Platform Heading Angle", "deg", Value::Float(159.974365), vec![0x71, 0xC2]),
            Item::new(39, "Outside Air Temperature", "C", Value::Int(-5), vec![0xFB]),
            Item::new(8, "Platform True Airspeed", "m/s", Value::Uint(147), vec![0x93]),
            Item::new(66, "Deprecated", "", Value::Bytes(vec![0xAB, 0x01]), vec![0xAB, 0x01]),
            Item::new(34, "Icing Detected", "", Value::Enum { code: 7, label: None }, vec![7]),
            Item::new(6, "Platform Pitch Angle", "deg", Value::OutOfRange, vec![0x80, 0x00]),
            Item::new(13, "Sensor Latitude", "deg", Value::Unknown, vec![]),
            Item::new(48, "Security Local Set", "", Value::Set(Box::new(nested)), vec![1, 1, 1, 4, 9]),
            Item::new(117, "Sensor Azimuth Rate", "deg/s", Value::List(floats), vec![]),
            Item::new(127, "Sensor Frame Rate Pack", "Hz", Value::Struct(rate), vec![]),
            Item::new(1, "Checksum", "", Value::Invalid("wrong length for this tag"), vec![0x12]),
        ];
        let want = concat!(
            r#"{"standard":"st0601","items":["#,
            r#"{"tag":2,"name":"Precision Time Stamp","units":"us","value":{"type":"time","value":1224807209913000},"raw":"000459f4a6aa4aa8"},"#,
            r#"{"tag":3,"name":"Mission ID","units":"","value":{"type":"text","value":"MISSION01"},"raw":"4d495353494f4e3031"},"#,
            r#"{"tag":5,"name":"Platform Heading Angle","units":"deg","value":{"type":"float","value":159.974365},"raw":"71c2"},"#,
            r#"{"tag":39,"name":"Outside Air Temperature","units":"C","value":{"type":"int","value":-5},"raw":"fb"},"#,
            r#"{"tag":8,"name":"Platform True Airspeed","units":"m/s","value":{"type":"uint","value":147},"raw":"93"},"#,
            r#"{"tag":66,"name":"Deprecated","units":"","value":{"type":"bytes","value":"ab01"},"raw":"ab01"},"#,
            r#"{"tag":34,"name":"Icing Detected","units":"","value":{"type":"enum","value":{"code":7,"label":null}},"raw":"07"},"#,
            r#"{"tag":6,"name":"Platform Pitch Angle","units":"deg","value":{"type":"out_of_range"},"raw":"8000"},"#,
            r#"{"tag":13,"name":"Sensor Latitude","units":"deg","value":{"type":"unknown"}},"#,
            r#"{"tag":48,"name":"Security Local Set","units":"","value":{"type":"set","value":{"standard":"st0102","items":["#,
            r#"{"tag":1,"name":"Security Classification","units":"","value":{"type":"enum","value":{"code":1,"label":"UNCLASSIFIED//"}},"raw":"01"}],"#,
            r#""checksum":{"type":"not_applicable"},"#,
            r#""error":{"kind":"truncated","message":"truncated: needed 5 bytes, 2 available"}}},"raw":"0101010409"},"#,
            r#"{"tag":117,"name":"Sensor Azimuth Rate","units":"deg/s","value":{"type":"list","value":["#,
            r#"{"type":"float","value":"NaN"},{"type":"float","value":"Infinity"},{"type":"float","value":"-Infinity"}]}},"#,
            r#"{"tag":127,"name":"Sensor Frame Rate Pack","units":"Hz","value":{"type":"struct","value":["#,
            r#"{"name":"Numerator","value":{"type":"uint","value":60000}},{"name":"Denominator","value":{"type":"uint","value":1001}}]}},"#,
            r#"{"tag":1,"name":"Checksum","units":"","value":{"type":"invalid","value":"wrong length for this tag"},"raw":"12"}],"#,
            r#""checksum":{"type":"mismatch","value":{"expected":4660,"computed":43981}},"#,
            r#""error":{"kind":"too_many_items","message":"too many items: 3 exceed the limit of 2"}}"#,
        );
        assert_eq!(serde_json::to_string(&p).unwrap(), want);
        // The other outcomes of a checksum check.
        let json = |c: Checksum| serde_json::to_string(&c).unwrap();
        assert_eq!(json(Checksum::Valid), r#"{"type":"valid"}"#);
        assert_eq!(json(Checksum::Missing), r#"{"type":"missing"}"#);
        // A config round-trips, and missing fields take their defaults.
        let c: Config = serde_json::from_str(r#"{"keep_raw":false}"#).unwrap();
        assert!(!c.keep_raw && c.max_items == Config::default().max_items);
    }
}
