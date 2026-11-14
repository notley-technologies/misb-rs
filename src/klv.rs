//! KLV glue. SMPTE ST 336 decoding (keys, BER lengths and tags, triplets,
//! local sets) comes from the `smpte-klv` crate; this module holds the
//! options MISB data is decoded with, the conversion of its errors to
//! [`Error`], and the big-endian integer and IEEE 754 helpers the standards
//! modules build on. Internal to the crate.

// Shared helpers: not every one is used by every standards module.
#![allow(dead_code)]

use crate::Error;
use smpte_klv::{DecodeOptions, ErrorKind, LengthEncoding, LocalSet, TagEncoding};

pub(crate) use smpte_klv::{LocalItem, Triplet, UniversalLabel};

/// How MISB KLV is decoded: SMPTE ST 336 framing, with the universal label
/// prefix required, but BER-OID tags padded with leading `0x80` bytes
/// tolerated, as encoders in the field produce them (ISO/IEC 8825-1 8.19.2
/// forbids them).
pub(crate) const OPTIONS: DecodeOptions = DecodeOptions::lenient();

/// Convert a `smpte-klv` error. `origin` is subtracted from the byte counts
/// of a truncation, so that they are measured from the start of the
/// structure that was cut short.
pub(crate) fn error(e: smpte_klv::Error, origin: usize) -> Error {
    match e.kind() {
        // Input cut short, or an item running past the end of the set that
        // holds it: both are a structure cut short.
        ErrorKind::UnexpectedEnd { needed, available } | ErrorKind::Overrun { needed, available } => {
            Error::Truncated { needed: needed.saturating_sub(origin), available: available.saturating_sub(origin) }
        }
        ErrorKind::InvalidKey => Error::NotSt0601,
        ErrorKind::NonMinimalOid | ErrorKind::OidOverflow | ErrorKind::TagNotRepresentable { .. } => {
            Error::BadTag
        }
        // Reserved, indefinite and overflowing lengths; nothing else can come
        // from the triplet and local set decoding used here.
        _ => Error::BadLength,
    }
}

/// Parse the key and length at the start of `buf`, without needing the
/// value.
pub(crate) fn header(buf: &[u8]) -> Result<smpte_klv::Header, Error> {
    smpte_klv::Header::parse_with(buf, &OPTIONS).map_err(|e| error(e, 0))
}

/// Parse one universal-key KLV triplet at the start of `buf`; trailing bytes
/// are ignored.
pub(crate) fn triplet(buf: &[u8]) -> Result<Triplet<'_>, Error> {
    Triplet::parse_with(buf, &OPTIONS).map_err(|e| error(e, 0))
}

/// Iterate over the items of a local set value with BER-OID tags and BER
/// lengths (SMPTE ST 336 section 7.4, MISB ST 0601 section 6.2). The
/// iterator yields one `Err` and then stops if an item is malformed or runs
/// past the end of the set; a truncation is measured from the start of the
/// item.
pub(crate) fn local_set(value: &[u8]) -> LocalItems<'_> {
    LocalItems(LocalSet::new(value, TagEncoding::BerOid, LengthEncoding::Ber).with_options(OPTIONS).iter())
}

/// Iterator returned by [`local_set`].
#[derive(Clone, Debug)]
pub(crate) struct LocalItems<'a>(smpte_klv::LocalItems<'a>);

impl<'a> LocalItems<'a> {
    /// Bytes of the set not yet parsed.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        self.0.remaining()
    }
}

impl<'a> Iterator for LocalItems<'a> {
    type Item = Result<LocalItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.0.offset();
        Some(self.0.next()?.map_err(|e| error(e, start)))
    }
}

/// Big-endian unsigned integer of 1 to 8 bytes; `None` when empty or
/// longer. An empty value is a zero-length item, which MISB ST 0107 reads
/// as "unknown", never as 0.
pub(crate) fn be_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)))
}

/// Big-endian two's complement signed integer of 1 to 8 bytes, sign
/// extended; `None` when empty or longer than 8 bytes.
pub(crate) fn be_int(bytes: &[u8]) -> Option<i64> {
    let v = be_uint(bytes)?;
    let shift = 64 - 8 * bytes.len() as u32;
    // Move the sign bit to bit 63, then arithmetic shift back.
    Some(((v << shift) as i64) >> shift)
}

/// Big-endian IEEE 754 binary32 (4 bytes) or binary64 (8 bytes) as `f64`;
/// `None` for any other length. MISB ST 0601 and ST 0903 use both widths.
pub(crate) fn be_float(bytes: &[u8]) -> Option<f64> {
    match bytes.len() {
        4 => Some(f64::from(f32::from_bits(be_uint(bytes)? as u32))),
        8 => Some(f64::from_bits(be_uint(bytes)?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K0601: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 1, 1, 0, 0, 0];

    #[test]
    fn triplet_parses() {
        let mut buf = K0601.to_vec();
        buf.extend([0x81, 0x03, 1, 2, 3, 0xEE]);
        let t = triplet(&buf).unwrap();
        assert_eq!(t.key(), UniversalLabel::from_bytes(K0601));
        assert_eq!(t.header_len(), 18);
        assert_eq!(t.value(), &[1, 2, 3]);
        assert_eq!(t.encoded_len(), 21);
        assert_eq!(t.as_bytes(), &buf[..21]);
    }

    #[test]
    fn triplet_errors() {
        assert_eq!(triplet(&[0x06, 0x0E, 0x2B, 0x35]), Err(Error::NotSt0601));
        assert_eq!(triplet(&[0x07]), Err(Error::NotSt0601));
        assert_eq!(triplet(&[]), Err(Error::Truncated { needed: 17, available: 0 }));
        assert_eq!(triplet(&K0601[..10]), Err(Error::Truncated { needed: 17, available: 10 }));
        assert_eq!(triplet(&K0601), Err(Error::Truncated { needed: 17, available: 16 }));
        let mut buf = K0601.to_vec();
        buf.extend([0x82, 0x01]);
        assert_eq!(triplet(&buf), Err(Error::Truncated { needed: 19, available: 18 }));
        let mut buf = K0601.to_vec();
        buf.extend([0x05, 1, 2]);
        assert_eq!(triplet(&buf), Err(Error::Truncated { needed: 22, available: 19 }));
        for bad in [0x80, 0xFF] {
            let mut buf = K0601.to_vec();
            buf.push(bad);
            assert_eq!(triplet(&buf), Err(Error::BadLength));
        }
        let mut bad = K0601;
        bad[0] = 0;
        assert_eq!(triplet(&bad), Err(Error::NotSt0601));
    }

    #[test]
    fn header_without_value() {
        let mut buf = K0601.to_vec();
        buf.extend([0x84, 0x7F, 0xFF, 0xFF, 0xFF]);
        let h = header(&buf).unwrap();
        assert_eq!((h.length().definite(), h.header_len()), (Some(0x7FFF_FFFF), 21));
        assert_eq!(header(&K0601[..5]), Err(Error::Truncated { needed: 17, available: 5 }));
        assert_eq!(header(&[0x07]), Err(Error::NotSt0601));
        let mut buf = K0601.to_vec();
        buf.push(0xFF);
        assert_eq!(header(&buf), Err(Error::BadLength));
    }

    #[test]
    fn triplet_long_lengths() {
        // ST 336 allows padded long-form lengths of any size.
        let mut buf = K0601.to_vec();
        buf.push(0x8A);
        buf.extend([0; 9]);
        buf.extend([2, 0xAA, 0xBB]);
        assert_eq!(triplet(&buf).unwrap().value(), &[0xAA, 0xBB]);
        // A length larger than any buffer is an error, not an overflow.
        let mut buf = K0601.to_vec();
        buf.extend([0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(triplet(&buf).is_err());
    }

    #[test]
    fn local_set_items() {
        // Tag 2 (1 byte), tag 129 two-byte OID, long-form length.
        let set = [0x02, 0x01, 0xAA, 0x81, 0x01, 0x81, 0x02, 0xBB, 0xCC];
        let items: Vec<_> = local_set(&set).collect::<Result<_, _>>().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].tag, items[0].value, items[0].offset), (2, &[0xAA][..], 0));
        assert_eq!((items[1].tag, items[1].value, items[1].offset), (129, &[0xBB, 0xCC][..], 3));
        assert_eq!(items[1].raw, &set[3..]);
        assert_eq!(local_set(&[]).count(), 0);
        // Padded BER-OID tags are tolerated.
        let items: Vec<_> = local_set(&[0x80, 0x05, 0x00]).collect::<Result<_, _>>().unwrap();
        assert_eq!(items[0].tag, 5);
    }

    #[test]
    fn local_set_stops_after_error() {
        let set = [0x02, 0x01, 0xAA, 0x03, 0x05, 0x01];
        let mut it = local_set(&set);
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.remaining(), &[0x03, 0x05, 0x01]);
        assert_eq!(it.next(), Some(Err(Error::Truncated { needed: 7, available: 3 })));
        assert_eq!(it.next(), None);

        let mut it = local_set(&[0x02, 0x80]);
        assert_eq!(it.next(), Some(Err(Error::BadLength)));
        assert_eq!(it.next(), None);

        let mut it = local_set(&[0x82]);
        assert_eq!(it.next(), Some(Err(Error::Truncated { needed: 2, available: 1 })));

        let mut it = local_set(&[0x02, 0x82, 0x01]);
        assert_eq!(it.next(), Some(Err(Error::Truncated { needed: 4, available: 3 })));

        let mut it = local_set(&[0xFF; 12]);
        assert_eq!(it.next(), Some(Err(Error::BadTag)));
    }

    #[test]
    fn integers() {
        // An empty value is a zero-length item ("unknown", MISB ST 0107), not 0.
        assert_eq!(be_uint(&[]), None);
        assert_eq!(be_uint(&[0xFF; 8]), Some(u64::MAX));
        assert_eq!(be_uint(&[0; 9]), None);
        assert_eq!(be_uint(&[0x12, 0x34, 0x56]), Some(0x123456));

        assert_eq!(be_int(&[]), None);
        assert_eq!(be_int(&[0; 9]), None);
        assert_eq!(be_int(&[0x7F]), Some(127));
        assert_eq!(be_int(&[0x80]), Some(-128));
        assert_eq!(be_int(&[0xFF, 0xFF, 0xFF]), Some(-1));
        assert_eq!(be_int(&[0x80, 0, 0, 0]), Some(i32::MIN as i64));
        assert_eq!(be_int(&[0x80, 0, 0, 0, 0, 0, 0, 0]), Some(i64::MIN));
        assert_eq!(be_int(&[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), Some(i64::MAX));
    }

    #[test]
    fn floats() {
        assert_eq!(be_float(&[0x3F, 0x80, 0, 0]), Some(1.0));
        assert_eq!(be_float(&[0xC0, 0x00, 0, 0]), Some(-2.0));
        let pi = [0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18];
        assert_eq!(be_float(&pi), Some(std::f64::consts::PI));
        assert_eq!(be_float(&[0x7F, 0x80, 0, 0]), Some(f64::INFINITY));
        assert!(be_float(&[0x7F, 0xC0, 0, 0]).unwrap().is_nan());
        assert_eq!(be_float(&[0; 3]), None);
        assert_eq!(be_float(&[]), None);
    }
}
