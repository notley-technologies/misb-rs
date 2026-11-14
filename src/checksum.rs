//! Packet checksums used by MISB standards.

/// MISB ST 0601 checksum (tag 1, see the tag 1 description in ST 0601): a
/// 16-bit running sum of the packet taken as big-endian 16-bit words.
///
/// `bytes` must run from the first byte of the 16-byte universal key up to
/// and including the checksum item's tag (0x01) and length (0x02) bytes,
/// leaving out the two checksum value bytes. Bytes at even offsets are the
/// high half of a word, bytes at odd offsets the low half; overflow wraps.
///
/// ```
/// // The worked example from the ST 0601 tag 1 description.
/// let sum = misb::checksum::st0601_checksum(&[0x06, 0x0E, 0x2B, 0x34, 0x02, 0x00, 0x81, 0xBB]);
/// assert_eq!(sum, 0xB4FD);
/// ```
#[must_use]
pub fn st0601_checksum(bytes: &[u8]) -> u16 {
    let mut words = bytes.chunks_exact(2);
    let sum = words.by_ref().fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_be_bytes([word[0], word[1]]))
    });
    match words.remainder() {
        [high] => sum.wrapping_add(u16::from(*high) << 8),
        _ => sum,
    }
}

/// The MISB CRC-16-CCITT (Motion Imagery Handbook Appendix D; the packet
/// CRC of ST 1107, ST 1108 and ST 1507, and the CRC MISB documents print
/// next to each universal label): polynomial 0x1021, initial value 0xFFFF
/// followed by 16 augmented zero bits, no reflection, no final XOR. That is
/// the "CRC-16/AUG-CCITT" parameter set, computed here from the equivalent
/// initial value 0x1D0F. Check value for the ASCII string `123456789` is
/// 0xE5CC. Not the ST 0601 checksum (see [`st0601_checksum`]).
///
/// ```
/// // ST 0601.19 section 6.2 prints the UAS Datalink LS key with (CRC 56773).
/// let key = [6, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 1, 1, 0, 0, 0];
/// assert_eq!(misb::checksum::crc16_ccitt(&key), 56773);
/// ```
#[must_use]
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0x1D0F;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// CRC-32/MPEG-2 (polynomial 0x04C11DB7, initial value 0xFFFFFFFF, no
/// reflection, no final XOR), the checksum of MISB ST 0806 tag 1. Check
/// value for `123456789` is 0x0376E6E7.
#[must_use]
pub fn crc32_mpeg2(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= u32::from(b) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ 0x04C1_1DB7 } else { crc << 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn st0601_worked_example() {
        // ST 0601 tag 1 example: 060E 2B34 0200 81BB sums to B4FD.
        assert_eq!(st0601_checksum(&[0x06, 0x0E, 0x2B, 0x34, 0x02, 0x00, 0x81, 0xBB]), 0xB4FD);
    }

    #[test]
    fn st0601_word_alignment_and_wrap() {
        assert_eq!(st0601_checksum(&[]), 0);
        assert_eq!(st0601_checksum(&[0x12]), 0x1200);
        assert_eq!(st0601_checksum(&[0x12, 0x34]), 0x1234);
        assert_eq!(st0601_checksum(&[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
        assert_eq!(st0601_checksum(&[0xFF, 0xFF, 0x00, 0x02]), 0x0001);
    }

    #[test]
    fn crc_check_values() {
        // CRC-16/AUG-CCITT check values.
        assert_eq!(crc16_ccitt(b"123456789"), 0xE5CC);
        assert_eq!(crc16_ccitt(b""), 0x1D0F);
        assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_E6E7);
        assert_eq!(crc32_mpeg2(b""), 0xFFFF_FFFF);
    }

    /// The CRC annotations MISB prints next to each universal label.
    #[test]
    fn crc16_matches_published_label_crcs() {
        let key = |b11: u8, b12: u8, b13: u8| [6, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, b11, b12, b13, 0, 0, 0];
        // ST 0601.19 section 6.2: UAS Datalink LS key (CRC 56773).
        assert_eq!(crc16_ccitt(&key(3, 1, 1)), 56773);
        // ST 0806.4: Remote Video Terminal LS key (CRC 17945).
        assert_eq!(crc16_ccitt(&key(3, 1, 2)), 17945);
        // ST 0903.6: VMTI LS key (CRC 51307).
        assert_eq!(crc16_ccitt(&key(3, 3, 6)), 51307);
    }

    /// Bitwise reference: initial value 0xFFFF, the message, then 16
    /// augmented zero bits (Motion Imagery Handbook Appendix D).
    #[test]
    fn crc16_equals_augmented_form() {
        fn augmented(bytes: &[u8]) -> u16 {
            let mut crc: u16 = 0xFFFF;
            let bits = bytes.iter().flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1)).chain([0; 16]);
            for bit in bits {
                let top = crc & 0x8000 != 0;
                crc = (crc << 1) | u16::from(bit);
                if top {
                    crc ^= 0x1021;
                }
            }
            crc
        }
        for msg in [&b""[..], b"1", b"123456789", &[0xFF; 40], &[0x00, 0x80, 0x7F]] {
            assert_eq!(crc16_ccitt(msg), augmented(msg), "{msg:02X?}");
        }
    }
}
