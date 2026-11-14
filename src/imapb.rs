//! MISB ST 1201 floating point to integer mapping ("IMAPB" form).
//!
//! ST 1201 maps a real range `[min, max]` onto an unsigned integer of `len`
//! bytes with a power-of-two scale, so a decoder can reverse it exactly.
//! Encoded values with the most significant bit set are not numbers in the
//! range but special values: infinities, NaNs and out-of-range flags (ST
//! 1201.5 section 7.2.3, Tables 1 to 3). The one exception is `0x80 00 ..
//! 00`, which is the number `max` when `max - min` is an exact power of two.
//!
//! The tables follow ST 1201.5.

use crate::Value;

/// The revision of MISB ST 1201 this module implements.
pub const REVISION: &str = "ST 1201.5";

/// Parameters of one ST 1201 IMAPB mapping: range and field length.
///
/// ```
/// use misb::imapb::Imapb;
/// // ST 0601 tag 103 Density Altitude Extended: IMAPB(-900, 40000, 3).
/// let map = Imapb::new(-900.0, 40_000.0, 3).unwrap();
/// let metres = map.decode(&[0x2F, 0x92, 0x1E]).as_f64().unwrap();
/// assert!((metres - 23_456.24).abs() < 0.01);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Imapb {
    min: f64,
    max: f64,
    len: usize,
    /// sF = 2^(dPow - bPow): forward scale (ST 1201.5 section 7.1.1).
    forward: f64,
    /// sR = 2^(bPow - dPow): reverse scale.
    reverse: f64,
    /// Offset that puts zero exactly on an integer when the range spans it.
    z_offset: f64,
    /// The integer zero maps to, `-floor(sF * min)`, when the range spans
    /// zero.
    y_zero: Option<u64>,
    /// The largest integer the forward mapping produces: the one `max` maps
    /// to, `floor(sF * (max - min) + zOffset)`, computed exactly as
    /// [`Imapb::real_to_int`] computes it so that encoder and decoder agree.
    y_max: u64,
}

/// Smallest integer `p` with `2^p >= v`, for finite `v > 0`, exactly from
/// the bits of `v`: `f64::log2` rounds spans a few ulps above a power of
/// two down to that power, and its result is not specified across
/// platforms.
fn ceil_log2(v: f64) -> i32 {
    let bits = v.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if exp == 0 {
        // Subnormal: v = frac * 2^-1074.
        let floor = 63 - frac.leading_zeros() as i32;
        -1074 + floor + i32::from(!frac.is_power_of_two())
    } else {
        exp - 1023 + i32::from(frac != 0)
    }
}

/// `2^e` as a normal `f64`, built from its bits so it is exact on every
/// platform; `None` outside the normal exponent range.
fn pow2(e: i32) -> Option<f64> {
    (-1022..=1023).contains(&e).then(|| f64::from_bits(((e + 1023) as u64) << 52))
}

/// An ST 1201 special value (ST 1201.5 section 7.2.3): the encoded field has
/// its most significant bit set and is not the in-range value `0x80 00 ..
/// 00`.
///
/// The three bits after the leading `1` select the kind; the remaining bits
/// carry an identifier for NaN, MISB-defined, user-defined and reserved
/// kinds. Patterns ST 1201.5 leaves undefined (an infinity or range flag
/// whose other bits are not zero) are classified as reserved or
/// MISB-defined, which [`Imapb::decode`] reports as invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Special {
    /// `11001` then zero bits: positive infinity (Table 2).
    PositiveInfinity,
    /// `11101` then zero bits: negative infinity (Table 2).
    NegativeInfinity,
    /// `11010...`: positive quiet NaN with identifier.
    PositiveQuietNan(u64),
    /// `11110...`: negative quiet NaN with identifier.
    NegativeQuietNan(u64),
    /// `11011...`: positive signalling NaN with identifier.
    PositiveSignalingNan(u64),
    /// `11111...`: negative signalling NaN with identifier.
    NegativeSignalingNan(u64),
    /// First byte `0xE0` and all other bytes zero: the measured value was
    /// below the range minimum (Table 3).
    BelowMinimum,
    /// First byte `0xE1` and all other bytes zero: the measured value was
    /// above the range maximum (Table 3).
    AboveMaximum,
    /// `11100...` other than the two range flags: other MISB-defined value
    /// with identifier.
    MisbDefined(u64),
    /// `11000...`: user-defined value with identifier.
    UserDefined(u64),
    /// `10...` other than `0x80 00 .. 00`, or an infinity pattern whose
    /// other bits are not zero (undefined in Table 2): reserved, with the
    /// bits after the kind as identifier.
    Reserved(u64),
}

impl Imapb {
    /// A mapping of `[min, max]` onto `len` bytes. `None` unless `len` is
    /// 1 to 8, `min < max` are finite, `max - min` is finite, and the ST 1201
    /// scale factors `sF` and `sR` are representable as normal `f64`.
    #[must_use]
    pub fn new(min: f64, max: f64, len: usize) -> Option<Imapb> {
        if !(1..=8).contains(&len) || !min.is_finite() || !max.is_finite() || min >= max {
            return None;
        }
        let span = max - min;
        if !span.is_finite() {
            return None;
        }
        // ST 1201.5 section 7.1.1: bPow = ceil(log2(b - a)), dPow = 8L - 1.
        let b_pow = ceil_log2(span);
        let d_pow = 8 * len as i32 - 1;
        let forward = pow2(d_pow - b_pow)?;
        let reverse = pow2(b_pow - d_pow)?;
        let spans_zero = min < 0.0 && max > 0.0;
        // sF is a power of two, so sF * min and its floor are exact.
        let z_offset = if spans_zero { forward * min - (forward * min).floor() } else { 0.0 };
        if !z_offset.is_finite() {
            return None;
        }
        // |sF * min| < sF * (max - min) <= 2^dPow <= 2^63, so this fits.
        let y_zero = spans_zero.then(|| (-(forward * min).floor()) as u64);
        // ST 1201.5 7.2.1 step 4a truncates, so no x <= max maps above this.
        // It is at most 2^dPow, the 0x80 00 .. 00 pattern, which only a
        // power-of-two span reaches.
        let top = 1u64 << d_pow;
        let y_max = ((forward * span + z_offset).floor() as u64).min(top);
        Some(Imapb { min, max, len, forward, reverse, z_offset, y_zero, y_max })
    }

    /// Range minimum.
    #[must_use]
    pub fn min(&self) -> f64 {
        self.min
    }

    /// Range maximum.
    #[must_use]
    pub fn max(&self) -> f64 {
        self.max
    }

    /// Field length in bytes, 1 to 8.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.len
    }

    /// Reverse mapping of an encoded integer (ST 1201.5 section 7.2.2):
    /// `x = sR * (y - zOffset) + min`. Does not check for special values or
    /// the range maximum; [`Imapb::decode`] does.
    ///
    /// When the range spans zero this is computed as `sR * (y - y0)` with
    /// `y0 = -floor(sF * min)`, which is algebraically identical (`zOffset =
    /// sF * min - floor(sF * min)`) and exact, so zero decodes to exactly
    /// 0.0 (ST 1201.5 section 7.1.2 step 6).
    ///
    /// ```
    /// let map = misb::imapb::Imapb::new(0.0, 360.0, 2).unwrap();
    /// assert_eq!(map.int_to_real(0x5A00), 360.0);
    /// ```
    #[must_use]
    pub fn int_to_real(&self, y: u64) -> f64 {
        match self.y_zero {
            // An integer difference, rounded once, times a power of two.
            Some(y0) => self.reverse * ((i128::from(y) - i128::from(y0)) as f64),
            None => self.reverse * (y as f64 - self.z_offset) + self.min,
        }
    }

    /// Forward mapping (ST 1201.5 section 7.2.1): `y = floor(sF * (x - min)
    /// + zOffset)`. `None` when `x` is outside `[min, max]` or not finite.
    /// Useful for building test data; the crate itself only decodes.
    ///
    /// ```
    /// let map = misb::imapb::Imapb::new(0.0, 360.0, 2).unwrap();
    /// assert_eq!(map.real_to_int(360.0), Some(0x5A00));
    /// assert_eq!(map.real_to_int(360.5), None);
    /// ```
    #[must_use]
    pub fn real_to_int(&self, x: f64) -> Option<u64> {
        if !(self.min..=self.max).contains(&x) {
            return None;
        }
        let y = (self.forward * (x - self.min) + self.z_offset).floor();
        let limit = 2f64.powi(8 * self.len as i32);
        if y < 0.0 || y >= limit {
            return None;
        }
        Some(y as u64)
    }

    /// Decode an encoded field: [`Value::Float`] for in-range values and
    /// infinities, `Float(NaN)` for NaNs, [`Value::OutOfRange`] for the
    /// below-minimum and above-maximum flags, and [`Value::Invalid`] for a
    /// wrong length, for a normal-pattern integer above the one `max` maps
    /// to (no conforming encoder produces one: ST 1201.5 7.2.1, 7.2.3
    /// Table 1), and for MISB-defined, user-defined, reserved and undefined
    /// special values.
    ///
    /// The low side is not range checked: when the range spans zero, `y = 0`
    /// legitimately decodes to a little below `min`.
    #[must_use]
    pub fn decode(&self, bytes: &[u8]) -> Value {
        if bytes.len() != self.len {
            return Value::Invalid("IMAPB field length does not match");
        }
        match special(bytes) {
            None => match crate::klv::be_uint(bytes) {
                Some(y) if y > self.y_max => Value::Invalid("IMAPB value above range maximum"),
                Some(y) => Value::Float(self.int_to_real(y)),
                None => Value::Invalid("IMAPB field longer than 8 bytes"),
            },
            Some(Special::PositiveInfinity) => Value::Float(f64::INFINITY),
            Some(Special::NegativeInfinity) => Value::Float(f64::NEG_INFINITY),
            Some(
                Special::PositiveQuietNan(_)
                | Special::NegativeQuietNan(_)
                | Special::PositiveSignalingNan(_)
                | Special::NegativeSignalingNan(_),
            ) => Value::Float(f64::NAN),
            Some(Special::BelowMinimum | Special::AboveMaximum) => Value::OutOfRange,
            Some(Special::MisbDefined(_)) => Value::Invalid("IMAPB MISB-defined special value"),
            Some(Special::UserDefined(_)) => Value::Invalid("IMAPB user-defined special value"),
            Some(Special::Reserved(_)) => Value::Invalid("IMAPB reserved special value"),
        }
    }
}

/// Decode an IMAPB field whose length is `bytes.len()` (1 to 8). See
/// [`Imapb::decode`]; a bad range or length gives [`Value::Invalid`].
///
/// ```
/// let v = misb::imapb::decode(0.0, 10.0, &[0x30]);
/// assert_eq!(v, misb::Value::Float(6.0));
/// ```
#[must_use]
pub fn decode(min: f64, max: f64, bytes: &[u8]) -> Value {
    match Imapb::new(min, max, bytes.len()) {
        Some(m) => m.decode(bytes),
        None => Value::Invalid("IMAPB range or length out of bounds"),
    }
}

/// Classify an encoded field: `None` for a normal mapped value, otherwise
/// the special value it encodes (ST 1201.5 section 7.2.3, Tables 2 and 3).
/// Empty input is `None`.
///
/// `0x80 00 .. 00` is classified as normal; whether it is a number depends
/// on the range (see [`Imapb::decode`]).
#[must_use]
pub fn special(bytes: &[u8]) -> Option<Special> {
    let (&first, rest) = bytes.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let rest_zero = rest.iter().all(|&b| b == 0);
    // 0x80 followed by zeros is y = 2^dPow, which the forward mapping
    // produces for x = max when (max - min) is an exact power of two.
    if first == 0x80 && rest_zero {
        return None;
    }
    let ident = |mask: u8| {
        rest.iter().take(7).fold(u64::from(first & mask), |v, &b| (v << 8) | u64::from(b))
    };
    if first & 0xC0 == 0x80 {
        return Some(Special::Reserved(ident(0x7F)));
    }
    // Table 3: the range flags are 0xE0 and 0xE1 followed by zero bits; any
    // other bits make it another (undefined) MISB-defined pattern.
    if first == 0xE0 && rest_zero {
        return Some(Special::BelowMinimum);
    }
    if first == 0xE1 && rest_zero {
        return Some(Special::AboveMaximum);
    }
    let id = ident(0x07);
    Some(match first & 0xF8 {
        // Table 2: infinities have their other bits zero filled.
        0xC8 if id == 0 => Special::PositiveInfinity,
        0xE8 if id == 0 => Special::NegativeInfinity,
        0xC8 | 0xE8 => Special::Reserved(id),
        0xD0 => Special::PositiveQuietNan(id),
        0xF0 => Special::NegativeQuietNan(id),
        0xD8 => Special::PositiveSignalingNan(id),
        0xF8 => Special::NegativeSignalingNan(id),
        0xC0 => Special::UserDefined(id),
        _ => Special::MisbDefined(id), // 0xE0 family other than the range flags
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(v: Value) -> f64 {
        v.as_f64().unwrap()
    }

    #[test]
    fn rejects_bad_parameters() {
        assert!(Imapb::new(0.0, 1.0, 0).is_none());
        assert!(Imapb::new(0.0, 1.0, 9).is_none());
        assert!(Imapb::new(1.0, 1.0, 2).is_none());
        assert!(Imapb::new(2.0, 1.0, 2).is_none());
        assert!(Imapb::new(f64::NAN, 1.0, 2).is_none());
        assert!(Imapb::new(0.0, f64::INFINITY, 2).is_none());
        let bad = Value::Invalid("IMAPB range or length out of bounds");
        assert_eq!(decode(0.0, 1.0, &[]), bad);
        assert_eq!(decode(0.0, 1.0, &[0; 9]), bad);
        let m = Imapb::new(0.0, 1.0, 2).unwrap();
        assert_eq!(m.decode(&[0]), Value::Invalid("IMAPB field length does not match"));
        assert_eq!((m.min(), m.max(), m.byte_len()), (0.0, 1.0, 2));
    }

    #[test]
    fn st0601_density_altitude_extended_example() {
        // ST 0601 tag 103 example: 23456.24 m encodes as 2F 92 1E.
        let m = Imapb::new(-900.0, 40_000.0, 3).unwrap();
        assert!((f(m.decode(&[0x2F, 0x92, 0x1E])) - 23_456.24).abs() < 0.01);
        assert_eq!(m.real_to_int(23_456.24), Some(0x2F921E));
    }

    #[test]
    fn small_and_wide_fields() {
        assert_eq!(decode(0.0, 10.0, &[0x30]), Value::Float(6.0));
        let pi = [0x00, 0x00, 0x00, 0x06, 0x48, 0x7E, 0x7C, 0x06];
        assert!((f(decode(0.0, 1e9, &pi)) - 3.14159).abs() < 1e-8);
    }

    #[test]
    fn zero_lands_exactly_when_range_spans_it() {
        for len in 1..=8 {
            let m = Imapb::new(-900.0, 19_000.0, len).unwrap();
            let y = m.real_to_int(0.0).unwrap();
            assert_eq!(m.int_to_real(y), 0.0, "len {len}");
        }
    }

    #[test]
    fn round_trip_within_resolution() {
        let m = Imapb::new(-180.0, 180.0, 4).unwrap();
        for x in [-180.0, -90.5, -1e-6, 0.0, 12.345678, 179.9999] {
            let y = m.real_to_int(x).unwrap();
            let back = m.int_to_real(y);
            assert!((back - x).abs() <= m.reverse, "{x} -> {back}");
            assert_eq!(f(m.decode(&(y as u32).to_be_bytes())), back);
        }
        assert_eq!(m.real_to_int(180.1), None);
        assert_eq!(m.real_to_int(f64::NAN), None);
    }

    #[test]
    fn max_of_power_of_two_range_uses_top_bit() {
        // Range of exactly 2^8: x = max maps to 0x8000, which is a number.
        let m = Imapb::new(0.0, 256.0, 2).unwrap();
        assert_eq!(m.real_to_int(256.0), Some(0x8000));
        assert_eq!(m.decode(&[0x80, 0x00]), Value::Float(256.0));
        assert_eq!(special(&[0x80, 0x00]), None);
    }

    #[test]
    fn special_values() {
        let m = Imapb::new(0.0, 100.0, 2).unwrap();
        assert_eq!(m.decode(&[0xC8, 0x00]), Value::Float(f64::INFINITY));
        assert_eq!(m.decode(&[0xE8, 0x00]), Value::Float(f64::NEG_INFINITY));
        assert!(f(m.decode(&[0xD0, 0x00])).is_nan());
        assert!(f(m.decode(&[0xF0, 0x01])).is_nan());
        assert!(f(m.decode(&[0xD8, 0x00])).is_nan());
        assert!(f(m.decode(&[0xF8, 0x00])).is_nan());
        assert_eq!(m.decode(&[0xE0, 0x00]), Value::OutOfRange);
        assert_eq!(m.decode(&[0xE1, 0x00]), Value::OutOfRange);
        assert!(matches!(m.decode(&[0xE2, 0x00]), Value::Invalid(_)));
        assert!(matches!(m.decode(&[0xC0, 0x05]), Value::Invalid(_)));
        assert!(matches!(m.decode(&[0x80, 0x01]), Value::Invalid(_)));
        assert!(matches!(m.decode(&[0xA0, 0x00]), Value::Invalid(_)));

        assert_eq!(special(&[]), None);
        assert_eq!(special(&[0x7F, 0xFF]), None);
        assert_eq!(special(&[0xC8]), Some(Special::PositiveInfinity));
        assert_eq!(special(&[0xE8, 0, 0, 0]), Some(Special::NegativeInfinity));
        assert_eq!(special(&[0xD1, 0x02]), Some(Special::PositiveQuietNan(0x0102)));
        assert_eq!(special(&[0xF0, 0x07]), Some(Special::NegativeQuietNan(7)));
        assert_eq!(special(&[0xDB, 0x00]), Some(Special::PositiveSignalingNan(0x0300)));
        assert_eq!(special(&[0xF8]), Some(Special::NegativeSignalingNan(0)));
        assert_eq!(special(&[0xC2, 0x00]), Some(Special::UserDefined(0x0200)));
        assert_eq!(special(&[0xE5, 0x01]), Some(Special::MisbDefined(0x0501)));
        assert_eq!(special(&[0x81, 0x00]), Some(Special::Reserved(0x0100)));
        assert_eq!(special(&[0x80, 0x00, 0x01]), Some(Special::Reserved(1)));
    }

    #[test]
    fn eight_byte_extremes_do_not_panic() {
        let m = Imapb::new(-1e300, 1e300, 8).unwrap();
        for b in [[0x00; 8], [0x7F; 8], [0xFF; 8]] {
            let _ = m.decode(&b);
        }
        // sF = 2^1059 is not representable: no mapping.
        assert!(Imapb::new(0.0, 1e-300, 8).is_none());
    }

    const ABOVE: Value = Value::Invalid("IMAPB value above range maximum");
    const RESERVED: Value = Value::Invalid("IMAPB reserved special value");
    const MISB: Value = Value::Invalid("IMAPB MISB-defined special value");

    fn be(y: u64, len: usize) -> Vec<u8> {
        y.to_be_bytes()[8 - len..].to_vec()
    }

    #[test]
    fn above_range_maximum_is_invalid() {
        // ST 1201.5 7.2.1 truncates, so no conforming encoder produces an
        // integer above the one max maps to.
        let m = Imapb::new(-900.0, 40_000.0, 3).unwrap();
        assert_eq!(m.real_to_int(40_000.0), Some(0x4F_E200));
        assert_eq!(m.decode(&[0x4F, 0xE2, 0x00]), Value::Float(40_000.0));
        assert_eq!(m.decode(&[0x4F, 0xE2, 0x01]), ABOVE);
        assert_eq!(m.decode(&[0x7F, 0xFF, 0xFF]), ABOVE);
        // ST 0601 tag 112 Platform Course Angle, IMAPB(0, 360, 2).
        assert_eq!(decode(0.0, 360.0, &[0x5A, 0x00]), Value::Float(360.0));
        for bad in [[0x5A, 0x01], [0x7F, 0xFF], [0x80, 0x00]] {
            assert_eq!(decode(0.0, 360.0, &bad), ABOVE, "{bad:02X?}");
        }
        // 0x80 00 is a number only when (max - min) is a power of two
        // (ST 1201.5 7.2.3, Table 1).
        assert_eq!(decode(-1000.0, 1000.0, &[0x80, 0x00]), ABOVE);
        assert_eq!(decode(0.0, 100.0, &[0x80, 0x00]), ABOVE);
        assert_eq!(decode(0.0, 100.0, &[0x7F]), ABOVE);
        assert_eq!(decode(-1.0, 1.0, &[0x80, 0x00]), Value::Float(1.0));
        assert_eq!(decode(0.0, 256.0, &[0x80, 0x00]), Value::Float(256.0));
        // The low side is not range checked: with zOffset, y = 0 decodes
        // below min (ST 1201).
        assert_eq!(decode(-900.0, 40_000.0, &[0x00]), Value::Float(-1024.0));
    }

    #[test]
    fn every_integer_up_to_max_is_a_number_and_none_above() {
        let ranges = [
            (0.0, 360.0),
            (-900.0, 40_000.0),
            (-1000.0, 1000.0),
            (0.0, 100.0),
            (-90.0, 90.0),
            (-180.0, 180.0),
            (-900.0, 9000.0),
            (-19.2, 19.2),
            (-9.9, 110.0),
            (0.1, 0.9),
            (-1.0, 1.0),
            (0.0, 256.0),
            (0.0, 1.5e6),
            (0.0, 1e9),
        ];
        for (min, max) in ranges {
            for len in 1..=2 {
                let m = Imapb::new(min, max, len).unwrap();
                let top = m.real_to_int(max).unwrap();
                for y in 0..=(1u64 << (8 * len - 1)) {
                    let v = m.decode(&be(y, len));
                    if y <= top {
                        assert!(matches!(v, Value::Float(x) if x.is_finite()), "IMAPB({min}, {max}, {len}) {y:#X}: {v:?}");
                    } else {
                        assert_eq!(v, ABOVE, "IMAPB({min}, {max}, {len}) {y:#X}");
                    }
                }
            }
        }
    }

    #[test]
    fn special_values_need_zero_filled_other_bits() {
        // ST 1201.5 Table 2 (infinities) and Table 3 (below minimum, above
        // maximum): the other bits are zero filled. Anything else is
        // undefined and decodes as invalid.
        let m = Imapb::new(-900.0, 40_000.0, 3).unwrap();
        assert_eq!(m.decode(&[0xC8, 0, 0]), Value::Float(f64::INFINITY));
        assert_eq!(m.decode(&[0xE8, 0, 0]), Value::Float(f64::NEG_INFINITY));
        assert_eq!(m.decode(&[0xE0, 0, 0]), Value::OutOfRange);
        assert_eq!(m.decode(&[0xE1, 0, 0]), Value::OutOfRange);
        assert_eq!(m.decode(&[0xC8, 0, 1]), RESERVED);
        assert_eq!(m.decode(&[0xCF, 0, 0]), RESERVED);
        assert_eq!(m.decode(&[0xE0, 5, 0]), MISB);
        assert_eq!(m.decode(&[0xE1, 0xFF, 0xFF]), MISB);
        let m = Imapb::new(0.0, 100.0, 3).unwrap();
        for bad in [[0xC9, 0, 0], [0xC8, 0, 1], [0xEF, 0, 0], [0xE8, 0x12, 0x34]] {
            assert_eq!(m.decode(&bad), RESERVED, "{bad:02X?}");
        }
        for bad in [[0xE0, 0, 1], [0xE1, 0x80, 0]] {
            assert_eq!(m.decode(&bad), MISB, "{bad:02X?}");
        }
        assert_eq!(special(&[0xC9]), Some(Special::Reserved(1)));
        assert_eq!(special(&[0xE0, 0, 1]), Some(Special::MisbDefined(1)));
        let m = Imapb::new(0.0, 100.0, 1).unwrap();
        assert_eq!(m.decode(&[0xC8]), Value::Float(f64::INFINITY));
        assert_eq!(m.decode(&[0xE8]), Value::Float(f64::NEG_INFINITY));
        for b in (0xC9..=0xCF).chain(0xE9..=0xEF) {
            assert_eq!(m.decode(&[b]), RESERVED, "{b:02X}");
        }
    }

    #[test]
    fn b_pow_is_exact_near_powers_of_two() {
        // f64 span 16.000000000000004: ceil(log2) is 5, not 4.
        let m = Imapb::new(-47.7, -31.7, 2).unwrap();
        assert_eq!(m.reverse, 2f64.powi(-10));
        for k in [2, 10, 16, 30, 52, 100] {
            let p = 2f64.powi(k);
            let above = Imapb::new(0.0, p * (1.0 + f64::EPSILON), 2).unwrap();
            assert_eq!(above.reverse, 2f64.powi(k + 1 - 15), "2^{k} + 1 ulp");
            let exact = Imapb::new(0.0, p, 2).unwrap();
            assert_eq!(exact.reverse, 2f64.powi(k - 15), "2^{k}");
        }
        // 2^10 + 1 ulp: bPow 11, so 0x40000000 is 1024 (ST 1201.5 7.1.2).
        let max = f64::from_bits(1024f64.to_bits() + 1);
        let m = Imapb::new(0.0, max, 4).unwrap();
        assert_eq!(m.decode(&[0x40, 0, 0, 0]), Value::Float(1024.0));
        for len in 1..=8 {
            let m = Imapb::new(0.0, max, len).unwrap();
            let y = m.real_to_int(max).unwrap();
            assert!(matches!(m.decode(&be(y, len)), Value::Float(_)), "len {len}");
        }
        // Subnormal spans.
        assert_eq!(ceil_log2(f64::from_bits(1)), -1074);
        assert_eq!(ceil_log2(f64::from_bits(3)), -1072);
        assert_eq!(ceil_log2(f64::from_bits(4)), -1072);
        assert_eq!(ceil_log2(f64::MIN_POSITIVE), -1022);
        assert_eq!(ceil_log2(f64::MAX), 1024);
        assert_eq!(ceil_log2(1.0), 0);
        assert_eq!(ceil_log2(0.75), 0);
        assert_eq!(ceil_log2(0.5), -1);
    }

    #[test]
    fn unrepresentable_scales_are_rejected() {
        assert!(Imapb::new(0.0, 1e-300, 8).is_none());
        // forward overflows and zOffset would be NaN.
        assert!(Imapb::new(-1e-310, 1e-310, 8).is_none());
        assert!(Imapb::new(-1e-310, 1e-310, 1).is_none());
        // A span that overflows f64.
        assert!(Imapb::new(-1e308, 1e308, 4).is_none());
        assert!(Imapb::new(-f64::MAX, f64::MAX, 8).is_none());
        // The widest representable span still works.
        assert!(Imapb::new(0.0, f64::MAX, 1).is_some());
    }

    #[test]
    fn spanning_ranges_decode_exactly() {
        // ST 1201.5 7.2.2: sR * (y - zOffset) + a == sR * (y + floor(sF * a)).
        for len in 1..=2 {
            let m = Imapb::new(-0.001, 1000.0, len).unwrap();
            let y = m.real_to_int(0.0).unwrap();
            assert_eq!(m.decode(&be(y, len)), Value::Float(0.0), "len {len}");
        }
        assert_eq!(decode(-19.2, 19.2, &[0x40, 0x66, 0x67]), Value::Float(13.0));
        assert_eq!(decode(-19.2, 19.2, &[0x3A, 0x66, 0x67]), Value::Float(10.0));
        for (min, max) in [(-19.2, 19.2), (-9.9, 110.0), (-0.001, 1000.0), (-900.0, 19_000.0)] {
            for len in 1..=8 {
                let m = Imapb::new(min, max, len).unwrap();
                let y = m.real_to_int(0.0).unwrap();
                assert_eq!(m.int_to_real(y), 0.0, "IMAPB({min}, {max}, {len})");
            }
        }
    }
}
