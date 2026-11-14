//! MISB ST 1010 Standard Deviation and Correlation Coefficient Floating
//! Length Pack (SDCC-FLP).
//!
//! ST 0601 tag 102 carries an SDCC-FLP: the standard deviations and
//! correlation coefficients of the N items that precede it in the packet
//! (ST 1010.3 section 8, ST 0601.19 section 8.102). Which items those are is
//! the parent set's concern; this module decodes the pack itself.
//!
//! # Wire format (ST 1010.3 section 7, Table 4)
//!
//! 1. Matrix Size N, a BER-OID (section 6.3.3).
//! 2. Parse Control, one byte (Mode 1) or two (Mode 2), told apart by the top
//!    bit of the first byte (section 6.3.2):
//!    - Mode 1 (Figure 6, Table 1): `0 SSS C RRR`, standard deviation length
//!      Slen 0 to 7, sparse flag CS, correlation length Clen 0 to 7.
//!    - Mode 2 (Figure 8, Table 2): `1 0 CS Cf RRRR` then `0 0 0 Sf SSSS`,
//!      Clen and Slen 0 to 15, and the formats Cf and Sf: 0 for IEEE 754, 1
//!      for MISB ST 1201 IMAPB.
//! 3. Bit Vector, present when CS is 1 and Clen is not 0 (Table 3): one bit
//!    per correlation coefficient, most significant bit first, set when the
//!    coefficient is transmitted; ceil(N(N-1)/16) bytes (Equation 5).
//! 4. N standard deviations of Slen bytes each, when Slen is not 0.
//! 5. The correlation coefficients of the upper triangle, row by row, Clen
//!    bytes each, when Clen is not 0: all N(N-1)/2, or only those whose bit is
//!    set.
//!
//! # Decoded value
//!
//! A [`Value::Struct`] with the Table 4 element names:
//!
//! | Field | Value |
//! |-------|-------|
//! | Matrix Size | [`Value::Uint`] N |
//! | Parse Control | [`Value::Struct`], see below |
//! | Bit Vector | [`Value::Bytes`], only when present |
//! | Standard Deviation Values | [`Value::List`] of N [`Value::Float`], only when Slen is not 0 |
//! | Correlation Coefficient Values | [`Value::List`] of N(N-1)/2 [`Value::Float`], only when Clen is not 0 |
//!
//! Parse Control holds Mode (1 or 2), Sparse (0 or 1), Standard Deviation
//! Length, Standard Deviation Format, Correlation Length and Correlation
//! Format, as [`Value::Uint`]s except the formats, which are
//! [`Value::Enum`]s: 0 "IEEE 754", 1 "ST 1201 IMAPB".
//! Correlation coefficient k of the list belongs to the pair of rows (i, j),
//! i < j, counted row by row: (0, 1), (0, 2), ..., (0, N-1), (1, 2), ...,
//! (N-2, N-1). In a sparse pack the coefficients the bit vector leaves out
//! are 0.0 (ST 1010.3 section 6.3.4, ST 0601.19 section 8.102.1); the bit
//! vector is kept to tell them from transmitted zeros.
//!
//! # Rules
//!
//! - Standard deviations. Mode 1 has no format bit: the parent document
//!   chooses, and ST 0601 uses IEEE 754 (ST 0601.19 section 8.102.1). An
//!   IMAPB standard deviation (Mode 2, Sf = 1) needs a range from the parent
//!   document, which ST 0601 does not define, so the list is
//!   [`Value::Invalid`]. A negative or NaN standard deviation is
//!   [`Value::Invalid`].
//! - Correlation coefficients are IMAPB(-1, 1, Clen) in Mode 1, and in Mode 2
//!   when Cf is 1 (Tables 2 and 4). An IEEE 754 coefficient outside -1 to 1
//!   (or NaN) is [`Value::Invalid`]; an IMAPB one above the range is too, and
//!   ST 1201 special values decode as
//!   [`Imapb::decode`](crate::imapb::Imapb::decode) describes.
//! - IEEE 754 values are binary32 (4 bytes) or binary64 (8 bytes) as MISB ST
//!   0107 defines them, which ST 1010.1-08 invokes; IMAPB values are 1 to 8
//!   bytes. A list whose length and format do not fit is a single
//!   [`Value::Invalid`].
//! - The whole pack is [`Value::Invalid`] when it is truncated, has bytes
//!   left over after the last element, has a Matrix Size of 0, has neither
//!   standard deviations nor correlation coefficients (ST 1010.2-12), sets a
//!   reserved Mode 2 bit, or has a parse control longer than two bytes (no
//!   mode ST 1010.3 defines). An empty value is a zero-length item, which
//!   MISB ST 0107 reads as unknown: [`Value::Unknown`] (ST 0601 forbids a
//!   zero-length tag 102, so the ST 0601 table reports it as
//!   [`Value::Invalid`] before calling this module).
//! - Accepted as they do not change how the pack parses: a Mode 1 parse
//!   control, which ST 0601 does not allow (ST 0601.10-22) but whose layout
//!   ST 1010 fully defines (the Mode is reported); non-zero padding bits at
//!   the end of the bit vector, which are ignored; a bit vector of all ones
//!   (ST 1010.2-11); and CS set with Clen 0, which carries no bit vector
//!   (Table 3).
//! - Memory: every count is checked against the bytes present before
//!   anything is allocated, and a matrix needing more than
//!   [`Config::max_items`](crate::Config::max_items) values in either list
//!   is [`Value::Invalid`]. Across all matrices in a packet, the sum of both
//!   list lengths is limited by [`Config::max_total_items`].

use crate::imapb::Imapb;
use crate::klv::be_float;
use crate::{Config, Field, Value};
use smpte_klv::{ber, ErrorKind};

/// Format code of IEEE 754 values (ST 1010.3 Table 2, Cf and Sf).
const IEEE: u64 = 0;
/// Format code of ST 1201 IMAPB values.
const IMAPB: u64 = 1;

/// Decode an SDCC-FLP, such as the value of ST 0601 tag 102, with the
/// default [`Config`] limits: a [`Value::Struct`] as the module
/// documentation describes, [`Value::Invalid`] for a malformed pack and
/// [`Value::Unknown`] for an empty one. Never panics.
///
/// ```
/// use misb::Value;
/// // ST 1010.3 Figure 7 layout: N = 2, Mode 1 parse control 0x40 (four-byte
/// // IEEE standard deviations, no correlations), then sigma 1.5 and 0.25.
/// let pack = [0x02, 0x40, 0x3F, 0xC0, 0, 0, 0x3E, 0x80, 0, 0];
/// let v = misb::st1010::decode(&pack);
/// assert_eq!(v.field("Matrix Size"), Some(&Value::Uint(2)));
/// let sigmas = v.field("Standard Deviation Values").and_then(Value::as_list).unwrap();
/// assert_eq!(sigmas, [Value::Float(1.5), Value::Float(0.25)]);
/// ```
#[must_use]
pub fn decode(value: &[u8]) -> Value {
    decode_with(value, &Config::default())
}

/// [`decode`], bounding both value lists by [`Config::max_items`]. Never
/// panics.
pub(crate) fn decode_with(value: &[u8], cfg: &Config) -> Value {
    if value.is_empty() {
        return Value::Unknown;
    }
    parse(value, cfg).unwrap_or_else(Value::Invalid)
}

/// The Parse Control element (ST 1010.3 section 6.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Control {
    mode: u8,
    sparse: bool,
    slen: usize,
    sigma_format: u64,
    clen: usize,
    rho_format: u64,
}

/// Read the Parse Control at the start of `b`; returns it and its size.
fn parse_control(b: &[u8]) -> Result<(Control, usize), &'static str> {
    let first = *b.first().ok_or("truncated: no parse control")?;
    if first & 0x80 == 0 {
        // Mode 1, Figure 6 and Table 1: F=0, Slen in bits 4-6, CS in bit 3,
        // Clen in bits 0-2. Correlations are always ST 1201; standard
        // deviations take the parent document's format, IEEE in ST 0601.
        let control = Control {
            mode: 1,
            sparse: first & 0x08 != 0,
            slen: usize::from((first >> 4) & 0x07),
            sigma_format: IEEE,
            clen: usize::from(first & 0x07),
            rho_format: IMAPB,
        };
        return Ok((control, 1));
    }
    let second = *b.get(1).ok_or("truncated: second parse control byte missing")?;
    if second & 0x80 != 0 {
        return Err("parse control longer than two bytes");
    }
    // Mode 2, Figure 8 and Table 2. Byte 1: F=1, R, CS, Cf, Clen (4 bits).
    // Byte 2: F=0, R, R, Sf, Slen (4 bits). Reserved bits are zero.
    if first & 0x40 != 0 || second & 0x60 != 0 {
        return Err("reserved parse control bits set");
    }
    let control = Control {
        mode: 2,
        sparse: first & 0x20 != 0,
        slen: usize::from(second & 0x0F),
        sigma_format: u64::from((second >> 4) & 1),
        clen: usize::from(first & 0x0F),
        rho_format: u64::from((first >> 4) & 1),
    };
    Ok((control, 2))
}

/// Split `n` bytes off the front of `rest`, or fail with `why`.
fn take<'a>(rest: &mut &'a [u8], n: u128, why: &'static str) -> Result<&'a [u8], &'static str> {
    let n = usize::try_from(n).map_err(|_| why)?;
    if rest.len() < n {
        return Err(why);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

/// Whether bit `i` of the bit vector is set, most significant bit first.
fn bit(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).map_or(false, |&b| b & (0x80 >> (i % 8)) != 0)
}

/// Number of set bits among the first `count` bits of `bits`.
fn ones(bits: &[u8], count: u128) -> u128 {
    let full = usize::try_from(count / 8).unwrap_or(usize::MAX).min(bits.len());
    let mut n: u128 = bits[..full].iter().map(|b| u128::from(b.count_ones())).sum();
    let rem = (count % 8) as u32;
    if rem > 0 {
        if let Some(&last) = bits.get(full) {
            n += u128::from((last >> (8 - rem)).count_ones());
        }
    }
    n
}

fn format(code: u64) -> Value {
    Value::Enum { code, label: Some(if code == IMAPB { "ST 1201 IMAPB" } else { "IEEE 754" }) }
}

fn parse(value: &[u8], cfg: &Config) -> Result<Value, &'static str> {
    // Matrix Size: BER-OID, padded forms tolerated as for local set tags.
    let (n, used) = ber::decode_oid(value, crate::klv::OPTIONS.strict_oid).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEnd { .. } => "truncated matrix size",
        _ => "matrix size does not fit in 64 bits",
    })?;
    if n == 0 {
        return Err("matrix size is 0");
    }
    let rest = value.get(used..).unwrap_or(&[]);
    let (pc, pc_len) = parse_control(rest)?;
    let mut rest = rest.get(pc_len..).unwrap_or(&[]);
    if pc.slen == 0 && pc.clen == 0 {
        return Err("neither standard deviations nor correlation coefficients (ST 1010.2-12)");
    }

    // Sizes in u128: N(N-1)/2 of a u64 N cannot overflow.
    let n_wide = u128::from(n);
    let count = n_wide * (n_wide - 1) / 2;
    let has_bits = pc.sparse && pc.clen > 0;
    let bits: &[u8] = if has_bits { take(&mut rest, (count + 7) / 8, "truncated bit vector")? } else { &[] };
    let sent = match (pc.clen, has_bits) {
        (0, _) => 0,
        (_, true) => ones(bits, count),
        (_, false) => count,
    };
    let sigma_bytes = take(&mut rest, n_wide * pc.slen as u128, "truncated standard deviation values")?;
    let rho_len = sent.checked_mul(pc.clen as u128).ok_or("truncated correlation coefficient values")?;
    let rho_bytes = take(&mut rest, rho_len, "truncated correlation coefficient values")?;
    if !rest.is_empty() {
        return Err("bytes left over after the correlation coefficient values");
    }

    // Every count is now bounded by the input; bound the lists by max_items.
    let too_many = |c: u128, len: usize| len > 0 && c > cfg.max_items as u128;
    if too_many(n_wide, pc.slen) || too_many(count, pc.clen) {
        return Err("matrix larger than Config::max_items allows");
    }
    // Each list's length is now at most max_items, so it fits in usize.
    let sigma_count = if pc.slen > 0 { n_wide as usize } else { 0 };
    let rho_count = if pc.clen > 0 { count as usize } else { 0 };

    let total = sigma_count.checked_add(rho_count).ok_or("matrix value count exceeds addressable memory")?;
    if !crate::registry::take_matrix_values(total) {
        return Err("matrix values exceed Config::max_total_items for this packet");
    }

    let mut fields = Vec::with_capacity(5);
    fields.push(Field { name: "Matrix Size", value: Value::Uint(n) });
    fields.push(Field {
        name: "Parse Control",
        value: Value::Struct(vec![
            Field { name: "Mode", value: Value::Uint(u64::from(pc.mode)) },
            Field { name: "Sparse", value: Value::Uint(u64::from(pc.sparse)) },
            Field { name: "Standard Deviation Length", value: Value::Uint(pc.slen as u64) },
            Field { name: "Standard Deviation Format", value: format(pc.sigma_format) },
            Field { name: "Correlation Length", value: Value::Uint(pc.clen as u64) },
            Field { name: "Correlation Format", value: format(pc.rho_format) },
        ]),
    });
    if has_bits {
        fields.push(Field { name: "Bit Vector", value: Value::Bytes(bits.to_vec()) });
    }
    if pc.slen > 0 {
        fields.push(Field { name: "Standard Deviation Values", value: sigmas(sigma_bytes, sigma_count, &pc) });
    }
    if pc.clen > 0 {
        let bits = if has_bits { Some(bits) } else { None };
        fields.push(Field { name: "Correlation Coefficient Values", value: rhos(rho_bytes, bits, rho_count, &pc) });
    }
    Ok(Value::Struct(fields))
}

/// The N standard deviations (`bytes` holds exactly N x Slen bytes).
fn sigmas(bytes: &[u8], n: usize, pc: &Control) -> Value {
    if pc.sigma_format == IMAPB {
        return Value::Invalid("ST 1201 standard deviations need a range from the parent document");
    }
    if pc.slen != 4 && pc.slen != 8 {
        return Value::Invalid("IEEE 754 standard deviations are not 4 or 8 bytes");
    }
    let mut out = Vec::with_capacity(n);
    for c in bytes.chunks_exact(pc.slen) {
        out.push(match be_float(c) {
            // Excludes NaN and negative values; -0.0 passes.
            Some(x) if x >= 0.0 => Value::Float(x),
            _ => Value::Invalid("negative or NaN standard deviation"),
        });
    }
    Value::List(out)
}

/// How the correlation coefficients decode.
enum RhoFormat {
    Ieee,
    Imapb(Imapb),
}

/// The N(N-1)/2 correlation coefficients, expanded with 0.0 where a sparse
/// pack leaves one out. `bytes` holds exactly the transmitted values.
fn rhos(bytes: &[u8], bits: Option<&[u8]>, count: usize, pc: &Control) -> Value {
    let format = if pc.rho_format == IMAPB {
        match Imapb::new(-1.0, 1.0, pc.clen) {
            Some(map) => RhoFormat::Imapb(map),
            None => return Value::Invalid("ST 1201 correlation coefficients longer than 8 bytes"),
        }
    } else if pc.clen == 4 || pc.clen == 8 {
        RhoFormat::Ieee
    } else {
        return Value::Invalid("IEEE 754 correlation coefficients are not 4 or 8 bytes");
    };
    let mut sent = bytes.chunks_exact(pc.clen);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        if let Some(bits) = bits {
            if !bit(bits, i) {
                out.push(Value::Float(0.0));
                continue;
            }
        }
        let Some(c) = sent.next() else {
            // Not reachable: the lengths were checked against the bit vector.
            out.push(Value::Invalid("truncated correlation coefficient values"));
            break;
        };
        out.push(match &format {
            RhoFormat::Ieee => match be_float(c) {
                Some(x) if (-1.0..=1.0).contains(&x) => Value::Float(x),
                _ => Value::Invalid("correlation coefficient outside -1 to 1"),
            },
            // ST 1201 special values, and a value above the range (ST
            // 1201.5 section 7.2.1), as Imapb::decode reports them.
            RhoFormat::Imapb(map) => map.decode(c),
        });
    }
    Value::List(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f32s(xs: &[f32]) -> Vec<u8> {
        xs.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    fn rho2(x: f64) -> Vec<u8> {
        let y = Imapb::new(-1.0, 1.0, 2).unwrap().real_to_int(x).unwrap() as u16;
        y.to_be_bytes().to_vec()
    }

    fn get<'a>(v: &'a Value, name: &str) -> &'a Value {
        v.field(name).unwrap_or_else(|| panic!("no field {name} in {v}"))
    }

    fn list(v: &Value) -> &[Value] {
        v.as_list().unwrap_or_else(|| panic!("not a list: {v:?}"))
    }

    fn invalid(v: &Value) -> bool {
        matches!(v, Value::Invalid(_))
    }

    fn names(v: &Value) -> Vec<&'static str> {
        v.as_fields().unwrap().iter().map(|f| f.name).collect()
    }

    #[test]
    fn parse_control_examples() {
        // ST 1010.3 Figure 7: 0x4B, Slen 4, sparse, Clen 3.
        let (pc, n) = parse_control(&[0x4B]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            pc,
            Control { mode: 1, sparse: true, slen: 4, sigma_format: IEEE, clen: 3, rho_format: IMAPB }
        );
        // Figure 9: 0xB308, sparse, ST 1201 Clen 3, IEEE Slen 8.
        let (pc, n) = parse_control(&[0xB3, 0x08]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            pc,
            Control { mode: 2, sparse: true, slen: 8, sigma_format: IEEE, clen: 3, rho_format: IMAPB }
        );
        // Every Mode 2 field at its maximum.
        let (pc, _) = parse_control(&[0xBF, 0x1F]).unwrap();
        assert_eq!(
            pc,
            Control { mode: 2, sparse: true, slen: 15, sigma_format: IMAPB, clen: 15, rho_format: IMAPB }
        );
        // 0x80 is a valid Mode 2 first byte (all fields zero).
        assert_eq!(parse_control(&[0x80, 0x04]).unwrap().0.slen, 4);
        assert_eq!(parse_control(&[0x7F]).unwrap().0, Control {
            mode: 1,
            sparse: true,
            slen: 7,
            sigma_format: IEEE,
            clen: 7,
            rho_format: IMAPB
        });
        // Errors.
        assert!(parse_control(&[]).is_err());
        assert!(parse_control(&[0x80]).is_err());
        assert!(parse_control(&[0x80, 0x80]).is_err());
        assert!(parse_control(&[0xC0, 0x04]).is_err());
        assert!(parse_control(&[0x80, 0x24]).is_err());
        assert!(parse_control(&[0x80, 0x44]).is_err());
    }

    #[test]
    fn figure_12_sparse_example() {
        // ST 1010.3 Figure 12: N = 5, Slen 4, Clen 2, bit vector 1010 0110
        // 1100 0000: coefficients (1,2) (1,4) (2,4) (2,5) (3,5) (4,5) in the
        // standard's 1-based numbering.
        let sig = [1.5f32, 2.0, 0.25, 8.0, 100.0];
        let rho = [0.5, -0.5, 0.25, 1.0, -1.0, 0.0];
        let mut pack = vec![0x05, 0x4A, 0xA6, 0xC0];
        pack.extend(f32s(&sig));
        for r in rho {
            pack.extend(rho2(r));
        }
        let v = decode(&pack);
        assert_eq!(get(&v, "Matrix Size"), &Value::Uint(5));
        assert_eq!(
            names(&v),
            [
                "Matrix Size",
                "Parse Control",
                "Bit Vector",
                "Standard Deviation Values",
                "Correlation Coefficient Values"
            ]
        );
        assert_eq!(
            get(&v, "Parse Control").to_string(),
            "{ Mode: 1, Sparse: 1, Standard Deviation Length: 4, Standard Deviation Format: IEEE 754 (0), \
             Correlation Length: 2, Correlation Format: ST 1201 IMAPB (1) }"
        );
        assert_eq!(get(&v, "Bit Vector"), &Value::Bytes(vec![0xA6, 0xC0]));
        let s: Vec<f64> = list(get(&v, "Standard Deviation Values")).iter().map(|x| x.as_f64().unwrap()).collect();
        assert_eq!(s, [1.5, 2.0, 0.25, 8.0, 100.0]);
        let r: Vec<f64> =
            list(get(&v, "Correlation Coefficient Values")).iter().map(|x| x.as_f64().unwrap()).collect();
        // Row-major (0,1) (0,2) (0,3) (0,4) (1,2) (1,3) (1,4) (2,3) (2,4) (3,4).
        assert_eq!(r, [0.5, 0.0, -0.5, 0.0, 0.0, 0.25, 1.0, 0.0, -1.0, 0.0]);

        // The same pack in Mode 2: 0xB2 0x04.
        let mut m2 = vec![0x05, 0xB2, 0x04];
        m2.extend(&pack[2..]);
        let v2 = decode(&m2);
        assert_eq!(get(get(&v2, "Parse Control"), "Mode"), &Value::Uint(2));
        assert_eq!(get(&v2, "Correlation Coefficient Values"), get(&v, "Correlation Coefficient Values"));
        assert_eq!(get(&v2, "Standard Deviation Values"), get(&v, "Standard Deviation Values"));
    }

    #[test]
    fn figure_13_sigma_only_and_full_matrix() {
        // Figure 13: N = 5, Slen 4, Clen 0: five values, no bit vector.
        let mut pack = vec![0x05, 0x40];
        pack.extend(f32s(&[1.0, 2.0, 3.0, 4.0, 5.0]));
        let v = decode(&pack);
        assert_eq!(names(&v), ["Matrix Size", "Parse Control", "Standard Deviation Values"]);
        assert_eq!(list(get(&v, "Standard Deviation Values")).len(), 5);

        // Mode 2, full matrix, IEEE binary64 sigma and binary32 rho.
        let mut pack = vec![0x03, 0x84, 0x08];
        for s in [0.5f64, 1.0, 2.0] {
            pack.extend(s.to_be_bytes());
        }
        pack.extend(f32s(&[0.1, -0.2, 0.3]));
        let v = decode(&pack);
        assert_eq!(get(get(&v, "Parse Control"), "Correlation Format"), &format(IEEE));
        let r = list(get(&v, "Correlation Coefficient Values"));
        assert_eq!(r[0], Value::Float(f64::from(0.1f32)));
        assert_eq!(r[1], Value::Float(f64::from(-0.2f32)));
        assert_eq!(list(get(&v, "Standard Deviation Values"))[2], Value::Float(2.0));

        // Correlations only (Slen 0), IMAPB, three bytes each.
        let map = Imapb::new(-1.0, 1.0, 3).unwrap();
        let mut pack = vec![0x03, 0x93, 0x00];
        for x in [1.0, -1.0, 0.0] {
            pack.extend(&map.real_to_int(x).unwrap().to_be_bytes()[5..]);
        }
        let v = decode(&pack);
        assert_eq!(names(&v), ["Matrix Size", "Parse Control", "Correlation Coefficient Values"]);
        let r: Vec<f64> =
            list(get(&v, "Correlation Coefficient Values")).iter().map(|x| x.as_f64().unwrap()).collect();
        assert_eq!(r, [1.0, -1.0, 0.0]);
    }

    #[test]
    fn matrix_size_forms() {
        // N = 1: no coefficients exist, a Clen is allowed and carries none.
        let mut pack = vec![0x01, 0x42];
        pack.extend(f32s(&[3.0]));
        let v = decode(&pack);
        assert_eq!(list(get(&v, "Correlation Coefficient Values")).len(), 0);
        // Sparse with N = 1: an empty bit vector.
        let mut pack = vec![0x01, 0x4A];
        pack.extend(f32s(&[3.0]));
        assert_eq!(get(&decode(&pack), "Bit Vector"), &Value::Bytes(vec![]));
        // Multi-byte BER-OID: N = 128, sigma only.
        let mut pack = vec![0x81, 0x00, 0x40];
        pack.extend(f32s(&[1.0; 128]));
        assert_eq!(get(&decode(&pack), "Matrix Size"), &Value::Uint(128));
        // Padded BER-OID is tolerated.
        let mut pack = vec![0x80, 0x02, 0x40];
        pack.extend(f32s(&[1.0, 2.0]));
        assert_eq!(get(&decode(&pack), "Matrix Size"), &Value::Uint(2));
        // Zero, unterminated, overflowing.
        assert!(invalid(&decode(&[0x00, 0x40])));
        assert!(invalid(&decode(&[0x81])));
        let mut over = vec![0xFF; 10];
        over.push(0x00);
        assert!(invalid(&decode(&over)));
        assert_eq!(decode(&[]), Value::Unknown);
    }

    #[test]
    fn exact_lengths() {
        let mut good = vec![0x02, 0x42];
        good.extend(f32s(&[1.0, 2.0]));
        good.extend(rho2(0.5));
        assert!(!invalid(&decode(&good)));
        // Every truncation is rejected, as is any extra byte. Nothing at
        // all is a zero-length item: unknown.
        assert_eq!(decode(&good[..0]), Value::Unknown);
        for cut in 1..good.len() {
            assert!(invalid(&decode(&good[..cut])), "cut at {cut}");
        }
        let mut long = good.clone();
        long.push(0);
        assert!(invalid(&decode(&long)));
        // Sparse: the bit vector decides how many coefficients follow.
        let mut sparse = vec![0x03, 0x4A, 0b1010_0000];
        sparse.extend(f32s(&[1.0, 2.0, 3.0]));
        sparse.extend(rho2(0.5));
        sparse.extend(rho2(-0.5));
        let v = decode(&sparse);
        let r: Vec<f64> =
            list(get(&v, "Correlation Coefficient Values")).iter().map(|x| x.as_f64().unwrap()).collect();
        assert_eq!(r, [0.5, 0.0, -0.5]);
        assert!(invalid(&decode(&sparse[..sparse.len() - 2])));
        let mut extra = sparse.clone();
        extra.extend(rho2(0.0));
        assert!(invalid(&decode(&extra)));
        // Neither list (ST 1010.2-12).
        assert!(invalid(&decode(&[0x02, 0x00])));
        assert!(invalid(&decode(&[0x02, 0x08])));
        assert!(invalid(&decode(&[0x02, 0x80, 0x00])));
        // CS set with Clen 0: no bit vector (Table 3).
        let mut pack = vec![0x02, 0x48];
        pack.extend(f32s(&[1.0, 2.0]));
        let v = decode(&pack);
        assert_eq!(names(&v), ["Matrix Size", "Parse Control", "Standard Deviation Values"]);
        assert_eq!(get(get(&v, "Parse Control"), "Sparse"), &Value::Uint(1));
        // Reserved bits and a third parse control byte.
        assert!(invalid(&decode(&[0x02, 0xC0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0])));
        assert!(invalid(&decode(&[0x02, 0x80, 0x84, 0x04])));
    }

    #[test]
    fn bit_vector_padding_and_all_ones() {
        // N = 3: three bits used, five padding bits ignored even when set.
        let mut pack = vec![0x03, 0x4A, 0b0111_1111];
        pack.extend(f32s(&[1.0, 2.0, 3.0]));
        pack.extend(rho2(0.25));
        pack.extend(rho2(0.75));
        let v = decode(&pack);
        let r: Vec<f64> =
            list(get(&v, "Correlation Coefficient Values")).iter().map(|x| x.as_f64().unwrap()).collect();
        assert_eq!(r, [0.0, 0.25, 0.75]);
        // All ones (ST 1010.2-11 forbids it) still decodes.
        let mut pack = vec![0x02, 0x0A, 0x80];
        pack.extend(rho2(0.5));
        assert_eq!(list(get(&decode(&pack), "Correlation Coefficient Values")), [Value::Float(0.5)]);
        // Larger matrix: N = 6 has 15 coefficients, two bit vector bytes.
        assert_eq!(ones(&[0xFF, 0xFF], 15), 15);
        assert_eq!(ones(&[0xFF, 0x01], 15), 8);
        assert_eq!(ones(&[0x00, 0x02], 15), 1);
        assert_eq!(ones(&[], 0), 0);
        assert!(bit(&[0x80], 0) && !bit(&[0x80], 1) && !bit(&[], 3));
    }

    #[test]
    fn value_formats() {
        // IMAPB standard deviations need a parent range: the list is invalid.
        let mut pack = vec![0x02, 0x80, 0x12];
        pack.extend([0, 1, 0, 2]);
        let v = decode(&pack);
        assert!(invalid(get(&v, "Standard Deviation Values")));
        assert_eq!(get(get(&v, "Parse Control"), "Standard Deviation Format"), &format(IMAPB));
        // IEEE lengths other than 4 or 8.
        for slen in [1u8, 2, 3, 5, 6, 7] {
            let mut pack = vec![0x01, 0x80, slen];
            pack.extend(vec![0; usize::from(slen)]);
            let v = decode(&pack);
            assert!(invalid(get(&v, "Standard Deviation Values")), "Slen {slen}");
            assert!(!invalid(&v));
        }
        let pack = [0x02, 0x82, 0x00, 0x12, 0x34];
        assert!(invalid(get(&decode(&pack), "Correlation Coefficient Values")));
        // IMAPB correlation coefficients up to 8 bytes; 9 to 15 are not supported.
        for clen in 1u8..=15 {
            let mut pack = vec![0x02, 0x90 | clen, 0x00];
            pack.extend(vec![0; usize::from(clen)]);
            let v = decode(&pack);
            let r = get(&v, "Correlation Coefficient Values");
            if clen <= 8 {
                let x = list(r)[0].as_f64().unwrap();
                assert!((-1.0..=-0.99).contains(&x), "Clen {clen}: {x}");
            } else {
                assert!(invalid(r), "Clen {clen}");
            }
        }
    }

    #[test]
    fn value_ranges_and_specials() {
        let pack = |sigma: f32, rho: f32| {
            let mut p = vec![0x02, 0x84, 0x04];
            p.extend(f32s(&[sigma, 1.0]));
            p.extend(f32s(&[rho]));
            decode(&p)
        };
        let s0 = |v: &Value| list(get(v, "Standard Deviation Values"))[0].clone();
        let r0 = |v: &Value| list(get(v, "Correlation Coefficient Values"))[0].clone();
        assert_eq!(s0(&pack(0.0, 0.0)), Value::Float(0.0));
        assert_eq!(s0(&pack(-0.0, 0.0)), Value::Float(-0.0));
        assert_eq!(s0(&pack(f32::INFINITY, 0.0)), Value::Float(f64::INFINITY));
        assert!(invalid(&s0(&pack(-1.0, 0.0))));
        assert!(invalid(&s0(&pack(f32::NAN, 0.0))));
        assert_eq!(r0(&pack(1.0, 1.0)), Value::Float(1.0));
        assert_eq!(r0(&pack(1.0, -1.0)), Value::Float(-1.0));
        assert!(invalid(&r0(&pack(1.0, 1.0001))));
        assert!(invalid(&r0(&pack(1.0, -1.5))));
        assert!(invalid(&r0(&pack(1.0, f32::NAN))));
        assert!(invalid(&r0(&pack(1.0, f32::NEG_INFINITY))));

        // IMAPB(-1, 1, 2) boundaries and ST 1201 special values.
        let imapb = |hi: u8, lo: u8| {
            let v = decode(&[0x02, 0x92, 0x00, hi, lo]);
            r0(&v)
        };
        assert_eq!(imapb(0x00, 0x00), Value::Float(-1.0));
        assert_eq!(imapb(0x40, 0x00), Value::Float(0.0));
        assert_eq!(imapb(0x80, 0x00), Value::Float(1.0));
        assert!(invalid(&imapb(0x80, 0x01)));
        assert_eq!(imapb(0xE0, 0x00), Value::OutOfRange);
        assert_eq!(imapb(0xE1, 0x00), Value::OutOfRange);
        assert_eq!(imapb(0xC8, 0x00), Value::Float(f64::INFINITY));
        assert!(imapb(0xD0, 0x00).as_f64().unwrap().is_nan());
        assert!(invalid(&imapb(0xC1, 0x00)), "user defined: not an ST 1010 signal");
        // IMAPB(-1, 1, 1): range 2 over one byte, 0x80 is 1.0, 0x81 reserved.
        let one = |b: u8| r0(&decode(&[0x02, 0x91, 0x00, b]));
        assert_eq!(one(0x00), Value::Float(-1.0));
        assert_eq!(one(0x40), Value::Float(0.0));
        assert_eq!(one(0x80), Value::Float(1.0));
        assert!(invalid(&one(0x81)));
        // IMAPB(-1, 1, 3): the largest integer maps to 1.0, one more is invalid.
        let three = |y: u32| r0(&decode(&[0x02, 0x93, 0x00, (y >> 16) as u8, (y >> 8) as u8, y as u8]));
        assert_eq!(three(0x80_0000), Value::Float(1.0));
        assert!(invalid(&three(0x80_0001)));
    }

    #[test]
    fn hostile_sizes_do_not_allocate() {
        // Huge N with sigma: rejected as truncated before any allocation.
        let mut pack = vec![0x8F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x84, 0x04];
        pack.extend([0; 16]);
        assert!(invalid(&decode(&pack)));
        // N = u64::MAX, correlations only: N(N-1)/2 x Clen overflows u128 checks.
        let mut pack = vec![0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x8F, 0x00];
        pack.extend([0; 32]);
        assert!(invalid(&decode(&pack)));
        // A sparse pack whose all-zero bit vector would expand to many
        // zeros: bounded by max_items. N = 1000: 499,500 coefficients,
        // 62,438 bit vector bytes.
        let mut pack = vec![0x87, 0x68, 0x0A];
        pack.extend(vec![0; (1000 * 999 / 2 + 7) / 8]);
        let v = decode(&pack);
        assert!(invalid(&v), "{v:?}");
        let mut cfg = Config::default();
        cfg.max_items = 500_000;
        let v = decode_with(&pack, &cfg);
        let r = list(get(&v, "Correlation Coefficient Values"));
        assert_eq!(r.len(), 499_500);
        assert!(r.iter().all(|x| *x == Value::Float(0.0)));
        // max_items applies to the sigma list as well.
        cfg.max_items = 1;
        let mut pack = vec![0x02, 0x40];
        pack.extend(f32s(&[1.0, 2.0]));
        assert!(invalid(&decode_with(&pack, &cfg)));
    }

    #[test]
    fn noise_never_panics() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut small = Config::default();
        small.max_items = 4;
        for round in 0..20_000 {
            let len = (next() % 48) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Favour small matrix sizes so the deeper paths are reached.
            if let Some(b) = buf.first_mut() {
                *b %= 8;
            }
            let v = if round % 2 == 0 { decode(&buf) } else { decode_with(&buf, &small) };
            let _ = v.to_string();
        }
    }
}
