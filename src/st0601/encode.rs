//! The ST 0601 half of the encoder: the inverse of each codec of the tag
//! table (`st0601-encode.md` section 3.6) and of each pack decoder (section
//! 3.7). Kept next to the decoder so both read the same [`DESCS`] entries.

use super::*;
use crate::encode::{
    field as get, put_int_min, put_oid, put_prefixed, put_uint_min, put_uint_n, wrap_angle, Ctx, EncodeError, ErrorKind,
    View,
};

/// Default IMAPB lengths (DECISIONS D-08, `st0601-encode.md` 3.8).
fn imapb_default_len(tag: Tag) -> usize {
    match tag {
        Tag::PlatformCourseAngle | Tag::OnBoardMiStoragePercentFull | Tag::ZoomPercentage => 2,
        _ => 3,
    }
}

/// Full-circle angles reduced modulo 360 into their range (DECISIONS D-07).
fn wraps(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::PlatformHeadingAngle
            | Tag::SensorRelativeAzimuthAngle
            | Tag::SensorRelativeElevationAngle
            | Tag::SensorRelativeRollAngle
            | Tag::WindDirection
            | Tag::PlatformMagneticHeading
            | Tag::AlternatePlatformHeading
            | Tag::PlatformCourseAngle
    )
}

/// Corner offsets: outside +/-0.075 deg they are not reported; items 82 to
/// 89 are (R-ST0601-ENCODE-40, D-07: an error under every policy).
fn corner_offset(tag: Tag) -> bool {
    (26..=33).contains(&(tag as u64))
}

/// Maximum text length in bytes (R-ST0601-ENCODE-28, -43).
fn text_max(tag: Tag) -> usize {
    if tag == Tag::TargetId {
        32
    } else {
        127
    }
}

/// Write the value of item `tag` (not its tag or length) into `out`.
/// `len` is an explicit IMAPB length.
pub(crate) fn encode_value(
    tag: Tag,
    v: View<'_>,
    len: Option<usize>,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let codec = tag.desc().codec;
    if len.is_some() && !matches!(codec, Codec::Imapb { .. }) {
        return Err(ctx.err(ErrorKind::WrongType, "an explicit length applies to IMAPB items only"));
    }
    if matches!(v, View::Unknown | View::Invalid) {
        return Err(ctx.err(ErrorKind::WrongType, "no value to encode"));
    }
    match codec {
        // R-ST0601-ENCODE-27: exactly the required length.
        Codec::Uint(Len::Exact(n)) => {
            let x = unsigned(ctx, v, max_uint(n))?;
            put_uint_n(out, x, n);
        }
        // R-ST0601-ENCODE-29: fewest bytes, at most the maximum length.
        Codec::Uint(Len::UpTo(n)) => {
            let x = unsigned(ctx, v, max_uint(n))?;
            put_uint_min(out, x);
        }
        Codec::Int(Len::Exact(n)) => {
            let (lo, hi) = int_range(n);
            let x = signed_int(ctx, v, lo, hi)?;
            put_uint_n(out, x as u64, n);
        }
        Codec::Int(Len::UpTo(n)) => {
            let (lo, hi) = int_range(n);
            let x = signed_int(ctx, v, lo, hi)?;
            put_int_min(out, x);
        }
        // R-ST0601-ENCODE-25: MISP microseconds.
        Codec::Time(len) => {
            let t = match v {
                View::Time(t) | View::Uint(t) => t,
                _ => return Err(ctx.err(ErrorKind::WrongType, "expected a MISP time")),
            };
            match len {
                Len::Exact(n) => put_uint_n(out, t, n),
                Len::UpTo(_) => put_uint_min(out, t),
            }
        }
        // Items 43 and 44: "uint8 round(x / 2)", 0 to 510 pixels.
        Codec::Scaled { len, factor } => {
            let span = max_uint(len) as f64 * factor as f64;
            let x = ctx.real(v)?;
            let x = ctx.in_range(x, 0.0, span)?;
            put_uint_n(out, (x / factor as f64).round() as u64, len);
        }
        // R-ST0601-ENCODE-33: round((x - offset) * (2^N - 1) / range), half
        // away from zero (D-06).
        Codec::Unsigned { len, range, offset } => {
            let mut x = ctx.real(v)?;
            if wraps(tag) {
                x = wrap_angle(x, offset, offset + range);
            }
            let x = ctx.in_range(x, offset, offset + range)?;
            let span = span_u(len);
            let code = ((x - offset) * span / range).round().clamp(0.0, span);
            put_uint_n(out, code as u64, len);
        }
        Codec::Signed { len, range, special } => signed_mapped(tag, v, len, range, special, ctx, out)?,
        Codec::Imapb { min, max, max_len } => {
            let n = len.unwrap_or_else(|| imapb_default_len(tag));
            if !(1..=max_len).contains(&n) {
                return Err(ctx.err(ErrorKind::OutOfRange, "IMAPB length outside 1 to the item's maximum"));
            }
            ctx.imapb(v, min, max, n, wraps(tag), out)?;
        }
        Codec::Text => ctx.text(v, text_max(tag), out)?,
        Codec::Enum(labels) => {
            let code = code_of(ctx, v, labels)?;
            out.push(code as u8);
        }
        Codec::Set(standard) => nested_set(standard, v, ctx, out)?,
        // Items 95, 97, 98, 99 are kept as bytes by the decoder (66 is
        // refused before this point).
        Codec::Bytes => match v {
            View::Bytes(b) | View::Set(b) if !b.is_empty() => {
                well_formed_set(ctx, b)?;
                out.extend_from_slice(b)
            }
            View::Bytes(_) | View::Set(_) => return Err(ctx.err(ErrorKind::NotAllowed, "empty value: use unknown")),
            _ => return Err(ctx.err(ErrorKind::WrongType, "expected the set's encoded items")),
        },
        Codec::Pack(_) => pack(tag, v, ctx, out)?,
    }
    Ok(())
}

fn max_uint(n: usize) -> u64 {
    if n >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * n)) - 1
    }
}

fn int_range(n: usize) -> (i64, i64) {
    if n >= 8 {
        (i64::MIN, i64::MAX)
    } else {
        let half = 1i64 << (8 * n - 1);
        (-half, half - 1)
    }
}

/// An unsigned integer item: an integer, or a number rounded ("uint8
/// round(x)"), in `[0, hi]` under the range policy.
fn unsigned(ctx: &mut Ctx<'_>, v: View<'_>, hi: u64) -> Result<u64, EncodeError> {
    if let View::Float(_) = v {
        return Ok(ctx.rounded(v, 0.0, hi as f64)? as u64);
    }
    let x = ctx.integer(v)?;
    if x <= hi {
        return Ok(x);
    }
    if ctx.strict() {
        return Err(ctx.err(ErrorKind::OutOfRange, "value too large for the item"));
    }
    ctx.warn("value clamped to the item's range");
    Ok(hi)
}

/// A signed integer item in `[lo, hi]` under the range policy.
fn signed_int(ctx: &mut Ctx<'_>, v: View<'_>, lo: i64, hi: i64) -> Result<i64, EncodeError> {
    if let View::Float(_) = v {
        return ctx.rounded(v, lo as f64, hi as f64);
    }
    let x = ctx.signed_integer(v)?;
    if (lo..=hi).contains(&x) {
        return Ok(x);
    }
    if ctx.strict() {
        return Err(ctx.err(ErrorKind::OutOfRange, "value outside the item's range"));
    }
    ctx.warn("value clamped to the item's range");
    Ok(x.clamp(lo, hi))
}

/// Signed mapped items (R-ST0601-ENCODE-33, -37 to -40): `round(x * (2^N -
/// 2) / range)`; the most negative code is the item's special value.
fn signed_mapped(
    tag: Tag,
    v: View<'_>,
    len: usize,
    range: f64,
    special: Special,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let indicator = |out: &mut Vec<u8>| {
        out.push(0x80);
        out.extend(std::iter::repeat(0).take(len - 1));
    };
    match (v, special) {
        (View::OutOfRange, Special::OutOfRange) | (View::OffEarth, Special::OffEarth) => {
            indicator(out);
            return Ok(());
        }
        (View::OffEarth, _) => return Err(ctx.err(ErrorKind::NotAllowed, "this item has no Off-Earth state")),
        // R-ST0601-ENCODE-39: the Reserved code is never written.
        (View::OutOfRange, _) => return Err(ctx.err(ErrorKind::NotAllowed, "this item has no Out of Range indicator")),
        _ => {}
    }
    let half = range / 2.0;
    let mut x = ctx.real(v)?;
    if wraps(tag) {
        x = wrap_angle(x, -half, half);
    }
    if !(-half..=half).contains(&x) {
        if let Special::OutOfRange = special {
            // R-ST0601-ENCODE-37: never clamped, never rejected.
            ctx.warn("value outside the range written as the Out of Range indicator");
            indicator(out);
            return Ok(());
        }
        if corner_offset(tag) {
            return Err(ctx.err(ErrorKind::OutOfRange, "corner offset beyond +/-0.075 deg: report items 82 to 89 instead"));
        }
        x = ctx.in_range(x, -half, half)?;
    }
    let span = span_s(len);
    let code = (x * span / range).round().clamp(-span / 2.0, span / 2.0) as i64;
    put_uint_n(out, code as u64, len);
    Ok(())
}

/// An enumeration code: by number, or by the standard's label.
fn code_of(ctx: &Ctx<'_>, v: View<'_>, labels: &Labels) -> Result<u64, EncodeError> {
    let code = match v {
        View::Text(name) => labels
            .names
            .iter()
            .position(|&n| n == name)
            .map(|i| i as u64)
            .ok_or_else(|| ctx.err(ErrorKind::InvalidCode, "no code has this label"))?,
        _ => ctx.integer(v)?,
    };
    match labels.label(code) {
        Some("Reserved") | None => Err(ctx.err(ErrorKind::InvalidCode, "code not defined by the standard")),
        Some(_) => Ok(code),
    }
}

/// Items 48, 73, 74, 100, 101 (R-ST0601-ENCODE-60, -61): the nested set's
/// items, no key, no length, no checksum.
fn nested_set(standard: Standard, v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match v {
        View::Set(b) | View::Bytes(b) if !b.is_empty() => {
            well_formed_set(ctx, b)?;
            out.extend_from_slice(b);
            Ok(())
        }
        View::Set(_) | View::Bytes(_) => Err(ctx.err(ErrorKind::NotAllowed, "empty set: use unknown")),
        View::Packet(p) if p.standard != standard => Err(ctx.err(ErrorKind::WrongType, "nested set of the wrong standard")),
        View::Packet(p) => match standard {
            Standard::St0102 => crate::st0102::encode::encode_set(p, ctx, out),
            Standard::St0903 => crate::st0903::encode::encode_set(p, ctx, out),
            // ST 0806 and Segment/Amend come with phase 7 (MUXING_PLAN.md
            // 6.1); until then their bytes pass through.
            _ => Err(ctx.err(ErrorKind::Unsupported, "pass this set's encoded items with Input::Set or set_raw")),
        },
        _ => Err(ctx.err(ErrorKind::WrongType, "expected a nested set")),
    }
}

/// Encoded set items must at least frame as a local set (BER-OID tags, BER
/// lengths, nothing left over), so no packet the encoder writes is
/// unreadable. `set_raw` is the unchecked path.
fn well_formed_set(ctx: &Ctx<'_>, b: &[u8]) -> Result<(), EncodeError> {
    if crate::klv::local_set(b).all(|item| item.is_ok()) {
        Ok(())
    } else {
        Err(ctx.err(ErrorKind::WrongType, "not well-formed local set items (tag, BER length, value)"))
    }
}

// ------------------------------------------------------------------- packs

/// A required pack field; the error names the field.
fn need<'a>(ctx: &Ctx<'_>, fields: &'a [Field], name: &'static str) -> Result<View<'a>, EncodeError> {
    match get(fields, name) {
        Some(v) if !matches!(v, Value::Unknown) => Ok(View::value(v)),
        _ => Err(ctx.err(ErrorKind::Missing, name)),
    }
}

/// An optional pack field (absent or unknown is `None`).
fn opt<'a>(fields: &'a [Field], name: &str) -> Option<View<'a>> {
    match get(fields, name) {
        Some(Value::Unknown) | None => None,
        Some(v) => Some(View::value(v)),
    }
}

fn fields<'a>(ctx: &Ctx<'_>, v: View<'a>) -> Result<&'a [Field], EncodeError> {
    match v {
        View::Struct(f) => Ok(f),
        _ => Err(ctx.err(ErrorKind::WrongType, "expected a pack (Value::Struct)")),
    }
}

fn list<'a>(ctx: &Ctx<'_>, v: View<'a>) -> Result<&'a [Value], EncodeError> {
    match v {
        View::List(l) => Ok(l),
        _ => Err(ctx.err(ErrorKind::WrongType, "expected a list (Value::List)")),
    }
}

/// An integer field in `0..=hi`.
fn small(ctx: &Ctx<'_>, v: View<'_>, hi: u64) -> Result<u64, EncodeError> {
    let x = ctx.integer(v)?;
    if x > hi {
        return Err(ctx.err(ErrorKind::OutOfRange, "pack field out of range"));
    }
    Ok(x)
}

/// A 0/1 flag field.
fn bit(ctx: &Ctx<'_>, v: Option<View<'_>>) -> Result<u64, EncodeError> {
    match v {
        None => Ok(0),
        Some(v) => match ctx.integer(v)? {
            x @ (0 | 1) => Ok(x),
            _ => Err(ctx.err(ErrorKind::InvalidCode, "flag must be 0 or 1")),
        },
    }
}

/// Text of a pack field into a scratch buffer.
fn pack_text(ctx: &mut Ctx<'_>, v: View<'_>, max: usize) -> Result<Vec<u8>, EncodeError> {
    let mut b = Vec::new();
    ctx.text(v, max, &mut b)?;
    Ok(b)
}

fn pack(tag: Tag, v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match tag {
        Tag::GenericFlagData => generic_flags(v, ctx, out),
        Tag::WeaponLoad => {
            let f = fields(ctx, v)?;
            let n = |name| need(ctx, f, name).and_then(|v| small(ctx, v, 15));
            out.push(((n("Station Number")? << 4) | n("Substation Number")?) as u8);
            out.push(((n("Weapon Type")? << 4) | n("Weapon Variant")?) as u8);
            Ok(())
        }
        Tag::WeaponFired => {
            let f = fields(ctx, v)?;
            let n = |name| need(ctx, f, name).and_then(|v| small(ctx, v, 15));
            out.push(((n("Station Number")? << 4) | n("Substation Number")?) as u8);
            Ok(())
        }
        Tag::LaserPrfCode => {
            // 8.62: three or four digits, each 1 to 8 (R-ST0601-ENCODE-42).
            let code = ctx.integer(v)?;
            let mut rest = code;
            let mut ok = (111..=8888).contains(&code);
            while ok && rest > 0 {
                ok = matches!(rest % 10, 1..=8);
                rest /= 10;
            }
            if !ok {
                return Err(ctx.err(ErrorKind::InvalidCode, "laser PRF code must be 3 or 4 digits of 1 to 8"));
            }
            put_uint_n(out, code, 2);
            Ok(())
        }
        Tag::ImageHorizonPixelPack => horizon(v, ctx, out),
        Tag::MiisCoreIdentifier => match v {
            View::Bytes(b) | View::Set(b) => {
                if let Value::Invalid(why) = crate::st1204::decode(b) {
                    return Err(ctx.err(ErrorKind::InvalidCode, why));
                }
                out.extend_from_slice(b);
                Ok(())
            }
            _ => crate::st1204::encode::encode_value(v, ctx, out),
        },
        // ST 1010 SDCC-FLP: phase 7; recorded bytes pass through.
        Tag::SdccFlp => match v {
            View::Bytes(b) | View::Set(b) if !b.is_empty() => {
                if let Value::Invalid(why) = crate::st1010::decode_with(b, &crate::Config::default()) {
                    return Err(ctx.err(ErrorKind::InvalidCode, why));
                }
                out.extend_from_slice(b);
                Ok(())
            }
            _ => Err(ctx.err(ErrorKind::Unsupported, "pass the SDCC-FLP bytes with Input::Bytes or set_raw")),
        },
        Tag::ControlCommand => {
            // 8.115.1, Table 7, D-25.
            let f = fields(ctx, v)?;
            let id = ctx.integer(need(ctx, f, "Command ID")?)?;
            let text = pack_text(ctx, need(ctx, f, "Command String")?, 127)?;
            put_oid(out, id);
            put_prefixed(out, &text);
            if let Some(t) = opt(f, "Command Time") {
                match t {
                    View::Time(t) | View::Uint(t) => put_uint_n(out, t, 8),
                    _ => return Err(ctx.err(ErrorKind::WrongType, "Command Time")),
                }
            }
            Ok(())
        }
        Tag::ControlCommandVerificationList => oid_list(v, ctx, out, |_, id| Ok(id)),
        Tag::ActiveWavelengthList => {
            let l = list(ctx, v)?;
            // R-ST0601-ENCODE-77: ID 0 is alone.
            if l.len() > 1 && l.iter().any(|x| matches!(View::value(x), View::Code(0) | View::Uint(0))) {
                return Err(ctx.err(ErrorKind::InvalidCode, "wavelength ID 0 must be the only ID"));
            }
            oid_list(v, ctx, out, |ctx, id| match WAVELENGTHS.label(id) {
                // R-ST0601-ENCODE-39: 7 to 20 are reserved.
                Some("Reserved") => Err(ctx.err(ErrorKind::InvalidCode, "wavelength IDs 7 to 20 are reserved")),
                _ => Ok(id),
            })
        }
        Tag::CountryCodes => country_codes(v, ctx, out),
        Tag::PositioningMethodSource => {
            // 8.124, Table 10: one byte, at least one bit (R-ST0601-ENCODE-42).
            let bits = match v {
                View::List(l) => {
                    let mut b = 0u64;
                    for x in l {
                        b |= 1 << small(ctx, View::value(x), 7)?;
                    }
                    b
                }
                _ => small(ctx, v, 0xFF)?,
            };
            if bits == 0 {
                return Err(ctx.err(ErrorKind::InvalidCode, "at least one positioning method must be set"));
            }
            out.push(bits as u8);
            Ok(())
        }
        Tag::SensorFrameRatePack => {
            // 8.127.1, D-19: a denominator of 1 is omitted, 0 never written.
            let f = fields(ctx, v)?;
            let num = ctx.integer(need(ctx, f, "Numerator")?)?;
            let den = match opt(f, "Denominator") {
                Some(d) => ctx.integer(d)?,
                None => 1,
            };
            if den == 0 {
                return Err(ctx.err(ErrorKind::OutOfRange, "frame rate denominator is zero"));
            }
            put_oid(out, num);
            if den != 1 {
                put_oid(out, den);
            }
            Ok(())
        }
        Tag::WavelengthsList => records(v, ctx, out, |f, ctx, rec| {
            put_oid(rec, ctx.integer(need(ctx, f, "Wavelength ID")?)?);
            ctx.imapb(need(ctx, f, "Minimum Wavelength")?, 0.0, 1e9, 4, false, rec)?;
            ctx.imapb(need(ctx, f, "Maximum Wavelength")?, 0.0, 1e9, 4, false, rec)?;
            ctx.text(need(ctx, f, "Wavelength Name")?, 127, rec)
        }),
        Tag::AirbaseLocations => {
            // 8.130.1, D-19: the recovery location is left out when it
            // equals the take-off location.
            let f = fields(ctx, v)?;
            let take_off = get(f, "Take-off Location").ok_or_else(|| ctx.err(ErrorKind::Missing, "Take-off Location"))?;
            let recovery = get(f, "Recovery Location");
            let mut loc = Vec::new();
            optional_location(take_off, ctx, &mut loc)?;
            put_prefixed(out, &loc);
            if let Some(r) = recovery {
                if !crate::encode::same_value(r, take_off) {
                    loc.clear();
                    optional_location(r, ctx, &mut loc)?;
                    put_prefixed(out, &loc);
                }
            }
            Ok(())
        }
        Tag::PayloadList => {
            let f = fields(ctx, v)?;
            put_oid(out, ctx.integer(need(ctx, f, "Payload Count")?)?);
            let recs = need(ctx, f, "Payload Records")?;
            records(recs, ctx, out, |f, ctx, rec| {
                put_oid(rec, ctx.integer(need(ctx, f, "Payload ID")?)?);
                put_oid(rec, code_of(ctx, need(ctx, f, "Payload Type")?, &PAYLOAD_TYPES)?);
                let name = pack_text(ctx, need(ctx, f, "Payload Name")?, 127)?;
                put_prefixed(rec, &name);
                Ok(())
            })
        }
        Tag::ActivePayloads => {
            // 8.139.1: bit n counted from the end; the fewest bytes, 00 for
            // none.
            let l = list(ctx, v)?;
            let mut bytes: Vec<u8> = vec![0];
            for x in l {
                let id = ctx.integer(View::value(x))?;
                let byte = usize::try_from(id / 8).map_err(|_| ctx.err(ErrorKind::OutOfRange, "payload ID too large"))?;
                if byte >= 1 << 16 {
                    return Err(ctx.err(ErrorKind::OutOfRange, "payload ID too large"));
                }
                if bytes.len() <= byte {
                    bytes.resize(byte + 1, 0);
                }
                bytes[byte] |= 1 << (id % 8);
            }
            out.extend(bytes.iter().rev());
            Ok(())
        }
        Tag::WeaponsStores => records(v, ctx, out, |f, ctx, rec| {
            for name in ["Station ID", "Hardpoint ID", "Carriage ID", "Store ID"] {
                put_oid(rec, ctx.integer(need(ctx, f, name)?)?);
            }
            // 8.140.1, Figure 78: general status in bits 0-7, engagement
            // flags in bits 8-11.
            let general = code_of(ctx, need(ctx, f, "General Status")?, &GENERAL_STATUS)?;
            let status = general
                | bit(ctx, opt(f, "Fuze Enabled"))? << 8
                | bit(ctx, opt(f, "Laser Enabled"))? << 9
                | bit(ctx, opt(f, "Target Enabled"))? << 10
                | bit(ctx, opt(f, "Weapon Armed"))? << 11;
            put_oid(rec, status);
            let kind = pack_text(ctx, need(ctx, f, "Weapon Type")?, 127)?;
            put_prefixed(rec, &kind);
            Ok(())
        }),
        Tag::WaypointList => records(v, ctx, out, |f, ctx, rec| {
            put_oid(rec, ctx.integer(need(ctx, f, "Waypoint ID")?)?);
            let order = ctx.signed_integer(need(ctx, f, "Prosecution Order")?)?;
            let order = i16::try_from(order).map_err(|_| ctx.err(ErrorKind::OutOfRange, "Prosecution Order"))?;
            rec.extend_from_slice(&order.to_be_bytes());
            let mode = opt(f, "Mode");
            let source = opt(f, "Source");
            let location = get(f, "Location");
            // Info and location may only be truncated from the end.
            if mode.is_some() || source.is_some() || location.is_some() {
                if location.is_some() && (mode.is_none() || source.is_none()) {
                    return Err(ctx.err(ErrorKind::Missing, "Mode and Source (needed before Location)"));
                }
                put_oid(rec, bit(ctx, mode)? | bit(ctx, source)? << 1);
            }
            if let Some(l) = location {
                location_dlp(l, ctx, rec)?;
            }
            Ok(())
        }),
        Tag::ViewDomain => view_domain(v, ctx, out),
        Tag::MetadataSubstreamIdPack => {
            // 8.143.1 (ST 0601.19-46, -47).
            let f = fields(ctx, v)?;
            let local = ctx.integer(need(ctx, f, "Local Id")?)?;
            put_oid(out, local);
            match (local, opt(f, "Universal Id")) {
                (0, Some(View::Text(s))) => {
                    out.extend_from_slice(&parse_uuid(s).ok_or_else(|| ctx.err(ErrorKind::WrongType, "Universal Id"))?)
                }
                (0, _) => return Err(ctx.err(ErrorKind::Missing, "Universal Id")),
                (_, None) => {}
                (_, Some(_)) => return Err(ctx.err(ErrorKind::NotAllowed, "a nonzero Local Id takes no Universal Id")),
            }
            Ok(())
        }
        _ => Err(ctx.err(ErrorKind::Unsupported, "no pack encoder for this item")),
    }
}

/// Item 47 (Table 3, R-ST0601-ENCODE-42): one byte, bits 6 and 7 zero.
fn generic_flags(v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let byte = match v {
        View::Struct(f) => {
            let mut b = 0u8;
            for (i, &(name, _, _)) in GENERIC_FLAGS.iter().enumerate() {
                b |= (bit(ctx, opt(f, name))? as u8) << i;
            }
            b
        }
        _ => {
            let x = ctx.integer(v)?;
            if x > 0x3F {
                return Err(ctx.err(ErrorKind::InvalidCode, "generic flag data bits 6 and 7 must be 0"));
            }
            x as u8
        }
    };
    out.push(byte);
    Ok(())
}

/// Item 81 (Table 6, D-24): four percentages, then all four geographic
/// values or none.
fn horizon(v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let f = fields(ctx, v)?;
    for name in ["Start x0", "Start y0", "End x1", "End y1"] {
        let p = need(ctx, f, name)?;
        // D-06: the percentages round to the nearest unit.
        let x = match p {
            View::Float(_) => ctx.rounded(p, 0.0, 100.0)? as u64,
            _ => small(ctx, p, 100)?,
        };
        out.push(x as u8);
    }
    const GEO: [(&str, f64); 4] =
        [("Start Latitude", 180.0), ("Start Longitude", 360.0), ("End Latitude", 180.0), ("End Longitude", 360.0)];
    let present = GEO.iter().filter(|(name, _)| opt(f, name).is_some()).count();
    match present {
        0 => Ok(()),
        4 => {
            for &(name, range) in &GEO {
                // The "error" indicator stands for a point that cannot be
                // computed (D-24).
                match need(ctx, f, name)? {
                    View::OutOfRange => out.extend_from_slice(&[0x80, 0, 0, 0]),
                    g => {
                        let x = ctx.real(g)?;
                        let x = ctx.in_range(x, -range / 2.0, range / 2.0)?;
                        let code = (x * S32 / range).round().clamp(-S32 / 2.0, S32 / 2.0) as i64;
                        put_uint_n(out, code as u64, 4);
                    }
                }
            }
            Ok(())
        }
        _ => Err(ctx.err(ErrorKind::Missing, "all four horizon latitudes and longitudes, or none")),
    }
}

/// Items 116 and 121: BER-OIDs back to back, at least one.
fn oid_list(
    v: View<'_>,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
    check: impl Fn(&Ctx<'_>, u64) -> Result<u64, EncodeError>,
) -> Result<(), EncodeError> {
    let l = list(ctx, v)?;
    if l.is_empty() {
        return Err(ctx.err(ErrorKind::Missing, "at least one identifier"));
    }
    for x in l {
        let id = ctx.integer(View::value(x))?;
        put_oid(out, check(ctx, id)?);
    }
    Ok(())
}

/// Item 122 (Table 9, D-19).
fn country_codes(v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let f = fields(ctx, v)?;
    let method = ctx.integer(need(ctx, f, "Coding Method")?)?;
    match country_coding_method(method) {
        // ST 0102 tag 12 table; "Omitted Value" codes are never written
        // (R-NESTED-ENCODE-028 applies to the same table).
        Some("Omitted Value") | None => return Err(ctx.err(ErrorKind::InvalidCode, "country coding method")),
        Some(_) => {}
    }
    let mut m = Vec::new();
    put_uint_min(&mut m, method);
    put_prefixed(out, &m);
    let names = ["Overflight Country", "Operator Country", "Country of Manufacture"];
    let last = names.iter().rposition(|n| opt(f, n).is_some()).unwrap_or(0);
    for name in &names[..=last] {
        match opt(f, name) {
            Some(c) => {
                let t = pack_text(ctx, c, 127)?;
                put_prefixed(out, &t);
            }
            // An unknown country is a zero length.
            None => out.push(0),
        }
    }
    Ok(())
}

/// A list of BER-length-prefixed records (items 128, 138, 140, 141).
fn records(
    v: View<'_>,
    ctx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
    record: impl Fn(&[Field], &mut Ctx<'_>, &mut Vec<u8>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    let l = list(ctx, v)?;
    let mut rec = Vec::new();
    for x in l {
        let View::Struct(f) = View::value(x) else {
            return Err(ctx.err(ErrorKind::WrongType, "expected a record (Value::Struct)"));
        };
        rec.clear();
        record(f, ctx, &mut rec)?;
        put_prefixed(out, &rec);
    }
    Ok(())
}

/// A location (Table 16): latitude IMAPB(-90, 90, 4), longitude
/// IMAPB(-180, 180, 4), optional HAE IMAPB(-900, 9000, 3).
fn location_dlp(v: &Value, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let f = fields(ctx, View::value(v))?;
    ctx.imapb(need(ctx, f, "Latitude")?, -90.0, 90.0, 4, false, out)?;
    ctx.imapb(need(ctx, f, "Longitude")?, -180.0, 180.0, 4, false, out)?;
    if let Some(h) = opt(f, "HAE") {
        ctx.imapb(h, -900.0, 9_000.0, 3, false, out)?;
    }
    Ok(())
}

/// A location whose zero length means unknown (8.130.1).
fn optional_location(v: &Value, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match v {
        Value::Unknown => Ok(()),
        _ => location_dlp(v, ctx, out),
    }
}

/// Item 142 (Table 25, D-19): pairs of start and range, `n` bytes each
/// (default 3); an unknown pair has length 0; trailing unknown pairs are
/// left out.
fn view_domain(v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    const PAIRS: [(&str, &str, f64, f64); 3] = [
        ("Azimuth Start", "Azimuth Range", 0.0, 360.0),
        ("Elevation Start", "Elevation Range", -180.0, 180.0),
        ("Roll Start", "Roll Range", 0.0, 360.0),
    ];
    let f = fields(ctx, v)?;
    let known = |(start, range, _, _): &(&str, &str, f64, f64)| opt(f, start).is_some() || opt(f, range).is_some();
    let Some(last) = PAIRS.iter().rposition(known) else {
        return Err(ctx.err(ErrorKind::Missing, "at least one view domain pair (or use unknown)"));
    };
    let mut pair = Vec::new();
    for &(start, range, min, max) in &PAIRS[..=last] {
        pair.clear();
        match (opt(f, start), opt(f, range)) {
            (None, None) => {}
            (Some(s), Some(r)) => {
                ctx.imapb(s, min, max, 3, true, &mut pair)?;
                ctx.imapb(r, 0.0, 360.0, 3, false, &mut pair)?;
            }
            _ => return Err(ctx.err(ErrorKind::Missing, "both the start and the range of a view domain pair")),
        }
        put_prefixed(out, &pair);
    }
    Ok(())
}

/// A UUID in 8-4-4-4-12 hex form (either case).
fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if hex.len() != 32 || s.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        let d = |c: u8| (c as char).to_digit(16);
        out[i] = (d(pair[0])? * 16 + d(pair[1])?) as u8;
    }
    Some(out)
}

/// The JSON Schema of one item's authoring value (feature `json`), from
/// its codec.
#[cfg(feature = "json")]
pub(crate) fn tag_schema(tag: Tag) -> serde_json::Value {
    use serde_json::json;
    let d = tag.desc();
    let nullable = |mut s: serde_json::Value| {
        let one_of = json!([s.take(), {"type": "null"}, {"type": "object", "required": ["special"]}]);
        json!({"oneOf": one_of})
    };
    let body = match d.codec {
        Codec::Uint(len) | Codec::Int(len) => {
            let n = match len {
                Len::Exact(n) | Len::UpTo(n) => n,
            };
            if matches!(d.codec, Codec::Uint(_)) {
                json!({"type": "integer", "minimum": 0, "maximum": max_uint(n)})
            } else {
                let (lo, hi) = int_range(n);
                json!({"type": "integer", "minimum": lo, "maximum": hi})
            }
        }
        Codec::Time(_) => json!({"type": ["integer", "string"], "description": "MISP microseconds or an RFC 3339 instant"}),
        Codec::Scaled { len, factor } => json!({"type": "number", "minimum": 0, "maximum": max_uint(len) * factor}),
        Codec::Unsigned { range, offset, .. } => json!({"type": "number", "minimum": offset, "maximum": offset + range}),
        Codec::Signed { range, .. } => json!({"type": "number", "minimum": -range / 2.0, "maximum": range / 2.0}),
        Codec::Imapb { min, max, .. } => json!({"type": "number", "minimum": min, "maximum": max}),
        Codec::Text => json!({"type": "string", "maxLength": text_max(tag)}),
        Codec::Enum(labels) => {
            let codes: Vec<u64> = (0..labels.names.len() as u64).collect();
            json!({"oneOf": [{"type": "integer", "enum": codes}, {"type": "string", "enum": labels.names}]})
        }
        Codec::Set(_) => json!({"type": "object", "description": "the nested set: ST 0102 items for tag 48, the decoder's JSON of a set, or {\"hex\": ..}"}),
        Codec::Bytes => json!({"type": "object", "required": ["hex"]}),
        Codec::Pack(_) => json!({"type": ["object", "array", "integer"], "description": "fields as the decoder names them (see the Tag documentation)"}),
    };
    let mut s = nullable(body);
    let units = if d.units.is_empty() { String::new() } else { format!(" ({})", d.units) };
    s["description"] = json!(format!("Tag {}: {}{}", tag as u64, d.name, units));
    s
}
