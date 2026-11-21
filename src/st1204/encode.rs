//! MISB ST 1204.3 MIIS Core Identifier encoding (feature `encode`): the
//! binary form of ST 1204.3 section 7.4.1 that ST 0601 tag 94 and ST 0903
//! tag 13 carry, and the canonical text form of section 7.4.2
//! (`docs/standards/nested-encode.md` section I, rules R-NESTED-ENCODE-160
//! to -168, decision D-29).
//!
//! [`CoreIdentifier`] holds the identifiers themselves; the usage value and
//! the order of the UUIDs are derived from them, never given separately
//! (D-29), so the usage byte always announces exactly the UUIDs that follow.
//!
//! ```
//! use misb::st1204::encode::{CoreIdentifier, IdType};
//! // ST 1204.3 section 7.4: physical sensor, virtual platform.
//! let text = "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/\
//!             16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3";
//! let id: CoreIdentifier = text.parse()?;
//! assert_eq!(id.sensor.map(|(kind, _)| kind), Some(IdType::Physical));
//! assert_eq!(id.usage(), 0x70);
//! let binary = id.encode()?;
//! assert_eq!(&binary[..2], &[0x01, 0x70]);
//! assert_eq!(binary.len(), 34);
//! assert_eq!(id.to_string(), text);
//! # Ok::<(), misb::encode::EncodeError>(())
//! ```

use super::{check_value, uuid_text, CoreId, UUID_LEN, VERSION};
use crate::encode::{field, Ctx, EncodeError, EncodeOptions, ErrorKind, View, Warning};
use crate::{Field, Standard, Value};
use std::fmt;
use std::str::FromStr;

/// How a sensor or platform identifier was assigned (ST 1204.3 section
/// 7.3.1, Table 3; the two-bit code of the usage value).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum IdType {
    /// `01` Managed: assigned by a managing authority.
    Managed = 1,
    /// `10` Virtual: computed or assigned in software.
    Virtual = 2,
    /// `11` Physical: tied to the hardware.
    Physical = 3,
}

impl IdType {
    /// The type with this two-bit code (1 to 3; 0 means no identifier).
    #[must_use]
    pub fn from_code(code: u8) -> Option<IdType> {
        Some(match code {
            1 => IdType::Managed,
            2 => IdType::Virtual,
            3 => IdType::Physical,
            _ => return None,
        })
    }

    /// The two-bit code of the usage value.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// A MISB ST 1204.3 MIIS Core Identifier.
///
/// Either a Foundational Core Identifier (a sensor ID, a platform ID and a
/// window ID, any combination but none at all) or a Minor Core Identifier
/// alone (ST 1204.3 section 7.1). Each identifier is a 16-byte UUID in
/// network byte order.
///
/// [`CoreIdentifier::encode`] writes the binary form (version `01`, the
/// derived usage value, the UUIDs in the order sensor, platform, window,
/// R-NESTED-ENCODE-160 to -163; no check value, -167) and checks the
/// identifiers as D-29 asks: at least one identifier, a Minor ID never with
/// a Foundational one (-164), no nil UUID (-166), and UUID versions 1, 4 or
/// 5 with the RFC 4122 variant (-165; a warning instead of an error under
/// [`crate::encode::Policy::Clamp`]). The text form ([`fmt::Display`],
/// [`str::parse`]) is the canonical one of section 7.4.2 with its check
/// value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CoreIdentifier {
    /// Sensor ID and how it was assigned.
    pub sensor: Option<(IdType, [u8; 16])>,
    /// Platform ID and how it was assigned.
    pub platform: Option<(IdType, [u8; 16])>,
    /// Window ID.
    pub window: Option<[u8; 16]>,
    /// Minor ID (a Minor Core Identifier: nothing else may be set).
    pub minor: Option<[u8; 16]>,
}

impl CoreIdentifier {
    /// An identifier with no component; add them with the `with_` methods.
    #[must_use]
    pub fn new() -> CoreIdentifier {
        CoreIdentifier::default()
    }

    /// A Minor Core Identifier.
    #[must_use]
    pub fn minor_id(id: [u8; 16]) -> CoreIdentifier {
        CoreIdentifier { minor: Some(id), ..CoreIdentifier::default() }
    }

    /// The same identifier with this sensor ID.
    #[must_use]
    pub fn with_sensor(mut self, kind: IdType, id: [u8; 16]) -> CoreIdentifier {
        self.sensor = Some((kind, id));
        self
    }

    /// The same identifier with this platform ID.
    #[must_use]
    pub fn with_platform(mut self, kind: IdType, id: [u8; 16]) -> CoreIdentifier {
        self.platform = Some((kind, id));
        self
    }

    /// The same identifier with this window ID.
    #[must_use]
    pub fn with_window(mut self, id: [u8; 16]) -> CoreIdentifier {
        self.window = Some(id);
        self
    }

    /// The usage value these identifiers give (ST 1204.3 Table 3,
    /// R-NESTED-ENCODE-161): bit 7 zero, bits 6-5 the sensor ID type, bits
    /// 4-3 the platform ID type, bit 2 window ID, bit 1 minor ID, bit 0 zero.
    #[must_use]
    pub fn usage(&self) -> u8 {
        let kind = |c: Option<(IdType, [u8; 16])>| c.map_or(0, |(k, _)| k.code());
        (kind(self.sensor) << 5)
            | (kind(self.platform) << 3)
            | (u8::from(self.window.is_some()) << 2)
            | (u8::from(self.minor.is_some()) << 1)
    }

    /// The UUIDs in wire order (R-NESTED-ENCODE-163: sensor, platform,
    /// window, each when present; or the minor ID).
    fn ids(&self) -> impl Iterator<Item = &[u8; 16]> + '_ {
        let s = self.sensor.as_ref().map(|(_, id)| id);
        let p = self.platform.as_ref().map(|(_, id)| id);
        s.into_iter().chain(p).chain(self.window.as_ref()).chain(self.minor.as_ref())
    }

    /// The binary Core Identifier with default options. Errors name ST
    /// 0601 tag 94.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut warnings = Vec::new();
        self.encode_with(&EncodeOptions::default(), &mut warnings)
    }

    /// As [`CoreIdentifier::encode`], under `opts` and collecting warnings.
    pub fn encode_with(&self, opts: &EncodeOptions, warnings: &mut Vec<Warning>) -> Result<Vec<u8>, EncodeError> {
        let mut ctx = Ctx::new(opts, warnings, Standard::St0601);
        ctx.tag = Some(94);
        let mut out = Vec::with_capacity(2 + 3 * UUID_LEN);
        self.write(&mut ctx, &mut out)?;
        Ok(out)
    }

    /// Check the identifiers (D-29) and write the binary form into `out`.
    pub(crate) fn write(&self, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let foundational = self.sensor.is_some() || self.platform.is_some() || self.window.is_some();
        // R-NESTED-ENCODE-162, ST 1204.3 section 7.1 EBNF: never no
        // identifier at all.
        if !foundational && self.minor.is_none() {
            return Err(ctx.err(ErrorKind::Missing, "a Core Identifier needs at least one identifier (R-NESTED-ENCODE-162)"));
        }
        // R-NESTED-ENCODE-164, ST 1204.1-28.
        if foundational && self.minor.is_some() {
            return Err(ctx.err(
                ErrorKind::NotAllowed,
                "a Minor ID is never combined with a sensor, platform or window ID (R-NESTED-ENCODE-164)",
            ));
        }
        for id in self.ids() {
            check_uuid(ctx, id)?;
        }
        // R-NESTED-ENCODE-160: version 1 as a one-byte BER-OID.
        out.push(VERSION as u8);
        out.push(self.usage());
        for id in self.ids() {
            out.extend_from_slice(id);
        }
        Ok(())
    }

    /// Read a binary Core Identifier (the value of ST 0601 tag 94 or ST
    /// 0903 tag 13), checked against the EBNF of ST 1204.3 section 7.1 as
    /// the decoder checks it.
    pub fn from_bytes(bytes: &[u8]) -> Result<CoreIdentifier, EncodeError> {
        let err = |reason| EncodeError::new(Standard::St0601, Some(94), ErrorKind::InvalidCode, reason);
        let id = CoreId::parse(bytes).map_err(err)?;
        let mut out = CoreIdentifier::default();
        let sensor = IdType::from_code((id.usage >> 5) & 0x03);
        let platform = IdType::from_code((id.usage >> 3) & 0x03);
        for (name, uuid) in id.ids.iter().flatten() {
            let uuid: [u8; 16] = (*uuid).try_into().map_err(|_| err("Core Identifier UUID is not 16 bytes"))?;
            match (*name, sensor, platform) {
                ("Sensor ID", Some(k), _) => out.sensor = Some((k, uuid)),
                ("Platform ID", _, Some(k)) => out.platform = Some((k, uuid)),
                ("Window ID", _, _) => out.window = Some(uuid),
                ("Minor ID", _, _) => out.minor = Some(uuid),
                _ => return Err(err("Core Identifier usage value does not match its UUIDs")),
            }
        }
        Ok(out)
    }

    /// Read the canonical text form of ST 1204.3 section 7.4.2, Table 8:
    /// `VVUU:ID/ID/ID:CC`, hex digits in either case, each UUID as 32 hex
    /// digits (dashes are ignored), and the Appendix B check value `CC`,
    /// which must match.
    pub fn parse(text: &str) -> Result<CoreIdentifier, EncodeError> {
        let err = |reason| EncodeError::new(Standard::St0601, Some(94), ErrorKind::InvalidCode, reason);
        let (head, rest) = text.split_once(':').ok_or_else(|| err("Core Identifier text needs ':' after VVUU"))?;
        let (ids, check) = rest.rsplit_once(':').ok_or_else(|| err("Core Identifier text needs ':' before its check value"))?;
        let mut bytes = hex(head).filter(|b| b.len() == 2).ok_or_else(|| err("Core Identifier text must start with 4 hex digits"))?;
        let check = match hex(check).as_deref() {
            Some(&[c]) => c,
            _ => return Err(err("Core Identifier check value must be 2 hex digits")),
        };
        // Section 7.4.2: the check value covers the hex digits before it.
        let body = &text[..text.len() - 3];
        if check_value(body) != check {
            return Err(err("Core Identifier check value does not match (ST 1204.3 Appendix B)"));
        }
        for id in ids.split('/') {
            let digits: String = id.chars().filter(|&c| c != '-').collect();
            match hex(&digits) {
                Some(b) if b.len() == UUID_LEN => bytes.extend_from_slice(&b),
                _ => return Err(err("Core Identifier UUID must be 32 hex digits")),
            }
        }
        CoreIdentifier::from_bytes(&bytes)
    }

    /// The canonical text form (ST 1204.3 section 7.4.2): upper case hex,
    /// UUIDs in groups of four, the Appendix B check value at the end.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = format!("{:02X}{:02X}:", VERSION, self.usage());
        for (i, id) in self.ids().enumerate() {
            if i > 0 {
                text.push('/');
            }
            text.push_str(&uuid_text(id));
        }
        let check = check_value(&text);
        text.push_str(&format!(":{check:02X}"));
        text
    }

    /// The identifier described by a decoded [`Value::Struct`] (the fields
    /// the decoder produces; the derived ones, `Canonical`, `Version`,
    /// `Usage Value` and `Check Value`, must agree with the identifiers
    /// when present) or by its canonical [`Value::Text`].
    pub(crate) fn from_view(v: View<'_>, ctx: &Ctx<'_>) -> Result<CoreIdentifier, EncodeError> {
        let relabel = |e: EncodeError| ctx.err(e.kind, e.reason);
        match v {
            View::Text(s) => CoreIdentifier::parse(s).map_err(relabel),
            View::Bytes(b) => CoreIdentifier::from_bytes(b).map_err(relabel),
            View::Struct(fields) => from_fields(fields, ctx),
            _ => Err(ctx.err(ErrorKind::WrongType, "expected a Core Identifier (struct, canonical text or bytes)")),
        }
    }
}

impl fmt::Display for CoreIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl FromStr for CoreIdentifier {
    type Err = EncodeError;

    fn from_str(s: &str) -> Result<CoreIdentifier, EncodeError> {
        CoreIdentifier::parse(s)
    }
}

/// The bytes of an even number of hex digits (either case).
fn hex(s: &str) -> Option<Vec<u8>> {
    let digits = s.as_bytes();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    digits
        .chunks(2)
        .map(|p| {
            let d = |c: u8| (c as char).to_digit(16);
            Some((d(p[0])? * 16 + d(p[1])?) as u8)
        })
        .collect()
}

/// R-NESTED-ENCODE-165, -166 (D-29): no nil UUID; versions 1, 4 and 5 with
/// the RFC 4122 variant (error when strict, warning otherwise).
fn check_uuid(ctx: &mut Ctx<'_>, id: &[u8; 16]) -> Result<(), EncodeError> {
    if id.iter().all(|&b| b == 0) {
        return Err(ctx.err(
            ErrorKind::InvalidCode,
            "nil UUID: temporary identifiers never leave the platform (R-NESTED-ENCODE-166)",
        ));
    }
    let version = id[6] >> 4;
    let variant = id[8] >> 6;
    if !matches!(version, 1 | 4 | 5) || variant != 0b10 {
        let reason = "UUID is not version 1, 4 or 5 with the RFC 4122 variant (R-NESTED-ENCODE-165)";
        if ctx.strict() {
            return Err(ctx.err(ErrorKind::InvalidCode, reason));
        }
        ctx.warn(reason);
    }
    Ok(())
}

/// A UUID from the decoder's text (`F592-F023-...`, or RFC 4122 form) or
/// from 16 bytes.
fn uuid_of(ctx: &Ctx<'_>, v: &Value) -> Result<[u8; 16], EncodeError> {
    let bad = || ctx.err(ErrorKind::WrongType, "Core Identifier UUID must be 32 hex digits or 16 bytes");
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| bad()),
        Value::Text(s) => {
            let digits: String = s.chars().filter(|&c| c != '-').collect();
            hex(&digits).and_then(|b| b.try_into().ok()).ok_or_else(bad)
        }
        _ => Err(bad()),
    }
}

/// The two-bit or one-bit type code of a decoded `... ID Type` field: an
/// enumeration code, an integer or the label.
fn type_code(ctx: &Ctx<'_>, v: &Value, labels: &[&str]) -> Result<u8, EncodeError> {
    let code = match v {
        Value::Text(s) => labels.iter().position(|l| *l == s.as_str()).map(|i| i as u64),
        Value::Enum { code, .. } | Value::Uint(code) => Some(*code),
        _ => None,
    };
    match code {
        Some(c) if (c as usize) < labels.len() => Ok(c as u8),
        _ => Err(ctx.err(ErrorKind::InvalidCode, "Core Identifier ID type code not in ST 1204.3 Table 3")),
    }
}

/// [`CoreIdentifier::from_view`] for a struct.
fn from_fields(fields: &[Field], ctx: &Ctx<'_>) -> Result<CoreIdentifier, EncodeError> {
    const TYPES: [&str; 4] = ["None", "Managed", "Virtual", "Physical"];
    const INCLUDED: [&str; 2] = ["None", "Included"];
    let component = [
        "Sensor ID Type",
        "Platform ID Type",
        "Window ID Type",
        "Minor ID Type",
        "Sensor ID",
        "Platform ID",
        "Window ID",
        "Minor ID",
    ];
    let id = if component.iter().any(|n| field(fields, n).is_some()) {
        let mut id = CoreIdentifier::default();
        // Each type code and its UUID go together.
        let device = |type_name, id_name| -> Result<Option<(IdType, [u8; 16])>, EncodeError> {
            let code = match field(fields, type_name) {
                Some(v) => type_code(ctx, v, &TYPES)?,
                None => 0,
            };
            match (IdType::from_code(code), field(fields, id_name)) {
                (Some(kind), Some(v)) => Ok(Some((kind, uuid_of(ctx, v)?))),
                (None, None) => Ok(None),
                _ => Err(ctx.err(ErrorKind::Missing, "each Core Identifier ID type needs its ID and the other way round")),
            }
        };
        let single = |type_name, id_name| -> Result<Option<[u8; 16]>, EncodeError> {
            let code = match field(fields, type_name) {
                Some(v) => type_code(ctx, v, &INCLUDED)?,
                None => 0,
            };
            match (code, field(fields, id_name)) {
                (1, Some(v)) => Ok(Some(uuid_of(ctx, v)?)),
                (0, None) => Ok(None),
                _ => Err(ctx.err(ErrorKind::Missing, "each Core Identifier ID type needs its ID and the other way round")),
            }
        };
        id.sensor = device("Sensor ID Type", "Sensor ID")?;
        id.platform = device("Platform ID Type", "Platform ID")?;
        id.window = single("Window ID Type", "Window ID")?;
        id.minor = single("Minor ID Type", "Minor ID")?;
        if let Some(Value::Text(canonical)) = field(fields, "Canonical") {
            if !canonical.eq_ignore_ascii_case(&id.to_text()) {
                return Err(ctx.err(ErrorKind::InvalidCode, "Core Identifier Canonical text disagrees with its IDs"));
            }
        }
        id
    } else {
        match field(fields, "Canonical") {
            Some(Value::Text(s)) => CoreIdentifier::parse(s).map_err(|e| ctx.err(e.kind, e.reason))?,
            _ => return Err(ctx.err(ErrorKind::Missing, "Core Identifier needs its IDs or its Canonical text")),
        }
    };
    let disagree = || ctx.err(ErrorKind::InvalidCode, "Core Identifier Version, Usage Value or Check Value disagrees with its IDs");
    let number = |name| match field(fields, name) {
        None => Ok(None),
        Some(Value::Uint(n)) => Ok(Some(*n)),
        Some(_) => Err(ctx.err(ErrorKind::WrongType, "Core Identifier Version, Usage Value and Check Value are integers")),
    };
    if number("Version")?.map_or(false, |v| v != VERSION) {
        return Err(disagree());
    }
    if number("Usage Value")?.map_or(false, |u| u != u64::from(id.usage())) {
        return Err(disagree());
    }
    let text = id.to_text();
    let check = text.rsplit(':').next().and_then(|c| u64::from_str_radix(c, 16).ok());
    if let Some(c) = number("Check Value")? {
        if Some(c) != check {
            return Err(disagree());
        }
    }
    Ok(id)
}

/// Write the binary Core Identifier for a decoded value (the
/// [`crate::Value::Struct`] the decoder produces, its canonical
/// [`crate::Value::Text`], or the binary bytes) into `out`, checked as
/// [`CoreIdentifier::encode`] checks it.
pub(crate) fn encode_value(v: View<'_>, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    CoreIdentifier::from_view(v, ctx)?.write(ctx, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::Policy;

    fn bin(s: &str) -> Vec<u8> {
        hex(&s.replace(' ', "")).unwrap()
    }

    /// Every ST 1204.3 example (section 7.4 and Appendix E), as in the
    /// decoder's tests: binary and canonical text.
    fn examples() -> Vec<(Vec<u8>, &'static str)> {
        let (bins, texts): (Vec<&str>, Vec<&str>) = [
            (
                "0170F592F02373364AF8AA9162C00F2EB2DA16B74341000841A0BE365B5AB96A3645",
                "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3",
            ),
            (
                "0154C7D1625398A241C2BA6E90F8FCC73914E047AB3E81BE41ED966409B02F445FAB5E71B0DC20FE4920821626D64F61D863",
                "0154:C7D1-6253-98A2-41C2-BA6E-90F8-FCC7-3914/E047-AB3E-81BE-41ED-9664-09B0-2F44-5FAB/5E71-B0DC-20FE-4920-8216-26D6-4F61-D863:C8",
            ),
            (
                "015008CE252ED0FA49E3B1A065E61D5720DCEAF18A27A0864019A586EAAF97157BFA",
                "0150:08CE-252E-D0FA-49E3-B1A0-65E6-1D57-20DC/EAF1-8A27-A086-4019-A586-EAAF-9715-7BFA:DA",
            ),
            (
                "0168F354666ED5524C0D9168A7454CEBA073840A4799BBC04BD597A756F64092AF7B",
                "0168:F354-666E-D552-4C0D-9168-A745-4CEB-A073/840A-4799-BBC0-4BD5-97A7-56F6-4092-AF7B:AA",
            ),
            (
                "0178865EFD9CEF8A41C38244B885AFCC40BFED8A9AB872E2416599797E5AF54A5B9A",
                "0178:865E-FD9C-EF8A-41C3-8244-B885-AFCC-40BF/ED8A-9AB8-72E2-4165-9979-7E5A-F54A-5B9A:25",
            ),
            (
                "0144340F463BAEC24F8CBD4592AEDE80E1C6F0AF86733A17424CB0603EE4A86B38F9",
                "0144:340F-463B-AEC2-4F8C-BD45-92AE-DE80-E1C6/F0AF-8673-3A17-424C-B060-3EE4-A86B-38F9:D9",
            ),
            ("0140BC76CFEF0BEE41A49618EB4B010D2F08", "0140:BC76-CFEF-0BEE-41A4-9618-EB4B-010D-2F08:B6"),
            (
                "01143D502DB64A9344C3B56E94AD7C4EE47645E28FAFC2D34A6E815B5FE6B0A96ABD",
                "0114:3D50-2DB6-4A93-44C3-B56E-94AD-7C4E-E476/45E2-8FAF-C2D3-4A6E-815B-5FE6-B0A9-6ABD:F1",
            ),
            ("01101AB8231E17E84748A133CE9389A7A060", "0110:1AB8-231E-17E8-4748-A133-CE93-89A7-A060:25"),
            ("0104C2A7D72496F747DBA23DA29730075876", "0104:C2A7-D724-96F7-47DB-A23D-A297-3007-5876:55"),
            ("010203DD9DEEFB48477B8204B0506F6B2A33", "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25"),
        ]
        .into_iter()
        .unzip();
        bins.iter().map(|b| bin(b)).zip(texts).collect()
    }

    fn ctx_encode(v: &Value) -> Result<Vec<u8>, EncodeError> {
        let opts = EncodeOptions::default();
        let mut w = Vec::new();
        let mut ctx = Ctx::new(&opts, &mut w, Standard::St0903);
        ctx.tag = Some(13);
        let mut out = Vec::new();
        encode_value(View::value(v), &mut ctx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn every_standard_example_round_trips() {
        for (binary, text) in examples() {
            // Binary -> identifier -> binary and text.
            let id = CoreIdentifier::from_bytes(&binary).unwrap();
            assert_eq!(id.encode().unwrap(), binary, "{text}");
            assert_eq!(id.to_text(), text);
            assert_eq!(id.to_string(), text);
            // Text -> identifier, either case.
            assert_eq!(text.parse::<CoreIdentifier>().unwrap(), id);
            assert_eq!(CoreIdentifier::parse(&text.to_lowercase()).unwrap(), id);
            // The decoder's struct, its canonical text and the bytes.
            let decoded = super::super::decode(&binary);
            assert_eq!(ctx_encode(&decoded).unwrap(), binary, "{text}");
            assert_eq!(ctx_encode(&Value::Text(text.into())).unwrap(), binary);
            assert_eq!(ctx_encode(&Value::Bytes(binary.clone())).unwrap(), binary);
            // Only the canonical text of the struct.
            let only_text = Value::Struct(vec![Field::new("Canonical", Value::Text(text.into()))]);
            assert_eq!(ctx_encode(&only_text).unwrap(), binary);
            // Only the components.
            let Value::Struct(fields) = &decoded else { panic!() };
            let parts: Vec<Field> = fields
                .iter()
                .filter(|f| f.name.ends_with(" ID") || f.name.ends_with(" ID Type"))
                .cloned()
                .collect();
            assert_eq!(ctx_encode(&Value::Struct(parts)).unwrap(), binary);
        }
    }

    #[test]
    fn usage_is_derived_from_the_identifiers() {
        let a = [0x11; 16];
        let mut uuid = a;
        uuid[6] = 0x41;
        uuid[8] = 0x81;
        let id = CoreIdentifier::new().with_sensor(IdType::Physical, uuid).with_platform(IdType::Virtual, uuid);
        assert_eq!(id.usage(), 0x70);
        let id = CoreIdentifier::new().with_sensor(IdType::Virtual, uuid).with_platform(IdType::Virtual, uuid).with_window(uuid);
        assert_eq!(id.usage(), 0x54);
        assert_eq!(id.encode().unwrap().len(), 50);
        assert_eq!(CoreIdentifier::new().with_platform(IdType::Managed, uuid).usage(), 0x08);
        assert_eq!(CoreIdentifier::new().with_window(uuid).usage(), 0x04);
        assert_eq!(CoreIdentifier::minor_id(uuid).usage(), 0x02);
        assert_eq!(CoreIdentifier::minor_id(uuid).encode().unwrap().len(), 18);
    }

    #[test]
    fn strict_checks_of_d29() {
        let mut v4 = [0x22; 16];
        v4[6] = 0x4F;
        v4[8] = 0xBF;
        let kind = |r: Result<Vec<u8>, EncodeError>| r.unwrap_err().kind;
        assert_eq!(kind(CoreIdentifier::new().encode()), ErrorKind::Missing);
        assert_eq!(kind(CoreIdentifier::minor_id(v4).with_window(v4).encode()), ErrorKind::NotAllowed);
        assert_eq!(kind(CoreIdentifier::new().with_window([0; 16]).encode()), ErrorKind::InvalidCode);
        // Version 3 and the Microsoft variant: errors when strict, warnings
        // otherwise; nil stays an error.
        let mut v3 = v4;
        v3[6] = 0x3F;
        let mut ms = v4;
        ms[8] = 0xCF;
        for bad in [v3, ms] {
            let id = CoreIdentifier::new().with_window(bad);
            assert_eq!(kind(id.encode()), ErrorKind::InvalidCode);
            let mut opts = EncodeOptions::default();
            opts.policy = Policy::Clamp;
            let mut w = Vec::new();
            assert_eq!(id.encode_with(&opts, &mut w).unwrap().len(), 18);
            assert_eq!(w.len(), 1);
            let mut w = Vec::new();
            assert!(CoreIdentifier::new().with_window([0; 16]).encode_with(&opts, &mut w).is_err());
        }
        let e = CoreIdentifier::new().encode().unwrap_err();
        assert_eq!((e.standard, e.tag), (Standard::St0601, Some(94)));
    }

    #[test]
    fn text_and_struct_errors() {
        let good = "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25";
        for bad in [
            "",
            "0102",
            "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33",
            "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:26",
            "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A3:25",
            "0202:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25",
            "01:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25",
            "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:2",
            "0102:03DD-9DEE-FB48-477B-8204-B050-6F6B-2A3Z:25",
            "0102:\u{e9}3DD-9DEE-FB48-477B-8204-B050-6F6B-2A33:25",
        ] {
            assert!(CoreIdentifier::parse(bad).is_err(), "{bad:?}");
        }
        assert!(CoreIdentifier::parse(good).is_ok());
        // A struct whose derived fields disagree with its IDs.
        let decoded = super::super::decode(&bin("010203DD9DEEFB48477B8204B0506F6B2A33"));
        let Value::Struct(mut fields) = decoded else { panic!() };
        let ok = Value::Struct(fields.clone());
        assert!(ctx_encode(&ok).is_ok());
        for f in fields.iter_mut().filter(|f| f.name == "Usage Value") {
            f.value = Value::Uint(0x04);
        }
        let e = ctx_encode(&Value::Struct(fields)).unwrap_err();
        assert_eq!((e.standard, e.tag, e.kind), (Standard::St0903, Some(13), ErrorKind::InvalidCode));
        // A type without its ID, and wrong value types.
        let lonely = Value::Struct(vec![Field::new("Window ID Type", Value::Uint(1))]);
        assert_eq!(ctx_encode(&lonely).unwrap_err().kind, ErrorKind::Missing);
        assert_eq!(ctx_encode(&Value::Uint(1)).unwrap_err().kind, ErrorKind::WrongType);
        assert_eq!(ctx_encode(&Value::Struct(vec![])).unwrap_err().kind, ErrorKind::Missing);
        assert_eq!(ctx_encode(&Value::Bytes(vec![1, 0])).unwrap_err().kind, ErrorKind::InvalidCode);
    }

    #[test]
    fn id_type_codes() {
        for k in [IdType::Managed, IdType::Virtual, IdType::Physical] {
            assert_eq!(IdType::from_code(k.code()), Some(k));
        }
        assert_eq!(IdType::from_code(0), None);
        assert_eq!(IdType::from_code(4), None);
    }
}
