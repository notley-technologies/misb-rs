//! MISB ST 1204 Motion Imagery Identification System (MIIS) Core Identifier.
//!
//! ST 0601 tag 94 and ST 0903 tag 13 carry the binary form of the Core
//! Identifier (ST 1204.3 section 7.4.1, Table 5):
//!
//! | bytes | field |
//! |-------|-------|
//! | BER-OID | Version, currently 1 (section 7.2) |
//! | 1 | Usage Value (section 7.3.1, Table 3) |
//! | 16 each | Sensor ID, Platform ID, Window ID, or the single Minor ID, in that order |
//!
//! The decoder turns it into a [`Value::Struct`] with these fields, in this
//! order (the ID fields only when the usage value includes them):
//!
//! | field | value |
//! |-------|-------|
//! | `Canonical` | [`Value::Text`]: the textual format of section 7.4.2, e.g. `0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3` |
//! | `Version` | [`Value::Uint`] |
//! | `Usage Value` | [`Value::Uint`], the usage byte of Table 3 |
//! | `Sensor ID Type`, `Platform ID Type` | [`Value::Enum`]: 0 None, 1 Managed, 2 Virtual, 3 Physical |
//! | `Window ID Type`, `Minor ID Type` | [`Value::Enum`]: 0 None, 1 Included |
//! | `Sensor ID`, `Platform ID`, `Window ID`, `Minor ID` | [`Value::Text`]: the UUID String Value of Table 8, 32 upper case hex digits in groups of four |
//! | `Check Value` | [`Value::Uint`]: the Appendix B check value that ends `Canonical` |
//!
//! These identifiers keep the canonical form ST 1204.3 defines (upper case,
//! groups of four), unlike the other UUIDs the crate decodes to text (ST
//! 0601 tag 143, the ST 0903 VTracker Track ID), which use the lowercase
//! RFC 4122 form.
//!
//! The binary form carries no check value; the decoder computes it for the
//! textual form. [`check_value`] computes it for any text, for example to
//! verify an identifier an operator typed in.
//!
//! A value that does not follow the EBNF of section 7.1 is
//! [`Value::Invalid`]: a version other than 1, a reserved usage bit set, a
//! usage value that includes no identifier, a Minor ID combined with
//! another identifier, or a length other than 2 + 16 bytes per included
//! identifier.

use crate::{Field, Value};

#[cfg(feature = "encode")]
#[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
pub mod encode;

/// Bytes in one identifier component (a UUID, ST 1204.3 Table 5).
const UUID_LEN: usize = 16;

/// The only Core Identifier version ST 1204.3 defines (section 7.2).
const VERSION: u64 = 1;

/// Upper case hex digits. ST 1204.3 section 7.4.2 allows either case and
/// recommends upper case; the XML schema of Listing 1 allows only upper.
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Names of the two-bit Sensor and Platform ID types (ST 1204.3 Table 3).
const DEVICE_TYPES: [&str; 4] = ["None", "Managed", "Virtual", "Physical"];

/// Names of the one-bit Window and Minor ID types (ST 1204.3 Table 3).
const INCLUDED: [&str; 2] = ["None", "Included"];

/// Decode a binary MIIS Core Identifier (ST 0601 tag 94, ST 0903 tag 13).
/// Never panics.
pub(crate) fn decode(value: &[u8]) -> Value {
    match CoreId::parse(value) {
        Ok(id) => id.to_value(),
        Err(why) => Value::Invalid(why),
    }
}

/// A Core Identifier that follows the ST 1204.3 section 7.1 EBNF.
struct CoreId<'a> {
    version: u64,
    usage: u8,
    /// The identifier components in wire order: sensor, platform, window
    /// (each when included), or the single minor ID.
    ids: [Option<(&'static str, &'a [u8])>; 3],
}

impl<'a> CoreId<'a> {
    fn parse(value: &'a [u8]) -> Result<CoreId<'a>, &'static str> {
        // Version: a BER-OID (Table 5). Leading 0x80 padding is tolerated as
        // for local set tags (see `klv::OPTIONS`).
        let (version, n) = smpte_klv::ber::decode_oid(value, false)
            .map_err(|_| "Core Identifier version is missing or malformed")?;
        if version != VERSION {
            // Section 7.2: the version tells a parser how to read the rest;
            // only version 1 is defined.
            return Err("unsupported Core Identifier version");
        }
        let rest = value.get(n..).unwrap_or_default();
        let (&usage, mut ids) = rest.split_first().ok_or("Core Identifier has no usage value")?;

        // Section 7.3.1, Table 3: bit 7 is reserved for a future multi-byte
        // usage value and bit 0 is reserved; both are always zero.
        if usage & 0x81 != 0 {
            return Err("Core Identifier usage value has a reserved bit set");
        }
        let sensor = (usage >> 5) & 0x03;
        let platform = (usage >> 3) & 0x03;
        let window = usage & 0x04 != 0;
        let minor = usage & 0x02 != 0;
        let foundational = sensor != 0 || platform != 0 || window;
        // Section 7.1 EBNF: the usage value is either a Foundational Core
        // Identifier (sensor, platform, window) or a Minor one, and never
        // ('None', 'None', 'None', 'None').
        if !foundational && !minor {
            return Err("Core Identifier usage value includes no identifier");
        }
        if foundational && minor {
            return Err("Minor Core Identifier combined with a Foundational one");
        }

        let wanted = [
            (sensor != 0, "Sensor ID"),
            (platform != 0, "Platform ID"),
            (window, "Window ID"),
            (minor, "Minor ID"),
        ];
        let count = wanted.iter().filter(|(on, _)| *on).count();
        // Table 5: each UUID is 16 bytes and nothing follows the last one.
        if Some(ids.len()) != count.checked_mul(UUID_LEN) {
            return Err("Core Identifier length does not match its usage value");
        }
        let mut out = [None; 3];
        let mut slot = 0;
        for (on, name) in wanted {
            if !on {
                continue;
            }
            // `count` is at most 3 (Minor excludes the others) and `ids`
            // holds exactly `count` UUIDs, so both are in range.
            let (id, tail) = ids.split_at(UUID_LEN.min(ids.len()));
            if let Some(s) = out.get_mut(slot) {
                *s = Some((name, id));
            }
            ids = tail;
            slot += 1;
        }
        Ok(CoreId { version, usage, ids: out })
    }

    fn to_value(&self) -> Value {
        // Section 7.4.2, Table 8: "VVUU:ID/ID/ID:CC". The version is 1, so
        // two hex digits.
        let mut text = String::with_capacity(4 + 3 * 40 + 3);
        push_hex(&mut text, u8::try_from(self.version).unwrap_or(0));
        push_hex(&mut text, self.usage);
        text.push(':');
        let mut uuids = Vec::with_capacity(3);
        for (i, (name, id)) in self.ids.iter().flatten().enumerate() {
            if i > 0 {
                text.push('/');
            }
            let s = uuid_text(id);
            text.push_str(&s);
            uuids.push(Field { name, value: Value::Text(s) });
        }
        let check = check_value(&text);
        text.push(':');
        push_hex(&mut text, check);

        let sensor = (self.usage >> 5) & 0x03;
        let platform = (self.usage >> 3) & 0x03;
        let window = (self.usage >> 2) & 0x01;
        let minor = (self.usage >> 1) & 0x01;
        let mut fields = vec![
            Field { name: "Canonical", value: Value::Text(text) },
            Field { name: "Version", value: Value::Uint(self.version) },
            Field { name: "Usage Value", value: Value::Uint(u64::from(self.usage)) },
            Field { name: "Sensor ID Type", value: label(sensor, &DEVICE_TYPES) },
            Field { name: "Platform ID Type", value: label(platform, &DEVICE_TYPES) },
            Field { name: "Window ID Type", value: label(window, &INCLUDED) },
            Field { name: "Minor ID Type", value: label(minor, &INCLUDED) },
        ];
        fields.extend(uuids);
        fields.push(Field { name: "Check Value", value: Value::Uint(u64::from(check)) });
        Value::Struct(fields)
    }
}

/// An enumerated value with its label from `names`.
fn label(code: u8, names: &[&'static str]) -> Value {
    Value::Enum { code: u64::from(code), label: names.get(usize::from(code)).copied() }
}

/// Append `b` as two upper case hex digits.
fn push_hex(s: &mut String, b: u8) {
    s.push(char::from(HEX[usize::from(b >> 4)]));
    s.push(char::from(HEX[usize::from(b & 0x0F)]));
}

/// The UUID String Value of ST 1204.3 Table 8: the hex digits of the UUID
/// with a dash after every four, e.g. `0102-0304-0506-0708-090A-0B0C-0D0E-0F10`.
fn uuid_text(id: &[u8]) -> String {
    let mut s = String::with_capacity(39);
    for (i, &b) in id.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push('-');
        }
        push_hex(&mut s, b);
    }
    s
}

/// pMap of ST 1204.3 Appendix B.1: `[a, b, c, d]` to `[a ^ b, c, d, a]`,
/// with `a` the most significant bit of the nibble.
const fn p_map(x: u8) -> u8 {
    let (a, b, c, d) = ((x >> 3) & 1, (x >> 2) & 1, (x >> 1) & 1, x & 1);
    ((a ^ b) << 3) | (c << 2) | (d << 1) | a
}

/// qMap of ST 1204.3 Appendix B.1: `[a, b, c, d]` to `[d, a ^ d, b, c]`.
const fn q_map(x: u8) -> u8 {
    let (a, b, c, d) = ((x >> 3) & 1, (x >> 2) & 1, (x >> 1) & 1, x & 1);
    (d << 3) | ((a ^ d) << 2) | (b << 1) | c
}

/// The permutation table of Appendix B.1: row 0 is the identity and row
/// `i` applies the map to row `i - 1`, for 15 rows (Table 14).
const fn permutations(q: bool) -> [[u8; 16]; 15] {
    let mut t = [[0u8; 16]; 15];
    let mut j = 0;
    while j < 16 {
        let mut v = j as u8;
        let mut i = 0;
        while i < 15 {
            t[i][j] = v;
            v = if q { q_map(v) } else { p_map(v) };
            i += 1;
        }
        j += 1;
    }
    t
}

/// P permutations of ST 1204.3 Appendix B.1 (Table 14, left).
const P: [[u8; 16]; 15] = permutations(false);

/// Q permutations of ST 1204.3 Appendix B.1 (Table 14, right).
const Q: [[u8; 16]; 15] = permutations(true);

/// The ST 1204.3 Appendix B check value of the hex digits in `text`.
///
/// Only hex digits (either case) count: separators such as `:`, `-` and
/// `/` and any other characters are skipped, as section 7.4.2 says the
/// check value "validates only the hex digits, not the separator
/// characters". To verify a textual Core Identifier, pass the text before
/// its final `:` and compare with the two hex digits after it.
///
/// ```
/// // The worked example of ST 1204.3 Appendix B.2, Table 15.
/// assert_eq!(misb::st1204::check_value("031FA3"), 0x79);
/// // The textual format example of ST 1204.3 section 7.4.2.
/// let text = "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/\
///             16B7-4341-0008-41A0-BE36-5B5A-B96A-3645";
/// assert_eq!(misb::st1204::check_value(text), 0xD3);
/// ```
pub fn check_value(text: &str) -> u8 {
    let mut p = 0u8;
    let mut q = 0u8;
    // Appendix B.2 numbers the digits from 1 and uses row i % 15. Keep the
    // row instead of the count so that no length can overflow it.
    let mut row = 0usize;
    for b in text.bytes() {
        let Some(digit) = (b as char).to_digit(16) else { continue };
        row = (row + 1) % 15;
        // `row` < 15 and `digit` < 16 by construction.
        let d = digit as usize;
        p ^= P[row][d];
        q ^= Q[row][d];
    }
    (p << 4) | q
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> =
            s.bytes().filter_map(|b| (b as char).to_digit(16)).map(|d| d as u8).collect();
        assert_eq!(digits.len() % 2, 0, "{s}");
        digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
    }

    fn canonical(v: &Value) -> &str {
        v.field("Canonical").and_then(Value::as_str).unwrap()
    }

    /// (binary value from the KLV form, textual form) of every example in
    /// ST 1204.3: section 7.4.1/7.4.2 and Appendix E examples E1 to E10.
    const EXAMPLES: [(&str, &str); 11] = [
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
    ];

    #[test]
    fn standard_examples() {
        for (bin, text) in EXAMPLES {
            let v = decode(&hex(bin));
            assert_eq!(canonical(&v), text);
            let check = u64::from_str_radix(&text[text.len() - 2..], 16).unwrap();
            assert_eq!(v.field("Check Value"), Some(&Value::Uint(check)));
            assert_eq!(v.field("Version"), Some(&Value::Uint(1)));
            // The check value of the text before the final ':' matches too.
            assert_eq!(u64::from(check_value(&text[..text.len() - 3])), check);
        }
    }

    #[test]
    fn section_7_4_example_fields() {
        // ST 1204.3 section 7.4.1 Figure 7: physical sensor, virtual platform.
        let v = decode(&hex(EXAMPLES[0].0));
        let fields = v.as_fields().unwrap();
        let names: Vec<_> = fields.iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            [
                "Canonical",
                "Version",
                "Usage Value",
                "Sensor ID Type",
                "Platform ID Type",
                "Window ID Type",
                "Minor ID Type",
                "Sensor ID",
                "Platform ID",
                "Check Value"
            ]
        );
        assert_eq!(v.field("Usage Value"), Some(&Value::Uint(0x70)));
        assert_eq!(
            v.field("Sensor ID Type"),
            Some(&Value::Enum { code: 3, label: Some("Physical") })
        );
        assert_eq!(
            v.field("Platform ID Type"),
            Some(&Value::Enum { code: 2, label: Some("Virtual") })
        );
        assert_eq!(v.field("Window ID Type"), Some(&Value::Enum { code: 0, label: Some("None") }));
        assert_eq!(v.field("Minor ID Type"), Some(&Value::Enum { code: 0, label: Some("None") }));
        assert_eq!(
            v.field("Sensor ID").and_then(Value::as_str),
            Some("F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA")
        );
        assert_eq!(
            v.field("Platform ID").and_then(Value::as_str),
            Some("16B7-4341-0008-41A0-BE36-5B5A-B96A-3645")
        );
        assert_eq!(v.field("Window ID"), None);
        assert_eq!(v.field("Check Value"), Some(&Value::Uint(0xD3)));
    }

    #[test]
    fn id_types_of_appendix_e() {
        // E1: virtual sensor and platform with a window.
        let v = decode(&hex(EXAMPLES[1].0));
        assert_eq!(
            v.field("Sensor ID Type"),
            Some(&Value::Enum { code: 2, label: Some("Virtual") })
        );
        assert_eq!(
            v.field("Window ID Type"),
            Some(&Value::Enum { code: 1, label: Some("Included") })
        );
        assert_eq!(
            v.field("Window ID").and_then(Value::as_str),
            Some("5E71-B0DC-20FE-4920-8216-26D6-4F61-D863")
        );
        // E3: managed platform.
        let v = decode(&hex(EXAMPLES[3].0));
        assert_eq!(
            v.field("Platform ID Type"),
            Some(&Value::Enum { code: 1, label: Some("Managed") })
        );
        // E8: platform only, so no sensor ID.
        let v = decode(&hex(EXAMPLES[8].0));
        assert_eq!(v.field("Sensor ID Type"), Some(&Value::Enum { code: 0, label: Some("None") }));
        assert_eq!(v.field("Sensor ID"), None);
        assert!(v.field("Platform ID").is_some());
        // E10: Minor Core Identifier.
        let v = decode(&hex(EXAMPLES[10].0));
        assert_eq!(
            v.field("Minor ID Type"),
            Some(&Value::Enum { code: 1, label: Some("Included") })
        );
        assert_eq!(
            v.field("Minor ID").and_then(Value::as_str),
            Some("03DD-9DEE-FB48-477B-8204-B050-6F6B-2A33")
        );
        assert_eq!(v.field("Sensor ID"), None);
    }

    #[test]
    fn check_value_worked_example() {
        // ST 1204.3 Appendix B.2 Table 15.
        assert_eq!(check_value("031FA3"), 0x79);
        // Lower case hex digits and separators give the same result.
        assert_eq!(check_value("03:1f-a/3"), 0x79);
        assert_eq!(check_value(""), 0);
        // Non-ASCII text is skipped without panicking.
        assert_eq!(check_value("0\u{e9}31FA3\u{1F600}"), 0x79);
        // A long text wraps the row index and still terminates.
        let long = "F".repeat(100_000);
        let _ = check_value(&long);
    }

    #[test]
    fn permutation_tables_match_table_14() {
        // ST 1204.3 Appendix B.1 examples.
        assert_eq!(p_map(13), 3);
        assert_eq!(q_map(13), 10);
        // Table 14, P permutations (hex digits per row).
        let p_rows = [
            "0123456789ABCDEF",
            "02468ACE9BDF1357",
            "048C9D15BF3726AE",
            "0891B32AF76E4CD5",
            "09B2F64D7EC5813A",
            "0BF47C83E51A926D",
            "0F78E1965A2DB4C3",
            "07E952BCAD43F816",
            "0E5BA4F1D386792C",
            "05AFD872369CEB41",
            "0AD739E46CB15F82",
            "0D3E6B58C1F2A794",
            "0365CFA91274DEB8",
            "06CA17DB24E835F9",
            "0C1D2E3F48596A7B",
        ];
        for (i, row) in p_rows.iter().enumerate() {
            let want: Vec<u8> =
                row.bytes().filter_map(|b| (b as char).to_digit(16)).map(|d| d as u8).collect();
            assert_eq!(P[i].to_vec(), want, "P row {i}");
            // Table 14 shows Q row k equal to P row (15 - k) mod 15.
            assert_eq!(Q[(15 - i) % 15].to_vec(), want, "Q row {}", (15 - i) % 15);
        }
    }

    #[test]
    fn rejects_values_outside_the_ebnf() {
        let id = "F592F02373364AF8AA9162C00F2EB2DA";
        let invalid = |s: &str| match decode(&hex(s)) {
            Value::Invalid(why) => why,
            other => panic!("{s}: {other:?}"),
        };
        // Empty, version only, truncated BER-OID version.
        let malformed = Value::Invalid("Core Identifier version is missing or malformed");
        assert_eq!(decode(&[]), malformed);
        assert_eq!(decode(&[0x81]), malformed);
        assert_eq!(invalid("01"), "Core Identifier has no usage value");
        // Versions other than 1, including multi-byte BER-OIDs.
        assert_eq!(invalid(&format!("0240{id}")), "unsupported Core Identifier version");
        assert_eq!(invalid(&format!("00 40{id}")), "unsupported Core Identifier version");
        assert_eq!(invalid(&format!("8101 40{id}")), "unsupported Core Identifier version");
        // Reserved bit 7 or bit 0, and a usage value with no identifier.
        let reserved = "Core Identifier usage value has a reserved bit set";
        assert_eq!(invalid(&format!("01C0{id}")), reserved);
        assert_eq!(invalid(&format!("0141{id}")), reserved);
        assert_eq!(invalid("0100"), "Core Identifier usage value includes no identifier");
        // A Minor ID with a sensor, platform or window ID.
        for usage in ["42", "12", "06"] {
            assert_eq!(
                invalid(&format!("01{usage}{id}{id}")),
                "Minor Core Identifier combined with a Foundational one"
            );
        }
        // Lengths that do not match the usage value.
        let mismatch = "Core Identifier length does not match its usage value";
        assert_eq!(invalid("0140"), mismatch);
        assert_eq!(invalid(&format!("0140{}", &id[..30])), mismatch);
        assert_eq!(invalid(&format!("0140{id}00")), mismatch);
        assert_eq!(invalid(&format!("0170{id}")), mismatch);
        assert_eq!(invalid(&format!("0154{id}{id}")), mismatch);
        assert_eq!(invalid(&format!("0154{id}{id}{id}{id}")), mismatch);
    }

    #[test]
    fn padded_version_is_tolerated() {
        // A BER-OID version 1 with a leading 0x80 pad byte.
        let v = decode(&hex(&format!("8001{}", &EXAMPLES[6].0[2..])));
        assert_eq!(canonical(&v), EXAMPLES[6].1);
    }

    #[test]
    fn nil_platform_id_still_decodes() {
        // ST 1204.3 section 6.1.5 pre-fill: a temporary all-zero platform ID.
        let v = decode(&hex(&format!("0170{}{}", &EXAMPLES[0].0[4..36], "0".repeat(32))));
        assert_eq!(
            v.field("Platform ID").and_then(Value::as_str),
            Some("0000-0000-0000-0000-0000-0000-0000-0000")
        );
    }

    #[test]
    fn every_usage_byte_and_length_is_safe() {
        // Exhaustive over usage bytes and lengths up to four UUIDs: never
        // panics, and only EBNF-conformant inputs decode.
        let mut ok = 0;
        for usage in 0..=255u8 {
            for len in 0..=66usize {
                let mut buf = vec![0xA5; len + 2];
                buf[0] = 1;
                buf[1] = usage;
                if let Value::Struct(fields) = decode(&buf) {
                    ok += 1;
                    let ids = fields.iter().filter(|f| f.name.ends_with(" ID")).count();
                    assert_eq!(len, ids * UUID_LEN);
                }
            }
        }
        // 4 x 4 x 2 sensor/platform/window combinations less the empty one,
        // plus the Minor ID alone.
        assert_eq!(ok, 4 * 4 * 2 - 1 + 1);
    }

    #[test]
    fn random_values_never_panic() {
        let mut x = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let len = (next() % 60) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if next() % 2 == 0 {
                if let Some(b) = buf.first_mut() {
                    *b = 1;
                }
            }
            match decode(&buf) {
                Value::Struct(f) => assert_eq!(f[0].name, "Canonical"),
                Value::Invalid(_) => {}
                other => panic!("{other:?}"),
            }
        }
    }
}
