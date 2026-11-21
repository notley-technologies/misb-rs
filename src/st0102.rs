//! MISB ST 0102 Security Metadata Local Set.
//!
//! Decoded where ST 0601 embeds it: tag 48, Security Local Set. ST 0601
//! requires the Local Set form there (ST 0601.19 section 8.48.1,
//! requirement ST 0601.14-31) and the value is the bare set, without the
//! 16-byte ST 0102 key or its length (ST 0601.19 section 6.3.3). The ST
//! 0102 Local Set has no checksum item of its own.
//!
//! Tags and types follow ST 0102.12 Table 2, the latest revision:
//!
//! | tag | value |
//! |-----|-------|
//! | 1 Security Classification | [`Value::Enum`] labelled `UNCLASSIFIED//` to `TOP SECRET//` (section 6.8.1) |
//! | 2, 12 country coding methods | [`Value::Enum`] labelled from Table 2; the two tags number the methods differently |
//! | 3 to 9, 11, 14 | [`Value::Text`], ISO/IEC 646 free text as sent |
//! | 10 Declassification Date | [`Value::Text`] `YYYYMMDD` |
//! | 13 Object Country Codes | [`Value::Text`] from UTF-16 (RFC 2781), see [`Tag::ObjectCountryCodes`] |
//! | 22 Version | [`Value::Uint`], the ST 0102 revision number |
//! | 23, 24 version dates | [`Value::Text`] `YYYY-MM-DD` |
//!
//! Tags 15 to 21 were deleted from the standard (16 to 18 in ST 0102.10,
//! the others in ST 0102.12); they are still decoded for older streams.
//!
//! A zero-length item means the value is unknown (MISB ST 0107, which
//! requirement ST 0102.10-02 invokes) and decodes to [`Value::Unknown`],
//! except for the items Table 2 marks Required (tags 1, 2, 3, 12, 13 and
//! 22): ST 0107 never lets a mandatory item be zero length, so those are
//! [`Value::Invalid`].
//!
//! Enumeration codes the standard does not define keep their code with no
//! label. A value of the wrong length or, for the dates, not in the
//! standard's format is [`Value::Invalid`]. The free text items are passed
//! through without checking their content, whose rules come from security
//! registers outside ST 0102 (for example CAPCO).
//!
//! An absent Version item means version 3 (requirement ST 0102.10-57), and
//! the absence of a Security Local Set does not mean the imagery is
//! unclassified (section 6.5).

use crate::{Config, Item, Value};

#[cfg(feature = "encode")]
pub(crate) mod encode;

/// Tags of the Security Metadata Local Set (ST 0102.12 Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tag {
    /// Security Classification: uint8 enumeration, required (section
    /// 6.1.1).
    SecurityClassification = 1,
    /// Classifying Country and Releasing Instructions Country Coding
    /// Method: uint8 enumeration, required (section 6.1.2).
    ClassifyingCountryCodingMethod = 2,
    /// Classifying Country: the country code preceded by `//`, required
    /// (section 6.1.3).
    ClassifyingCountry = 3,
    /// Security-SCI/SHI Information (section 6.1.4).
    SciShiInformation = 4,
    /// Caveats (section 6.1.5).
    Caveats = 5,
    /// Releasing Instructions: country codes separated by blanks (section
    /// 6.1.6).
    ReleasingInstructions = 6,
    /// Classified By (section 6.1.7).
    ClassifiedBy = 7,
    /// Derived From (section 6.1.8).
    DerivedFrom = 8,
    /// Classification Reason (section 6.1.9).
    ClassificationReason = 9,
    /// Declassification Date, `YYYYMMDD` (section 6.1.10).
    DeclassificationDate = 10,
    /// Classification and Marking System (section 6.1.11).
    ClassificationAndMarkingSystem = 11,
    /// Object Country Coding Method: uint8 enumeration, required since
    /// version 6; when absent from older sets, GENC two-letter codes are
    /// meant (section 6.1.12).
    ObjectCountryCodingMethod = 12,
    /// Object Country Codes: codes separated by `;`, required (section
    /// 6.1.13).
    ///
    /// ST 0102.10 and later encode the value as UTF-16 (RFC 2781); up to ST
    /// 0102.9 it was 8-bit free text, and encoders in the field still send
    /// that. Every coding method of tag 12 uses ASCII codes, so the decoder
    /// reads UTF-16 when the value starts with a byte order mark, or when
    /// it has an even length and every high (first) byte is zero, which is
    /// how UTF-16BE spells those codes (or every second byte is zero:
    /// UTF-16LE from an encoder that left out the byte order mark).
    /// Otherwise the value is read as UTF-8 text if valid, else, at an even
    /// length, as UTF-16BE (RFC 2781 section 4.3: no byte order mark means
    /// big-endian), else as UTF-8. Malformed sequences become U+FFFD;
    /// [`Item::raw`] keeps the bytes.
    ObjectCountryCodes = 13,
    /// Classification Comments (section 6.1.14).
    ClassificationComments = 14,
    /// UMID: 32-byte SMPTE ST 330 Unique Material Identifier ("UMID Video"
    /// before ST 0102.10). Deleted in ST 0102.12.
    Umid = 15,
    /// UMID Audio: 32 bytes. Deleted in ST 0102.10.
    UmidAudio = 16,
    /// UMID Data: 32 bytes. Deleted in ST 0102.10.
    UmidData = 17,
    /// UMID System: 32 bytes. Deleted in ST 0102.10.
    UmidSystem = 18,
    /// Stream ID: ISO/IEC 13818-1 `stream_id`, uint8. Deleted in ST
    /// 0102.12.
    StreamId = 19,
    /// Transport Stream ID: ISO/IEC 13818-1 `transport_stream_id`, uint16.
    /// Deleted in ST 0102.12.
    TransportStreamId = 20,
    /// Item Designator ID: the 16-byte universal label of the linked
    /// element, set or pack. Deleted in ST 0102.12.
    ItemDesignatorId = 21,
    /// Version: uint16 ST 0102 revision number, e.g. 12 for ST 0102.12
    /// (section 6.1.15). Required since version 4; version 3 when absent.
    Version = 22,
    /// Classifying Country and Releasing Instructions Country Coding
    /// Method Version Date, `YYYY-MM-DD` (section 6.1.16).
    ClassifyingCountryCodingMethodVersionDate = 23,
    /// Object Country Coding Method Version Date, `YYYY-MM-DD` (section
    /// 6.1.17).
    ObjectCountryCodingMethodVersionDate = 24,
}

impl Tag {
    /// The tag with this number, if the standard defines it.
    pub fn from_u64(n: u64) -> Option<Tag> {
        Some(match n {
            1 => Tag::SecurityClassification,
            2 => Tag::ClassifyingCountryCodingMethod,
            3 => Tag::ClassifyingCountry,
            4 => Tag::SciShiInformation,
            5 => Tag::Caveats,
            6 => Tag::ReleasingInstructions,
            7 => Tag::ClassifiedBy,
            8 => Tag::DerivedFrom,
            9 => Tag::ClassificationReason,
            10 => Tag::DeclassificationDate,
            11 => Tag::ClassificationAndMarkingSystem,
            12 => Tag::ObjectCountryCodingMethod,
            13 => Tag::ObjectCountryCodes,
            14 => Tag::ClassificationComments,
            15 => Tag::Umid,
            16 => Tag::UmidAudio,
            17 => Tag::UmidData,
            18 => Tag::UmidSystem,
            19 => Tag::StreamId,
            20 => Tag::TransportStreamId,
            21 => Tag::ItemDesignatorId,
            22 => Tag::Version,
            23 => Tag::ClassifyingCountryCodingMethodVersionDate,
            24 => Tag::ObjectCountryCodingMethodVersionDate,
            _ => return None,
        })
    }

    /// Name from the standard.
    pub fn name(self) -> &'static str {
        match self {
            Tag::SecurityClassification => "Security Classification",
            Tag::ClassifyingCountryCodingMethod => {
                "Classifying Country and Releasing Instructions Country Coding Method"
            }
            Tag::ClassifyingCountry => "Classifying Country",
            Tag::SciShiInformation => "Security-SCI/SHI Information",
            Tag::Caveats => "Caveats",
            Tag::ReleasingInstructions => "Releasing Instructions",
            Tag::ClassifiedBy => "Classified By",
            Tag::DerivedFrom => "Derived From",
            Tag::ClassificationReason => "Classification Reason",
            Tag::DeclassificationDate => "Declassification Date",
            Tag::ClassificationAndMarkingSystem => "Classification and Marking System",
            Tag::ObjectCountryCodingMethod => "Object Country Coding Method",
            Tag::ObjectCountryCodes => "Object Country Codes",
            Tag::ClassificationComments => "Classification Comments",
            Tag::Umid => "UMID",
            Tag::UmidAudio => "UMID Audio",
            Tag::UmidData => "UMID Data",
            Tag::UmidSystem => "UMID System",
            Tag::StreamId => "Stream ID",
            Tag::TransportStreamId => "Transport Stream ID",
            Tag::ItemDesignatorId => "Item Designator ID",
            Tag::Version => "Version",
            Tag::ClassifyingCountryCodingMethodVersionDate => {
                "Classifying Country and Releasing Instructions Country Coding Method Version Date"
            }
            Tag::ObjectCountryCodingMethodVersionDate => {
                "Object Country Coding Method Version Date"
            }
        }
    }

    /// Units string; "" when none. No ST 0102 item has units.
    pub fn units(self) -> &'static str {
        ""
    }
}

impl From<Tag> for u64 {
    fn from(t: Tag) -> u64 {
        t as u64
    }
}

crate::value::tag_key!(Tag, crate::Standard::St0102);

/// Reason given for a zero-length item of a Required tag.
const NO_ZLI: &str = "zero-length item not allowed for this tag";

/// Decode one item of the set. Never panics.
pub(crate) fn decode_item(tag: u64, value: &[u8], depth: usize, cfg: &Config) -> Item {
    let Some(t) = Tag::from_u64(tag) else {
        return crate::registry::unknown_item(tag, value, depth, cfg);
    };
    let decoded = decode_value(t, value);
    crate::registry::item(tag, t.name(), t.units(), decoded, value, cfg)
}

/// Whether the tag is Required in ST 0102.12 Table 2 (tag 12 since version
/// 6, tag 22 since version 4; once present they are never unknown).
fn required(t: Tag) -> bool {
    matches!(
        t,
        Tag::SecurityClassification
            | Tag::ClassifyingCountryCodingMethod
            | Tag::ClassifyingCountry
            | Tag::ObjectCountryCodingMethod
            | Tag::ObjectCountryCodes
            | Tag::Version
    )
}

/// The value of one item of a known tag (ST 0102.12 Table 2).
fn decode_value(t: Tag, v: &[u8]) -> Value {
    if v.is_empty() {
        return if required(t) { Value::Invalid(NO_ZLI) } else { Value::Unknown };
    }
    match t {
        Tag::SecurityClassification => enumeration(v, classification),
        Tag::ClassifyingCountryCodingMethod => enumeration(v, classifying_coding_method),
        Tag::ObjectCountryCodingMethod => enumeration(v, object_coding_method),
        Tag::ClassifyingCountry
        | Tag::SciShiInformation
        | Tag::Caveats
        | Tag::ReleasingInstructions
        | Tag::ClassifiedBy
        | Tag::DerivedFrom
        | Tag::ClassificationReason
        | Tag::ClassificationAndMarkingSystem
        | Tag::ClassificationComments => text(v),
        Tag::DeclassificationDate => date(v, false),
        Tag::ObjectCountryCodes => Value::Text(object_country_codes(v)),
        Tag::Umid | Tag::UmidAudio | Tag::UmidData | Tag::UmidSystem => {
            fixed_bytes(v, 32, "UMID is not 32 bytes")
        }
        Tag::StreamId => fixed_uint(v, 1, "Stream ID is not 1 byte"),
        Tag::TransportStreamId => fixed_uint(v, 2, "Transport Stream ID is not 2 bytes"),
        Tag::ItemDesignatorId => fixed_bytes(v, 16, "Item Designator ID is not 16 bytes"),
        Tag::Version => fixed_uint(v, 2, "Version is not 2 bytes"),
        Tag::ClassifyingCountryCodingMethodVersionDate
        | Tag::ObjectCountryCodingMethodVersionDate => date(v, true),
    }
}

/// Tag 1 labels: the Universal Set strings of section 6.8.1 and Table 2.
pub(crate) fn classification(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "UNCLASSIFIED//",
        0x02 => "RESTRICTED//",
        0x03 => "CONFIDENTIAL//",
        0x04 => "SECRET//",
        0x05 => "TOP SECRET//",
        _ => return None,
    })
}

/// Tag 2 labels (Table 2). Up to ST 0102.7, 0x08 was "1059 Numeric" and
/// 0x09 "Other"; the labels follow ST 0102.12, which omits both.
pub(crate) fn classifying_coding_method(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "ISO-3166 Two Letter",
        0x02 => "ISO-3166 Three Letter",
        0x03 => "FIPS 10-4 Two Letter",
        0x04 => "FIPS 10-4 Four Letter",
        0x05 => "ISO-3166 Numeric",
        0x06 => "1059 Two Letter",
        0x07 => "1059 Three Letter",
        0x08 | 0x09 => "Omitted Value",
        0x0A => "FIPS 10-4 Mixed",
        0x0B => "ISO 3166 Mixed",
        0x0C => "STANAG 1059 Mixed",
        0x0D => "GENC Two Letter",
        0x0E => "GENC Three Letter",
        0x0F => "GENC Numeric",
        0x10 => "GENC Mixed",
        _ => return None,
    })
}

/// Tag 12 labels (Table 2). The numbering differs from tag 2 from 0x03 on.
/// ST 0601 tag 122 (Country Codes) uses the same coding method values.
pub(crate) fn object_coding_method(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "ISO-3166 Two Letter",
        0x02 => "ISO-3166 Three Letter",
        0x03 => "ISO-3166 Numeric",
        0x04 => "FIPS 10-4 Two Letter",
        0x05 => "FIPS 10-4 Four Letter",
        0x06 => "1059 Two Letter",
        0x07 => "1059 Three Letter",
        0x08..=0x0C => "Omitted Value",
        0x0D => "GENC Two Letter",
        0x0E => "GENC Three Letter",
        0x0F => "GENC Numeric",
        0x40 => "GENC AdminSub",
        _ => return None,
    })
}

/// A one-byte enumeration (uint8, length 1 in Table 2).
fn enumeration(v: &[u8], label: fn(u8) -> Option<&'static str>) -> Value {
    match *v {
        [b] => Value::Enum { code: u64::from(b), label: label(b) },
        _ => Value::Invalid("enumeration is not 1 byte"),
    }
}

/// ISO/IEC 646 text, kept exactly as sent (lossy UTF-8 for bytes above
/// 0x7F, which ISO/IEC 646 does not define).
fn text(v: &[u8]) -> Value {
    // MISB ST 0107.4 6.3.3.2: a single 00 byte is the empty string
    // (DECISIONS P-1).
    if v == [0] {
        return Value::Text(String::new());
    }
    Value::Text(String::from_utf8_lossy(v).into_owned())
}

/// A big-endian unsigned integer of exactly `len` bytes.
fn fixed_uint(v: &[u8], len: usize, why: &'static str) -> Value {
    match crate::klv::be_uint(v) {
        Some(n) if v.len() == len => Value::Uint(n),
        _ => Value::Invalid(why),
    }
}

/// Opaque bytes of exactly `len` bytes.
fn fixed_bytes(v: &[u8], len: usize, why: &'static str) -> Value {
    if v.len() == len {
        Value::Bytes(v.to_vec())
    } else {
        Value::Invalid(why)
    }
}

/// A calendar date: `YYYYMMDD` (tag 10, requirement ST 0102.10-22) or, with
/// `dashed`, the ISO 8601 `YYYY-MM-DD` of tags 23 and 24 (sections 6.1.16
/// and 6.1.17). The day must exist in the proleptic Gregorian calendar.
fn date(v: &[u8], dashed: bool) -> Value {
    let why = if dashed { "date is not YYYY-MM-DD" } else { "date is not YYYYMMDD" };
    let digits: Option<[u8; 8]> = match (dashed, v) {
        (false, &[y0, y1, y2, y3, m0, m1, d0, d1]) => Some([y0, y1, y2, y3, m0, m1, d0, d1]),
        (true, &[y0, y1, y2, y3, b'-', m0, m1, b'-', d0, d1]) => {
            Some([y0, y1, y2, y3, m0, m1, d0, d1])
        }
        _ => None,
    };
    let Some(digits) = digits else { return Value::Invalid(why) };
    if !digits.iter().all(u8::is_ascii_digit) {
        return Value::Invalid(why);
    }
    let num = |s: &[u8]| s.iter().fold(0u32, |n, &d| n * 10 + u32::from(d - b'0'));
    let (year, month, day) = (num(&digits[..4]), num(&digits[4..6]), num(&digits[6..]));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Value::Invalid(why),
    };
    if !(1..=days).contains(&day) {
        return Value::Invalid(why);
    }
    text(v)
}

/// Tag 13 text: UTF-16 (RFC 2781) since ST 0102.10, 8-bit text before. See
/// [`Tag::ObjectCountryCodes`] for how the two are told apart.
fn object_country_codes(v: &[u8]) -> String {
    match v {
        // RFC 2781 section 3.2: a byte order mark selects the byte order.
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        // ASCII codes in UTF-16BE: every high byte zero.
        _ if v.len() % 2 == 0 && v.iter().step_by(2).all(|&b| b == 0) => utf16(v, true),
        // The same codes from an encoder that wrote UTF-16LE without the byte
        // order mark: every second byte zero, which no 8-bit text has.
        _ if v.len() % 2 == 0 && v.iter().skip(1).step_by(2).all(|&b| b == 0) => {
            utf16(v, false)
        }
        _ => match std::str::from_utf8(v) {
            Ok(s) => s.to_owned(),
            Err(_) if v.len() % 2 == 0 => utf16(v, true),
            Err(_) => String::from_utf8_lossy(v).into_owned(),
        },
    }
}

/// UTF-16 code units of `v` in the given byte order, decoded lossily. An
/// odd trailing byte becomes U+FFFD.
fn utf16(v: &[u8], big_endian: bool) -> String {
    let pairs = v.chunks_exact(2);
    let odd = !pairs.remainder().is_empty();
    let units = pairs.map(|p| {
        let pair = [p[0], p[1]];
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    });
    let mut s: String =
        char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect();
    if odd {
        s.push(char::REPLACEMENT_CHARACTER);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::decode_set;
    use crate::{Packet, Standard};

    fn item(tag: u64, v: &[u8]) -> Value {
        decode_item(tag, v, 1, &Config::default()).value
    }

    #[test]
    fn empty_string_is_a_single_null() {
        // MISB ST 0107.4 6.3.3.2 (DECISIONS P-1).
        assert_eq!(item(5, &[0x00]), Value::Text(String::new()));
        assert_eq!(item(5, &[]), Value::Unknown);
    }

    fn text_of(s: &str) -> Value {
        Value::Text(s.into())
    }

    /// The ST 0102 set nested in ST 0601 tag 48 of the ST 0902.8 Annex C
    /// Table 10 "Dynamic & Constant" example packet.
    const ST0902_ANNEX_C: [u8; 28] = [
        0x01, 0x01, 0x01, 0x02, 0x01, 0x07, 0x03, 0x05, 0x2F, 0x2F, 0x55, 0x53, 0x41, 0x0C, 0x01,
        0x07, 0x0D, 0x06, 0x00, 0x55, 0x00, 0x53, 0x00, 0x41, 0x16, 0x02, 0x00, 0x0A,
    ];

    #[test]
    fn st0902_example_set() {
        let p: Packet = decode_set(Standard::St0102, &ST0902_ANNEX_C, 1, &Config::default());
        assert!(p.is_ok());
        assert_eq!(p.items.len(), 6);
        assert_eq!(
            p.get(Tag::SecurityClassification),
            Some(&Value::Enum { code: 1, label: Some("UNCLASSIFIED//") })
        );
        assert_eq!(
            p.get(Tag::ClassifyingCountryCodingMethod),
            Some(&Value::Enum { code: 7, label: Some("1059 Three Letter") })
        );
        assert_eq!(p.get(Tag::ClassifyingCountry), Some(&text_of("//USA")));
        assert_eq!(
            p.get(Tag::ObjectCountryCodingMethod),
            Some(&Value::Enum { code: 7, label: Some("1059 Three Letter") })
        );
        assert_eq!(p.get(Tag::ObjectCountryCodes), Some(&text_of("USA")));
        assert_eq!(p.get(Tag::Version), Some(&Value::Uint(10)));
        let first = &p.items[0];
        assert_eq!(first.name, "Security Classification");
        assert_eq!(first.raw, [0x01]);
        assert_eq!(p.items[5].to_string(), " 22 Version: 10");
    }

    /// MISB ST 0902.8 Annex C Table 10 "Dynamic & Constant", a complete ST
    /// 0601 packet with ST 0102 in tag 48 and ST 1204 in tag 94.
    const ST0902_TABLE_10: &str = "
        06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 81 D2 02 08 00 04 60 50 58 4E 01 80
        03 0A 4D 69 73 73 69 6F 6E 20 31 32 05 02 71 C2 06 02 FD 3D 07 02 08 B8 0A 08 50 72
        65 64 61 74 6F 72 0B 07 45 4F 20 4E 6F 73 65 0C 0E 47 65 6F 64 65 74 69 63 20 57 47
        53 38 34 0D 04 55 95 B6 6D 0E 04 5B 53 60 C4 0F 02 C2 21 10 02 CD 9C 11 02 D9 17 12
        04 72 4A 0A 20 13 04 87 F8 4B 86 14 04 7D C5 5E CE 15 04 03 83 09 26 16 02 12 81 17
        04 F1 01 A2 29 18 04 14 BC 08 2B 19 02 34 F3 30 1C 01 01 01 02 01 07 03 05 2F 2F 55
        53 41 0C 01 07 0D 06 00 55 00 53 00 41 16 02 00 0A 41 01 06 5E 22 01 70 F5 92 F0 23
        73 36 4A F8 AA 91 62 C0 0F 2E B2 DA 16 B7 43 41 00 08 41 A0 BE 36 5B 5A B9 6A 36 45
        01 02 3E 1E";

    #[test]
    fn st0902_packet_end_to_end() {
        let bytes: Vec<u8> = ST0902_TABLE_10
            .split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), 228);
        let p = crate::decode(&bytes).unwrap();
        assert_eq!(p.checksum, crate::Checksum::Valid);
        let security = p.get(48u64).and_then(Value::as_set).unwrap();
        assert_eq!(security.standard, Standard::St0102);
        assert_eq!(security, &decode_set(Standard::St0102, &ST0902_ANNEX_C, 1, &Config::default()));
        assert_eq!(
            security.get(Tag::SecurityClassification),
            Some(&Value::Enum { code: 1, label: Some("UNCLASSIFIED//") })
        );
        let miis = p.get(94u64).unwrap();
        assert_eq!(
            miis.field("Canonical").and_then(Value::as_str),
            Some(
                "0170:F592-F023-7336-4AF8-AA91-62C0-0F2E-B2DA/\
                 16B7-4341-0008-41A0-BE36-5B5A-B96A-3645:D3"
            )
        );
    }

    #[test]
    fn tag_table() {
        for n in 0..=255u64 {
            match Tag::from_u64(n) {
                Some(t) => {
                    assert!((1..=24).contains(&n));
                    assert_eq!(u64::from(t), n);
                    assert!(!t.name().is_empty());
                    assert_eq!(t.units(), "");
                }
                None => assert!(n == 0 || n > 24, "{n}"),
            }
        }
        assert_eq!(Tag::from_u64(u64::MAX), None);
        assert_eq!(Tag::SciShiInformation.name(), "Security-SCI/SHI Information");
        assert_eq!(
            Tag::ObjectCountryCodingMethodVersionDate.name(),
            "Object Country Coding Method Version Date"
        );
    }

    #[test]
    fn classification_codes() {
        let labels =
            ["UNCLASSIFIED//", "RESTRICTED//", "CONFIDENTIAL//", "SECRET//", "TOP SECRET//"];
        for (code, label) in (1u8..).zip(labels) {
            assert_eq!(item(1, &[code]), Value::Enum { code: u64::from(code), label: Some(label) });
        }
        // Undefined codes keep their value without a label.
        assert_eq!(item(1, &[0]), Value::Enum { code: 0, label: None });
        assert_eq!(item(1, &[6]), Value::Enum { code: 6, label: None });
        assert_eq!(item(1, &[0xFF]), Value::Enum { code: 255, label: None });
        assert_eq!(item(1, &[]), Value::Invalid(NO_ZLI));
        assert_eq!(item(1, &[0, 1]), Value::Invalid("enumeration is not 1 byte"));
    }

    #[test]
    fn coding_methods_differ_between_tags_2_and_12() {
        let label = |tag: u64, code: u8| match item(tag, &[code]) {
            Value::Enum { label, .. } => label,
            other => panic!("{other:?}"),
        };
        assert_eq!(label(2, 0x03), Some("FIPS 10-4 Two Letter"));
        assert_eq!(label(12, 0x03), Some("ISO-3166 Numeric"));
        assert_eq!(label(2, 0x05), Some("ISO-3166 Numeric"));
        assert_eq!(label(12, 0x05), Some("FIPS 10-4 Four Letter"));
        assert_eq!(label(2, 0x0A), Some("FIPS 10-4 Mixed"));
        assert_eq!(label(12, 0x0A), Some("Omitted Value"));
        assert_eq!(label(2, 0x10), Some("GENC Mixed"));
        assert_eq!(label(12, 0x10), None);
        assert_eq!(label(2, 0x40), None);
        assert_eq!(label(12, 0x40), Some("GENC AdminSub"));
        // Every code in Table 2 has a label and nothing else does.
        let tag2: Vec<u8> = (0..=255).filter(|&c| classifying_coding_method(c).is_some()).collect();
        assert_eq!(tag2, (1..=0x10).collect::<Vec<u8>>());
        let tag12: Vec<u8> = (0..=255).filter(|&c| object_coding_method(c).is_some()).collect();
        let mut want: Vec<u8> = (1..=0x0F).collect();
        want.push(0x40);
        assert_eq!(tag12, want);
        assert_eq!(item(12, &[]), Value::Invalid(NO_ZLI));
    }

    #[test]
    fn free_text_items() {
        for tag in [3, 4, 5, 6, 7, 8, 9, 11, 14] {
            assert_eq!(item(tag, b"//CAN USA"), text_of("//CAN USA"), "tag {tag}");
        }
        // Bytes outside ISO/IEC 646 do not fail the item.
        assert_eq!(item(5, &[b'F', 0xFF, b'O']), text_of("F\u{FFFD}O"));
        // Content is not checked: a missing "//" is still text.
        assert_eq!(item(3, b"GB"), text_of("GB"));
    }

    #[test]
    fn dates() {
        assert_eq!(item(10, b"20991231"), text_of("20991231"));
        assert_eq!(item(10, b"20240229"), text_of("20240229"));
        assert_eq!(item(10, b"20000229"), text_of("20000229"));
        for bad in [
            &b"2099123"[..],
            b"209912310",
            b"2099-12-31",
            b"20991301",
            b"20990001",
            b"20991200",
            b"20990431",
            b"21000229",
            b"20230229",
            b"2099123X",
            b" 0991231",
        ] {
            assert_eq!(item(10, bad), Value::Invalid("date is not YYYYMMDD"), "{bad:?}");
        }
        for tag in [23, 24] {
            assert_eq!(item(tag, b"2016-07-08"), text_of("2016-07-08"));
            let bad_dates =
                [&b"20160708"[..], b"2016-7-08", b"2016/07/08", b"2016-02-30", b"2016-07-0"];
            for bad in bad_dates {
                assert_eq!(item(tag, bad), Value::Invalid("date is not YYYY-MM-DD"), "{bad:?}");
            }
        }
    }

    #[test]
    fn object_country_codes_encodings() {
        // UTF-16BE without a byte order mark, as ST 0102.10 and later send it.
        let be = [0, b'C', 0, b'A', 0, b'N', 0, b';', 0, b'U', 0, b'S', 0, b'A'];
        assert_eq!(item(13, &be), text_of("CAN;USA"));
        // UTF-16LE without a byte order mark (not RFC 2781, seen from
        // non-conformant encoders).
        assert_eq!(item(13, &[b'U', 0, b'S', 0, b'A', 0]), text_of("USA"));
        // Byte order marks.
        assert_eq!(item(13, &[0xFE, 0xFF, 0, b'U', 0, b'S']), text_of("US"));
        assert_eq!(item(13, &[0xFF, 0xFE, b'U', 0, b'S', 0]), text_of("US"));
        assert_eq!(item(13, &[0xFE, 0xFF]), text_of(""));
        // 8-bit text from ST 0102.9 and earlier, and non-conformant encoders,
        // whatever the length.
        assert_eq!(item(13, b"US"), text_of("US"));
        assert_eq!(item(13, b"USA"), text_of("USA"));
        assert_eq!(item(13, b"CAN;USA;GB"), text_of("CAN;USA;GB"));
        // Not UTF-8 and even: big-endian UTF-16, here U+00C9 U+0041 ("EA").
        assert_eq!(item(13, &[0x00, 0xC9, 0x00, 0x41]), text_of("\u{C9}A"));
        assert_eq!(item(13, &[0xD8, 0x3D, 0xDE, 0x00]), text_of("\u{1F600}"));
        // Unpaired surrogate and odd lengths become U+FFFD.
        assert_eq!(item(13, &[0xFE, 0xFF, 0xD8, 0x00]), text_of("\u{FFFD}"));
        assert_eq!(item(13, &[0xFE, 0xFF, 0, b'U', 0]), text_of("U\u{FFFD}"));
        assert_eq!(item(13, &[0xFF, b'U', 0xC0]), text_of("\u{FFFD}U\u{FFFD}"));
    }

    #[test]
    fn version_and_legacy_items() {
        assert_eq!(item(22, &[0x00, 0x0C]), Value::Uint(12));
        assert_eq!(item(22, &[0x0C]), Value::Invalid("Version is not 2 bytes"));
        assert_eq!(item(22, &[0, 0, 0x0C]), Value::Invalid("Version is not 2 bytes"));
        let umid = [0x5A; 32];
        for tag in 15..=18 {
            assert_eq!(item(tag, &umid), Value::Bytes(umid.to_vec()));
            assert_eq!(item(tag, &umid[..31]), Value::Invalid("UMID is not 32 bytes"));
        }
        assert_eq!(item(19, &[0xE0]), Value::Uint(0xE0));
        assert_eq!(item(19, &[0xE0, 0]), Value::Invalid("Stream ID is not 1 byte"));
        assert_eq!(item(20, &[0x12, 0x34]), Value::Uint(0x1234));
        assert_eq!(item(20, &[0x12]), Value::Invalid("Transport Stream ID is not 2 bytes"));
        let ul = [0x06, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 1, 1, 0, 0, 0];
        assert_eq!(item(21, &ul), Value::Bytes(ul.to_vec()));
        assert_eq!(item(21, &ul[..15]), Value::Invalid("Item Designator ID is not 16 bytes"));
    }

    #[test]
    fn zero_length_items() {
        // MISB ST 0107 (invoked by ST 0102.10-02): a zero-length item is
        // unknown, except for the items Table 2 marks Required.
        let required = [1, 2, 3, 12, 13, 22];
        for tag in 1..=24u64 {
            let it = decode_item(tag, &[], 1, &Config::default());
            let want = if required.contains(&tag) { Value::Invalid(NO_ZLI) } else { Value::Unknown };
            assert_eq!(it.value, want, "tag {tag}");
            assert!(it.raw.is_empty());
        }
    }

    #[test]
    fn unknown_tags_are_raw() {
        let it = decode_item(25, &[1, 2], 1, &Config::default());
        assert_eq!(it.name, "Unknown");
        assert_eq!(it.value, Value::Bytes(vec![1, 2]));
        let it = decode_item(1 << 40, &[], 1, &Config::default());
        assert_eq!(it.tag, 1 << 40);
        assert_eq!(it.name, "Unknown");
    }

    #[test]
    fn raw_is_kept_for_invalid_values() {
        let it = decode_item(10, b"bad", 1, &Config::default());
        assert_eq!(it.value, Value::Invalid("date is not YYYYMMDD"));
        assert_eq!(it.raw, b"bad");
    }

    #[test]
    fn hostile_values_never_panic() {
        // Every tag with a spread of lengths and byte patterns.
        let mut buf = Vec::new();
        for len in 0..80usize {
            for fill in [0x00u8, 0x2F, 0x80, 0xFE, 0xFF] {
                buf.clear();
                buf.extend((0..len).map(|i| fill.wrapping_add(i as u8)));
                for tag in 0..=30 {
                    let it = decode_item(tag, &buf, 1, &Config::default());
                    assert_eq!(it.raw, buf);
                }
            }
        }
    }

    /// A small xorshift generator so the random tests are repeatable.
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    #[test]
    fn random_sets_never_panic() {
        let mut next = rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..5_000 {
            // Well-framed items with random tags and values.
            let mut set = Vec::new();
            for _ in 0..next() % 8 {
                let len = (next() % 40) as u8;
                set.push((next() % 27) as u8);
                set.push(len);
                set.extend((0..len).map(|_| next() as u8));
            }
            let p = decode_set(Standard::St0102, &set, 1, &Config::default());
            assert_eq!(p.error, None);
            // Random bytes, mostly malformed.
            let len = (next() % 64) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let p = decode_set(Standard::St0102, &junk, 1, &Config::default());
            assert!(p.items.len() <= junk.len());
        }
    }
}
