//! MISB ST 0102.12 Security Metadata Local Set encoding, the value of ST
//! 0601 tag 48 (`nested-encode.md` section C, rules R-NESTED-ENCODE-023 to
//! -049).

use super::{classifying_coding_method, object_coding_method, Tag};
use crate::encode::{put_item, Ctx, EncodeError, EncodeOptions, ErrorKind, Warning};
use crate::{Packet, Standard, Value};

/// ST 0102 Security Classification (tag 1, Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum Classification {
    /// `UNCLASSIFIED//` (0x01).
    Unclassified = 0x01,
    /// `RESTRICTED//` (0x02).
    Restricted = 0x02,
    /// `CONFIDENTIAL//` (0x03).
    Confidential = 0x03,
    /// `SECRET//` (0x04).
    Secret = 0x04,
    /// `TOP SECRET//` (0x05).
    TopSecret = 0x05,
}

impl Classification {
    /// The classification with this code (R-NESTED-ENCODE-025: 1 to 5).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Classification> {
        Some(match code {
            0x01 => Classification::Unclassified,
            0x02 => Classification::Restricted,
            0x03 => Classification::Confidential,
            0x04 => Classification::Secret,
            0x05 => Classification::TopSecret,
            _ => return None,
        })
    }
}

/// An ST 0102 Security Local Set to write into ST 0601 tag 48.
///
/// [`Security::encode`] requires the six items ST 0102.12 Table 2 marks
/// Required (tags 1, 2, 3, 12, 13 and 22, R-NESTED-ENCODE-048) and checks
/// every value against the standard; [`Security::encode_partial`] allows a
/// subset, for the operational exceptions of ST 0102.12 section 6.4 and the
/// tag 12 and 13 only sets of ST 1607 children. The classification is
/// never defaulted: the caller states it.
///
/// ```
/// use misb::encode::{Classification, Security};
/// let mut s = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
/// s.caveats = Some("FOUO".into());
/// let items = s.encode().unwrap();
/// assert_eq!(&items[..3], &[0x01, 0x01, 0x01]);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Security {
    /// Tag 1, Security Classification. Required.
    pub classification: Option<Classification>,
    /// Tag 2, coding method of tags 3 and 6 (the tag 2 column of Table 2:
    /// 0x01 to 0x07, 0x0A to 0x10). Required.
    pub country_coding_method: Option<u8>,
    /// Tag 3, Classifying Country: `//` and the code, e.g. `//US`. A value
    /// without the leading `//` gets it. Required.
    pub classifying_country: Option<String>,
    /// Tag 4, SCI/SHI information; ends with `//` (R-NESTED-ENCODE-032).
    pub sci_shi: Option<String>,
    /// Tag 5, Caveats (FOUO goes here, R-NESTED-ENCODE-033).
    pub caveats: Option<String>,
    /// Tag 6, Releasing Instructions: codes separated by single blanks.
    pub releasing_instructions: Option<String>,
    /// Tag 7, Classified By.
    pub classified_by: Option<String>,
    /// Tag 8, Derived From.
    pub derived_from: Option<String>,
    /// Tag 9, Classification Reason.
    pub classification_reason: Option<String>,
    /// Tag 10, Declassification Date, `YYYYMMDD`.
    pub declassification_date: Option<String>,
    /// Tag 11, Classification and Marking System.
    pub marking_system: Option<String>,
    /// Tag 12, Object Country Coding Method (the tag 12 column of Table 2:
    /// 0x01 to 0x07, 0x0D to 0x0F, 0x40). Required.
    pub object_country_coding_method: Option<u8>,
    /// Tag 13, Object Country Codes, separated by `;`. Required.
    pub object_country_codes: Option<String>,
    /// Tag 14, Classification Comments.
    pub comments: Option<String>,
    /// Tag 22, Version (default 12 for ST 0102.12, DECISIONS D-03).
    pub version: Option<u16>,
    /// Tag 23, Classifying Country Coding Method Version Date, `YYYY-MM-DD`.
    pub country_coding_method_date: Option<String>,
    /// Tag 24, Object Country Coding Method Version Date, `YYYY-MM-DD`.
    pub object_country_coding_method_date: Option<String>,
}

impl Security {
    /// A set with the five caller-supplied required values (tag 22 is
    /// written as 12).
    #[must_use]
    pub fn new(
        classification: Classification,
        country_coding_method: u8,
        classifying_country: &str,
        object_country_coding_method: u8,
        object_country_codes: &str,
    ) -> Security {
        Security {
            classification: Some(classification),
            country_coding_method: Some(country_coding_method),
            classifying_country: Some(classifying_country.to_string()),
            object_country_coding_method: Some(object_country_coding_method),
            object_country_codes: Some(object_country_codes.to_string()),
            ..Security::default()
        }
    }

    /// The set's items, ready for ST 0601 tag 48 (pass them as
    /// [`crate::encode::Input::Set`]). Requires the Required items.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut warnings = Vec::new();
        self.encode_with(&EncodeOptions::default(), &mut warnings, false)
    }

    /// As [`Security::encode`], allowing any subset of the items
    /// (R-NESTED-ENCODE-048); present values are still checked.
    pub fn encode_partial(&self) -> Result<Vec<u8>, EncodeError> {
        let mut warnings = Vec::new();
        self.encode_with(&EncodeOptions::default(), &mut warnings, true)
    }

    /// As [`Security::encode`] or [`Security::encode_partial`], collecting
    /// warnings (for example a legacy FIPS 10-4 coding method).
    pub fn encode_with(
        &self,
        opts: &EncodeOptions,
        warnings: &mut Vec<Warning>,
        partial: bool,
    ) -> Result<Vec<u8>, EncodeError> {
        let mut ctx = Ctx::new(opts, warnings, Standard::St0102);
        let mut out = Vec::new();
        self.write(&mut ctx, partial, &mut out)?;
        Ok(out)
    }

    fn write(&self, ctx: &mut Ctx<'_>, partial: bool, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let required = |ctx: &mut Ctx<'_>, tag: u64, present: bool| {
            ctx.tag = Some(tag);
            if present || partial {
                Ok(())
            } else {
                Err(ctx.err(ErrorKind::Missing, "required by ST 0102.12 Table 2"))
            }
        };
        let version = self.version.or(if partial { None } else { Some(12) });
        required(ctx, 1, self.classification.is_some())?;
        required(ctx, 2, self.country_coding_method.is_some())?;
        required(ctx, 3, self.classifying_country.is_some())?;
        required(ctx, 12, self.object_country_coding_method.is_some())?;
        required(ctx, 13, self.object_country_codes.is_some())?;
        ctx.tag = None;
        // R-NESTED-ENCODE-022: ascending tags; -044: tags 15 to 21 never.
        if let Some(c) = self.classification {
            put_item(out, 1, &[c as u8]);
        }
        if let Some(m) = self.country_coding_method {
            ctx.tag = Some(2);
            check_country_method(ctx, m, false)?;
            put_item(out, 2, &[m]);
        }
        if let Some(c) = &self.classifying_country {
            ctx.tag = Some(3);
            // R-NESTED-ENCODE-030: "//" then the code.
            let c = if c.starts_with("//") { c.clone() } else { format!("//{c}") };
            if c.len() <= 2 {
                return Err(ctx.err(ErrorKind::Missing, "classifying country code"));
            }
            put_item(out, 3, &ascii(ctx, &c)?);
        }
        let texts: [(u64, &Option<String>); 3] =
            [(4, &self.sci_shi), (5, &self.caveats), (6, &self.releasing_instructions)];
        for (tag, value) in texts {
            if let Some(v) = value {
                ctx.tag = Some(tag);
                let b = ascii(ctx, v)?;
                match tag {
                    // R-NESTED-ENCODE-032: entries end with "//".
                    4 if !v.ends_with("//") => return Err(ctx.err(ErrorKind::WrongType, "SCI/SHI must end with //")),
                    // R-NESTED-ENCODE-034: single blanks, never underscores.
                    6 if v.contains("  ") || v.contains('_') => {
                        return Err(ctx.err(ErrorKind::WrongType, "releasing instructions are separated by single blanks"))
                    }
                    _ => {}
                }
                put_item(out, tag, &b);
            }
        }
        let texts: [(u64, &Option<String>); 3] =
            [(7, &self.classified_by), (8, &self.derived_from), (9, &self.classification_reason)];
        for (tag, value) in texts {
            if let Some(v) = value {
                ctx.tag = Some(tag);
                put_item(out, tag, &ascii(ctx, v)?);
            }
        }
        if let Some(d) = &self.declassification_date {
            ctx.tag = Some(10);
            // R-NESTED-ENCODE-036: YYYYMMDD, a real date.
            if super::date(d.as_bytes(), false) != Value::Text(d.clone()) {
                return Err(ctx.err(ErrorKind::WrongType, "declassification date must be a real YYYYMMDD date"));
            }
            put_item(out, 10, d.as_bytes());
        }
        if let Some(v) = &self.marking_system {
            ctx.tag = Some(11);
            put_item(out, 11, &ascii(ctx, v)?);
        }
        if let Some(m) = self.object_country_coding_method {
            ctx.tag = Some(12);
            check_country_method(ctx, m, true)?;
            put_item(out, 12, &[m]);
        }
        if let Some(codes) = &self.object_country_codes {
            ctx.tag = Some(13);
            // R-NESTED-ENCODE-039, -049: at least one code, ";" with no
            // blanks; -040: UTF-16BE without a byte order mark.
            if codes.is_empty() || codes.split(';').any(|c| c.is_empty() || c.contains(' ')) {
                return Err(ctx.err(ErrorKind::WrongType, "object country codes are separated by ';' with no blanks"));
            }
            let utf16: Vec<u8> = codes.encode_utf16().flat_map(u16::to_be_bytes).collect();
            put_item(out, 13, &utf16);
        }
        if let Some(v) = &self.comments {
            ctx.tag = Some(14);
            put_item(out, 14, &ascii(ctx, v)?);
        }
        if let Some(v) = version {
            // R-NESTED-ENCODE-042: uint16, exactly 2 bytes.
            put_item(out, 22, &v.to_be_bytes());
        }
        let dates: [(u64, &Option<String>); 2] =
            [(23, &self.country_coding_method_date), (24, &self.object_country_coding_method_date)];
        for (tag, value) in dates {
            if let Some(d) = value {
                ctx.tag = Some(tag);
                // R-NESTED-ENCODE-043: YYYY-MM-DD, a real date.
                if super::date(d.as_bytes(), true) != Value::Text(d.clone()) {
                    return Err(ctx.err(ErrorKind::WrongType, "version date must be a real YYYY-MM-DD date"));
                }
                put_item(out, tag, d.as_bytes());
            }
        }
        if out.is_empty() {
            ctx.tag = None;
            return Err(ctx.err(ErrorKind::Missing, "a security set needs at least one item"));
        }
        Ok(())
    }

    /// The set described by a decoded ST 0102 [`Packet`] (strings, codes
    /// and the version as the decoder reports them).
    pub fn from_set(set: &Packet) -> Result<Security, EncodeError> {
        let e = |tag, kind, reason| EncodeError::new(Standard::St0102, Some(tag), kind, reason);
        if set.standard != Standard::St0102 {
            return Err(EncodeError::new(Standard::St0102, None, ErrorKind::WrongType, "not an ST 0102 set"));
        }
        let mut s = Security::default();
        for item in &set.items {
            let text = || match &item.value {
                Value::Text(t) => Ok(Some(t.clone())),
                _ => Err(e(item.tag, ErrorKind::WrongType, "expected text")),
            };
            let code = || match &item.value {
                Value::Enum { code, .. } | Value::Uint(code) => {
                    u8::try_from(*code).map_err(|_| e(item.tag, ErrorKind::InvalidCode, "code out of range"))
                }
                _ => Err(e(item.tag, ErrorKind::WrongType, "expected a code")),
            };
            match Tag::from_u64(item.tag) {
                Some(Tag::SecurityClassification) => {
                    s.classification = Some(
                        Classification::from_code(code()?)
                            .ok_or_else(|| e(1, ErrorKind::InvalidCode, "classification is 1 to 5"))?,
                    )
                }
                Some(Tag::ClassifyingCountryCodingMethod) => s.country_coding_method = Some(code()?),
                Some(Tag::ClassifyingCountry) => s.classifying_country = text()?,
                Some(Tag::SciShiInformation) => s.sci_shi = text()?,
                Some(Tag::Caveats) => s.caveats = text()?,
                Some(Tag::ReleasingInstructions) => s.releasing_instructions = text()?,
                Some(Tag::ClassifiedBy) => s.classified_by = text()?,
                Some(Tag::DerivedFrom) => s.derived_from = text()?,
                Some(Tag::ClassificationReason) => s.classification_reason = text()?,
                Some(Tag::DeclassificationDate) => s.declassification_date = text()?,
                Some(Tag::ClassificationAndMarkingSystem) => s.marking_system = text()?,
                Some(Tag::ObjectCountryCodingMethod) => s.object_country_coding_method = Some(code()?),
                Some(Tag::ObjectCountryCodes) => s.object_country_codes = text()?,
                Some(Tag::ClassificationComments) => s.comments = text()?,
                Some(Tag::Version) => match item.value {
                    Value::Uint(v) => {
                        s.version = Some(u16::try_from(v).map_err(|_| e(22, ErrorKind::OutOfRange, "version"))?)
                    }
                    _ => return Err(e(22, ErrorKind::WrongType, "expected an integer")),
                },
                Some(Tag::ClassifyingCountryCodingMethodVersionDate) => s.country_coding_method_date = text()?,
                Some(Tag::ObjectCountryCodingMethodVersionDate) => s.object_country_coding_method_date = text()?,
                // R-NESTED-ENCODE-044: deleted tags are never written.
                _ => return Err(e(item.tag, ErrorKind::NotAllowed, "tag not defined by ST 0102.12")),
            }
        }
        Ok(s)
    }
}

/// R-NESTED-ENCODE-027 to -029, -038: a code of the right column, never an
/// "Omitted Value"; FIPS 10-4 methods are legacy-only (warning).
fn check_country_method(ctx: &mut Ctx<'_>, m: u8, object: bool) -> Result<(), EncodeError> {
    let label = if object { object_coding_method(m) } else { classifying_coding_method(m) };
    match label {
        None | Some("Omitted Value") => Err(ctx.err(ErrorKind::InvalidCode, "country coding method not in ST 0102.12 Table 2")),
        Some(l) => {
            if l.starts_with("FIPS") {
                ctx.warn("FIPS 10-4 country coding is for legacy systems only");
            }
            Ok(())
        }
    }
}

/// R-NESTED-ENCODE-045 (D-05): printable ASCII, 0x20 to 0x7E, as ISO 646
/// text; the empty string is the single byte 00 (R-NESTED-ENCODE-019).
fn ascii(ctx: &Ctx<'_>, s: &str) -> Result<Vec<u8>, EncodeError> {
    if s.is_empty() {
        return Ok(vec![0]);
    }
    if !s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err(ctx.err(ErrorKind::WrongType, "ST 0102 text is printable ASCII (ISO/IEC 646) only"));
    }
    if s.starts_with(' ') || s.ends_with(' ') {
        return Err(ctx.err(ErrorKind::WrongType, "text may not start or end with a blank (MISB ST 0107)"));
    }
    Ok(s.as_bytes().to_vec())
}

/// Re-encode a decoded ST 0102 set (ST 0601 tag 48 given as a
/// [`Value::Set`]). Items whose recorded bytes still decode to their value
/// are written from those bytes; the rest is checked as by [`Security`].
pub(crate) fn encode_set(set: &Packet, ctx: &mut Ctx<'_>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let cfg = crate::Config::default();
    let unchanged = !set.items.is_empty()
        && set.items.iter().all(|i| {
            !i.raw.is_empty()
                && crate::encode::same_value(
                    &crate::registry::decode_item_of(Standard::St0102, i.tag, &i.raw, 1, &cfg).value,
                    &i.value,
                )
        });
    if unchanged {
        for i in &set.items {
            put_item(out, i.tag, &i.raw);
        }
        return Ok(());
    }
    let s = Security::from_set(set)?;
    let tag = ctx.tag.unwrap_or(48);
    ctx.within(Standard::St0102, tag, |ctx| s.write(ctx, true, out))
}
