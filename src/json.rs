//! NDJSON authoring format for the encoder (feature `json`).
//!
//! One JSON object per line describes one ST 0601 packet (MUXING_PLAN.md
//! section 6.4):
//!
//! ```json
//! {"time": "2026-11-17T15:04:05.123456Z", "time_scale": "utc", "items": {"MissionId": "MISSION01", "13": 38.88, "SensorLongitude": -77.04, "SlantRange": null}}
//! {"time_us": 1763391874123374, "items": {"SecurityLocalSet": {"SecurityClassification": "UNCLASSIFIED//", "ClassifyingCountryCodingMethod": "GENC Two Letter", "ClassifyingCountry": "//US", "ObjectCountryCodingMethod": 13, "ObjectCountryCodes": "US"}}}
//! ```
//!
//! - `time` is an RFC 3339 instant and then `time_scale` (`"utc"` or
//!   `"misp"`) is mandatory, so UTC and MISP time are never confused;
//!   `time_us` is a microsecond count, MISP time unless `time_scale` says
//!   `"utc"` (a POSIX count). UTC is converted with a leap second table.
//! - `items` maps tags to values in engineering units. A key is the tag
//!   number (`"13"`), the [`crate::st0601::Tag`] variant name
//!   (`"SensorLatitude"`) or the standard's name (`"Sensor Latitude"`).
//!   `null` writes a zero-length item ("unknown"); a missing key writes
//!   nothing.
//! - Values: numbers; text (and enumeration labels, and RFC 3339 instants
//!   for the time items in the record's `time_scale`); `{"special":
//!   "off_earth" | "out_of_range" | "below_minimum" | "above_maximum"}`;
//!   `{"hex": "..."}` for bytes and encoded sets; objects and arrays for
//!   packs and lists, with the field names the decoder uses. Tag 48 takes
//!   an object of ST 0102 items (keys as for ST 0601, values as numbers,
//!   labels or text), checked like [`crate::encode::Security::encode`].
//!   Nested sets (tags 48, 74) also accept the decoder's own JSON of a set.
//! - `version` overrides tag 65; `interpolate` maps tags to `"hold"`,
//!   `"linear"`, `"angle"` or `"geodesic"` ([`Interpolation`]) for a
//!   [`crate::track::Track`]: [`Record::to_keyframe`] (or `From`) turns a
//!   record into a track keyframe with its hints. The packet encoder
//!   ignores them.
//!
//! A line in the decoder's own JSON (the `misb` serde output of a
//! [`crate::Packet`], or the `{"offset":..,"packet":{..}}` lines of the
//! `json` example) is accepted too and re-encoded with
//! [`crate::encode::encode_packet`], so `decode -> JSON -> edit -> encode`
//! works and unchanged items keep their recorded bytes. [`schema`] returns
//! the JSON Schema of the authoring format, generated from the tag table.
//!
//! # Live control commands
//!
//! A live injector's control channel takes one command object per line
//! (MUXING_PLAN.md section 6.7), applied to a
//! [`MetadataState`]:
//!
//! ```json
//! {"set": {"SensorLatitude": 38.8, "SlantRange": null}}
//! {"clear": ["MissionId", "13"]}
//! {"clear_all": true, "set": {"MissionId": "M2"}, "version": 19, "emit": true}
//! ```
//!
//! [`parse_commands`] reads a line into [`Command`]s (the order they apply
//! in is documented there), [`apply_commands`] applies them to a state as
//! one change and reports whether a packet was asked for, and
//! [`apply_line`] does both. [`control_schema`] is their JSON Schema.

use crate::encode::{encode_packet, EncodeError, EncodeOptions, Input, Security, St0601Builder};
use crate::state::MetadataState;
use crate::track::Keyframe;
use crate::{st0102, st0601, Field, Item, LeapSeconds, MispTime, Packet, Standard, UtcDateTime, Value};
use serde_json::{Map, Value as Json};
use std::fmt;

/// Why a line could not be read or encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct JsonError {
    /// What is wrong, naming the key when one is at fault.
    pub message: String,
    /// The encoder's error, when it is the cause.
    pub encode: Option<EncodeError>,
}

impl JsonError {
    fn new(message: impl Into<String>) -> JsonError {
        JsonError { message: message.into(), encode: None }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for JsonError {}

impl From<EncodeError> for JsonError {
    fn from(e: EncodeError) -> JsonError {
        JsonError { message: e.to_string(), encode: Some(e) }
    }
}

/// How a track fills in a tag between keyframes; defined in
/// [`crate::track`] and re-exported here, where it first appeared.
pub use crate::track::Interpolation;

/// One authoring record.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Record {
    /// Tag 2.
    pub time: MispTime,
    /// Tag 65 override.
    pub version: Option<u8>,
    /// The items in line order; [`Input::Value`]`(`[`Value::Unknown`]`)`
    /// stands for `null`.
    pub items: Vec<(st0601::Tag, Input)>,
    /// Interpolation hints.
    pub interpolate: Vec<(st0601::Tag, Interpolation)>,
}

impl Record {
    /// A builder holding this record's packet.
    pub fn to_builder(&self, opts: &EncodeOptions) -> Result<St0601Builder, EncodeError> {
        let mut b = St0601Builder::with_options(self.time, opts.clone());
        if let Some(v) = self.version {
            b.version(v);
        }
        for (tag, input) in &self.items {
            match input {
                Input::Value(Value::Unknown) => b.unknown(*tag)?,
                _ => b.set(*tag, input.clone())?,
            };
        }
        Ok(b)
    }

    /// The [`Keyframe`] of this record for a [`crate::track::Track`]: its
    /// time, version, items and interpolation hints.
    #[must_use]
    pub fn to_keyframe(&self) -> Keyframe {
        Keyframe {
            time: self.time,
            version: self.version,
            items: self.items.clone(),
            interpolate: self.interpolate.clone(),
        }
    }
}

impl From<Record> for Keyframe {
    /// The keyframe of an authoring record (one NDJSON line), interpolation
    /// hints included.
    fn from(r: Record) -> Keyframe {
        Keyframe { time: r.time, version: r.version, items: r.items, interpolate: r.interpolate }
    }
}

/// Encode one line (authoring record or decoder JSON) to an ST 0601 packet.
pub fn encode_line(line: &str, opts: &EncodeOptions, table: &LeapSeconds) -> Result<Vec<u8>, JsonError> {
    let json: Json = serde_json::from_str(line).map_err(|e| JsonError::new(format!("not JSON: {e}")))?;
    if let Some(packet) = decoded_packet(&json)? {
        return Ok(encode_packet(&packet, opts)?);
    }
    Ok(parse_record_json(&json, table)?.to_builder(opts)?.finish()?)
}

/// Read an authoring record.
pub fn parse_record(line: &str, table: &LeapSeconds) -> Result<Record, JsonError> {
    let json: Json = serde_json::from_str(line).map_err(|e| JsonError::new(format!("not JSON: {e}")))?;
    parse_record_json(&json, table)
}

/// Read a line of the decoder's JSON back into a [`Packet`].
pub fn parse_decoded(line: &str) -> Result<Packet, JsonError> {
    let json: Json = serde_json::from_str(line).map_err(|e| JsonError::new(format!("not JSON: {e}")))?;
    decoded_packet(&json)?.ok_or_else(|| JsonError::new("not the decoder's JSON of a packet"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scale {
    Utc,
    Misp,
}

fn parse_record_json(json: &Json, table: &LeapSeconds) -> Result<Record, JsonError> {
    let obj = json.as_object().ok_or_else(|| JsonError::new("a record is a JSON object"))?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "time" | "time_us" | "time_scale" | "version" | "items" | "interpolate") {
            return Err(JsonError::new(format!("unknown key {key:?}")));
        }
    }
    let scale = match obj.get("time_scale") {
        None => None,
        Some(Json::String(s)) if s == "utc" => Some(Scale::Utc),
        Some(Json::String(s)) if s == "misp" => Some(Scale::Misp),
        Some(_) => return Err(JsonError::new("time_scale must be \"utc\" or \"misp\"")),
    };
    let time = match (obj.get("time"), obj.get("time_us")) {
        (Some(_), Some(_)) => return Err(JsonError::new("give time or time_us, not both")),
        (Some(Json::String(s)), None) => {
            let scale = scale.ok_or_else(|| JsonError::new("time_scale is required with time"))?;
            instant(s, scale, table)?
        }
        (Some(_), None) => return Err(JsonError::new("time is an RFC 3339 string")),
        (None, Some(t)) => {
            let us = t.as_u64().ok_or_else(|| JsonError::new("time_us is a non-negative integer"))?;
            match scale.unwrap_or(Scale::Misp) {
                Scale::Misp => MispTime::from_micros(us),
                Scale::Utc => i64::try_from(us)
                    .ok()
                    .and_then(|us| MispTime::from_posix_utc_micros(us, table))
                    .ok_or_else(|| JsonError::new("time_us cannot be converted from UTC"))?,
            }
        }
        (None, None) => return Err(JsonError::new("time or time_us is required")),
    };
    let version = match obj.get("version") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| JsonError::new("version is 0 to 255"))?,
        ),
    };
    let mut items = Vec::new();
    if let Some(map) = obj.get("items") {
        let map = map.as_object().ok_or_else(|| JsonError::new("items is an object"))?;
        for (key, value) in map {
            let tag = st0601_tag(key)?;
            match tag {
                st0601::Tag::Checksum | st0601::Tag::PrecisionTimeStamp => {
                    return Err(JsonError::new(format!("{key}: tags 1 and 2 are written by the encoder")))
                }
                _ => {}
            }
            let input = item_input(tag, value, scale, table).map_err(|e| JsonError::new(format!("{key}: {e}")))?;
            items.push((tag, input));
        }
    }
    let mut interpolate = Vec::new();
    if let Some(map) = obj.get("interpolate") {
        let map = map.as_object().ok_or_else(|| JsonError::new("interpolate is an object"))?;
        for (key, value) in map {
            let how = value
                .as_str()
                .and_then(Interpolation::from_name)
                .ok_or_else(|| JsonError::new(format!("{key}: interpolation is hold, linear, angle or geodesic")))?;
            interpolate.push((st0601_tag(key)?, how));
        }
    }
    Ok(Record { time, version, items, interpolate })
}

fn instant(s: &str, scale: Scale, table: &LeapSeconds) -> Result<MispTime, JsonError> {
    let t: UtcDateTime = s.parse().map_err(|_| JsonError::new(format!("{s:?} is not an RFC 3339 UTC instant")))?;
    match scale {
        Scale::Utc => MispTime::from_utc(t, table).ok_or_else(|| JsonError::new(format!("{s} is not a valid UTC instant"))),
        // A MISP reading on 86,400-second days (the format of Value::Time).
        Scale::Misp => {
            if t.second == 60 {
                return Err(JsonError::new("MISP time has no second 60"));
            }
            let us = misp_reading_micros(&t).ok_or_else(|| JsonError::new("time before 1970"))?;
            Ok(MispTime::from_micros(us))
        }
    }
}

/// Microseconds of a calendar reading on 86,400-second days.
fn misp_reading_micros(t: &UtcDateTime) -> Option<u64> {
    let days = {
        let y = i64::from(t.year) - i64::from(t.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(t.month);
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + i64::from(t.day) - 1;
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    };
    let secs = days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second);
    u64::try_from(secs.checked_mul(1_000_000)?.checked_add(i64::from(t.micros))?).ok()
}

/// A tag by number, variant name or standard name.
fn st0601_tag(key: &str) -> Result<st0601::Tag, JsonError> {
    let found = match key.parse::<u64>() {
        Ok(n) => st0601::Tag::from_u64(n),
        Err(_) => (1..=143)
            .filter_map(st0601::Tag::from_u64)
            .find(|t| t.name() == key || format!("{t:?}") == key),
    };
    found.ok_or_else(|| JsonError::new(format!("{key:?} is not an ST 0601 tag")))
}

fn st0102_tag(key: &str) -> Result<st0102::Tag, JsonError> {
    let found = match key.parse::<u64>() {
        Ok(n) => st0102::Tag::from_u64(n),
        Err(_) => (1..=24)
            .filter_map(st0102::Tag::from_u64)
            .find(|t| t.name() == key || format!("{t:?}") == key),
    };
    found.ok_or_else(|| JsonError::new(format!("{key:?} is not an ST 0102 tag")))
}

fn item_input(tag: st0601::Tag, v: &Json, scale: Option<Scale>, table: &LeapSeconds) -> Result<Input, JsonError> {
    let is_time = matches!(
        tag,
        st0601::Tag::PrecisionTimeStamp | st0601::Tag::EventStartTime | st0601::Tag::TakeOffTime
    );
    Ok(match v {
        Json::Null => Input::Value(Value::Unknown),
        Json::Bool(_) => return Err(JsonError::new("booleans are not ST 0601 values")),
        Json::Number(n) => number(n)?,
        Json::String(s) if is_time => {
            let scale = scale.ok_or_else(|| JsonError::new("time_scale is required for time strings"))?;
            Input::Time(instant(s, scale, table)?)
        }
        Json::String(s) => Input::Text(s.clone()),
        Json::Object(o) => {
            if let Some(input) = special(o)? {
                return Ok(input);
            }
            if tag == st0601::Tag::SecurityLocalSet && !o.contains_key("items") {
                return Ok(Input::Set(security(o)?.encode()?));
            }
            if o.contains_key("items") && o.contains_key("standard") {
                let p = packet(v)?;
                return Ok(Input::Value(Value::Set(Box::new(p))));
            }
            Input::Value(authoring_value(v)?)
        }
        Json::Array(_) => Input::Value(authoring_value(v)?),
    })
}

fn number(n: &serde_json::Number) -> Result<Input, JsonError> {
    if let Some(u) = n.as_u64() {
        Ok(Input::Uint(u))
    } else if let Some(i) = n.as_i64() {
        Ok(Input::Int(i))
    } else {
        n.as_f64().map(Input::Float).ok_or_else(|| JsonError::new("number out of range"))
    }
}

/// `{"special": ..}` and `{"hex": ..}`.
fn special(o: &Map<String, Json>) -> Result<Option<Input>, JsonError> {
    if o.len() != 1 {
        return Ok(None);
    }
    if let Some(s) = o.get("special") {
        return Ok(Some(match s.as_str() {
            Some("off_earth") => Input::OffEarth,
            Some("out_of_range") => Input::OutOfRange,
            Some("below_minimum") => Input::BelowMinimum,
            Some("above_maximum") => Input::AboveMaximum,
            _ => return Err(JsonError::new("special is off_earth, out_of_range, below_minimum or above_maximum")),
        }));
    }
    if let Some(h) = o.get("hex") {
        let h = h.as_str().ok_or_else(|| JsonError::new("hex is a string"))?;
        return Ok(Some(Input::Bytes(hex(h)?)));
    }
    Ok(None)
}

fn hex(s: &str) -> Result<Vec<u8>, JsonError> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return Err(JsonError::new("hex has an odd number of digits"));
    }
    digits
        .chunks(2)
        .map(|p| {
            let d = |c: u8| (c as char).to_digit(16);
            match (d(p[0]), d(p[1])) {
                (Some(a), Some(b)) => Ok((a * 16 + b) as u8),
                _ => Err(JsonError::new("hex has a non-hex digit")),
            }
        })
        .collect()
}

/// A pack or list value of the authoring format.
fn authoring_value(v: &Json) -> Result<Value, JsonError> {
    Ok(match v {
        Json::Null => Value::Unknown,
        Json::Bool(_) => return Err(JsonError::new("booleans are not ST 0601 values")),
        Json::Number(n) => match number(n)? {
            Input::Uint(u) => Value::Uint(u),
            Input::Int(i) => Value::Int(i),
            Input::Float(f) => Value::Float(f),
            _ => unreachable!("number() returns a number"),
        },
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(a) => Value::List(a.iter().map(authoring_value).collect::<Result<_, _>>()?),
        Json::Object(o) => {
            if let Some(s) = special(o)? {
                return match s {
                    Input::OutOfRange => Ok(Value::OutOfRange),
                    Input::Bytes(b) => Ok(Value::Bytes(b)),
                    _ => Err(JsonError::new("only out_of_range is allowed inside a pack")),
                };
            }
            let mut fields = Vec::with_capacity(o.len());
            for (name, value) in o {
                let name = field_name(name).ok_or_else(|| JsonError::new(format!("unknown pack field {name:?}")))?;
                fields.push(Field::new(name, authoring_value(value)?));
            }
            Value::Struct(fields)
        }
    })
}

/// Tag 48 as an object of ST 0102 items.
fn security(o: &Map<String, Json>) -> Result<Security, JsonError> {
    let mut s = Security::default();
    for (key, value) in o {
        let tag = st0102_tag(key)?;
        let e = |m: &str| JsonError::new(format!("{key}: {m}"));
        let text = || value.as_str().map(str::to_string).ok_or_else(|| e("expected text"));
        let code = |labels: fn(u8) -> Option<&'static str>| -> Result<u8, JsonError> {
            match value {
                Json::Number(n) => n.as_u64().and_then(|c| u8::try_from(c).ok()).ok_or_else(|| e("code is 0 to 255")),
                Json::String(l) => (0..=255u8).find(|&c| labels(c) == Some(l.as_str())).ok_or_else(|| e("no code has this label")),
                _ => Err(e("expected a code or its label")),
            }
        };
        match tag {
            st0102::Tag::SecurityClassification => {
                let c = match value {
                    Json::String(l) => {
                        let l = l.trim_end_matches('/');
                        (1..=5u8)
                            .find(|&c| st0102::classification(c).map(|x| x.trim_end_matches('/')) == Some(l))
                            .ok_or_else(|| e("unknown classification"))?
                    }
                    _ => code(st0102::classification)?,
                };
                s.classification =
                    Some(crate::encode::Classification::from_code(c).ok_or_else(|| e("classification is 1 to 5"))?);
            }
            st0102::Tag::ClassifyingCountryCodingMethod => s.country_coding_method = Some(code(st0102::classifying_coding_method)?),
            st0102::Tag::ObjectCountryCodingMethod => s.object_country_coding_method = Some(code(st0102::object_coding_method)?),
            st0102::Tag::ClassifyingCountry => s.classifying_country = Some(text()?),
            st0102::Tag::SciShiInformation => s.sci_shi = Some(text()?),
            st0102::Tag::Caveats => s.caveats = Some(text()?),
            st0102::Tag::ReleasingInstructions => s.releasing_instructions = Some(text()?),
            st0102::Tag::ClassifiedBy => s.classified_by = Some(text()?),
            st0102::Tag::DerivedFrom => s.derived_from = Some(text()?),
            st0102::Tag::ClassificationReason => s.classification_reason = Some(text()?),
            st0102::Tag::DeclassificationDate => s.declassification_date = Some(text()?),
            st0102::Tag::ClassificationAndMarkingSystem => s.marking_system = Some(text()?),
            st0102::Tag::ObjectCountryCodes => s.object_country_codes = Some(text()?),
            st0102::Tag::ClassificationComments => s.comments = Some(text()?),
            st0102::Tag::Version => {
                s.version = Some(value.as_u64().and_then(|v| u16::try_from(v).ok()).ok_or_else(|| e("version is 0 to 65535"))?)
            }
            st0102::Tag::ClassifyingCountryCodingMethodVersionDate => s.country_coding_method_date = Some(text()?),
            st0102::Tag::ObjectCountryCodingMethodVersionDate => s.object_country_coding_method_date = Some(text()?),
            _ => return Err(e("this ST 0102 tag was deleted and is not written")),
        }
    }
    Ok(s)
}

// ------------------------------------------------------- control commands

/// One live control command (MUXING_PLAN.md section 6.7), for the control
/// channel of a live injector driven by a [`MetadataState`].
///
/// A command line is one JSON object; its keys combine freely and
/// [`parse_commands`] returns them in the order they are applied:
///
/// 1. `"clear_all": true`: [`Command::ClearAll`];
/// 2. `"clear": [keys]`: [`Command::Clear`];
/// 3. `"set": {items}`: [`Command::Set`];
/// 4. `"unknown": [keys]`: [`Command::Unknown`];
/// 5. `"version": n` or `null`: [`Command::Version`];
/// 6. `"emit": true`: [`Command::Emit`].
///
/// So `{"clear_all": true, "set": {..}}` replaces the whole state. Keys and
/// values of `set` are exactly those of an authoring record's `items`
/// (`null` marks an item unknown), and the keys of `clear` and `unknown`
/// are tag numbers (as strings or numbers), variant names or the
/// standard's names. One tag may appear in only one of `clear`, `set` and
/// `unknown` (and tag 65 not with `version`), so the order never decides a
/// conflict. `"time_scale"` (`"utc"` or `"misp"`) gives the scale of RFC
/// 3339 strings for the time items in `set`. An empty object is no
/// command. [`control_schema`] is the JSON Schema.
///
/// ```json
/// {"set": {"SensorLatitude": 38.8, "SlantRange": null}}
/// {"clear": ["MissionId", "13"], "unknown": ["SlantRange"], "emit": true}
/// {"clear_all": true}
/// {"version": 19}
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Command {
    /// Stop reporting every item and drop the version override
    /// ([`MetadataState::clear_all`]).
    ClearAll,
    /// Stop reporting these items ([`MetadataState::clear`]).
    Clear(Vec<st0601::Tag>),
    /// Set these items ([`MetadataState::set`]); `Input::Value(Value::Unknown)`
    /// (JSON `null`) marks one unknown.
    Set(Vec<(st0601::Tag, Input)>),
    /// Mark these items unknown ([`MetadataState::unknown`]).
    Unknown(Vec<st0601::Tag>),
    /// Override tag 65, or with `None` return to the default
    /// ([`MetadataState::set_version`]).
    Version(Option<u8>),
    /// Send a packet now. Not a change to the state: [`apply_commands`]
    /// reports it in [`Applied::emit`] for the caller to act on.
    Emit,
}

/// What [`apply_commands`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Applied {
    /// A packet was asked for now ([`Command::Emit`]).
    pub emit: bool,
    /// The state changed (its [`MetadataState::revision`] moved).
    pub changed: bool,
}

/// Read one control command line into its commands, in the order they
/// apply (see [`Command`]). Errors name the key at fault. `table` converts
/// UTC time strings in `set`.
pub fn parse_commands(line: &str, table: &LeapSeconds) -> Result<Vec<Command>, JsonError> {
    let json: Json = serde_json::from_str(line).map_err(|e| JsonError::new(format!("not JSON: {e}")))?;
    let obj = json.as_object().ok_or_else(|| JsonError::new("a command is a JSON object"))?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "set" | "clear" | "clear_all" | "unknown" | "version" | "emit" | "time_scale") {
            return Err(JsonError::new(format!("unknown command key {key:?}")));
        }
    }
    let flag = |key: &str| match obj.get(key) {
        None => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(JsonError::new(format!("{key} is true or false"))),
    };
    let scale = match obj.get("time_scale") {
        None => None,
        Some(Json::String(s)) if s == "utc" => Some(Scale::Utc),
        Some(Json::String(s)) if s == "misp" => Some(Scale::Misp),
        Some(_) => return Err(JsonError::new("time_scale must be \"utc\" or \"misp\"")),
    };
    let tags = |key: &str| -> Result<Vec<st0601::Tag>, JsonError> {
        let Some(v) = obj.get(key) else { return Ok(Vec::new()) };
        let list = v.as_array().ok_or_else(|| JsonError::new(format!("{key} is an array of tags")))?;
        let mut out = Vec::with_capacity(list.len());
        for entry in list {
            let name = match entry {
                Json::String(s) => s.clone(),
                Json::Number(n) => n.to_string(),
                _ => return Err(JsonError::new(format!("{key}: a tag is a number or a name"))),
            };
            let tag = st0601_tag(&name).map_err(|e| JsonError::new(format!("{key}: {e}")))?;
            if matches!(tag, st0601::Tag::Checksum | st0601::Tag::PrecisionTimeStamp) {
                return Err(JsonError::new(format!("{key}: {name}: tags 1 and 2 are written by the encoder")));
            }
            out.push(tag);
        }
        Ok(out)
    };
    let clear = tags("clear")?;
    let unknown = tags("unknown")?;
    let mut set = Vec::new();
    if let Some(v) = obj.get("set") {
        let map = v.as_object().ok_or_else(|| JsonError::new("set is an object of items"))?;
        for (key, value) in map {
            let tag = st0601_tag(key).map_err(|e| JsonError::new(format!("set: {e}")))?;
            if matches!(tag, st0601::Tag::Checksum | st0601::Tag::PrecisionTimeStamp) {
                return Err(JsonError::new(format!("set: {key}: tags 1 and 2 are written by the encoder")));
            }
            let input = item_input(tag, value, scale, table).map_err(|e| JsonError::new(format!("set: {key}: {e}")))?;
            set.push((tag, input));
        }
    }
    let version = match obj.get("version") {
        None => None,
        Some(Json::Null) => Some(None),
        Some(v) => Some(Some(
            v.as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| JsonError::new("version is 0 to 255, or null for the default"))?,
        )),
    };
    // A tag in two lists would be decided by the order alone: refuse it.
    let mut lists: Vec<(&str, st0601::Tag)> = Vec::new();
    lists.extend(clear.iter().map(|&t| ("clear", t)));
    lists.extend(set.iter().map(|&(t, _)| ("set", t)));
    lists.extend(unknown.iter().map(|&t| ("unknown", t)));
    if version.is_some() {
        lists.push(("version", st0601::Tag::UasDatalinkLsVersionNumber));
    }
    for (i, &(a, tag)) in lists.iter().enumerate() {
        if let Some(&(b, _)) = lists[i + 1..].iter().find(|&&(_, t)| t == tag) {
            let what = if a == b { format!("twice in {a}") } else { format!("in both {a} and {b}") };
            return Err(JsonError::new(format!("tag {} ({}) is {what}", tag as u64, tag.name())));
        }
    }
    let mut out = Vec::new();
    if flag("clear_all")? {
        out.push(Command::ClearAll);
    }
    if !clear.is_empty() {
        out.push(Command::Clear(clear));
    }
    if !set.is_empty() {
        out.push(Command::Set(set));
    }
    if !unknown.is_empty() {
        out.push(Command::Unknown(unknown));
    }
    if let Some(v) = version {
        out.push(Command::Version(v));
    }
    if flag("emit")? {
        out.push(Command::Emit);
    }
    Ok(out)
}

/// Apply commands to `state` in order, as one change: every value is
/// checked as [`MetadataState::set`] checks it, and if any command fails
/// the state is left as it was (so a snapshot never sees half of a command
/// line). Values are set at MISP time `at` (usually now). The error names
/// the item at fault.
pub fn apply_commands(commands: &[Command], state: &mut MetadataState, at: MispTime) -> Result<Applied, JsonError> {
    let before = state.revision();
    let mut next = state.clone();
    let mut emit = false;
    for c in commands {
        match c {
            Command::ClearAll => next.clear_all(),
            Command::Clear(tags) => {
                for &tag in tags {
                    next.clear(tag);
                }
            }
            Command::Set(items) => {
                for (tag, input) in items {
                    next.set(*tag, input.clone(), at)?;
                }
            }
            Command::Unknown(tags) => {
                for &tag in tags {
                    next.unknown(tag, at)?;
                }
            }
            Command::Version(v) => {
                next.set_version(*v);
            }
            Command::Emit => emit = true,
        }
    }
    *state = next;
    Ok(Applied { emit, changed: state.revision() != before })
}

/// [`parse_commands`] then [`apply_commands`]: one control line applied to
/// `state` at MISP time `at`.
pub fn apply_line(line: &str, state: &mut MetadataState, at: MispTime, table: &LeapSeconds) -> Result<Applied, JsonError> {
    apply_commands(&parse_commands(line, table)?, state, at)
}

// ------------------------------------------------------- the decoder's JSON

/// The packet of a decoder JSON line, or `None` for another shape.
fn decoded_packet(json: &Json) -> Result<Option<Packet>, JsonError> {
    let obj = match json.as_object() {
        Some(o) => o,
        None => return Ok(None),
    };
    // The `json` example wraps the packet: {"offset": .., "packet": {..}}.
    let inner = match obj.get("packet") {
        Some(p) if obj.contains_key("offset") => p,
        _ => json,
    };
    match inner.as_object() {
        Some(o) if o.get("items").map_or(false, Json::is_array) && o.contains_key("standard") => packet(inner).map(Some),
        _ => Ok(None),
    }
}

fn standard(s: &str) -> Option<Standard> {
    Some(match s {
        "st0601" => Standard::St0601,
        "st0102" => Standard::St0102,
        "st0806" => Standard::St0806,
        "st0903" => Standard::St0903,
        _ => return None,
    })
}

fn packet(v: &Json) -> Result<Packet, JsonError> {
    let o = v.as_object().ok_or_else(|| JsonError::new("a packet is an object"))?;
    let std = o
        .get("standard")
        .and_then(Json::as_str)
        .and_then(standard)
        .ok_or_else(|| JsonError::new("unknown standard"))?;
    let mut p = Packet::new(std);
    for item in o.get("items").and_then(Json::as_array).ok_or_else(|| JsonError::new("items is an array"))? {
        let tag = item.get("tag").and_then(Json::as_u64).ok_or_else(|| JsonError::new("an item has no tag"))?;
        let value = decoded_value(item.get("value").ok_or_else(|| JsonError::new(format!("tag {tag} has no value")))?)
            .map_err(|e| JsonError::new(format!("tag {tag}: {e}")))?;
        let raw = match item.get("raw") {
            Some(Json::String(h)) => hex(h)?,
            _ => Vec::new(),
        };
        p.items.push(Item::new(tag, "", "", value, raw));
    }
    Ok(p)
}

/// A [`Value`] from its serde form, `{"type": .., "value": ..}`.
fn decoded_value(v: &Json) -> Result<Value, JsonError> {
    let kind = v.get("type").and_then(Json::as_str).ok_or_else(|| JsonError::new("a value has no type"))?;
    let inner = v.get("value");
    let need = || inner.ok_or_else(|| JsonError::new(format!("{kind} without a value")));
    Ok(match kind {
        "uint" => Value::Uint(need()?.as_u64().ok_or_else(|| JsonError::new("uint"))?),
        "int" => Value::Int(need()?.as_i64().ok_or_else(|| JsonError::new("int"))?),
        "time" => Value::Time(need()?.as_u64().ok_or_else(|| JsonError::new("time"))?),
        "float" => Value::Float(match need()? {
            Json::String(s) if s == "NaN" => f64::NAN,
            Json::String(s) if s == "Infinity" => f64::INFINITY,
            Json::String(s) if s == "-Infinity" => f64::NEG_INFINITY,
            n => n.as_f64().ok_or_else(|| JsonError::new("float"))?,
        }),
        "text" => Value::Text(need()?.as_str().ok_or_else(|| JsonError::new("text"))?.to_string()),
        "bytes" => Value::Bytes(hex(need()?.as_str().ok_or_else(|| JsonError::new("bytes"))?)?),
        "enum" => {
            let e = need()?;
            let code = e.get("code").and_then(Json::as_u64).ok_or_else(|| JsonError::new("enum code"))?;
            // Labels matter to the encoder only for the Off-Earth state.
            let label = match e.get("label").and_then(Json::as_str) {
                Some("N/A (Off-Earth)") => Some("N/A (Off-Earth)"),
                _ => None,
            };
            Value::Enum { code, label }
        }
        "out_of_range" => Value::OutOfRange,
        "unknown" => Value::Unknown,
        "set" => Value::Set(Box::new(packet(need()?)?)),
        "list" => Value::List(
            need()?
                .as_array()
                .ok_or_else(|| JsonError::new("list"))?
                .iter()
                .map(decoded_value)
                .collect::<Result<_, _>>()?,
        ),
        "struct" => {
            let mut fields = Vec::new();
            for f in need()?.as_array().ok_or_else(|| JsonError::new("struct"))? {
                let name = f.get("name").and_then(Json::as_str).ok_or_else(|| JsonError::new("field without a name"))?;
                let name = field_name(name).ok_or_else(|| JsonError::new(format!("unknown pack field {name:?}")))?;
                fields.push(Field::new(name, decoded_value(f.get("value").ok_or_else(|| JsonError::new(name))?)?));
            }
            Value::Struct(fields)
        }
        "invalid" => Value::Invalid("invalid in the decoder's JSON"),
        other => return Err(JsonError::new(format!("unknown value type {other:?}"))),
    })
}

/// The decoder's static name for a pack field (the value model keeps
/// `&'static str` names; an unknown name is an error, which also catches
/// typos).
pub(crate) fn field_name(name: &str) -> Option<&'static str> {
    FIELD_NAMES.iter().copied().find(|&n| n == name)
}

/// Every pack field name the decoders produce (a test checks the list
/// against decoded data).
static FIELD_NAMES: &[&str] = &[
    // ST 0601 packs.
    "Laser Range", "Auto-Track", "IR Polarity", "Icing Status", "Slant Range", "Image Invalid",
    "Station Number", "Substation Number", "Weapon Type", "Weapon Variant",
    "Start x0", "Start y0", "End x1", "End y1", "Start Latitude", "Start Longitude", "End Latitude", "End Longitude",
    "Command ID", "Command String", "Command Time",
    "Coding Method", "Overflight Country", "Operator Country", "Country of Manufacture",
    "Numerator", "Denominator",
    "Wavelength ID", "Minimum Wavelength", "Maximum Wavelength", "Wavelength Name",
    "Take-off Location", "Recovery Location", "Latitude", "Longitude", "HAE",
    "Payload Count", "Payload Records", "Payload ID", "Payload Type", "Payload Name",
    "Station ID", "Hardpoint ID", "Carriage ID", "Store ID", "General Status",
    "Fuze Enabled", "Laser Enabled", "Target Enabled", "Weapon Armed",
    "Waypoint ID", "Prosecution Order", "Mode", "Source", "Location",
    "Azimuth Start", "Azimuth Range", "Elevation Start", "Elevation Range", "Roll Start", "Roll Range",
    "Local Id", "Universal Id",
    // ST 1204.
    "Canonical", "Version", "Usage Value", "Sensor ID Type", "Platform ID Type", "Window ID Type", "Minor ID Type",
    "Sensor ID", "Platform ID", "Window ID", "Minor ID", "Check Value",
    // ST 0903.
    "Target Centroid", "Target Priority", "Target Confidence Level", "Target Height", "Target ID",
    "Target Location Latitude Offset", "Target Location Longitude Offset", "Target Location",
    "Detection Status", "VMask", "VObject", "VObject Series", "VFeature", "VFeature Series", "VTracker",
    "VChip", "VChip Series", "Track ID", "Track Boundary Series", "Track History Series", "First Observation Time",
    "Latest Observation Time", "Number of Track Points", "Confidence", "Confidence Level", "Algorithm",
    "Algorithm ID", "Ontology", "Ontology ID", "Ontology Class", "Pixel Contour", "Bit Mask Series", "Pixel",
    "Run Length", "Image Type", "Embedded Image", "Velocity", "Acceleration", "North", "East", "Up", "Height",
    "Sigma North", "Sigma East", "Sigma Up", "Rho East-North", "Rho East-Up", "Rho North-Up",
    "MIIS ID", "Precision Time Stamp", "Value", "Label", "Tag", "Name",
    // ST 0806.
    "POI/AOI Number", "POI/AOI Type", "POI/AOI Label", "POI/AOI Text", "POI/AOI Source ID", "POI Latitude",
    "POI Longitude", "POI Altitude", "POI Source Icon", "Operation ID", "Data Type", "Numeric ID",
    "Numeric ID for Data Type", "User Data",
    "Corner Latitude Point 1 (Decimal Degrees)", "Corner Longitude Point 1 (Decimal Degrees)",
    "Corner Latitude Point 3 (Decimal Degrees)", "Corner Longitude Point 3 (Decimal Degrees)",
    // ST 1010.
    "Matrix Size", "Parse Control", "Sparse", "Standard Deviation Format", "Standard Deviation Length",
    "Correlation Format", "Correlation Length", "Standard Deviation Values", "Correlation Coefficient Values",
    "Number of Frames", "Error",
    // From the decoders' field tables.
    "Bounding Box Bottom Right", "Bounding Box Bottom Right Latitude Offset",
    "Bounding Box Bottom Right Longitude Offset", "Bounding Box Top Left", "Bounding Box Top Left Latitude Offset",
    "Bounding Box Top Left Longitude Offset", "Centroid Pixel Column", "Centroid Pixel Row", "Class", "FPA Index",
    "Geospatial Contour Series", "Image IRI", "Parent ID", "Schema", "Schema Feature", "Target Color",
    "Target History", "Target Intensity", "Version IRI",
];

// ------------------------------------------------------------------ schema

/// The JSON Schema (draft 2020-12) of an authoring record, generated from
/// the ST 0601 tag table.
#[must_use]
pub fn schema() -> Json {
    let items = item_schemas();
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "MISB ST 0601 authoring record (misb NDJSON, one record per line)",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "time": {"type": "string", "description": "RFC 3339 UTC or MISP reading; needs time_scale"},
            "time_us": {"type": "integer", "minimum": 0, "description": "MISP microseconds, or POSIX UTC with time_scale utc"},
            "time_scale": {"enum": ["utc", "misp"]},
            "version": {"type": "integer", "minimum": 0, "maximum": 255, "description": "tag 65 override (default 19)"},
            "items": {
                "type": "object",
                "description": "Keys: the Tag variant name (listed), the tag number or the standard's name. null = unknown.",
                "properties": items,
                "patternProperties": {"^[0-9]+$": {}}
            },
            "interpolate": {
                "type": "object",
                "additionalProperties": {"enum": ["hold", "linear", "angle", "geodesic"]}
            }
        },
        "oneOf": [{"required": ["time", "time_scale"]}, {"required": ["time_us"]}]
    })
}

/// The schema of each item value, keyed by `Tag` variant name.
fn item_schemas() -> Map<String, Json> {
    let mut items = Map::new();
    for tag in (3..=143).filter_map(st0601::Tag::from_u64) {
        if matches!(tag, st0601::Tag::Deprecated | st0601::Tag::MetadataSubstreamIdPack) {
            continue;
        }
        items.insert(format!("{tag:?}"), st0601::encode::tag_schema(tag));
    }
    items
}

/// The JSON Schema (draft 2020-12) of a live control command line (see
/// [`Command`]), generated from the ST 0601 tag table like [`schema`].
#[must_use]
pub fn control_schema() -> Json {
    let tag_list = serde_json::json!({
        "type": "array",
        "items": {"oneOf": [{"type": "string"}, {"type": "integer", "minimum": 3, "maximum": 143}]},
        "description": "Tags: the Tag variant name, the tag number or the standard's name."
    });
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "MISB ST 0601 live control command (misb NDJSON, one command per line)",
        "description": "Applied in this order: clear_all, clear, set, unknown, version, emit. A tag may appear in only one of clear, set and unknown.",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "clear_all": {"type": "boolean", "description": "stop reporting every item and drop the version override"},
            "clear": tag_list.clone(),
            "set": {
                "type": "object",
                "description": "Items as in an authoring record. null = unknown.",
                "properties": item_schemas(),
                "patternProperties": {"^[0-9]+$": {}}
            },
            "unknown": tag_list,
            "version": {"oneOf": [{"type": "integer", "minimum": 0, "maximum": 255}, {"type": "null"}], "description": "tag 65 override; null for the default (19)"},
            "emit": {"type": "boolean", "description": "send a packet now"},
            "time_scale": {"enum": ["utc", "misp"], "description": "scale of RFC 3339 strings for the time items in set"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misp_reading() {
        let t: UtcDateTime = "2022-07-12T09:05:32.000618Z".parse().unwrap();
        assert_eq!(misp_reading_micros(&t), Some(1_657_616_732_000_618));
    }

    #[test]
    fn field_names_are_unique() {
        let mut v: Vec<&str> = FIELD_NAMES.to_vec();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n);
    }
}
