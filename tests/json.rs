//! The NDJSON authoring format and the decoder-JSON round trip.
#![forbid(unsafe_code)]
mod common;

use common::*;
use misb::encode::{Classification, EncodeOptions, Input, Security, St0601Builder};
use misb::json::{encode_line, parse_decoded, parse_record, Interpolation};
use misb::st0601::Tag;
use misb::{LeapSeconds, MispTime, Value};

fn encode(line: &str) -> Result<Vec<u8>, misb::json::JsonError> {
    encode_line(line, &EncodeOptions::default(), LeapSeconds::builtin())
}

#[test]
fn authoring_record_matches_the_builder() {
    let line = r#"{"time_us": 1224807209913000, "items": {"MissionId": "MISSION01", "13": 60.176822966978335,
        "Sensor Longitude": 128.42675904204452, "SlantRange": null, "IcingDetected": "Icing Detected",
        "TargetWidthExtended": {"special": "above_maximum"}, "SensorFrameRatePack": {"Numerator": 60000, "Denominator": 1001}}}"#
        .replace('\n', " ");
    let mut b = St0601Builder::new(MispTime::from_micros(1_224_807_209_913_000));
    b.set(Tag::MissionId, "MISSION01").unwrap();
    b.set(Tag::SensorLatitude, 60.176_822_966_978_335).unwrap();
    b.set(Tag::SensorLongitude, 128.426_759_042_044_52).unwrap();
    b.unknown(Tag::SlantRange).unwrap();
    b.set(Tag::IcingDetected, Input::Code(2)).unwrap();
    b.set(Tag::TargetWidthExtended, Input::AboveMaximum).unwrap();
    let rate = Value::Struct(vec![
        misb::Field::new("Numerator", Value::Uint(60_000)),
        misb::Field::new("Denominator", Value::Uint(1001)),
    ]);
    b.set(Tag::SensorFrameRatePack, rate).unwrap();
    assert_eq!(encode(&line).unwrap(), b.finish().unwrap());
}

#[test]
fn time_scales() {
    let utc = encode(r#"{"time": "2022-07-12T09:05:03.000700Z", "time_scale": "utc"}"#).unwrap();
    let misp = encode(r#"{"time": "2022-07-12T09:05:32.000618Z", "time_scale": "misp"}"#).unwrap();
    let count = encode(r#"{"time_us": 1657616732000618}"#).unwrap();
    let posix = encode(r#"{"time_us": 1657616703000700, "time_scale": "utc"}"#).unwrap();
    assert_eq!(utc, misp);
    assert_eq!(utc, count);
    assert_eq!(utc, posix);
    let p = misb::decode(&utc).unwrap();
    assert_eq!(p.get(Tag::PrecisionTimeStamp), Some(&Value::Time(1_657_616_732_000_618)));
    // An ISO time needs its scale; so do time strings inside items.
    assert!(encode(r#"{"time": "2022-07-12T09:05:03Z"}"#).is_err());
    assert!(encode(r#"{"time_us": 1, "items": {"EventStartTime": "2022-07-12T09:05:03Z"}}"#).is_err());
    let t = encode(r#"{"time_us": 1, "time_scale": "misp", "items": {"EventStartTime": "2022-07-12T09:05:32.000618Z"}}"#)
        .unwrap();
    assert_eq!(misb::decode(&t).unwrap().get(Tag::EventStartTime), Some(&Value::Time(1_657_616_732_000_618)));
}

#[test]
fn security_object() {
    let line = r#"{"time_us": 1, "items": {"SecurityLocalSet": {"SecurityClassification": "UNCLASSIFIED//",
        "ClassifyingCountryCodingMethod": "GENC Two Letter", "3": "//US", "Object Country Coding Method": 13,
        "ObjectCountryCodes": "US", "Caveats": "FOUO"}}}"#
        .replace('\n', " ");
    let mut s = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
    s.caveats = Some("FOUO".into());
    let mut b = St0601Builder::new(MispTime::from_micros(1));
    b.set(Tag::SecurityLocalSet, Input::Set(s.encode().unwrap())).unwrap();
    assert_eq!(encode(&line).unwrap(), b.finish().unwrap());
    // The required items are checked.
    let missing = r#"{"time_us": 1, "items": {"SecurityLocalSet": {"SecurityClassification": 1}}}"#;
    assert!(encode(missing).unwrap_err().message.contains("ST 0102"));
}

#[test]
fn errors_name_the_key() {
    for (line, needle) in [
        (r#"{"time_us": 1, "items": {"Bogus": 1}}"#, "Bogus"),
        (r#"{"time_us": 1, "items": {"SensorLatitude": 91}}"#, "tag 13 (Sensor Latitude)"),
        (r#"{"time_us": 1, "items": {"1": 1}}"#, "tags 1 and 2"),
        (r#"{"time_us": 1, "extra": 1}"#, "extra"),
        (r#"{"time_us": 1, "items": {"SensorFrameRatePack": {"Numerater": 1}}}"#, "Numerater"),
        (r#"{"time_us": 1, "items": {"MissionId": true}}"#, "booleans"),
        ("not json", "not JSON"),
    ] {
        let e = encode(line).unwrap_err();
        assert!(e.message.contains(needle), "{line}: {e}");
    }
}

#[test]
fn interpolation_hints_and_version() {
    let r = parse_record(
        r#"{"time_us": 5, "version": 17, "items": {"SensorLatitude": 1.5}, "interpolate": {"SensorLatitude": "geodesic"}}"#,
        LeapSeconds::builtin(),
    )
    .unwrap();
    assert_eq!(r.interpolate, [(Tag::SensorLatitude, Interpolation::Geodesic)]);
    assert_eq!(r.version, Some(17));
    let p = misb::decode(&r.to_builder(&EncodeOptions::default()).unwrap().finish().unwrap()).unwrap();
    assert_eq!(p.get(65u8), Some(&Value::Uint(17)));
}

/// Every packet of the test corpus survives decode -> JSON -> encode byte
/// for byte, which also proves the field name table covers what the
/// decoders produce.
#[test]
fn decoder_json_round_trips() {
    let mut packets = vec![spec_packet_a(), spec_packet_b()];
    for i in 0..64 {
        packets.push(rich(i));
        packets.push(sample(i));
    }
    packets.push(St0601::new().time(7).set(74, vmti_set()).set(73, rvt_set()).set(48, security_set()).item(65, &[19]).build());
    for bytes in packets {
        let p = misb::decode(&bytes).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back = parse_decoded(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
        assert_eq!(misb::encode::encode_packet(&back, &EncodeOptions::default()).unwrap(), bytes, "{json}");
        // The `json` example's envelope too.
        let line = format!(r#"{{"offset": 0, "packet": {json}}}"#);
        assert_eq!(encode(&line).unwrap(), bytes);
    }
}

#[test]
fn edited_decoder_json_is_re_encoded_from_the_value() {
    let p = misb::decode(&spec_packet_b()).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&p).unwrap();
    // Change Sensor Latitude's value but leave its stale raw bytes.
    for item in json["items"].as_array_mut().unwrap() {
        if item["tag"] == 13 {
            item["value"]["value"] = serde_json::json!(45.0);
        }
    }
    let out = encode(&json.to_string()).unwrap();
    let q = misb::decode(&out).unwrap();
    assert!(q.is_ok());
    assert!((q.get(Tag::SensorLatitude).unwrap().as_f64().unwrap() - 45.0).abs() < 1e-7);
    assert_eq!(q.items.len(), p.items.len());
}

#[test]
fn committed_schema_is_current() {
    let generated = serde_json::to_string_pretty(&misb::json::schema()).unwrap() + "\n";
    // A Windows checkout may have turned the line endings into CRLF.
    let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/schema/st0601-authoring.schema.json"))
        .expect("docs/schema/st0601-authoring.schema.json")
        .replace("\r\n", "\n");
    assert!(
        generated == committed,
        "regenerate with: cargo run --features json --example klvencode -- --schema > docs/schema/st0601-authoring.schema.json"
    );
    // Every documented key parses as a tag.
    let schema = misb::json::schema();
    for key in schema["properties"]["items"]["properties"].as_object().unwrap().keys() {
        let line = format!(r#"{{"time_us": 1, "items": {{"{key}": null}}}}"#);
        let r = parse_record(&line, LeapSeconds::builtin());
        assert!(r.is_ok(), "{key}: {:?}", r.err());
    }
}
