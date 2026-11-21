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

// ------------------------------------------------------------ keyframes

#[test]
fn records_become_track_keyframes() {
    use misb::track::{Keyframe, Track, TrackConfig};
    let lines = [
        r#"{"time_us": 1000000, "version": 18, "items": {"MissionId": "M1", "SlantRange": 1000, "SensorLatitude": 0, "SensorLongitude": 170}, "interpolate": {"SlantRange": "hold"}}"#,
        r#"{"time_us": 2000000, "items": {"SlantRange": 2000, "SensorLatitude": 0, "SensorLongitude": -170}}"#,
    ];
    let records: Vec<_> = lines.iter().map(|l| parse_record(l, LeapSeconds::builtin()).unwrap()).collect();
    let k = records[0].to_keyframe();
    assert_eq!(k.time, MispTime::from_micros(1_000_000));
    assert_eq!(k.version, Some(18));
    assert_eq!(k.interpolate, [(Tag::SlantRange, Interpolation::Hold)]);
    assert_eq!(Keyframe::from(records[0].clone()), k);
    let t = Track::from_keyframes(TrackConfig::new(), records.into_iter().map(Keyframe::from)).unwrap();
    let s = t.sample(MispTime::from_micros(1_500_000)).unwrap();
    assert_eq!(s.get(Tag::SlantRange), Some(&Input::Uint(1000)), "the hint holds it");
    assert_eq!(s.get(Tag::SensorLongitude).and_then(Input::as_f64).map(f64::abs), Some(180.0));
    assert_eq!(s.version(), Some(18));
    // A hint that cannot apply is refused when the keyframe is pushed.
    let bad = parse_record(r#"{"time_us": 1, "items": {"SlantRange": 1}, "interpolate": {"SlantRange": "geodesic"}}"#, LeapSeconds::builtin())
        .unwrap();
    let e = Track::from_keyframes(TrackConfig::new(), [bad.into()]).unwrap_err();
    assert!(e.to_string().contains("tag 21 (Slant Range)"), "{e}");
}

// ------------------------------------------------------------ control commands

mod control {
    use misb::encode::Input;
    use misb::json::{apply_commands, apply_line, control_schema, parse_commands, Command};
    use misb::state::MetadataState;
    use misb::st0601::Tag;
    use misb::{LeapSeconds, MispTime, Value};

    fn parse(line: &str) -> Result<Vec<Command>, misb::json::JsonError> {
        parse_commands(line, LeapSeconds::builtin())
    }

    fn t(us: u64) -> MispTime {
        MispTime::from_micros(1_700_000_000_000_000 + us)
    }

    #[test]
    fn each_command() {
        assert_eq!(
            parse(r#"{"set": {"SensorLatitude": 38.8, "SlantRange": null, "13": 1}}"#).unwrap_err().message,
            "tag 13 (Sensor Latitude) is twice in set"
        );
        assert_eq!(
            parse(r#"{"set": {"SensorLatitude": 38.8, "SlantRange": null}}"#).unwrap(),
            [Command::Set(vec![(Tag::SensorLatitude, Input::Float(38.8)), (Tag::SlantRange, Input::Value(Value::Unknown))])]
        );
        assert_eq!(
            parse(r#"{"clear": ["MissionId", "13", 14, "Slant Range"]}"#).unwrap(),
            [Command::Clear(vec![Tag::MissionId, Tag::SensorLatitude, Tag::SensorLongitude, Tag::SlantRange])]
        );
        assert_eq!(parse(r#"{"clear_all": true}"#).unwrap(), [Command::ClearAll]);
        assert_eq!(parse(r#"{"clear_all": false}"#).unwrap(), []);
        assert_eq!(parse(r#"{"unknown": ["SlantRange"]}"#).unwrap(), [Command::Unknown(vec![Tag::SlantRange])]);
        assert_eq!(parse(r#"{"version": 19}"#).unwrap(), [Command::Version(Some(19))]);
        assert_eq!(parse(r#"{"version": null}"#).unwrap(), [Command::Version(None)]);
        assert_eq!(parse(r#"{"emit": true}"#).unwrap(), [Command::Emit]);
        assert_eq!(parse("{}").unwrap(), []);
    }

    #[test]
    fn combinations_come_in_the_documented_order() {
        let cmds = parse(
            r#"{"emit": true, "version": 17, "unknown": ["SlantRange"], "set": {"MissionId": "M2"}, "clear": ["13"], "clear_all": true}"#,
        )
        .unwrap();
        assert_eq!(
            cmds,
            [
                Command::ClearAll,
                Command::Clear(vec![Tag::SensorLatitude]),
                Command::Set(vec![(Tag::MissionId, Input::Text("M2".into()))]),
                Command::Unknown(vec![Tag::SlantRange]),
                Command::Version(Some(17)),
                Command::Emit,
            ]
        );
    }

    #[test]
    fn errors_name_the_problem() {
        for (line, needle) in [
            ("[1]", "a command is a JSON object"),
            ("nope", "not JSON"),
            (r#"{"sett": {}}"#, "unknown command key \"sett\""),
            (r#"{"set": [1]}"#, "set is an object of items"),
            (r#"{"set": {"Bogus": 1}}"#, "set: \"Bogus\" is not an ST 0601 tag"),
            (r#"{"set": {"2": 1}}"#, "set: 2: tags 1 and 2 are written by the encoder"),
            (r#"{"set": {"MissionId": true}}"#, "set: MissionId: booleans"),
            (r#"{"set": {"EventStartTime": "2026-01-01T00:00:00Z"}}"#, "time_scale is required"),
            (r#"{"clear": "MissionId"}"#, "clear is an array of tags"),
            (r#"{"clear": [true]}"#, "clear: a tag is a number or a name"),
            (r#"{"clear": ["1"]}"#, "tags 1 and 2"),
            (r#"{"unknown": ["Nope"]}"#, "unknown: \"Nope\" is not an ST 0601 tag"),
            (r#"{"clear_all": 1}"#, "clear_all is true or false"),
            (r#"{"emit": "yes"}"#, "emit is true or false"),
            (r#"{"version": 256}"#, "version is 0 to 255"),
            (r#"{"time_scale": "tai"}"#, "time_scale must be"),
            (r#"{"set": {"SlantRange": 1}, "clear": ["SlantRange"]}"#, "tag 21 (Slant Range) is in both clear and set"),
            (r#"{"set": {"SlantRange": 1}, "unknown": ["21"]}"#, "is in both set and unknown"),
            (r#"{"set": {"65": 17}, "version": 18}"#, "tag 65 (UAS Datalink LS Version Number) is in both set and version"),
        ] {
            let e = parse(line).unwrap_err();
            assert!(e.message.contains(needle), "{line}: {e}");
        }
        // A time string with its scale is fine.
        let c = parse(r#"{"time_scale": "misp", "set": {"EventStartTime": "2022-07-12T09:05:32.000618Z"}}"#).unwrap();
        assert_eq!(c, [Command::Set(vec![(Tag::EventStartTime, Input::Time(MispTime::from_micros(1_657_616_732_000_618)))])]);
    }

    #[test]
    fn applying_commands_to_a_state() {
        let mut s = MetadataState::new();
        let table = LeapSeconds::builtin();
        let r = apply_line(r#"{"set": {"MissionId": "M1", "SensorLatitude": 38.8, "SlantRange": null}}"#, &mut s, t(0), table).unwrap();
        assert_eq!((r.emit, r.changed), (false, true));
        assert_eq!(s.get(Tag::SlantRange), Some(&Input::Value(Value::Unknown)));
        assert_eq!(s.set_at(Tag::MissionId), Some(t(0)));
        let r = apply_line(r#"{"emit": true}"#, &mut s, t(1), table).unwrap();
        assert_eq!((r.emit, r.changed), (true, false));
        apply_line(r#"{"clear": ["MissionId"], "unknown": ["13"], "version": 18}"#, &mut s, t(2), table).unwrap();
        assert!(s.get(Tag::MissionId).is_none());
        assert_eq!(s.get(Tag::SensorLatitude), Some(&Input::Value(Value::Unknown)));
        assert_eq!(s.version(), Some(18));
        apply_line(r#"{"clear_all": true, "set": {"MissionId": "M2"}}"#, &mut s, t(3), table).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), None);
        assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("M2".into())));
        let r = apply_line(r#"{"clear": ["SlantRange"]}"#, &mut s, t(4), table).unwrap();
        assert!(!r.changed, "clearing an item without a value changes nothing");
    }

    #[test]
    fn a_failing_line_changes_nothing() {
        let mut s = MetadataState::new();
        let table = LeapSeconds::builtin();
        apply_line(r#"{"set": {"MissionId": "M1", "SensorLatitude": 10}}"#, &mut s, t(0), table).unwrap();
        let rev = s.revision();
        // The latitude is out of range; the clear_all and the mission id
        // before it must not take effect either.
        let e = apply_line(r#"{"clear_all": true, "set": {"MissionId": "M2", "SensorLatitude": 91}}"#, &mut s, t(1), table)
            .unwrap_err();
        assert!(e.message.contains("tag 13 (Sensor Latitude)"), "{e}");
        assert!(e.encode.is_some());
        assert_eq!(s.revision(), rev);
        assert_eq!(s.get(Tag::MissionId), Some(&Input::Text("M1".into())));
        let e = apply_commands(&[Command::Unknown(vec![Tag::ControlCommand])], &mut s, t(1)).unwrap_err();
        assert!(e.message.contains("tag 115"), "{e}");
        assert_eq!(s.revision(), rev);
    }

    #[test]
    fn committed_control_schema_is_current() {
        let generated = serde_json::to_string_pretty(&control_schema()).unwrap() + "\n";
        let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/schema/st0601-control.schema.json"))
            .expect("docs/schema/st0601-control.schema.json")
            .replace("\r\n", "\n");
        assert!(
            generated == committed,
            "regenerate with: cargo run --features json --example klvencode -- --control-schema > docs/schema/st0601-control.schema.json"
        );
        // Every documented item key parses in a set command.
        let schema = control_schema();
        for key in schema["properties"]["set"]["properties"].as_object().unwrap().keys() {
            let line = format!(r#"{{"set": {{"{key}": null}}}}"#);
            assert!(parse(&line).is_ok(), "{key}");
        }
    }
}
