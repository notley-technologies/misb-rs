//! JSON output (the `serde` feature) of decoded packets: a byte-exact
//! golden of a published packet, and the encodings JSON needs for values
//! it cannot carry directly. The unit tests hold the golden of every value
//! kind built by hand.
#![cfg(feature = "serde")]

mod common;

use common::*;
use misb::{Config, Decoder};

/// MISB ST 0902.8 Annex C Table 11, as JSON. The floats are the values the
/// bytes decode to with the ST 0601.19 formulas (shortest round-trip form).
#[test]
fn golden_st0902_packet_b() {
    let p = misb::decode(&spec_packet_b()).unwrap();
    let want = concat!(
        r#"{"standard":"st0601","items":["#,
        r#"{"tag":2,"name":"Precision Time Stamp","units":"us","value":{"type":"time","value":1231798102000000},"raw":"00046050584e0180"},"#,
        r#"{"tag":5,"name":"Platform Heading Angle","units":"deg","value":{"type":"float","value":159.97436484321355},"raw":"71c2"},"#,
        r#"{"tag":6,"name":"Platform Pitch Angle","units":"deg","value":{"type":"float","value":-0.4315317239906003},"raw":"fd3d"},"#,
        r#"{"tag":7,"name":"Platform Roll Angle","units":"deg","value":{"type":"float","value":3.4058656575212867},"raw":"08b8"},"#,
        r#"{"tag":13,"name":"Sensor Latitude","units":"deg","value":{"type":"float","value":60.176822966978335},"raw":"5595b66d"},"#,
        r#"{"tag":14,"name":"Sensor Longitude","units":"deg","value":{"type":"float","value":128.42675904204452},"raw":"5b5360c4"},"#,
        r#"{"tag":15,"name":"Sensor True Altitude","units":"m","value":{"type":"float","value":14190.719462882427},"raw":"c221"},"#,
        r#"{"tag":16,"name":"Sensor Horizontal Field of View","units":"deg","value":{"type":"float","value":144.5712977798123},"raw":"cd9c"},"#,
        r#"{"tag":17,"name":"Sensor Vertical Field of View","units":"deg","value":{"type":"float","value":152.64362554360267},"raw":"d917"},"#,
        r#"{"tag":18,"name":"Sensor Relative Azimuth Angle","units":"deg","value":{"type":"float","value":160.71921143697557},"raw":"724a0a20"},"#,
        r#"{"tag":19,"name":"Sensor Relative Elevation Angle","units":"deg","value":{"type":"float","value":-168.79232483394085},"raw":"87f84b86"},"#,
        r#"{"tag":20,"name":"Sensor Relative Roll Angle","units":"deg","value":{"type":"float","value":176.86543764939194},"raw":"7dc55ece"},"#,
        r#"{"tag":21,"name":"Slant Range","units":"m","value":{"type":"float","value":68590.98329874477},"raw":"03830926"},"#,
        r#"{"tag":22,"name":"Target Width","units":"m","value":{"type":"float","value":722.8198672465096},"raw":"1281"},"#,
        r#"{"tag":23,"name":"Frame Center Latitude","units":"deg","value":{"type":"float","value":-10.542388633146132},"raw":"f101a229"},"#,
        r#"{"tag":24,"name":"Frame Center Longitude","units":"deg","value":{"type":"float","value":29.157890122923018},"raw":"14bc082b"},"#,
        r#"{"tag":25,"name":"Frame Center Elevation","units":"m","value":{"type":"float","value":3216.0372320134275},"raw":"34f3"},"#,
        r#"{"tag":65,"name":"UAS Datalink LS Version Number","units":"","value":{"type":"uint","value":6},"raw":"06"},"#,
        r#"{"tag":1,"name":"Checksum","units":"","value":{"type":"uint","value":23595},"raw":"5c2b"}],"#,
        r#""checksum":{"type":"valid"},"error":null}"#,
    );
    assert_eq!(serde_json::to_string(&p).unwrap(), want);
}

/// ST 1201 special values decode to non-finite floats, which JSON carries as
/// strings; zero-length items are "unknown" without raw bytes; out-of-range
/// and invalid values keep theirs.
#[test]
fn decoded_special_values() {
    let bytes = St0601::new()
        .item(117, &[0xD0, 0x00]) // IMAPB quiet NaN
        .item(118, &[0xC8, 0x00]) // IMAPB +infinity
        .item(119, &[0xE8, 0x00]) // IMAPB -infinity
        .item(13, &[]) // unknown
        .item(6, &[0x80, 0x00]) // out of range
        .item(5, &[1]) // wrong length
        .build();
    let p = misb::decode(&bytes).unwrap();
    let json = serde_json::to_value(&p).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items[0]["value"], serde_json::json!({"type": "float", "value": "NaN"}));
    assert_eq!(items[1]["value"]["value"], "Infinity");
    assert_eq!(items[2]["value"]["value"], "-Infinity");
    assert_eq!(items[3]["value"], serde_json::json!({"type": "unknown"}));
    assert!(items[3].get("raw").is_none(), "an empty raw is left out");
    assert_eq!(items[4]["value"], serde_json::json!({"type": "out_of_range"}));
    assert_eq!(items[4]["raw"], "8000");
    assert_eq!(items[5]["value"]["type"], "invalid");
    assert_eq!(items[5]["raw"], "01");
}

/// Errors, nested sets and checksum outcomes from real decoding.
#[test]
fn decoded_errors_and_checksums() {
    let mut bad = St0601::new().time(1).set(100, Set::new().raw(&[3, 9])).build();
    corrupt_checksum(&mut bad);
    let json = serde_json::to_value(misb::decode(&bad).unwrap()).unwrap();
    assert_eq!(json["checksum"]["type"], "mismatch");
    assert!(json["checksum"]["value"]["expected"].is_u64() && json["checksum"]["value"]["computed"].is_u64());
    let segment = &json["items"][1]["value"];
    assert_eq!(segment["type"], "set");
    assert_eq!(segment["value"]["error"]["kind"], "truncated");
    assert!(segment["value"]["error"]["message"].as_str().unwrap().starts_with("truncated: needed"));
    let missing = St0601::new().time(1).no_checksum().build();
    let json = serde_json::to_value(misb::decode(&missing).unwrap()).unwrap();
    assert_eq!(json["checksum"], serde_json::json!({"type": "missing"}));
    let mut off = Config::default();
    off.verify_checksum = false;
    let json = serde_json::to_value(misb::decode_with(&missing, &off).unwrap()).unwrap();
    assert_eq!(json["checksum"], serde_json::json!({"type": "not_applicable"}));
}

/// A stream as JSON Lines: one line per packet whatever the text holds, and
/// the counters and received packets serialize too.
#[test]
fn json_lines() {
    let hostile = St0601::new().time(1).item(3, b"line one\nline two\r\n\x1b[2J\"quoted\"").build();
    let mut s = hostile.clone();
    s.extend(rich(2));
    s.extend(spec_packet_a());
    let mut d = Decoder::new();
    d.push(&s);
    d.finish();
    let mut lines = Vec::new();
    while let Some(r) = d.next_received() {
        let line = serde_json::to_string(&r).unwrap();
        assert!(!line.contains('\n'));
        lines.push(line);
    }
    assert_eq!(lines.len(), 3);
    let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(first["offset"], 0);
    assert_eq!(first["bytes"].as_str().unwrap().len(), hostile.len() * 2);
    assert_eq!(first["packet"]["items"][1]["value"]["value"], "line one\nline two\r\n\u{1b}[2J\"quoted\"");
    let stats = serde_json::to_value(d.stats()).unwrap();
    assert_eq!(stats["packets"], 3);
    assert_eq!(stats["bytes"], s.len() as u64);
    // Every packet of the rich sample serializes and parses back.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["packet"]["standard"], "st0601");
    }
}
