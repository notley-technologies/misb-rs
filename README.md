# misb

A Rust and C decoder and encoder for MISB ST 0601 UAS Datalink Local Set metadata. The decoder accepts a KLV buffer or a live byte stream, verifies the packet checksum and reports each item with its name, engineering value and units. The encoder builds conformant packets from engineering values, driven by the same tag tables, and re-encodes decoded packets byte for byte. Applications supply the bytes and control the memory limits; the library never does I/O or reads the clock.

The decoder uses SMPTE ST 336 framing and accepts KLV extracted from MPEG transport streams. [smpte-klv](https://github.com/notley-technologies/smpte-klv-rs) · [mpegts](https://github.com/notley-technologies/mpegts-rs)

## Usage

Whole buffer:

```rust
fn show(bytes: &[u8]) -> Result<(), misb::Error> {
    let packet = misb::decode(bytes)?;          // one ST 0601 packet at the start of the buffer
    println!("{packet}");                        // title, checksum outcome, one line per item
    for item in &packet {
        println!("{:3} {}: {} {}", item.tag, item.name, item.value, item.units);
    }

    for packet in misb::decode_iter(bytes) {    // every ST 0601 packet in the buffer, one at a time
        println!("{} items, checksum {:?}", packet.len(), packet.checksum);
    }
    Ok(())
}
```

`decode` fails with `Error::NotSt0601` when the buffer does not start with the ST 0601 key (the key's version byte, byte 8, is not compared), `Error::Truncated` when the packet is cut short, `Error::TooLarge` when its declared length is over `Config::max_packet_bytes` (checked before the value is needed) and `Error::BadLength` for a malformed length. `decode_prefix` also returns the bytes the packet occupies, to step through a buffer packet by packet. `decode_iter` and `decode_all` skip damaged bytes and other keys like the stream decoder below; `decode_iter` holds one packet at a time, `decode_all` collects them all. `decode_with`, `decode_all_with` and `decode_iter_with` take a `Config`.

Live feed, pushed in chunks of any size. Packets split across pushes are reassembled, and after corrupt or missing bytes the decoder resynchronises on the next universal key (every key starts `06 0E 2B 34`):

```rust
fn run(mut read: impl FnMut() -> Option<Vec<u8>>) {
    let mut decoder = misb::Decoder::new();
    while let Some(chunk) = read() {
        decoder.push(&chunk);
        while let Some(packet) = decoder.next_packet() {   // drain after every push
            println!("{packet}");
        }
    }
    decoder.finish();                                       // end of input
    for packet in decoder.packets() {
        println!("{packet}");
    }
    println!("{:?}", decoder.stats());
}
```

Use one `Decoder` per feed, and drain it with `next_packet` after every push. Complete packets wait in a queue of at most `Config::max_buffer_bytes`; a packet that would overfill it is dropped and counted in `stats().dropped`, and one push larger than the queue can do that by itself even if you drain straight after it. For a whole file, `decode_iter` delivers every accepted packet even with a small queue. For a live feed, `push_with` also prevents queue drops when `max_buffer_bytes` is at least `max_packet_bytes` plus 1 KiB. The packets found do not depend on how the input is split as long as nothing is dropped. `finish()` marks the end of input: an incomplete trailing packet is dropped and counted. `next_received()` returns a packet together with its exact bytes and its stream offset. `reset()` forgets everything.

## Reading values

Each local set has a `Tag` enum (`st0601::Tag`, `st0102::Tag`, `st0806::Tag`, `st0903::Tag`) with `from_u64`, `name` and `units`. `Packet::get`, `item` and `get_all` take a `Tag` or a bare tag number (`u8`, `u16`, `u32`, `u64`):

```rust
use misb::{st0102, st0601::Tag, Packet, Value};

fn show(packet: &Packet) {
    let lat = packet.get(Tag::SensorLatitude).and_then(Value::as_f64);         // degrees
    let lon = packet.get(Tag::SensorLongitude).and_then(Value::as_f64);
    let time = packet.get(Tag::PrecisionTimeStamp).and_then(Value::as_time);   // MISP microseconds
    let mission = packet.get(3u8).and_then(Value::as_str);                     // tag 3, Mission ID
    println!("{lat:?} {lon:?} {time:?} {mission:?}");

    // A nested set is a Value::Set: look its items up with its own Tag enum.
    if let Some(security) = packet.get(Tag::SecurityLocalSet).and_then(Value::as_set) {
        println!("classification: {:?}", security.get(st0102::Tag::SecurityClassification));
    }
    // Tags that may repeat (ST 0601 tags 100, 101, 102 and 115).
    for segment in packet.get_all(Tag::SegmentLocalSet) {
        println!("{}", segment.value);
    }
}
```

A `Tag` of another standard finds nothing: ST 0102 tag 1 is not ST 0601 tag 1, so step into the nested set first. A bare number is looked up in the packet's own standard.

Every `Item` keeps `raw`, the value bytes exactly as received (see `Config::keep_raw`), so nothing is lost when a value cannot be interpreted. `packet.error` is set when parsing stopped early; the items decoded before the problem are kept. `packet.is_ok()` is true when the packet and every set nested in it parsed without error and the checksum is neither a mismatch nor missing. Individual values can still be `Invalid` or `OutOfRange`: check `Value::is_valid()` for the items you use. The packet-level rules of ST 0601 (tag 2 first, tag 65 present, no repeats except where allowed) are left to the application.

## Supported standards

Only ST 0601 packets are decoded at top level. Packets with any other universal key, standalone ST 0102 or ST 0903 packets included, are skipped by their declared length (up to `Config::max_skip_bytes`) and counted in `Stats::skipped_keys`. The other standards are decoded where ST 0601 embeds them:

| Standard | Revision followed | Where | Decoded as |
|---|---|---|---|
| MISB ST 0601 UAS Datalink Local Set | ST 0601.19 | top level | `Packet` of `Standard::St0601`: names and types for tags 1 to 143, checksum (tag 1) verified. Tag numbers are never reassigned, so packets from earlier revisions decode with the same table. |
| MISB ST 0102 Security Metadata Local Set | ST 0102.12 | ST 0601 tag 48 | `Value::Set` of `Standard::St0102`; tags 15 to 21, deleted from the standard, still decode |
| MISB ST 0806 Remote Video Terminal Local Set | ST 0806.4 | ST 0601 tag 73 | `Value::Set` of `Standard::St0806`, with its Point of Interest, Area of Interest and User Defined sets as `Value::Struct`s; its CRC is reported, not verified (ST 0601 leaves it out of the nested set) |
| MISB ST 0903 VMTI Local Set | ST 0903.6, accepting ST 0903.5 data | ST 0601 tag 74 | `Value::Set` of `Standard::St0903`; the VTarget Series and the VMask, VObject, VFeature, VTracker, VChip, Algorithm and Ontology sets as `Value::List`s and `Value::Struct`s |
| MISB ST 1204 MIIS Core Identifier | ST 1204.3 | ST 0601 tag 94, ST 0903 tag 13 | `Value::Struct` with the canonical text form and its check value; `st1204::check_value` computes the check value of any text, such as a typed identifier |
| MISB ST 1607 Segment and Amend Local Sets | | ST 0601 tags 100 and 101 | `Value::Set` of `Standard::St0601` |
| MISB ST 1010 SDCC-FLP | ST 1010.3 | ST 0601 tag 102 | `Value::Struct` of standard deviations and correlation coefficients; `st1010::decode` decodes one pack |
| MISB ST 1201 IMAPB | ST 1201.5 | every IMAPB item | `Value::Float`, including the special values; the `imapb` module maps both ways |
| MISB ST 0603 time | ST 0603.5 | ST 0601 tags 2, 72, 131, and time items of the nested sets | `Value::Time` |
| MISB ST 0107 | | every set | zero-length items as `Value::Unknown`, unknown tags kept as raw bytes |
| ISO/IEC 13818-1 section 2.12.4 metadata AU cells | | sync KLV (MISB ST 1402) | `au_cells` |

`Standard::revision()` and `imapb::REVISION` return these revisions at run time, and `misb::VERSION` the crate version, for audit records. The SAR Motion Imagery (ST 1206), Range Image (ST 1002), Geo-Registration (ST 1601) and Composite Imaging (ST 1602) sets, ST 0601 tags 95, 97, 98 and 99, and the deprecated tag 66 stay `Value::Bytes`. An item with a tag the standard does not define is named "Unknown" and keeps its bytes as `Value::Bytes`; inside the sets ST 0806 and ST 0903 decode as `Value::Struct`s it is a field named "Unknown" holding its tag and bytes.

The public `checksum` module has the ST 0601 checksum (`st0601_checksum`) and the CRCs MISB documents use (`crc16_ccitt`, `crc32_mpeg2`); `imapb` has `Imapb::new(min, max, len)` with `int_to_real`, `real_to_int` and `decode`, and the special value classifier `imapb::special`.

## Values

| `Value` | Holds | Accessors |
|---|---|---|
| `Uint(u64)` | unmapped unsigned integers | `as_u64()`; `as_i64()` when it fits; `as_f64()` |
| `Int(i64)` | unmapped signed integers | `as_i64()`; `as_u64()` when not negative; `as_f64()` |
| `Float(f64)` | engineering value after the standard's mapping (degrees, metres, ...); an ST 1201 special value can make it NaN or infinite | `as_f64()` |
| `Text(String)` | strings, as lossy UTF-8 | `as_str()` (unescaped) |
| `Bytes(Vec<u8>)` | opaque data | `as_bytes()` |
| `Time(u64)` | MISP time (MISB ST 0603): microseconds since 1970-01-01T00:00:00 on a scale without leap seconds, so not UTC (see below) | `as_time()` |
| `Enum { code, label }` | enumerated code, with the standard's label when it defines one | `as_u64()` gives the code; `label` |
| `OutOfRange` | the standard's reserved "out of range" or error encoding (e.g. `0x8000` for a mapped int16) | none; `is_valid()` is false |
| `Unknown` | a zero-length item: the producer says the value is not known (MISB ST 0107) | none (every accessor returns `None`); `is_valid()` is true |
| `Set(Box<Packet>)` | a nested local set, already decoded | `as_set()` |
| `List(Vec<Value>)` | series and variable-length lists | `as_list()` |
| `Struct(Vec<Field>)` | packs and sets with named fields | `as_fields()`, `field(name)` |
| `Invalid(&'static str)` | a value that could not be decoded, with the reason; `raw` keeps the bytes | none; `is_valid()` is false |

`Value`, `Packet`, `Item`, `Field`, `Checksum`, `Standard`, `Error`, `Config` and `Stats` are `#[non_exhaustive]`: match `Value` with a wildcard arm, and build a `Config` from `Config::default()`. `Packet::new`, `Item::new` and `Field::new` build values for tests and tools.

A zero-length item decodes to `Unknown` where the standard lets a producer send one (ST 0601.19 section 6.5, MISB ST 0107), and to `Invalid` with a reason where it forbids it:

- ST 0601: the mandatory tags 1, 2 and 65 and the tags that may repeat, 100, 101, 102 and 115. A zero-length field inside the packs of tags 122, 130 and 142 is `Unknown`.
- ST 0102: the tags its Table 2 marks Required, 1, 2, 3, 12, 13 and 22.
- ST 0806: the CRC (tag 1), the subordinate sets (tags 11 to 13, which may repeat) and the items those sets must contain (Point of Interest tags 1 to 3, Area of Interest tags 1 to 6, User Defined tags 1 and 2).
- ST 0903: VMTI tags 1 and 4, VChip tag 1, Algorithm tags 1 to 3 and Ontology tags 1, 3 and 4. An empty element of a Series is not an item and is `Invalid`.
- A zero-length item with a tag the standard does not define stays an empty `Bytes`.

`Value` implements `Display` for people: text is printed with control and bidirectional formatting characters escaped, so hostile metadata cannot forge log lines or send terminal escapes. `Time` prints as `2008-10-24T00:13:29.913000 MISP` on a calendar of 86,400-second days with no leap-second correction. That equals UTC only for encoders that write POSIX time: MISP time is TAI - 8.000082 s (ST 0603.5 section 6), so a conforming time stamp reads ahead of UTC by (TAI - UTC) - 8.000082 s, which is 28.999918 s since 2017-01-01 (ST 0601 tag 136 carries the leap seconds). The library applies no offset.

## Checksum

ST 0601 tag 1 is a 16-bit running sum of the packet as big-endian words, from the first key byte through tag 1's own length byte (`checksum::st0601_checksum`), and ST 0601.8-11 requires it as the last item. `Packet::checksum` reports:

| `Checksum` | Meaning |
|---|---|
| `Valid` | the last item is a 2-byte tag 1 and it matches |
| `Mismatch { expected, computed }` | it does not match. Also reported when damage moved the item boundaries so that tag 1 is no longer the last item, but the packet still ends with `01 02 hi lo` and its bytes do not sum to `hi lo`. |
| `Missing` | no 2-byte tag 1 as the last item, so the packet cannot be verified. A failure, like `Mismatch`: `is_ok()` is false. Matching bytes never make a packet `Valid` unless tag 1 is the last item. |
| `NotApplicable` | nested sets, and every packet when `verify_checksum` and `reject_bad_checksum` are both off |

By default the decoder returns failing packets, marked as above and counted in `stats().checksum_errors` and `stats().checksum_missing`. ST 0601.8-08 asks receivers to discard them: set `Config::reject_bad_checksum` and the `Decoder` (and so `decode_all_with` and `decode_iter_with`) drops every packet that is `Mismatch` or `Missing`, still counting them, and adds their bytes to `bytes_skipped`. `decode` and `decode_with` never drop a packet; check `packet.checksum` or `packet.is_ok()`. The CRC of a nested ST 0806 set and the checksum of a nested ST 0903 set are reported as items, not verified: ST 0601 leaves them out of the nested form.

## Encoding

The `encode` feature (on whenever `capi` is, so by default) adds `misb::encode`. `St0601Builder` writes one packet: tag 2 first, tag 65 (19) and the checksum added for you, the other items in ascending tag order, every length and tag in its minimal BER form. Each value is checked as it is set, against the tag table the decoder uses:

```rust
#[cfg(feature = "encode")]
fn build() -> Result<Vec<u8>, misb::encode::EncodeError> {
    use misb::encode::{Classification, Input, Security, St0601Builder};
    use misb::{st0601::Tag, LeapSeconds, MispTime};

    let now = MispTime::from_utc("2026-11-20T21:04:05.123456Z".parse().unwrap(), LeapSeconds::builtin()).unwrap();
    let security = Security::new(Classification::Unclassified, 0x0D, "//US", 0x0D, "US");
    let mut b = St0601Builder::new(now);
    b.set(Tag::MissionId, "MISSION01")?
        .set(Tag::SensorLatitude, 38.8895)?                // degrees
        .set(Tag::SensorEllipsoidHeight, 1850.0)?          // metres
        .set(Tag::FrameCenterLatitude, Input::OffEarth)?   // a state the item defines
        .unknown(Tag::SlantRange)?                         // zero-length item: now unknown
        .set(Tag::SecurityLocalSet, Input::Set(security.encode()?))?;
    b.finish()                                             // or finish_into(&mut reused_buffer)
}
```

- **Values.** `Input` takes engineering units (`f64` for mapped and IMAPB items, integers, text, `MispTime`, enumeration codes or labels), the special states some items define (`OffEarth`, `OutOfRange`, `BelowMinimum`, `AboveMaximum`), already encoded nested sets, and any decoded `Value`, so packs and lists use the field names the decoder produces. Linear maps round half away from zero and IMAPB truncates, as ST 0601 and ST 1201 specify; IMAPB items take a default length per tag, or `set_imapb` for another.
- **Checks.** `Policy::Strict` (default) rejects a value outside its range, except that items with an "Out of Range" indicator write it and IMAPB items write their below/above flag, each with a `Warning`; full-circle angles wrap. `Policy::Clamp` clamps with a warning. NaN, infinity, undefined or Reserved codes, duplicates, deprecated item 66, root-level 143, 75 with 104, text over its maximum, and zero-length mandatory items are always errors. Text is cleaned as MISB ST 0107 requires. Pre-encoded set bytes must frame as a local set; `set_raw` passes recorded bytes through unchecked.
- **Re-encoding.** `encode_packet` writes a decoded `Packet` back: items whose recorded bytes still decode to their value are copied, so valid packets come back unchanged (including IMAPB flags the value model cannot tell apart), and edited items are encoded from their value.
- **VMTI.** `Vmti` and its parts (`VTarget`, `Location`, `Motion`, `VMask`, `VObject`, `VFeature`, `VTracker`, `VChip`, `Algorithm`, `Ontology`) build the ST 0903.6 set for tag 74 with every rule of the standard checked (unique target ids, pairs, references between sets, IMAPB special values including the VMTI "invalid" pattern); `misb::st0903::encode::offsets` computes target offsets from the frame centre. A packet carrying VMTI needs tags 23 and 24. Decoded VMTI sets re-encode, keeping each unchanged element's recorded bytes. `CoreIdentifier` writes the ST 1204.3 MIIS Core Identifier (tag 94, VMTI tag 13) from its parts or its canonical text.
- **Security.** `Security` builds the ST 0102.12 set for tag 48: the six Required items, valid coding methods only (never an "Omitted Value"; FIPS 10-4 warns), ASCII text, real dates, UTF-16BE country codes, version 12. `encode_partial` allows a subset; `Security::from_set` reads a decoded set.
- **Tests.** Every ST 0601.19 item example and both ST 0902.8 Annex C packets re-encode byte for byte from their values; every code of the 8- and 16-bit maps and random 32-bit codes decode and encode to themselves; random inputs never yield an unreadable packet.

The rules come from the phase 0 documents in [docs/standards](docs/standards/); the code cites their rule ids.

## MISP time

ST 0601 tag 2 is MISP time (MISB ST 0603.5): TAI - 8.000082 s, 28.999918 s ahead of UTC since 2017, not POSIX time. `MispTime` converts from and to UTC with a leap second table (`LeapSeconds::builtin()`, valid before 2027-07-01 per IERS Bulletin C 72, or `LeapSeconds::from_list` for a newer one), handles 23:59:60, and covers 1970 to 1972 with the Handbook's rate formula. `MispTime::from_posix_assuming_no_offset` exists for systems that must match encoders writing POSIX time, so that choice is explicit. `LeapSeconds::st0601_leap_seconds` gives the tag 136 value (29).

## JSON

With the `serde` feature, `Packet`, `Item`, `Value`, `Field`, `Checksum`, `Standard`, `Error`, `Stats`, `Received` and `Config` implement `Serialize`, and `Config` also implements `Deserialize`, with missing fields taking their defaults. A packet with tags 2, 5, 13 (zero length), 48 and 1, through `serde_json` (line breaks added):

```json
{"standard":"st0601","items":[
  {"tag":2,"name":"Precision Time Stamp","units":"us","value":{"type":"time","value":1224807209913000},"raw":"000459f4a6aa4aa8"},
  {"tag":5,"name":"Platform Heading Angle","units":"deg","value":{"type":"float","value":159.97436484321355},"raw":"71c2"},
  {"tag":13,"name":"Sensor Latitude","units":"deg","value":{"type":"unknown"}},
  {"tag":48,"name":"Security Local Set","units":"","value":{"type":"set","value":{"standard":"st0102","items":[
    {"tag":1,"name":"Security Classification","units":"","value":{"type":"enum","value":{"code":1,"label":"UNCLASSIFIED//"}},"raw":"01"}],
    "checksum":{"type":"not_applicable"},"error":null}},"raw":"010101"},
  {"tag":1,"name":"Checksum","units":"","value":{"type":"uint","value":31826},"raw":"7c52"}],
 "checksum":{"type":"valid"},"error":null}
```

- A `Value` is an object with a snake_case `"type"` (`uint`, `int`, `float`, `text`, `bytes`, `time`, `enum`, `out_of_range`, `unknown`, `set`, `list`, `struct`, `invalid`) and, for variants that carry data, a `"value"`: an enum's is `{"code":..,"label":..}` (`label` may be `null`), a struct's is a list of `{"name":..,"value":..}` fields and an invalid value's is the reason.
- A non-finite `Float` is the string `"NaN"`, `"Infinity"` or `"-Infinity"`; JSON has no such numbers.
- Byte strings (`Bytes`, `Item::raw`, `Received::bytes`) are lowercase hex. `raw` is left out when it is empty, as for an `Unknown` item or a valid value with `keep_raw` off.
- `Checksum` has the same shape: `{"type":"valid"}`, `{"type":"mismatch","value":{"expected":4660,"computed":43981}}`, `{"type":"missing"}`, `{"type":"not_applicable"}`.
- `Standard` is `"st0601"`, `"st0102"`, `"st0806"` or `"st0903"`.
- `Error` is `{"kind":..,"message":..}`, the stable `Error::kind()` name and the `Display` text, e.g. `{"kind":"truncated","message":"truncated: needed 5 bytes, 2 available"}`. The kinds are `truncated`, `bad_length`, `bad_tag`, `too_large`, `too_many_items`, `not_st0601`, `too_deep` and `invalid_config`.
- `Stats` is an object of its counters, `Received` is `{"packet":..,"offset":..,"bytes":..}`, and `Config` an object of its fields.

A byte-for-byte test (`json_golden` in `src/lib.rs`) pins this format for every kind of value, a nested set that stopped with an error and a checksum mismatch.

### NDJSON authoring

The `json` feature reads one packet per line, for people and scripts:

```json
{"time": "2026-11-20T21:04:05.123456Z", "time_scale": "utc", "items": {"MissionId": "MISSION01", "13": 38.8895, "Sensor Longitude": -77.0353, "SlantRange": null, "SecurityLocalSet": {"SecurityClassification": "UNCLASSIFIED//", "ClassifyingCountryCodingMethod": "GENC Two Letter", "ClassifyingCountry": "//US", "ObjectCountryCodingMethod": 13, "ObjectCountryCodes": "US"}}}
```

Keys are tag numbers, `Tag` variant names or the standard's names; values are engineering units; `null` writes "unknown". `time_scale` is required with an RFC 3339 `time`, so UTC and MISP time are never confused (`time_us` is MISP microseconds). Lines of the decoder's own JSON (above) are accepted too, so `decode, edit, encode` round trips. `misb::json::encode_line` encodes a line; `misb::json::schema()` is the JSON Schema, generated from the tag table and committed as [docs/schema/st0601-authoring.schema.json](docs/schema/st0601-authoring.schema.json) (a test keeps it current).

## Configuration

Every buffer is bounded and configurable through `Config`. Start from the defaults and change the fields you need:

```rust
fn decoder() -> Result<misb::Decoder, misb::Error> {
    let mut config = misb::Config::default();
    config.reject_bad_checksum = true;   // drop ST 0601 packets whose checksum is missing or wrong
    config.keep_raw = false;             // keep Item::raw only where the value did not decode
    misb::Decoder::with_config(config)   // Error::InvalidConfig for limits the library refuses
}
```

| Field | Default | Rule | Purpose |
|---|---|---|---|
| `max_packet_bytes` | 1 MiB | not 0 | largest ST 0601 packet value. The decoder skips longer packets without buffering them (counted in `stats.oversized`); `decode_with` returns `Error::TooLarge` as soon as it reads the length. |
| `max_buffer_bytes` | 4 MiB | not 0 | complete packets queued until `next_packet`, each charged its size plus about 64 bytes. A packet that would go over is dropped (counted in `stats.dropped`); an empty queue always takes one. |
| `max_skip_bytes` | 1 MiB | not 0 | longest KLV triplet the decoder skips by its declared length (another key, or an oversized ST 0601 packet). A longer length is treated as damage (counted in `stats.bad_lengths`) and the decoder resynchronises on the next key after its first byte, so one bit error in a length cannot blind it for gigabytes. |
| `max_depth` | 8 | at most 32 (`Config::MAX_DEPTH_LIMIT`) | deepest nesting of sets inside sets; 0 decodes the top level only. A deeper `Value::Set` is left empty with `Error::TooDeep`, and a deeper set decoded as a `Value::Struct` (inside ST 0806 and ST 0903) is `Value::Invalid`. ST 0601 nests about four levels at most. |
| `max_items` | 65,536 | not 0 | items decoded from one set, and elements of one variable-length list or pack. A local set reports `Error::TooManyItems`. An oversized list or pack reports `Value::Invalid`. |
| `max_total_items` | 65,536 | not 0 | items decoded from one ST 0601 packet, counting every nested set; parsing stops with `Error::TooManyItems`. The same limit separately caps ST 1010 matrix elements across the packet |
| `verify_checksum` | true | | check the ST 0601 checksum; when off (and `reject_bad_checksum` is off) every packet reports `Checksum::NotApplicable` |
| `reject_bad_checksum` | false | | the decoder drops packets whose checksum is `Mismatch` or `Missing` (see Checksum); implies `verify_checksum` |
| `keep_raw` | true | | copy every item's value bytes into `Item::raw`. When off, `raw` is kept only for `Invalid` and `OutOfRange` values and for nested sets that stopped with an error, which saves most of a decoded packet's memory. |

`Config::validate()` checks the rules and names the first one broken in `Error::InvalidConfig`. Every function that takes a `Config` calls it first, before looking at any input: `Decoder::with_config`, `decode_with`, `decode_prefix`, `decode_all_with` and `decode_iter_with`. `decode`, `decode_all`, `decode_iter` and `Decoder::new` use the defaults, which are valid, and cannot fail on the config. Large limits are accepted: `usize::MAX` means "no limit of its own", and the other limits still bound memory (a `max_packet_bytes` above `isize::MAX - 256` behaves as that).

## Statistics

`Decoder::stats()`, `DecodeIter::stats()` and the `Stats` that `decode_all_with` returns hold these counters. Byte counts are of input bytes.

| Field | Counts |
|---|---|
| `packets` | packets returned by `next_packet` |
| `bytes` | bytes pushed |
| `packet_bytes` | bytes of the packets returned, key and length included |
| `bytes_skipped` | bytes not delivered in any packet: garbage between packets, packets with other keys, oversized, dropped and rejected packets, incomplete bytes at `finish` |
| `resyncs` | runs of unrecognised bytes skipped to find the next universal key |
| `skipped_keys` | KLV packets skipped because their key is not the ST 0601 key |
| `oversized` | ST 0601 packets skipped for a value over `max_packet_bytes` |
| `bad_lengths` | candidate keys followed by a malformed length (reserved, indefinite, impossibly large, or a triplet to skip over `max_skip_bytes`) or with a reserved category byte |
| `dropped` | complete packets dropped because the queue was full (`max_buffer_bytes`) |
| `truncated_at_finish` | incomplete KLV triplets cut off by `finish` |
| `checksum_errors` | ST 0601 packets whose checksum did not match, returned or rejected |
| `checksum_missing` | ST 0601 packets without a checksum as their last item, returned or rejected; counted only when the checksum is checked |
| `malformed` | packets returned with `Packet::error` set |
| `nested_errors` | packets returned whose top level parsed but with a nested set that stopped with an error |

The framing counters (`bytes`, `bytes_skipped`, `resyncs`, `skipped_keys`, `oversized`, `bad_lengths`, `truncated_at_finish`, `dropped`) are current after every push; the packet counters count packets as they are taken with `next_packet`. Once every packet is taken, every pushed byte is in exactly one of `packet_bytes`, `bytes_skipped` or a partial packet still buffered.

## Memory and recursion

- A live decoder holds at most one partial packet. Its queue charges each complete packet for its wire bytes and framing overhead. An empty queue can accept one packet larger than `max_buffer_bytes`.
- A decoded packet holds up to `max_total_items` local-set items. Text, byte strings, pack fields and series elements need additional storage. Nested sets can each retain a copy of their encoded value. Set `keep_raw = false` to avoid most of those copies.
- `decode_all` retains every decoded packet. `decode_iter` and `push_with` deliver one at a time. Whole-buffer decoding can enlarge its internal queue to hold the frames completed by a slice even when the configured live queue is smaller.
- Nesting is bounded by `max_depth`, and never deeper than `Config::MAX_DEPTH_LIMIT` (32) even for a config that skipped validation, so hostile nesting cannot exhaust the stack. Walks over decoded packets (`is_ok`) are iterative.

## With mpegts

Subscribe to the KLV streams with [mpegts](https://github.com/notley-technologies/mpegts-rs) and push the payloads into one `misb::Decoder` per PID: a decoder reassembles packets split across PES packets, and bytes from two PIDs must never meet in one decoder. Async KLV (MISB ST 1402, stream type 0x06) is a plain byte stream:

```rust ignore
use mpegts::{Codec, Demuxer, Select, Subscription, Unit};
use std::collections::HashMap;

let mut demux = Demuxer::new();
demux.subscribe(Subscription::new(Select::Codec(Codec::KlvAsync), Unit::Pes))?;
let mut decoders: HashMap<u16, misb::Decoder> = HashMap::new();

demux.push(&ts_bytes);
for out in demux.outputs() {
    let decoder = decoders.entry(out.pid).or_default();
    decoder.push_with(out.payload(), |packet| handle(out.pid, packet));
}
```

Sync KLV (stream type 0x15) carries ISO/IEC 13818-1 metadata access unit cells. When the PID carries one metadata service, `mpegts` can remove the cell headers. Feed each PES payload with `push_with` to drain packets as they complete.

```rust ignore
demux.subscribe(Subscription::new(Select::Codec(Codec::KlvSync), Unit::Pes).strip_metadata_au())?;

for out in demux.outputs() {
    let decoder = decoders.entry(out.pid).or_default();
    decoder.push_with(out.payload(), |packet| handle_at(out.pid, packet, out.pts));
}
```

For a PID carrying multiple services, keep the cell headers so the decoder can route fragments by service ID. Keep the decoder map across calls to the demultiplexer.

```rust ignore
let mut services: HashMap<(u16, u8), misb::Decoder> = HashMap::new();
demux.subscribe(Subscription::new(Select::Codec(Codec::KlvSync), Unit::Pes))?;

for out in demux.outputs() {
    for cell in misb::au_cells(out.payload()) {
        let cell = cell?;
        let decoder = services.entry((out.pid, cell.service_id)).or_default();
        decoder.push_with(cell.data, |packet| handle_service(out.pid, cell.service_id, packet, out.pts));
    }
}
```

A packet comes out on the push that completes it, so `out.pts` is the PTS of the PES packet that carried its last bytes. To recover the starting PTS, record each decoder's `stats().bytes` and `out.pts` before each push. Drain it with `next_received()` and find the latest recorded byte count at or before `Received::offset` for that PID and service.

## Inserting into transport streams

The `mux` feature (adds `mpegts` with its `mux` feature, re-exported as `misb::mpegts`) puts metadata into an existing transport stream. `FileMux` couples a scheduler that decides which metadata goes in with which PTS to the `mpegts` injector that places it, as synchronous (stream_type 0x15, ST 1402.2) or asynchronous (0x06, RP 217) KLV. Every input packet goes out unchanged except the PAT, the target PMT and the KLV PID.

```rust ignore
use misb::mux::{AnchorSpec, Carriage, FileMux, FileMuxConfig, KlvSamples, Rate};

// A recorded .klv file: every packet goes in byte for byte at its own
// tag 2 time, mapped to PTS through the anchor.
let mut samples = KlvSamples::new();
samples.push(&klv_file);
samples.finish();
let mut cfg = FileMuxConfig::new(Carriage::Sync);
cfg.schedule.anchor = AnchorSpec::FirstFrame(first_frame_time); // or SourceStart, or Pts { pts, misp }
let mut mux = FileMux::new(cfg, std::iter::from_fn(move || samples.next_sample()))?;
let mut out = Vec::new();
for chunk in input_ts.chunks(65_536) {
    mux.push(chunk, &mut out)?;
}
let stats = mux.finish(&mut out)?;
```

- **Sources.** `Sample::packet` is a recorded packet, written unchanged: its tag 2 is never modified (st1402-time.md D-6). `Sample::items` holds items to encode; NDJSON authoring records convert with `Sample::from(record)` (feature `json`). Any iterator of samples works, so a tool can read a large file incrementally.
- **Anchor.** One mapping between MISP time and the program clock: the first video frame at a given MISP time, the first frame at the first sample's time, or an explicit PTS and time. Conversions follow D-11 (PTS to MISP floors, MISP to PTS rounds to the nearest 90 kHz tick) and count across the 2^33 PTS wrap-around. A program clock discontinuity carries the time line across.
- **Rate.** `Rate::Explicit` sends every sample at its own time (the only choice for recorded packets; `snap_to_frames` moves the PTS to the nearest frame without touching tag 2). `EveryFrame`, `EveryNthFrame(n)` and `Hz(f)` sample items at video frames in presentation order (B-frames are reordered), with tag 2 = the frame's MISP time and PTS = the frame's PTS, so the two agree exactly; a sample older than `max_hold_ms` is not repeated.
- **Timing.** Units are handed to the injector `horizon_ms` ahead of the input's clock and placed in the ISO/IEC 13818-1 window, right before the frame they describe. Late samples are counted, never sent late.
- **Pacing tools** time the input themselves and use `FileMux::push_packet(packet, clock, sink)`, so each output packet keeps the time of the input packet it came with.
- **Constant bitrate.** `cfg.inject.with_rate(RateMode::Cbr { .. })` keeps the packet count and every PCR in place by filling null packets, and fails or drops loudly without room.

The C library built with `capi` and `mux` (`make FEATURES=mux`) also exports the mpegts C API, demuxer and injector included, and `make install` puts `mpegts.h` next to `misb.h`, so a C program that demuxes, injects and decodes links one library.

## C API

The header is [include/misb.h](include/misb.h). Its opening comment states the rules every function follows, and [examples/c/misb_dump.c](examples/c/misb_dump.c) shows the usual flow:

```c
misb_decoder *decoder;
misb_packet *packet;
if (misb_decoder_new(NULL, &decoder) != MISB_OK)   /* NULL: default config */
    return 1;
misb_decoder_push(decoder, data, len);             /* drain after every push */
while (misb_decoder_next(decoder, &packet) == MISB_OK) {
    misb_item item = {sizeof item};
    if (misb_packet_find(packet, 13, &item) == MISB_OK && item.kind == MISB_VALUE_FLOAT)
        printf("sensor latitude %f\n", item.float_value);
    misb_packet_free(packet);
}
misb_decoder_free(decoder);
```

- **Status codes.** Functions return a `misb_status`: `MISB_OK` (0), `MISB_EMPTY` (1, nothing to return: no packet waiting, no such item, no more cells) or a negative error: `MISB_ERR_NULL` (-1, a required pointer was NULL), `MISB_ERR_INVALID` (-2, an invalid argument or struct field, including a config the library refuses), `MISB_ERR_RANGE` (-3, an index or offset out of range), `MISB_ERR_PARSE` (-4, not a complete ST 0601 packet or AU cell), `MISB_ERR_PANIC` (-5, an internal error, which poisons a decoder) and `MISB_ERR_POISONED` (-6, the decoder failed earlier; free it). No panic crosses into C. `misb_status_string` describes a status.
- **Value kinds.** `misb_item.kind` is one `MISB_VALUE_*` per `Value` variant: `UINT` 1, `INT` 2, `FLOAT` 3, `TEXT` 4, `BYTES` 5, `TIME` 6, `ENUM` 7, `OUT_OF_RANGE` 8, `SET` 9, `LIST` 10, `STRUCT` 11, `INVALID` 12, `UNKNOWN` 13. The header documents which fields each kind sets. A packet is a tree: its root (`misb_packet_root`) is a `SET` whose children are the items; walk it with `misb_item_child`, `misb_item_find` and `misb_item_field`. `misb_packet_info_get` and `misb_set_info_get` give the standard (`MISB_STANDARD_*`), the checksum outcome (`MISB_CHECKSUM_*`, where `MISSING` is a failure like `MISMATCH`) and the parse error (`MISB_ERROR_*`).
- **Configuration.** `misb_config_default` fills a `misb_config` with the Rust defaults; `misb_decoder_new` and `misb_decode_ex` return `MISB_ERR_INVALID` for a config the library refuses (the rules above, and flags other than 0 or 1). `misb_decoder_stats` fills a `misb_stats` with the counters above. Push large buffers in slices: with the default limits, slices of up to 64 KiB, drained after each, never drop a packet.
- **Lifetimes.** A packet owns everything it hands out: every pointer in a `misb_item` or `misb_packet_info` filled from it stays valid and unchanged until `misb_packet_free`, and a packet does not depend on the decoder or the input it came from. `misb_au_cell.data` points into the caller's input. Strings from `misb_version`, `misb_status_string` and the `misb_*_name` functions are static. Text is NUL-terminated but can contain NUL bytes, so use `data_len`.
- **Threads.** A decoder is used from one thread at a time (it may move between threads); a packet never changes after it is created, so any number of threads may read one.
- **Compatibility.** Structs that cross the boundary start with `struct_size`, so fields can be added at the end compatibly. Within one `MISB_ABI_VERSION`, functions, constants and fields are only added, and codes are never reused; treat an unknown value kind as opaque and an unknown error code as an error. The shared library's soname carries the ABI version (`libmisb.so.1`), and `misb_abi_version()` lets a program check it at run time. `MISB_VALUE_TIME` is MISP time, not UTC.

Install the shared and static libraries, the header, a pkg-config file and a CMake package:

```bash
make
sudo make install      # PREFIX=/usr/local by default; DESTDIR, LIBDIR, INCLUDEDIR honoured
```

`make` always lets Cargo check what is up to date; `sudo make install` after it installs what `make` built without running Cargo as root. Then build with pkg-config or CMake:

```bash
cc app.c $(pkg-config --cflags --libs misb)
```

```cmake
find_package(misb 0.2 REQUIRED)
target_link_libraries(app PRIVATE misb::misb)   # or misb::misb_static
```

- Static linking needs the system libraries listed by `pkg-config --static --libs misb`; the CMake static target adds them. Link with `-Wl,--gc-sections` to drop unused code.
- Two Rust static libraries in one program can clash; use the shared library in that case.
- On Windows, `cargo build --release` produces `misb.dll`, its import library `misb.dll.lib`, and the static `misb.lib`.

### Encoding from C

The same library encodes. An opaque `misb_encoder` builds one packet at a time with a setter per kind of value; a rejected value returns `MISB_ERR_ENCODE`, adds nothing, and `misb_encoder_last_error` says why (standard, tag, `MISB_ENCODE_ERR_*` kind and a static reason):

```c
misb_encoder *e;
uint8_t buf[1024];
size_t len;
uint64_t now;
misb_utc utc = {sizeof utc, 2026, 11, 20, 21, 4, 5, 123456};
misb_misp_from_utc(&utc, &now);                        /* MISP time, not POSIX time */
if (misb_encoder_new(NULL, now, &e) != MISB_OK)
    return 1;
misb_encoder_set_text(e, 3, "MISSION01", 9);
misb_encoder_set_f64(e, 13, 38.8895);                  /* degrees */
misb_encoder_set_special(e, 23, MISB_SPECIAL_OFF_EARTH);
if (misb_encoder_finish(e, buf, sizeof buf, &len) == MISB_OK)
    fwrite(buf, 1, len, stdout);
misb_encoder_reset(e, now + 33367);                    /* next packet, buffers reused */
misb_encoder_free(e);
```

`misb_security_encode` builds the tag 48 set from a `misb_security` struct, `misb_encode_packet` re-encodes a decoded `misb_packet`, and `misb_misp_from_utc`, `misb_misp_from_posix_us` and `misb_misp_to_utc` convert time. Output functions take a buffer and its capacity and return `MISB_ERR_TOO_SMALL` with the size needed in `*len`. An encoder follows the decoder's rules on threads and poisoning.

## Examples

```bash
cargo run --release --example klvdump -- packets.klv                  # every packet and item, then the counters
cargo run --release --example klvdump -- cells.bin --sync             # input is metadata AU cells
producer | cargo run --release --example klvdump                      # standard input, decoded as it arrives
cargo run --release --features serde --example json -- packets.klv    # JSON Lines, one packet per line
cargo run --release --features json --example klvencode -- in.ndjson > out.klv   # NDJSON records to packets
cargo run --release --features json --example klvencode -- --schema   # the authoring JSON Schema
```

`klvdump` also takes `--quiet` (counters only); `json` takes `--sync` and `--bytes` (each packet's bytes as received, in hex) and writes the counters to standard error. With `--sync`, both examples read one access unit cell at a time, keep a decoder per service and exit with an error for a truncated cell.

The C example prints every packet of a file (or standard input) as a tree of items:

```bash
cmake -S examples/c -B build -DCMAKE_PREFIX_PATH=/usr/local   # after make install; -DMISB_STATIC=ON to link statically
cmake --build build
./build/misb_dump packets.klv
```

## Benchmark

```bash
cargo run --release --example throughput                                   # about 30 MB of synthetic ST 0601 packets
cargo run --release --example throughput -- packets.klv --runs 50 --chunk whole,1316
```

Prints min, mean, median, p95 and max per push size, in milliseconds, MB/s and packets/s. Each synthetic run must return every generated packet, byte and top-level item with clean decoder counters. With a file, each run must match the first run and report zero queue drops. `whole` feeds the buffer with `push_with`; the other sizes push chunk by chunk and drain after each push, as a live feed does. `--warmup N` sets the unmeasured runs and `--no-raw` decodes with `keep_raw` off.

## Tests

```bash
cargo test --all-features
cargo test                     # default features: the serde tests are left out
```

Test packets are built in code or taken from the examples in the published MISB standards. The standalone Rust examples in this README run as doctests. The mpegts excerpts show integration with a separate crate. The C tests compile programs against the header and the shared library, check that the header's constants and struct layouts match the Rust side and that exported symbols match the header, compare what a C program reads with what the Rust API decodes, compile the header as C++, and run `make install` into a temporary prefix to build the example through pkg-config and CMake, shared and static. Each part is skipped when its tools are missing.

## Fuzzing

Three harnesses in [tests/harness](tests/harness/mod.rs) accept any bytes. They check that nothing panics; that the packets and counters do not depend on how the input is split into pushes and the stream decoder, `decode_all_with`, `decode_iter_with` and `decode_prefix` agree; that every decoded packet stays within its `Config` limits and every input byte is counted once; that slices within the rule in `include/misb.h` never drop a packet; and that the C API returns only documented status codes and shows the same tree as the Rust API:

- `decode`: raw bytes.
- `stream`: the bytes drive a generator of ST 0601 packets, nested sets and corruption, so mutations explore packet structure.
- `capi`: sequences of C API calls, including invalid arguments and mismatched struct sizes.

`cargo test` replays the saved inputs in `tests/fuzz_regressions/<target>/` and runs 1,500 mutations each for `decode` and `stream`, and 1,000 for `capi`, on the stable toolchain. `MISB_FUZZ_SEED=<n>` picks a different random sequence. For longer runs, or coverage-guided fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
MISB_FUZZ_ITERATIONS=200000 cargo test --release --test fuzz
cargo +nightly fuzz run stream
cargo +nightly fuzz run decode fuzz/corpus/decode my-packets/
```

The stable runner saves a failing input under `target/fuzz-failures/`. Once it is fixed, add the input to `tests/fuzz_regressions/<target>/` so every test run replays it.

## Building

Features: `capi` (default, the C ABI; implies `encode`), `encode` (the encoder, no extra dependencies), `json` (NDJSON authoring, adds serde_json), `serde`, and `mux` (inserting into transport streams, adds mpegts). The default `capi` feature exports ABI version 1. For a Rust-only build, set `default-features = false` on the `misb` dependency. Cargo then excludes the C adapter and the compiler forbids unsafe Rust throughout the decoder. The `serde` feature works in either build.

The minimum supported Rust version is 1.70 for the library (`cargo check --lib`); the optional `serde` feature needs 1.71, the version its derive and proc-macro dependencies require.

Add the Git dependency to a Rust project with `cargo add misb --git https://github.com/notley-technologies/misb-rs`. The manifest pins the Notley Technologies implementation of SMPTE ST 336 by commit. The package named `smpte-klv` on crates.io is a separate project. See the contributor guide for local development with both checkouts. [CONTRIBUTING.md](CONTRIBUTING.md)

`cargo build --release` produces the Rust, shared and static libraries. The C installation and linking commands are in the [C API section](#c-api).

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Notley Technologies and Noah Davis.

Licensed under the [Apache License, Version 2.0](LICENSE).
