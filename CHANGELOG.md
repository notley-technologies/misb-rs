# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/). Changes to the C ABI are called out separately.

## Unreleased

### Changed

- The C ABI is enabled by default. Rust consumers can disable default features to build the decoder with unsafe Rust forbidden.
- `Config::max_total_items` now also bounds the combined number of ST 1010 matrix values in one packet. A matrix that would exceed this allowance is marked invalid, and decoding continues.
- The throughput benchmark checks every synthetic run against the known number of bytes, packets and top-level items. The stable fuzz tests report an error if a regression corpus cannot be read.

### Added

- Decoding of MISB ST 0601.19 UAS Datalink Local Set packets, all 143 tags, with values in engineering units and the checksum (tag 1) verified. Only ST 0601 is decoded at top level; packets with other universal keys are skipped and counted in `Stats::skipped_keys`.
- The sets ST 0601 embeds, decoded where it embeds them: ST 0102.12 security metadata (tag 48), ST 0806.4 remote video terminal with its POI, AOI and User Defined sets (tag 73), ST 0903.6 VMTI with its target series and nested sets (tag 74), ST 1204.3 MIIS identifiers (tag 94, and ST 0903 tag 13), ST 1607 Segment and Amend sets (tags 100 and 101) and ST 1010.3 SDCC-FLP packs (tag 102). ST 1201.5 IMAPB values, ST 0603 MISP time and the ST 0107 rules apply throughout. The ST 1206, ST 1002, ST 1601 and ST 1602 sets (tags 95, 97, 98, 99) are kept as bytes.
- `Value`, with `Value::Unknown` for zero-length items the standards allow and `Value::Invalid` with a reason for those they forbid, accessors (`as_f64`, `as_u64`, `as_i64`, `as_str`, `as_bytes`, `as_time`, `as_set`, `as_list`, `as_fields`, `field`, `is_valid`) and a `Display` that escapes control and bidirectional characters and labels MISP calendar readings. `Value::Time` is MISP time, which is not UTC; nothing converts it.
- `Packet::get`, `item` and `get_all`, taking a sealed `TagKey`: a bare tag number or one of the `Tag` enums of `st0601`, `st0102`, `st0806` and `st0903`. A `Tag` of another standard finds nothing.
- `Checksum` outcomes `Valid`, `Mismatch`, `Missing` and `NotApplicable`. A top-level packet without tag 1 as its last item is `Missing`, a failure: `Packet::is_ok` is false and `Config::reject_bad_checksum` drops it. Damage that moved the item boundaries is reported as `Mismatch` where the trailing checksum shows it.
- `decode`, `decode_with` and `decode_prefix` for one packet, `decode_all`, `decode_all_with`, `decode_iter` and `decode_iter_with` for whole buffers, and a streaming `Decoder` (`push`, `push_with`, `next_packet`, `next_received`, `finish`, `reset`) that accepts chunks of any size and resynchronises after damage.
- `Config` with a limit for every buffer and loop (`max_packet_bytes`, `max_buffer_bytes`, `max_skip_bytes`, `max_depth`, `max_items`, `max_total_items`) and the options `verify_checksum`, `reject_bad_checksum` and `keep_raw`. `Config::validate` refuses zero limits and a `max_depth` above `Config::MAX_DEPTH_LIMIT` (32); every function that takes a `Config` calls it and returns `Error::InvalidConfig`.
- `Stats` counters for packets, bytes, skipped and dropped data, resyncs, other keys, oversized packets, bad lengths, checksum errors and missing checksums, malformed packets and nested errors.
- `Error`, with `Error::kind()` names that stay stable across releases.
- ISO/IEC 13818-1 metadata access unit cells for sync KLV (`au_cells`).
- The `checksum` module (ST 0601 checksum, MISB CRC-16-CCITT, CRC-32/MPEG-2), the `imapb` module (`Imapb::new`, `int_to_real`, `real_to_int`, `decode`, `special`), `st1010::decode` and `st1204::check_value`.
- `Standard::revision`, `imapb::REVISION` and `VERSION`, for audit records.
- Optional `serde` support: `Serialize` for `Packet`, `Item`, `Value`, `Field`, `Checksum`, `Standard`, `Error`, `Stats`, `Received` and `Config`, and `Deserialize` for `Config`. Values and checksums are tagged objects, errors are `{"kind", "message"}`, non-finite floats are strings and bytes are lowercase hex; a byte-for-byte test pins the format.
- SMPTE ST 336 framing (universal keys, BER lengths, BER-OID tags, local sets and stream resynchronisation) through a pinned revision of the Notley Technologies `smpte-klv` crate.
- Fuzz harnesses (`decode`, `stream`, `capi`) for the stable toolchain and cargo-fuzz, with saved regression inputs replayed by `cargo test`.
- Examples: `klvdump`, `json` (needs the `serde` feature), `throughput` and the C `misb_dump`. The Rust dump tools stream synchronous access unit cells per service. The throughput benchmark checks for dropped packets and consistent counters.

### C ABI

- Stable C ABI (`include/misb.h`, ABI version 1) with `make install`, pkg-config and CMake support: stream decoder, one-shot `misb_decode` and `misb_decode_ex`, a value tree per packet, AU cells, configuration (`misb_config`) and counters (`misb_stats`).
- Status codes `MISB_OK`, `MISB_EMPTY` and `MISB_ERR_*`; value kinds `MISB_VALUE_UINT` (1) to `MISB_VALUE_UNKNOWN` (13); error codes `MISB_ERROR_NONE` (0) to `MISB_ERROR_INVALID_CONFIG` (8). A config the library refuses gives `MISB_ERR_INVALID`.
