# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/). Changes to the C ABI are called out separately.

## Unreleased (0.2.0)

### Added

- The encoder, behind the `encode` feature (no extra dependencies): `misb::encode::St0601Builder` builds ST 0601.19 packets from engineering values with the inverse of every codec of the decoder's tag table and of every pack decoder; `encode_packet` re-encodes decoded packets, copying items whose recorded bytes still decode to their value; `Security` builds and checks the ST 0102.12 set of tag 48; `EncodeOptions` (strict or clamp policy, item order, packet size limit, legacy items, ASCII only), `Input`, `EncodeError` with an `ErrorKind` and `Warning`. Every ST 0601.19 item example and both ST 0902.8 Annex C packets re-encode byte for byte.
- VMTI encoding (`misb::encode::Vmti`, `VTarget`, `Location`, `Motion`, `VMask`, `PixelRun`, `VObject`, `VFeature`, `VTracker`, `VChip`, `ImageType`, `Algorithm`, `Ontology`, `Imap`, `DetectionStatus`; also at `misb::st0903::encode`, with `offsets`): the ST 0903.6 set for tag 74, with the ST 1201 special values and re-encoding of decoded sets. `St0601Builder` requires tags 23 and 24 with tag 74 (D-31; under the clamp policy only when a VTarget uses offsets). The ST 0903.6 and ST 1204.3 examples re-encode byte for byte.
- `CoreIdentifier` and `IdType` (`misb::encode`, also `misb::st1204::encode`): the ST 1204.3 MIIS Core Identifier, binary and canonical text, for tag 94 and VMTI tag 13.
- `MispTime`, `UtcDateTime` and `LeapSeconds`: MISB ST 0603.5 time with a dated leap second table (valid before 2027-07-01, IERS Bulletin C 72), 23:59:60, the 1970 to 1972 rate rule, and the tag 136 value.
- The NDJSON authoring format, behind the `json` feature (adds `serde_json`): `misb::json::encode_line`, `parse_record`, `parse_decoded` (the decoder's own JSON back into a `Packet`), and `schema()`, committed as `docs/schema/st0601-authoring.schema.json`.
- The `klvencode` example (NDJSON records or decoder JSON to packets; `--schema`).
- Inserting metadata into transport streams, behind the `mux` feature (adds `mpegts`, pinned by revision and re-exported as `misb::mpegts`): `misb::mux::FileMux` (a metadata source scheduled into an input stream by the `mpegts` injector; `push`, `push_packet` for pre-timed input, `finish`), `Scheduler` (samples to timed units from the injected stream's frames and clock; explicit times or sampling at frames in presentation order; snapping; carrying the time line across clock discontinuities), `Anchor` and `PtsUnwrapper` (MISP time to PTS and back per st1402-time.md D-11, across the 2^33 wrap), `Sample` and `KlvSamples` (recorded `.klv` packets kept byte for byte; items to encode; NDJSON records via `From`), `Rate` and `RateLimiter`.
- `make FEATURES=mux` builds a C library that also exports the mpegts C API, and installs `mpegts.h` next to `misb.h`; a test checks both libraries export exactly what the two headers declare.
- `misb::st0604` (every build): MISB ST 0604.6 timestamps carried in video. The three identifiers (`MISP_MICROSECTIME`, `HEVC_MICROSECONDS_UUID`, `HEVC_NANOSECONDS_UUID`, `Identifier`), the ST 0603.5 Time Status byte (`TimeStatus` with its six valid values, default `9F` lock unknown, and `Jump`), `Timestamp` (microseconds or nanoseconds per identifier, `misp_time` rounding nanoseconds half up per D-11) and `decode` / `decode_payload`, which accept any identifier in any codec and report non-`FF` separators, unexpected status bits and trailing bytes as `Warnings` (D-14). With `encode`: `Timestamp::to_bytes` (28 bytes) and `Timestamp::payload` (the 12-byte user_data_payload_byte).
- `misb::state` (feature `encode`): `MetadataState`, the current ST 0601 values of a live source, each checked by the encoder's rules when set and stamped with its MISP time (`set`, `unknown`, `clear`, `clear_all`, `set_version`, `set_security`, `set_vmti`, `revision`, `next_expiry`); `Staleness` and `StalePolicy` (maximum age, per-tag overrides, omit or write unknown); `Snapshot`, an immutable, shareable set of values at one time that encodes to one packet (`encode_at`, `to_builder`, `fill`, `items`, `to_items`, `same_items`).
- `misb::track` (feature `encode`): `Track`, keyframes sampled at any time with per-item `Interpolation` (`Hold`, `Linear`, `Angle` the shorter way around at 360 or +/-180, `Geodesic` great-circle interpolation of the `GEODESIC_PAIRS`), defaults from the tag table (`default_interpolation`, `check_interpolation`), `TrackConfig` (overrides, `max_gap`, `hold_before_first`, staleness), `Keyframe` with sticky interpolation hints, and a streaming API (`push`, `ready`, `sample`, `prune`, `finish`) whose memory is bounded by the lookahead.
- JSON (feature `json`): `Record::to_keyframe` and `From<Record> for Keyframe`; live control commands `Command`, `parse_commands`, `apply_commands` (atomic, reports `Applied::emit`) and `apply_line`, with `control_schema()` committed as `docs/schema/st0601-control.schema.json`; `klvencode --control-schema`.
- `Input::as_f64` and `Input::is_unknown`.
- Live injection (feature `mux`): `misb::mux::LiveMux` with `LiveMuxConfig`, `LiveAnchor` (wall clock, first frame, PTS), `LiveMuxStats` and `LiveMuxError`. Each video frame the rate admits gets a packet built from a snapshot of a `MetadataState`; `push` takes the arrival time, `state_mut`, `emit`, `apply_line` (feature `json`) change what is sent; B-frames are reordered for the metadata only; with the extrapolating injector clock nothing is held (zero added latency).
- MISB ST 0604 timestamps in the video (feature `mux`): `VideoTimestamps` (`Off`, `AddWhenMissing`, `Rewrite`), `VideoTimestampOptions` (lock bit, H.265 nanoseconds), `VideoTimestampStats` and `frame_timestamp`; `FileMuxConfig::video_timestamps` and `FileMuxStats::video`. Written with the anchor's time, one per access unit, through the `mpegts` injector's SEI user data support (st1402-time.md D-12).
- The video's ST 0604 timestamps as the anchor: `ScheduleConfig::video_anchor` and `video_anchor_tolerance_us`, `Scheduler::frame_with_video`, `ScheduleStats::video_times` and `reanchors` (D-15); `Scheduler::frame_time` and `take_jump` for timestamp writers.
- Interpolated sampling: `ScheduleConfig::interpolate` samples items through a `misb::track::Track` at every frame; `Sample::interpolate`, `Sample::with_interpolation` and `Sample::to_keyframe`; NDJSON records keep their hints; `ScheduleError::Track`.

### Fixed

- A synchronous unit whose PTS would go back (after the anchor moved back) is counted as late instead of failing the injector with an out-of-order error.

### Changed

- Tag 47 (Generic Flag Data) is exactly one byte with bits 6 and 7 zero, as its Required Length and Table 3 say; anything else is `Value::Invalid` (phase 0 DECISIONS P-4).
- A string value of exactly `00` decodes to the empty string (MISB ST 0107.4 6.3.3.2), in ST 0601, ST 0102 and ST 0903 (P-1).
- The documentation of tag 136 had the sign backwards: UTC is about tag 2 minus its value (P-3).
- The `capi` feature implies `encode`, so the C library always carries the encoder.
- `misb::json::Interpolation` is now defined in `misb::track` and re-exported from `misb::json`, so the old path still works.

### C ABI

- The encoder: `misb_encoder_new`, `_free`, `_reset`, `_set_version`, `_set_f64`, `_set_uint`, `_set_int`, `_set_time`, `_set_code`, `_set_text`, `_set_special`, `_set_imapb`, `_set_bytes`, `_set_raw`, `_unknown`, `_finish`, `_last_error`, `_warning_count`, `_warning`; `misb_encode_options_default`, `misb_security_encode`, `misb_encode_packet`; `misb_misp_from_utc`, `misb_misp_from_posix_us`, `misb_misp_to_utc`, `misb_leap_seconds_valid_until`; the structs `misb_encode_options`, `misb_encode_error`, `misb_security` and `misb_utc`; status codes `MISB_ERR_ENCODE` (-7) and `MISB_ERR_TOO_SMALL` (-8) and the constants `MISB_POLICY_*`, `MISB_ORDER_*`, `MISB_SPECIAL_*`, `MISB_ENCODE_WARNING` and `MISB_ENCODE_ERR_*`. The `capi` feature now implies `encode`, so the C library is one artifact. All additive within ABI version 1.
- The header's description of MISP time had the offset to UTC wrong by 10 s (it is TAI - UTC less 8.000082 s).
- ST 0604 timestamps: `misb_st0604_decode`, `misb_st0604_encode` and `misb_st0604_encode_payload`, the struct `misb_st0604`, and the constants `MISB_ST0604_ID_*`, `MISB_ST0604_STATUS_*` and `MISB_ST0604_WARN_*`. Additive within ABI version 1.
- Live injection in libraries built with `capi` and `mux`, declared in the new header `include/misb_live.h` (installed by `make FEATURES=mux`): `misb_live_config_default`, `misb_live_new`, `_free`, `_push`, `_finish`, `_set_f64`, `_set_uint`, `_set_int`, `_set_code`, `_set_text`, `_set_set`, `_unknown`, `_clear`, `_clear_all`, `_emit`, `_last_error`, `_error`, `_stats`; the structs `misb_live_config` and `misb_live_counters`, the callback type `misb_live_packets_fn`, the status `MISB_ERR_STREAM` (-9) and the `MISB_LIVE_*` constants, among them `MISB_LIVE_CELLS_PER_AU`, which numbers metadata cells from 0 in each access unit for receivers such as MediaMTX that require it (one counter per stream otherwise, DECISIONS X-8). Additive within ABI version 1.

## 0.1.0

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
