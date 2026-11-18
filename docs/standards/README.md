# Standards notes for encoding and muxing

These documents record what the planned `encode` and `mux` features (ST 0601, ST 0102 and ST 0903 encoders, MISP time, KLV injection into MPEG-TS) must do to conform, settled before any code was written. Every rule cites the standard, section or requirement id, with a short verbatim quote.

| File | Covers |
|---|---|
| [DECISIONS.md](DECISIONS.md) | The consolidated decisions and quick-reference values. Read this first; it wins over the topic files where they differ. |
| [st0601-encode.md](st0601-encode.md) | MISB ST 0601.19 encoding rules, MISB ST 0107.4, the MISB ST 0902.8 minimum metadata set, and a per-tag encoder table. |
| [nested-encode.md](nested-encode.md) | MISB ST 0102.12 security and ST 0903.6 VMTI sets nested in ST 0601, ST 1201.5 IMAPB and ST 1204.3 encoding. |
| [st1402-time.md](st1402-time.md) | MISB ST 1402.2 sync and async KLV carriage, SMPTE RP 217, MISB ST 0603.5 MISP time and MISB ST 0604.6 timestamps in video. |

The transport stream rules (ISO/IEC 13818-1) live with the `mpegts` crate: [mpegts-rs/docs/standards](https://github.com/notley-technologies/mpegts-rs/tree/main/docs/standards). Paths such as `specs/src/ST0601.19.txt:123` point into a local copy of the official documents, which are not redistributed; the document, section and quote identify each source without it.
