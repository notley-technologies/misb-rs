# Phase 0: encoding the nested sets (ST 0102 in ST 0601 tag 48, ST 0903 in tag 74, ST 1201 IMAPB, ST 1204 Core Identifier)

> Phase 0 record. Where this document and [DECISIONS.md](DECISIONS.md) disagree (sections 1 and 3 there), DECISIONS.md wins. Source paths `specs/src/...` refer to the workspace copy of the official documents, which are not redistributed here.

Topic: `nested-encode`. Scope: every rule an encoder (`misb::encode`, behind the `encode` feature) must follow to write the MISB ST 0102 Security Metadata Local Set as the value of ST 0601 tag 48 and the MISB ST 0903 VMTI Local Set as the value of ST 0601 tag 74, including the ST 1201 IMAPB forward mapping and the ST 1204 MIIS Core Identifier that VMTI uses. Later agents implement exactly this document; rule ids are cited in code comments.

## 1. Sources

| Id | Document | Revision, date | Where obtained (stable copy) |
|---|---|---|---|
| S0102 | MISB ST 0102.12 Security Metadata Universal and Local Sets for Motion Imagery Data | 0102.12, 22 June 2017 | `specs/src/ST0102.12.pdf` and extracted `ST0102.12.txt`; PDF from the Wayback capture of `https://gwg.nga.mil/misb/docs/standards/ST0102.12.pdf` (see `specs/tables/st0102.md`). Latest ST 0102 revision; jMISB also targets 0102.12. |
| S0903 | MISB ST 0903.6 Video Moving Target Indicator Metadata | 0903.6, 21 October 2021, editorial updates 01/21/2022 and 05/08/2024 | `specs/src/ST0903.6.txt` (NSG Registry copy, see `specs/tables/st0903.md`) |
| S1201 | MISB ST 1201.5 Floating Point to Integer Mapping | 1201.5, 24 June 2021, editorial updates 11/06/2021 and 05/15/2022 | `specs/src/ST1201.5.txt` |
| S1204 | MISB ST 1204.3 Motion Imagery Identification System - Core Identifier | 1204.3, 27 February 2020 | `specs/src/ST1204.3.txt` |
| S0601 | MISB ST 0601.19 UAS Datalink Local Set | 0601.19, 02 March 2023 (corrections 05/10/2024, 06/11/2025) | `specs/src/ST0601.19.txt` (Internet Archive copy of the NSG Registry S3 object, see `specs/tables/st0601-a.md`). Sections 6.3.3, 6.5, 8.48, 8.74 and Table 1. |
| S0107 | MISB ST 0107.4 KLV Metadata in Motion Imagery | 0107.4, 28 February 2019 | `specs/src/ST0107.4.txt` (Wayback capture, see `specs/tables/misc.md`). ST 0903.6 Appendix C invokes ST 0107.5 (21 October 2021), which could not be obtained (Unresolved U-06). |
| S336 | SMPTE ST 336:2017 Data Encoding Protocol Using Key-Length-Value | 2017 | `specs/src/SMPTE-ST336-2017.txt`; section 7.4 and Table 5 (byte 6 of a Local Set key). |
| S0902 | MISB ST 0902.8 Motion Imagery Sensor Minimum Metadata Set | 0902.8, 1 November 2018 | `specs/src/ST0902.8.txt`; Annex C Table 10 is the only published byte-level example of a tag 48 value. |
| T0102, T0903 | Earlier verified tag tables | 2026-11 | `specs/tables/st0102.md`, `specs/tables/st0903.md` (decoder references; this document adds the encoder side, changes nothing in them, and settles `st0102.md` open point 6 with SMPTE ST 336 Table 5, rule 023) |
| DEC | Read-side code | as checked out on 2026-11-17 | `misb-rs/src/st0102.rs`, `st0903.rs`, `imapb.rs`, `st1204.rs`, `checksum.rs` |
| J | jMISB (cross-check only) | commit `ede21c112c17ff13afe2b2e42011fbea57d76972` (2 June 2026); implements ST 0903.5, ST 0102.12, ST 1201.5, ST 1204.3 | upstream jMISB (github.com/WestRidgeSystems/jmisb) (`api/src/main/java/org/jmisb/api/klv/{st0102,st0903,st1201,st1204}`). Deviations from the official text are listed in Appendix A. |
| K | klv (cbrl/klv, header-only C++23; cross-check for IMAPB and ST 1204 only) | commit `8d4f919` | upstream cbrl/klv (`include/klv/codecs/imapb.hpp`, `include/klv/misb1204/*.hpp`) |

Every example in section 3.12 was produced by a small reference encoder written from the text above and then decoded by the existing misb-rs decoder (`misb::decode` on a complete ST 0601 packet), which checked every value; see Appendix B for the probe program.

Conventions in this document:
- "rule NNN" means R-NESTED-ENCODE-NNN; "D-NN" is a decision in section 4; "U-NN" an unresolved item in section 5.
- Hex bytes are written `0D 06 00 55`; a TLV is tag, BER length, value.
- "Who" names the component that implements a rule: `misb::encode` (the builders and the byte writer), `misb::state` (target lifecycle and snapshots, part of the `encode` feature), `misb::mux` (scheduling: when tag 48 or 74 is put in a packet), and the conformance checker (which verifies the rule on any stream, ours or not).
- Strict mode (the default from the muxing plan, section 6.1) rejects input that would break a rule; lenient mode is named where a rule allows one.
- "VMTI-MI" is the imagery the VMTI process ran on; "user-MI" is the imagery carried in the stream (ST 0903.6 section 8.1). The builder takes a flag saying whether they are the same (D-30).

## 2. Rules

### A. ST 0601 carriage of the nested sets (tags 48 and 74)

**R-NESTED-ENCODE-001** The value of ST 0601 tag 48 is the bare ST 0102 Local Set: the sequence of its tag-length-value items, with no 16-byte ST 0102 key and no ST 0102 length in front. The same holds for tag 74 and the VMTI Local Set.
- Who: misb::encode; conformance checker
- Source: ST 0601.19 section 6.3.3
- Quote: "The Value then contains a set of TLV triplets defined by another standard or document. The Value does not include the nested Local Set’s key or length." (`specs/src/ST0601.19.txt:259`)

**R-NESTED-ENCODE-002** A nested set never carries its own checksum or CRC item. ST 0102 defines none; the VMTI checkSum (VMTI item 1) is therefore never written inside tag 74 (see also rule 052).
- Who: misb::encode; conformance checker
- Source: ST 0601.19 section 6.3.3
- Quote: "If the nested Local Set defines a checksum (or CRC) item, the Value does not include the checksum (or CRC) item." (`specs/src/ST0601.19.txt:260`)

**R-NESTED-ENCODE-003** Tag 48 always carries the ST 0102 Local Set form (one-byte enumerations, Table 2), never the Universal Set (16-byte keys, text enumerations, Table 1).
- Who: misb::encode; conformance checker
- Source: ST 0601.19 section 8.48.1, requirement ST 0601.14-31
- Quote: "When incorporating the ST 0102 Security Metadata set into an instance of the UAS Datalink Local Set, the ST 0102 format shall use the Local Set format." (`specs/src/ST0601.19.txt:3370`)

**R-NESTED-ENCODE-004** The ST 0601 length of tag 48 is the total byte count of the ST 0102 items it contains (BER, fewest bytes, rule 012).
- Who: misb::encode
- Source: ST 0601.19 section 8.48
- Quote: "The length field is the size of all MISB ST 0102 metadata items to be packaged within item 48" (`specs/src/ST0601.19.txt:3364`)

**R-NESTED-ENCODE-005** Tag 74 carries the ST 0903 VMTI Local Set; its ST 0601 length is the total byte count of the VMTI items (BER, fewest bytes).
- Who: misb::encode
- Source: ST 0601.19 section 8.74
- Quote: "Use the MISB ST 0903 Local Set within the MISB ST 0601 Item 74." (`specs/src/ST0601.19.txt:4267`)
- Quote: "The length field is the size of all VMTI LS metadata items to be packaged within Item 74" (`specs/src/ST0601.19.txt:4268`)

**R-NESTED-ENCODE-006** Tags 48 (0x30) and 74 (0x4A) are one-byte BER-OID tags; each appears at most once per ST 0601 packet (MUL = N) and neither may be placed in an SDCC-FLP (SDCC = N). Their length is variable and not limited by ST 0601.
- Who: misb::encode; conformance checker
- Source: ST 0601.19 Table 1, sections 8.48 and 8.74
- Quote: "48 Security Local Set None set V N N MISB ST 0102 local let Security Metadata items" (`specs/src/ST0601.19.txt:558`)
- Quote: "74 VMTI Local Set None set V N N MISB ST 0903 VMTI Local Set metadata items" (`specs/src/ST0601.19.txt:592`)

**R-NESTED-ENCODE-007** ST 0601 allows a zero-length item for tags 48 and 74 (not mandatory, MUL = N), while ST 0107 discourages ZLIs for child Local Sets. The encoder never writes a ZLI for tag 48 and writes one for tag 74 only on an explicit request (Decision D-06).
- Who: misb::encode
- Source: ST 0601.19 section 6.5; ST 0107.4 section 6.3.4
- Quote: "all items within the UAS Datalink Local Set may use Zero Length Items (ZLI)." (`specs/src/ST0601.19.txt:369`)
- Quote: "Unless a standard allows it, the use of ZLI for a child Local Set is discouraged." (`specs/src/ST0107.4.txt:251`)

**R-NESTED-ENCODE-008** An ST 0601 packet that carries tag 74 also carries tag 2 (always present anyway) and Frame Center Latitude and Longitude (tags 23 and 24), which ST 0903.6 Table 6 lists as Required parent items for embedded VMTI. They are mandatory whenever a VTarget uses offset items 10, 11, 13 to 16 (Decision D-31).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 8.2, Table 6
- Quote: "Table 6: Parent Metadata Supporting Items Metadata Items Presence Precision Time Stamp Required Frame Center Latitude Required Frame Center Longitude Required" (`specs/src/ST0903.6.txt:537`)

**R-NESTED-ENCODE-009** One VMTI LS (one tag 74 per packet) describes detections from one VMTI-MI (one sensor); detections from several sensors are never mixed in one VMTI LS.
- Who: misb::encode (API shape)
- Source: ST 0903.6 Appendix B.1 (informative)
- Quote: "Each VMTI process operating for a given sensor requires its own individual VMTI LS. That is, a VMTI LS should never contain a mixture of moving targets detected by different sensors." (`specs/src/ST0903.6.txt:2572`)

**R-NESTED-ENCODE-010** VTarget offset items are relative to the Frame Center Latitude and Longitude of the same ST 0601 packet (embedded-VMTI).
- Who: misb::encode
- Source: ST 0903.6 section 8.2
- Quote: "The VMTI LS may then rely on the 0601 LS’s Frame Center Latitude/Longitude for specifying VTarget corner offsets." (`specs/src/ST0903.6.txt:547`)

### B. MISB ST 0107 rules that apply inside both nested sets

**R-NESTED-ENCODE-011** Everything inside tags 48 and 74 follows MISB ST 0107 (rules 012 to 021).
- Who: misb::encode; conformance checker
- Source: ST 0102.10-02; ST 0903.4-01
- Quote: "ST 0102.10-02 All security metadata shall be expressed in accordance with MISB ST 0107 [9]." (`specs/src/ST0102.12.txt:146`)
- Quote: "ST 0903.4-01 All metadata shall be expressed in accordance with MISB ST 0107." (`specs/src/ST0903.6.txt:665`)

**R-NESTED-ENCODE-012** Every BER length (item lengths, Series element lengths, VTarget Pack lengths, the run length of a pixel run) uses short form below 128 and otherwise long form with the fewest bytes (0x81 nn, 0x82 nn nn, ...). Never 0x80, never padded long form.
- Who: misb::encode; conformance checker
- Source: ST 0107.3-05
- Quote: "All instances of item Length fields within a MISB defined KLV Universal or Local Set shall be BER Short form or BER Long form encoded using the fewest possible bytes." (`specs/src/ST0107.4.txt:128`)

**R-NESTED-ENCODE-013** Items with a required length are written with exactly that many bytes: ST 0102 tags 1, 2, 12 (1 byte), 22 (2), 10 (8), 23 and 24 (10); VMTI item 2 (8); VTarget 4, 5, 7, 23 (1) and 8 (3); VTracker 1 (16), 3 and 4 (8), 7 (1); the Location (10/16/22), Velocity and Acceleration (6/12/18) packs. ST 0903 IMAPB items with a nominal length are covered by D-14.
- Who: misb::encode; conformance checker
- Source: ST 0107.3-06
- Quote: "Value, the encoded Value shall match the number of bytes defined by the required Length." (`specs/src/ST0107.4.txt:140`)

**R-NESTED-ENCODE-014** Items with a maximum length ("Vn" in ST 0903.6) never exceed it.
- Who: misb::encode; conformance checker
- Source: ST 0107.3-07
- Quote: "Value, the encoded Value shall not exceed the number of bytes defined by the maximum Length." (`specs/src/ST0107.4.txt:143`)

**R-NESTED-ENCODE-015** Variable-length unsigned integers (every "uint Vn" of ST 0903.6) are written with the fewest bytes: no leading 0x00 bytes; the value zero is one byte 0x00 (a zero-length item would mean unknown).
- Who: misb::encode; conformance checker
- Source: ST 0107.3-10; ST 0903.6 Appendix C
- Quote: "encoded value shall remove leading zero or leading sign extension bytes." (`specs/src/ST0107.4.txt:185`)

**R-NESTED-ENCODE-016** IMAPB items whose length may vary (VObject and VFeature confidence, "IMAP V3") use the fewest bytes that keep the system's precision (Decision D-14).
- Who: misb::encode
- Source: ST 0107.3-09
- Quote: "“IMAPB,” and the Local Set item allows variable length encoding, the encoded Value shall use the fewest number of bytes , while maintaining system precision ." (`specs/src/ST0107.4.txt:181`)

**R-NESTED-ENCODE-017** Mandatory items are never zero length: ST 0102 tags 1, 2, 3, 12, 13, 22; VMTI items 4 and 6; VChip 1; Algorithm 1 to 3; Ontology 1, 3, 4.
- Who: misb::encode; conformance checker
- Source: ST 0107.4-16
- Quote: "Required or mandatory items of a Local Set shall always be reported with positive lengths (i.e. Zero -Length Items (ZLI) are not allowed for these items) ." (`specs/src/ST0107.4.txt:267`)

**R-NESTED-ENCODE-018** Neither ST 0102 nor ST 0903 declares Report-on-Change, so the encoder writes no zero-length items inside either set: an item that is not known is left out (Decision D-06).
- Who: misb::encode
- Source: ST 0107.4 section 6.3.4
- Quote: "if a standard does not declare its use , Report -on-Change is not used within said standard ." (`specs/src/ST0107.4.txt:223`)

**R-NESTED-ENCODE-019** A utf8 item that is an empty string is written as the single byte 0x00 (length 1); a zero-length utf8 item means unknown and is not written (rule 018).
- Who: misb::encode
- Source: ST 0107.4 section 6.3.3.2
- Quote: "The empty string uses a single null character (0x00) with no other characters to indicate the string is blank ." (`specs/src/ST0107.4.txt:196`)

**R-NESTED-ENCODE-020** utf8 values (VMTI items 3 and 10; VChip 1, 2; Algorithm 2 to 4; Ontology 3 to 6) carry no leading or trailing 0x00, 0x09, 0x0A, 0x0D or 0x20 characters.
- Who: misb::encode; conformance checker
- Source: ST 0107.3-12
- Quote: "Value is not the empty string, the encoded value shall have all leading and trailing, null (0x00), tab (0x09), line feed (0x0A), carriage return (0x0D), and space (0x20) characters removed , unless the item definition allows them ." (`specs/src/ST0107.4.txt:214`)

**R-NESTED-ENCODE-021** utf8 values contain none of 0x00 to 0x08, 0x0B, 0x0C, 0x0E to 0x1F and 0x7F.
- Who: misb::encode; conformance checker
- Source: ST 0107.3-13
- Quote: "ranges (inclusive) of 0x00 through 0x0 8, 0x0B , 0x0C, 0x0E through 0x1F, and character 0x7F removed , unless the item definition allows them." (`specs/src/ST0107.4.txt:219`)

**R-NESTED-ENCODE-022** Item order inside a Local Set is free in KLV; the encoder fixes it (ascending tag, Decision D-01) except where a standard pins a position (VMTI item 2 first, rule 054).
- Who: misb::encode
- Source: SMPTE ST 336:2017 section 7.4
- Quote: "Data items may be in any order within the Local Set and may be present or absent." (`specs/src/SMPTE-ST336-2017.txt:791`)

### C. ST 0102.12 Security Metadata Local Set in tag 48

**R-NESTED-ENCODE-023** ST 0102 items use one-byte tags and BER lengths: the ST 0102 Local Set key has byte 6 = 0x03, which SMPTE ST 336 Table 5 defines as BER length with a 1-byte Local Tag (this settles open point 6 of `specs/tables/st0102.md`). All defined tags are below 25.
- Who: misb::encode; conformance checker
- Source: ST 0102.12 section 6.7; SMPTE ST 336:2017 Table 5
- Quote: "06 0E 2B 34 02 03 01 01 0E 01 03 03 02 00 00 00 (CRC 40980)." (`specs/src/ST0102.12.txt:476`)
- Quote: "0x03 ASN.1 BER short or long 1 byte Any length" (`specs/src/SMPTE-ST336-2017.txt:826`)

**R-NESTED-ENCODE-024** The set conforms to SMPTE ST 336 Local Set rules.
- Who: misb::encode; conformance checker
- Source: ST 0102.12-66
- Quote: "ST 0102.12-66 The Security Metadata Local Set shall conform to SMPTE ST 336 [3] KLV encoding rules." (`specs/src/ST0102.12.txt:479`)

**R-NESTED-ENCODE-025** Tag 1 Security Classification is present in every set, one byte, value 0x01 UNCLASSIFIED//, 0x02 RESTRICTED//, 0x03 CONFIDENTIAL//, 0x04 SECRET// or 0x05 TOP SECRET//. No other value is written.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-03; Table 2
- Quote: "ST 0102.10-03 Motion Imagery Data shall contain the Security Classification metadata element." (`specs/src/ST0102.12.txt:168`)
- Quote: "UNCLASSIFIED// (0x01) RESTRICTED// (0x02) 1 Security Classification uint8 CONFIDENTIAL// (0x03) 1 Required SECRET// (0x04) TOP SECRET// (0x05)" (`specs/src/ST0102.12.txt:496`)

**R-NESTED-ENCODE-026** Unclassified imagery is still marked: tag 48 is sent with tag 1 = 0x01.
- Who: misb::encode; misb::mux
- Source: ST 0102.10-54, ST 0102.10-51
- Quote: "ST 0102.10-54 Unclassified Motion Imagery Data shall be marked with Security Metadata." (`specs/src/ST0102.12.txt:326`)
- Quote: "be "UNCLASSIFIED//" for Security Classification." (`specs/src/ST0102.12.txt:328`)

**R-NESTED-ENCODE-027** Tag 2 (coding method for tags 3 and 6) is present in every set, one byte, from the tag 2 column of Table 2 (0x01 to 0x07, 0x0A to 0x10). GENC AdminSub is not a tag 2 value. Tag 2 and tag 12 number the methods differently from 0x03 on.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-04; section 6.1.2; Table 2
- Quote: "ST 0102.10-04 Motion Imagery Data shall contain the Classifying Country or Releasing Instructions Country Coding Method metadata element." (`specs/src/ST0102.12.txt:180`)
- Quote: "GENC administrative subdivision codes are not applicable." (`specs/src/ST0102.12.txt:175`)
- Quote: "FIPS 10-4 Two Letter (0x03) FIPS 10-4 Four Letter (0x04) ISO-3166 Numeric (0x05)" (`specs/src/ST0102.12.txt:503`)

**R-NESTED-ENCODE-028** Codes Table 2 lists as "Omitted Value" (tag 2: 0x08, 0x09; tag 12: 0x08 to 0x0C) are never written.
- Who: misb::encode; conformance checker
- Source: ST 0102.12 Table 2
- Quote: "Omitted Value (0x08) 1 Required Country Coding Method Omitted Value (0x09)" (`specs/src/ST0102.12.txt:508`)

**R-NESTED-ENCODE-029** FIPS 10-4 / GEC methods (tag 2: 0x03, 0x04, 0x0A; tag 12: 0x04, 0x05) are for legacy systems only; the encoder accepts them but reports a warning.
- Who: misb::encode
- Source: ST 0102.12 sections 6.1.2, 6.1.12, 6.10
- Quote: "GEC two-letter or four-letter alphabetic country code (legacy systems only)" (`specs/src/ST0102.12.txt:173`)

**R-NESTED-ENCODE-030** Tag 3 Classifying Country is present in every set: "//" followed by the country code in the method tag 2 names (for example "//CZE" GENC, "//GB" ISO 3166).
- Who: misb::encode; conformance checker
- Source: ST 0102.10-05; section 6.1.3
- Quote: "ST 0102.10-05 Motion Imagery Data shall contain the Classifying Country metadata element." (`specs/src/ST0102.12.txt:189`)
- Quote: "The Classifying Country metadata element contains a value for the classifying country code preceded by a double slash "//."" (`specs/src/ST0102.12.txt:183`)

**R-NESTED-ENCODE-031** Tag 4 SCI/SHI is written when, and only when, special handling or compartment information applies.
- Who: misb::encode (caller input)
- Source: ST 0102.10-06
- Quote: "Motion Imagery Data shall contain the Sensitive Compartmented Information (SCI) / Special Handling Instructions (SHI) metadata element." (`specs/src/ST0102.12.txt:197`)

**R-NESTED-ENCODE-032** Tag 4 syntax: a single entry ends with "//"; several digraphs, trigraphs or names are separated by a single "/" and end with "//", all in one item.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-08 to -11
- Quote: "ST 0102.10-09 Multiple digraphs, trigraphs, or compartment names shall be separated by a single forward slash" (`specs/src/ST0102.12.txt:202`)
- Quote: "ST 0102.10-11 Multiple SCI/SHI digraphs, trigraphs, or compartment names shall be concatenated in one metadata element free text [18] entry." (`specs/src/ST0102.12.txt:206`)

**R-NESTED-ENCODE-033** Tag 5 Caveats is written whenever caveats or code words apply, and is the item that marks FOUO.
- Who: misb::encode (caller input)
- Source: ST 0102.10-13, -14
- Quote: "ST 0102.10-13 When caveats or code words are used, all Motion Imagery Data shall contain the Caveats metadata element." (`specs/src/ST0102.12.txt:213`)
- Quote: "ST 0102.10-14 The Caveats metadata element shall be used to indicate FOR OFFICIAL USE ONLY (FOUO) data." (`specs/src/ST0102.12.txt:215`)

**R-NESTED-ENCODE-034** Tag 6 Releasing Instructions is written whenever releasing instructions apply: country codes (method per tag 2) separated by single blanks (0x20, never underscore), all in one item.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-15 to -17
- Quote: "ST 0102.10-15 When releasing instructions are used, all Motion Imagery Data shall contain the Releasing Instructions metadata element." (`specs/src/ST0102.12.txt:221`)
- Quote: "ST 0102.10-17 Multiple country codes shall be concatenated in one Releasing Instructions metadata element." (`specs/src/ST0102.12.txt:224`)

**R-NESTED-ENCODE-035** With a Mixed tag 2 method (0x0A, 0x0B, 0x0C, 0x10), tags 3 and 6 hold di-graphs or tri-graphs (one width, not both) from that source plus approved CAPCO tetragraphs.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-58
- Quote: "ST 0102.10-58 The Mixed Country Coding Method shall be used to support di- or tri-graphs (but not both) from GEC, ISO 3166, GENC and STANAG 1059, respectively, and approved tetragraphs in the same field." (`specs/src/ST0102.12.txt:589`)

**R-NESTED-ENCODE-036** Tag 10 Declassification Date is exactly 8 ISO 646 bytes YYYYMMDD, a real calendar date.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-22; Table 2
- Quote: "ST 0102.10-22 The Declassification Date metadata element format shall be YYYYMMDD." (`specs/src/ST0102.12.txt:254`)
- Quote: "10 Declassification Date ISO/IEC 646 [18] YYYYMMDD 8 Context" (`specs/src/ST0102.12.txt:534`)

**R-NESTED-ENCODE-037** Tag 11 Classification and Marking System is free ISO 646 text.
- Who: misb::encode
- Source: ST 0102.10-21
- Quote: "ST 0102.10-21 The Classification or Marking System metadata element shall be free text." (`specs/src/ST0102.12.txt:260`)

**R-NESTED-ENCODE-038** Tag 12 Object Country Coding Method is present in every set (mandatory since ST 0102.6), one byte from the tag 12 column of Table 2 (0x01 to 0x07, 0x0D to 0x0F, 0x40 GENC AdminSub).
- Who: misb::encode; conformance checker
- Source: ST 0102.12 section 6.1.12; Table 2
- Quote: "Use of this element in version 6 of this Standard and later is mandatory." (`specs/src/ST0102.12.txt:268`)
- Quote: "ISO-3166 Numeric (0x03) FIPS 10-4 Two Letter (0x04) FIPS 10-4 Four Letter (0x05)" (`specs/src/ST0102.12.txt:539`)
- Quote: "GENC AdminSub (0x40)" (`specs/src/ST0102.12.txt:552`)

**R-NESTED-ENCODE-039** Tag 13 Object Country Codes is present in every set; it contains the code of the region under the frame centre, optionally more codes; all codes in one item.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-23, -25, -26
- Quote: "ST 0102.10-23 Motion Imagery Data shall contain the Object Country Code metadata element." (`specs/src/ST0102.12.txt:276`)
- Quote: "ST 0102.10-25 Multiple Object Country Codes shall be concatenated in one Object Country Code metadata element entry." (`specs/src/ST0102.12.txt:279`)
- Quote: "ST 0102.10-26 The object country code of the geographic region lying under the center of the image frame shall populate the Object Country Code metadata element." (`specs/src/ST0102.12.txt:281`)

**R-NESTED-ENCODE-040** Tag 13 is RFC 2781 UTF-16; the encoder writes UTF-16BE without a byte order mark, as the published ST 0902.8 example does (Decision D-04).
- Who: misb::encode; conformance checker
- Source: ST 0102.12 Table 2; ST 0902.8 Annex C Table 10
- Quote: "13 Object Country Codes RFC 2781 [26] [27] Refs [15] [16] [28] [29] Variable Required" (`specs/src/ST0102.12.txt:553`)
- Quote: "48/13 Object Country Codes \u0055\u0053\u0041 USA 0D 06 00 55 00" (`specs/src/ST0902.8.txt:481`)

**R-NESTED-ENCODE-041** Tag 14 Classification Comments carries only non-essential security information (caller content); optional.
- Who: misb::encode (caller input)
- Source: ST 0102.10-27
- Quote: "ST 0102.10-27 The Classification Comments metadata element shall only be used to convey non-essential security-related information." (`specs/src/ST0102.12.txt:292`)

**R-NESTED-ENCODE-042** Tag 22 Version is present in every set: uint16, exactly 2 bytes, the ST 0102 revision. The encoder writes 12 (0x00 0x0C) for ST 0102.12 (Decision D-03).
- Who: misb::encode; conformance checker
- Source: ST 0102.10-56; Table 2
- Quote: "ST 0102.10-56 The Security Metadata Version shall be included in all Security Metadata Universal and Local Sets utilizing version four (4) of the security metadata or later." (`specs/src/ST0102.12.txt:298`)
- Quote: "Value is version number of this 22 Version uint16 document; e. g. for ST 0102.10, 2 Required this value is 0x000A" (`specs/src/ST0102.12.txt:555`)

**R-NESTED-ENCODE-043** Tags 23 and 24 (coding method version dates) are optional; when written they are exactly 10 ISO 646 bytes YYYY-MM-DD.
- Who: misb::encode; conformance checker
- Source: ST 0102.12 sections 6.1.16, 6.1.17; Table 2
- Quote: "As ISO 3166 is updated by dated circulars, not by version revision, the ISO 8601 YYYY-MM-DD formatted date is used." (`specs/src/ST0102.12.txt:314`)
- Quote: "24 Object Country Coding ISO/IEC 646 [18] YYYY-MM-DD 10 Optional" (`specs/src/ST0102.12.txt:562`)

**R-NESTED-ENCODE-044** Tags 15 to 21 (UMIDs, Stream ID, Transport Stream ID, Item Designator ID) were deleted and are never written by the builder.
- Who: misb::encode; conformance checker
- Source: ST 0102.12 section 4 (revision history)
- Quote: "Deleted keys: UMID, Stream ID, Transport Stream ID, Item Designator" (`specs/src/ST0102.12.txt:117`)

**R-NESTED-ENCODE-045** All text items except tag 13 are ISO/IEC 646 (7-bit) text; the encoder accepts printable ASCII 0x20 to 0x7E only (Decision D-05).
- Who: misb::encode; conformance checker
- Source: ST 0102.12 Table 2, reference [18]
- Quote: "4 Security-SCI/SHI ISO/IEC 646 [18] Security Ref [1] Variable Context" (`specs/src/ST0102.12.txt:521`)
- Quote: "ISO/IEC 646:1991 Information Technology" (`specs/src/ST0102.12.txt:55`)

**R-NESTED-ENCODE-046** A Security set (tag 48) is sent whenever classification, handling, releasability or another mandatory field changes, and at least every 30 seconds. Default: in every ST 0601 packet (Decision D-08).
- Who: misb::mux; conformance checker
- Source: ST 0102.10-49, -50
- Quote: "ST 0102.10-49 A Security Metadata set shall be repeated / updated whenever classification, special handling instructions, releasability, or other mandatory fields change value." (`specs/src/ST0102.12.txt:318`)
- Quote: "ST 0102.10-50 Security Metadata Sets shall be repeated no less than every thirty (30) seconds." (`specs/src/ST0102.12.txt:321`)

**R-NESTED-ENCODE-047** A missing tag 48 does not mean unclassified; the scheduler must not drop tag 48 to save bandwidth.
- Who: misb::mux
- Source: ST 0102.12 section 6.5
- Quote: "The absence of Security Metadata does not signify Motion Imagery Data as Unclassified." (`specs/src/ST0102.12.txt:337`)

**R-NESTED-ENCODE-048** Partial sets are an operational exception decided by a security official; the strict builder requires the six Required items, and a separate opt-in allows a partial set (Decision D-07).
- Who: misb::encode
- Source: ST 0102.12 section 6.4
- Quote: "For some operational situations or applications not all metadata elements in Section 6.1 may be required." (`specs/src/ST0102.12.txt:331`)

**R-NESTED-ENCODE-049** Several tag 13 codes are separated by ";" with no spaces.
- Who: misb::encode; conformance checker
- Source: ST 0102.10-24
- Quote: "ST 0102.10-24 Multiple Object Country Codes shall be separated by a semi-colon" (`specs/src/ST0102.12.txt:277`)

### D. ST 0903.6 VMTI Local Set in tag 74: set level

**R-NESTED-ENCODE-050** The VMTI LS uses BER-OID tags and BER lengths (its key has byte 6 = 0x0B); every set inside it (VTarget Pack items, VMask, VObject, VFeature, VTracker, VChip, Algorithm, Ontology) uses one-byte tags and BER lengths. All defined tags are below 128, so each tag is one byte (VMTI 101, 102, 103 = 0x65, 0x66, 0x67). Section 9.2 prints "byte 6 = 0x2B" for the VMTI LS, which in ST 336 means 1-byte lengths; the key and the described behaviour (BER lengths) win (Unresolved U-01).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 sections 9.2, 10.1; SMPTE ST 336:2017 Table 5
- Quote: "06.0E.2B.34.02.0B.01.01.0E.01.03.03.06.00.00.00 (CRC 51307)" (`specs/src/ST0903.6.txt:938`)
- Quote: "use byte 6 = 0x03 meaning 1-byte UINT tags and BER short/long lengths" (`specs/src/ST0903.6.txt:716`)
- Quote: "0x0B ASN.1 BER short or long ASN.1 OID BER" (`specs/src/SMPTE-ST336-2017.txt:827`)

**R-NESTED-ENCODE-051** Every item appears at most once in each Local Set instance: the VMTI LS, each VTarget Pack and each nested set.
- Who: misb::encode; conformance checker
- Source: ST 0903.5-98
- Quote: "ST 0903.5-98 Within an instance of a Local Set, items within that Local Set shall be used only once." (`specs/src/ST0903.6.txt:723`)

**R-NESTED-ENCODE-052** VMTI item 1 checkSum is omitted inside tag 74.
- Who: misb::encode; conformance checker
- Source: ST 0903.6-120
- Quote: "ST 0903.6-120 Where the VMTI LS is embedded-VMTI, the VMTI LS checkSum (Item 1) shall be omitted." (`specs/src/ST0903.6.txt:992`)

**R-NESTED-ENCODE-053** VMTI item 2 precisionTimeStamp (8 bytes, the VMTI-MI-Timestamp) may be omitted when it equals ST 0601 tag 2 of the same packet and must be written when it differs (Decision D-11).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 8.4, ST 0903.6-118, Table 9
- Quote: "For embedded-VMTI, systems may omit the VMTI LS precisionTimeStamp item if the parent instance’s Precision Time Stamp (e.g., ST 0601 Item 2) is equal to the VMTI-MI-Timestamp." (`specs/src/ST0903.6.txt:628`)
- Quote: "ST 0903.6-118 Where the VMTI LS is embedded-VMTI and the parent instance contains a Precision Time Stamp not equal to the VMTI-MI-Timestamp, the VMTI LS instance shall contain the precisionTimeStamp item (Item 2) equal to the VMTI-MI- Timestamp." (`specs/src/ST0903.6.txt:635`)
- Quote: "2 precisionTimeStamp µs uint 8 Microsecond count from Epoch of 1970; See" (`specs/src/ST0903.6.txt:945`)

**R-NESTED-ENCODE-054** When item 2 is written it is the first item of the VMTI LS.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-14
- Quote: "ST 0903.4-14 Where a precisionTimeStamp (Item 2) is present in a VMTI LS, it shall be the first item in the VMTI LS." (`specs/src/ST0903.6.txt:1009`)

**R-NESTED-ENCODE-055** VMTI item 2 and VTracker items 3 and 4 are MISP time (ST 0603): microseconds since 1970-01-01 without leap seconds, uint64, 8 bytes.
- Who: misb::encode
- Source: ST 0903.4-13; section 10.1.2
- Quote: "ST 0903.4-13 Timestamps specifying a Precision Time Stamp shall comply with MISB ST 0603." (`specs/src/ST0903.6.txt:731`)
- Quote: "since the MISP Time System epoch of midnight (00:00:00), January 1, 1970, and the microsecond count does NOT include leap seconds." (`specs/src/ST0903.6.txt:996`)

**R-NESTED-ENCODE-056** When the VMTI time differs from the ST 0601 tag 2 time by more than two VMTI-MI frame periods, VTarget offset items 10, 11, 13 to 16 are not used; targetLocation (17) and geospatialContourSeries (18) are used instead.
- Who: misb::encode; conformance checker
- Source: ST 0903.6-142
- Quote: "is greater than the period of two VMTI-MI frames, the VMTI LS instance shall use the VTarget targetLocation (Item 17) and geospatialContourSeries (Item 18) instead of the offset items" (`specs/src/ST0903.6.txt:650`)

**R-NESTED-ENCODE-057** VMTI item 3 vmtiSystemName: utf8, at most 32 characters (at most 128 bytes); optional.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.1.3, Table 9
- Quote: "targets identified as a string of 32 UTF-8 characters. Note that UTF-8 allows up to four bytes per character; thus, this value can expand up to 128 bytes maximum." (`specs/src/ST0903.6.txt:1013`)

**R-NESTED-ENCODE-058** VMTI item 4 vmtiLsVersionNum is in every VMTI LS: uint V2, fewest bytes; the encoder writes 6 as 04 01 06 (Decision D-10).
- Who: misb::encode; conformance checker
- Source: ST 0903.5-99; section 10.1.4; Table 9
- Quote: "ST 0903.5-99 All instances of the VMTI LS shall contain vmtiLsVersionNum (Item 4)." (`specs/src/ST0903.6.txt:1028`)
- Quote: "metadata. Values of 1 through 65535 correspond to document revisions 1 through 65535." (`specs/src/ST0903.6.txt:1022`)
- Quote: "4 vmtiLsVersionNum N/A uint V2 Version number of the VMTI LS used to" (`specs/src/ST0903.6.txt:949`)

**R-NESTED-ENCODE-059** VMTI item 5 totalNumTargetsDetected (uint V3, 0 to 16,777,215) is written whenever it differs from item 6; it is the size of the system's target list and may differ from the number of VTarget Packs (Decision D-12).
- Who: misb::encode; conformance checker
- Source: ST 0903.4-18; section 10.1.5; Table 9
- Quote: "ST 0903.4-18 Where the VMTI LS totalNumTargetsDetected in a frame (Item 5) is different from the VMTI LS numTargetsReported (Item 6), the totalNumTargetsDetected in the frame shall be specified." (`specs/src/ST0903.6.txt:1040`)
- Quote: "model’s target list; this value may be different than the number of elements in the vTargetSeries." (`specs/src/ST0903.6.txt:1031`)
- Quote: "5 totalNumTargetsDetected N/A uint V3 Total number of targets in VMTI system’s" (`specs/src/ST0903.6.txt:951`)

**R-NESTED-ENCODE-060** VMTI item 6 numTargetsReported (uint V3) is in every VMTI LS; the encoder sets it to the number of VTarget Packs in item 101 (0 when there is no item 101).
- Who: misb::encode; conformance checker
- Source: ST 0903.4-19; Table 9
- Quote: "ST 0903.4-19 The VMTI LS numTargetsReported (Item 6) shall always be specified." (`specs/src/ST0903.6.txt:1053`)
- Quote: "6 numTargetsReported N/A uint V3 Number of targets reported following a" (`specs/src/ST0903.6.txt:953`)

**R-NESTED-ENCODE-061** VMTI item 7 (motionImageryFrameNumber) is deprecated and never written.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.1.7
- Quote: "ST 0903.6 deprecates this item; refer to versions prior to ST 0903.6 for information on its use." (`specs/src/ST0903.6.txt:1055`)

**R-NESTED-ENCODE-062** VMTI item 8 frameWidth (uint V3, never 0) is written in every VMTI LS that contains a pixel-number item (VTarget 1, 2, 3; VMask 1, 2).
- Who: misb::encode; conformance checker
- Source: ST 0903.6-121; section 10.1.8; Table 9
- Quote: "ST 0903.6-121 Where a VMTI LS instance includes metadata items using the pixel number representation, the VMTI LS instance shall contain the frameWidth item (Item 8) set to the frame width of the VMTI-MI." (`specs/src/ST0903.6.txt:1065`)
- Quote: "the number of pixels in a row of the image where pixels appear in row-major order. Do not use a value of zero." (`specs/src/ST0903.6.txt:1058`)
- Quote: "8 frameWidth pixels uint V3 Width of the Motion Imagery frame in pixels" (`specs/src/ST0903.6.txt:956`)

**R-NESTED-ENCODE-063** VMTI item 9 frameHeight (uint V3) is optional and never 0.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.1.9
- Quote: "The frameHeight is not a required value. Do not use a value of zero." (`specs/src/ST0903.6.txt:1070`)

**R-NESTED-ENCODE-064** VMTI item 10 vmtiSourceSensor: utf8, at most 128 characters (512 bytes); sent again whenever the VMTI-MI changes.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.1.10
- Quote: "The value is a free text string of 128 UTF-8 characters. UTF-8 allows up to four bytes per character, so this value can expand up to 512 bytes maximum." (`specs/src/ST0903.6.txt:1082`)
- Quote: "Any change to the VMTI-MI requires updating this metadata item." (`specs/src/ST0903.6.txt:1081`)

**R-NESTED-ENCODE-065** VMTI items 11 and 12 (horizontal and vertical field of view) are IMAPB(0, 180, 2), 2 bytes, 0 to 180 degrees, and are required when the VMTI-MI differs from the user-MI (otherwise ST 0601 tags 16 and 17 provide them).
- Who: misb::encode; conformance checker
- Source: ST 0903.4-26, -27; sections 10.1.11, 10.1.12; Table 9
- Quote: "ST 0903.4-26 Where the user-MI is different from the VMTI-MI, the VMTI LS shall contain the vmtiHorizontalFov (Item11)." (`specs/src/ST0903.6.txt:1098`)
- Quote: "ST 0903.4-27 Where the user-MI is different from the VMTI-MI, the VMTI LS instance shall contain the vmtiVerticalFov (Item12)." (`specs/src/ST0903.6.txt:1113`)
- Quote: "Valid Values: The set of real numbers from 0 to 180 inclusive." (`specs/src/ST0903.6.txt:1092`)
- Quote: "11 vmtiHorizontalFov ° IMAPB 2 Horizontal field of view of imaging sensor" (`specs/src/ST0903.6.txt:961`)

**R-NESTED-ENCODE-066** VMTI item 13 miisId (ST 1204 binary Core Identifier, group I) is required when the VMTI-MI differs from the user-MI and may be omitted when it is the same.
- Who: misb::encode; conformance checker
- Source: ST 0903.6-124; section 10.1.13
- Quote: "ST 0903.6-124 Where the VMTI-MI is different than the user-MI, the VMTI LS shall contain the VMTI-MI’s MIIS in the miisId (Item 13)." (`specs/src/ST0903.6.txt:1126`)
- Quote: "When using embedded-VMTI and the VMTI-MI is the same as the user-MI, the VMTI system may omit this item in the VMTI LS instance." (`specs/src/ST0903.6.txt:1121`)

**R-NESTED-ENCODE-067** VMTI item 101 vTargetSeries contains only VTarget Packs, each with a different targetId.
- Who: misb::encode; conformance checker
- Source: ST 0903.6-126; section 10.1.14
- Quote: "The vTargetSeries item is a Series type which contains VTarget Packs only (see Figure 14)." (`specs/src/ST0903.6.txt:1131`)
- Quote: "ST 0903.6-126 Each VTarget Pack element in a VMTI LS vTargetSeries (Item 101) shall have a unique targetId." (`specs/src/ST0903.6.txt:1155`)

**R-NESTED-ENCODE-068** A Series (items 101, 102, 103; VTarget 18, 106, 107; VObject 5; VTracker 5, 9; VMask 2) is a sequence of elements, each a BER length followed by the element; element order carries no meaning (Decision D-02).
- Who: misb::encode
- Source: ST 0903.6 section 9.1.3
- Quote: "Since all elements are of the same type, element order is not important." (`specs/src/ST0903.6.txt:700`)
- Quote: "the Value is a collection of length-element pairs with the length (“L”) specifying the number of bytes of the “Element”." (`specs/src/ST0903.6.txt:702`)

**R-NESTED-ENCODE-069** VMTI items 102 algorithmSeries and 103 ontologySeries contain one or more Algorithm or Ontology LS; when there is none the item is left out.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 sections 10.1.15, 10.1.16
- Quote: "The algorithmSeries item is a Series type which contains one or more Algorithm Local Sets." (`specs/src/ST0903.6.txt:1170`)
- Quote: "The ontologySeries item is a Series type which contains one or more Ontology Local Sets." (`specs/src/ST0903.6.txt:1177`)

**R-NESTED-ENCODE-070** "Vn" means 1 to n bytes; ST 0903.6 encoders write the fewest bytes (ST 0107.5 via Appendix C).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 9.1, Appendix C
- Quote: "For example, “V4” indicates an encoded value specified with a minimum of one byte to a maximum of four bytes." (`specs/src/ST0903.6.txt:662`)
- Quote: "This change means LS values must use the minimum number of bytes, i.e., the value does not include zero or sign extension padding bytes." (`specs/src/ST0903.6.txt:2734`)

**R-NESTED-ENCODE-071** Every floating point item uses ST 1201 IMAPB (group H).
- Who: misb::encode; conformance checker
- Source: ST 0903.4-03
- Quote: "ST 0903.4-03 Floating point to integer mappings shall comply with MISB ST 1201." (`specs/src/ST0903.6.txt:693`)

**R-NESTED-ENCODE-072** A measured value outside an item's IMAPB range is sent as IMAP_BELOW_MINIMUM (first byte 0xE0) or IMAP_ABOVE_MAXIMUM (0xE1) instead of the value (Decision D-15 for how the API asks for it).
- Who: misb::encode
- Source: ST 0903.6 section 9.1.1
- Quote: "If an item’s measured value is below this standard’s defined range the VMTI system sends the IMAP_BELOW_MINIMUM signal value in place of the measurement." (`specs/src/ST0903.6.txt:677`)

**R-NESTED-ENCODE-073** An illegal computed value (divide by zero, a ray above the horizon) is sent as the "Invalid" signal: first byte 0xC1, the rest of the item's bytes 0x00 (C1 00 00 for a 3-byte offset, C1 00 00 00 for a 4-byte latitude).
- Who: misb::encode
- Source: ST 0903.6 section 9.1.1
- Quote: "VMTI systems specify the “Invalid” signal using an IMAP User Defined Special Value of byte 0xC1. For packs requiring fixed length, the software pads the value with zero bytes to accommodate the correct length," (`specs/src/ST0903.6.txt:688`)

**R-NESTED-ENCODE-074** A geospatial value that does not exist (no ground intersection) is either left out or sent as "Invalid".
- Who: misb::encode
- Source: ST 0903.6 section 9.2.3.2
- Quote: "In these cases, either do not report the value or report the value using the “Invalid” value, see Section 9.1.1." (`specs/src/ST0903.6.txt:792`)

**R-NESTED-ENCODE-075** Pixel numbers count from 1 at the top-left pixel, row by row: pixel = column + (row - 1) * frameWidth.
- Who: misb::encode
- Source: ST 0903.6 section 9.2.3.1
- Quote: "pixel number = Column + ((Row - 1) × frame width))" (`specs/src/ST0903.6.txt:749`)

**R-NESTED-ENCODE-076** The Len column of the ST 0903.6 tables is a nominal length; the encoder writes exactly the table length for fixed IMAPB items (Decision D-14).
- Who: misb::encode
- Source: ST 0903.6 section 9.2.4
- Quote: "Len indicates the nominal length of an item in bytes." (`specs/src/ST0903.6.txt:802`)

### E. VTarget Series and VTarget Pack

**R-NESTED-ENCODE-080** A VTarget Pack element is: BER length of the pack, then the targetId (BER-OID, no tag, no length), then the pack's TLV items.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2, Figure 15
- Quote: "The VTarget Pack contains two items: a BER-OID encoded Value (Item 1) which is a targetId, and one or more VTarget TLV items (collectively as Item 2) as shown in Figure 15." (`specs/src/ST0903.6.txt:1184`)

**R-NESTED-ENCODE-081** At least one TLV item follows the targetId.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-10
- Quote: "ST 0903.4-10 Where using a VTarget Pack, at least one Tag-Length-Value item shall follow the targetId." (`specs/src/ST0903.6.txt:1209`)

**R-NESTED-ENCODE-082** The targetId is a BER-OID of at most 9 bytes (0 to 2^63 - 1), with the fewest bytes (first byte never 0x80). Example 1234 -> 89 52.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.1, Table 10; ST 0107.4 section 6.3.1
- Quote: "The targetId is BER- OID encoded to convey the length and has no Tag." (`specs/src/ST0903.6.txt:1323`)
- Quote: "N/A targetId N/A BER-OID V9 target id and first value in a" (`specs/src/ST0903.6.txt:1219`)
- Quote: "ASN.1 forbids the use of 0x8 0 in the first byte of a BER -OID val ue." (`specs/src/ST0107.4.txt:113`)

**R-NESTED-ENCODE-083** A targetId is unique, stays the same for the life of the target, and is never reused for another target, even after the target is dropped.
- Who: misb::state (encode feature)
- Source: ST 0903.6-129; section 7.2
- Quote: "ST 0903.6-129 When a VMTI system creates a target, the targetId shall be unique and remain the same throughout the lifecycle of the target." (`specs/src/ST0903.6.txt:1330`)
- Quote: "system does not reuse the identifier for any other target, even if the target is no longer part of the target list" (`specs/src/ST0903.6.txt:414`)

**R-NESTED-ENCODE-084** VTarget Pack TLV items use the embedded-Local-Set rules of section 9.2 (one-byte tags, BER lengths).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2
- Quote: "The TLV structure follows the same parsing rules for an embedded Local Set as defined in Section 9.2." (`specs/src/ST0903.6.txt:1211`)

**R-NESTED-ENCODE-085** A VTarget with detectionStatus Active-Moving (1) or Active-Stopped (3) contains a centroid: item 1, or items 19 and 20, or items 2 and 3.
- Who: misb::encode; conformance checker
- Source: ST 0903.6-127, -128
- Quote: "ST 0903.6-127 Where the VTarget LS’s instance includes detectionStatus (Item 23) set to Active- Moving, the instance shall contain at least one of the following representations:" (`specs/src/ST0903.6.txt:1310`)
- Quote: "ST 0903.6-128 Where the VTarget LS’s instance includes detectionStatus (Item 23) set to Active- Stopped, the VTarget LS shall contain at least one of the following representations:" (`specs/src/ST0903.6.txt:1315`)

**R-NESTED-ENCODE-086** Items 19 and 20 are written together or not at all.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-37, -38
- Quote: "ST 0903.4-37 Where VTarget Pack centroidPixCol (Item 20) is present, VTarget Pack centroidPixRow (Item 19) shall be present." (`specs/src/ST0903.6.txt:1566`)
- Quote: "ST 0903.4-38 Where VTarget Pack centroidPixRow (Item 19) is present, VTarget Pack centroidPixCol (Item 20) shall be present." (`specs/src/ST0903.6.txt:1582`)

**R-NESTED-ENCODE-087** Item 1 targetCentroid: pixel number, uint V6, 1 to 2^48 - 1. Example 409,600 -> 01 03 06 40 00.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.2; Table 10
- Quote: "Range: All integer values from 1 to 0xFFFFFFFFFFFF (281,474,976,710,655)." (`specs/src/ST0903.6.txt:1336`)
- Quote: "1 targetCentroid Number uint V6 within the Motion Imagery frame" (`specs/src/ST0903.6.txt:1226`)

**R-NESTED-ENCODE-088** Items 2 and 3 are the top-left and bottom-right pixel numbers of the pixel bounding box (uint V6, 1 to 2^48 - 1).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.3; Table 10
- Quote: "VTarget Pack Items 2 and 3 define a target’s pixel bounding box with two numbers." (`specs/src/ST0903.6.txt:1357`)

**R-NESTED-ENCODE-089** Item 4 targetPriority: uint8, 1 to 255 (1 = highest).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.5; Table 10
- Quote: "Valid Values: 1 to 255, where 1 is the highest priority." (`specs/src/ST0903.6.txt:1373`)
- Quote: "4 targetPriority N/A uint 1 Priority or validity of target based" (`specs/src/ST0903.6.txt:1236`)

**R-NESTED-ENCODE-090** Item 5 targetConfidenceLevel: uint8, 0 to 100.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.6
- Quote: "Valid Values: The set of integer values from 0 to 100 inclusive." (`specs/src/ST0903.6.txt:1384`)

**R-NESTED-ENCODE-091** Item 6 targetHistory: uint V2, 0 to 65,535 (0 = new detection).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.7; Table 10
- Quote: "Valid Values: 0 to 65535 frames, where a value of 0 denotes the target as a new detection." (`specs/src/ST0903.6.txt:1395`)
- Quote: "6 targetHistory N/A uint V2 Number of previous times the" (`specs/src/ST0903.6.txt:1240`)

**R-NESTED-ENCODE-092** Item 7 percentageOfTargetPixels: uint8, 1 to 100.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.8
- Quote: "Valid Values: The set of integer numbers from 1 to 100 inclusive." (`specs/src/ST0903.6.txt:1403`)

**R-NESTED-ENCODE-093** Item 8 targetColor: exactly 3 bytes R, G, B (not minimised).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.9; Table 10
- Quote: "Represent the RGB color value as: first byte = Red, second byte = Green, third byte = Blue." (`specs/src/ST0903.6.txt:1412`)
- Quote: "8 targetColor N/A uint 3 Dominant color of the target" (`specs/src/ST0903.6.txt:1246`)

**R-NESTED-ENCODE-094** Item 9 targetIntensity: uint V3, 0 to 2^24 - 1.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.10; Table 10
- Quote: "The targetIntensity item is the dominant intensity of the target with dynamic range up to 24 bits." (`specs/src/ST0903.6.txt:1422`)
- Quote: "9 targetIntensity N/A uint V3 Dominant intensity of the target" (`specs/src/ST0903.6.txt:1247`)

**R-NESTED-ENCODE-095** Items 10, 11 (target) and 13 to 16 (geospatial bounding box corners) are offsets in degrees from the parent's Frame Center Latitude / Longitude, IMAPB(-19.2, 19.2, 3), 3 bytes, -19.2 to 19.2.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 sections 10.2.2.11 to 10.2.2.17
- Quote: "Conversion: IMAPB(-19.2, 19.2, 3) Valid Values: The set of real numbers from -19.2 to 19.2 inclusive." (`specs/src/ST0903.6.txt:1445`)
- Quote: "The targetLocationOffsetLat adds to the Frame Center Latitude to determine the latitude of the target." (`specs/src/ST0903.6.txt:1439`)

**R-NESTED-ENCODE-096** Item 12 targetHae: IMAPB(-900, 19000, 2), 2 bytes, metres above the WGS84 ellipsoid.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.13
- Quote: "ellipsoid (HAE). Conversion: IMAPB(-900, 19000, 2). Valid Values: The set of real numbers from -900 to 19,000 inclusive." (`specs/src/ST0903.6.txt:1468`)

**R-NESTED-ENCODE-097** targetLocation (item 17) is preferred over offsets even when embedded; the encoder offers both and documents the preference.
- Who: misb::encode
- Source: ST 0903.6 section 10.2.2.18
- Quote: "However, even when using embedded-VMTI, targetLocation is preferred vice offset calculations." (`specs/src/ST0903.6.txt:1538`)

**R-NESTED-ENCODE-098** Items 19 and 20 (centroid row, column): uint V4, 1 to 2^32 - 1.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 sections 10.2.2.20, 10.2.2.21; Table 10
- Quote: "Valid Values: Integer values in the range 1 to 232-1." (`specs/src/ST0903.6.txt:1560`)
- Quote: "19 centroidPixRow N/A uint V4 target centroid within the Motion" (`specs/src/ST0903.6.txt:1279`)

**R-NESTED-ENCODE-099** VTarget items 21 (FPA index), 102 (single VObject) and 103 (single VFeature) are deprecated and never written; their content goes in 107 vObjectSeries and VObject 5.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 Table 10
- Quote: "21 Item DEPRECATED --- --- --- ST 0903.6 deprecates this item" (`specs/src/ST0903.6.txt:1284`)
- Quote: "102 Item DEPRECATED --- --- --- ST 0903.6 deprecates this item 103 Item DEPRECATED --- --- --- ST 0903.6 deprecates this item" (`specs/src/ST0903.6.txt:1296`)

**R-NESTED-ENCODE-100** Item 22 algorithmId: uint V3 (so at most 2^24 - 1), equal to an algorithmId of the algorithmSeries (item 102) of the same VMTI LS.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.23; Table 10
- Quote: "The algorithmId value equals one of the Id values in the algorithmSeries." (`specs/src/ST0903.6.txt:1589`)
- Quote: "22 algorithmId N/A uint V3 algorithm in Algorithm Series" (`specs/src/ST0903.6.txt:1286`)

**R-NESTED-ENCODE-101** Item 23 detectionStatus: uint8, 0 Inactive, 1 Active-Moving, 2 Dropped, 3 Active-Stopped, 4 Active-Coasting.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 Table 5, Table 10
- Quote: "Value Status Description 0 Inactive" (`specs/src/ST0903.6.txt:394`)
- Quote: "23 detectionStatus N/A uint 1 for a given entity (Inactive, Active-" (`specs/src/ST0903.6.txt:1290`)

**R-NESTED-ENCODE-102** Item 101 vMask holds a polygon of three or more points and/or a bit mask (group G).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.25
- Quote: "Specifying the shape of the outline is by (1) three or more points representing the vertices of a polygon within a Motion Imagery frame, or (2) a bit mask" (`specs/src/ST0903.6.txt:1596`)

**R-NESTED-ENCODE-103** Item 105 vChip (one chip) and item 106 vChipSeries (several) are not both written; the first chip of a vChipSeries comes from the VMTI-MI frame of the detection (Decision D-21).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.2.2.30, ST 0903.6-143
- Quote: "When a system uses Item 106 vChipSeries, there is no need for Item 105." (`specs/src/ST0903.6.txt:1625`)
- Quote: "ST 0903.6-143 The image chip within the first VChip LS in a vChipSeries shall be from the VMTI- MI frame where the target was detected." (`specs/src/ST0903.6.txt:1636`)

**R-NESTED-ENCODE-104** The standalone-only restrictions (omit items 10, 11, 13 to 16; targetLocation mandatory, ST 0903.6-130) do not apply inside tag 74; the encoder must not apply them to embedded VMTI, and must apply them if a standalone mode is added later.
- Who: misb::encode
- Source: ST 0903.6-116, -130
- Quote: "ST 0903.6-116 Where using standalone-VMTI, VTarget LS instances shall omit items 10, 11, 13, 14, 15, and 16 (listed in Table 8)." (`specs/src/ST0903.6.txt:599`)

**R-NESTED-ENCODE-105** Offset items are only valid in embedded VMTI, which is the only mode this phase writes.
- Who: misb::encode
- Source: ST 0903.4-35
- Quote: "ST 0903.4-35 VTarget Pack boundaryBottomRightLonOffset (Item 16) shall only be present when using embedded-VMTI." (`specs/src/ST0903.6.txt:1529`)

**R-NESTED-ENCODE-106** Dropped targets are not in the target list; by default the encoder does not report a target whose status is Dropped (2), and the state layer retires its targetId (Decision D-39).
- Who: misb::state (encode feature)
- Source: ST 0903.6 sections 6, 7.2
- Quote: "The target list does not include targets in the Dropped state." (`specs/src/ST0903.6.txt:223`)
- Quote: "When a system decides to discontinue managing a target, the system changes the state to Dropped and the system removes the target from the target list." (`specs/src/ST0903.6.txt:434`)

**R-NESTED-ENCODE-107** A new target starts in Active-Moving (detection by movement) or Active-Stopped (detection without movement).
- Who: misb::state (encode feature)
- Source: ST 0903.6 section 7.2
- Quote: "When the system creates a target, the system assigns the target a unique identifier and sets the state to" (`specs/src/ST0903.6.txt:409`)

### F. Location, Velocity, Acceleration and BoundarySeries

**R-NESTED-ENCODE-110** Location, Velocity and Acceleration are truncation packs: groups are dropped only whole and only from the end; no filler values stand in for unknown elements of a group that is sent.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-62, -63
- Quote: "ST 0903.4-62 Truncation of Location, Velocity, and Acceleration Defined-Length Truncation Packs shall be allowed only as a group." (`specs/src/ST0903.6.txt:2089`)
- Quote: "ST 0903.4-63 Within a Location, Velocity, or Acceleration Defined-Length Truncation Pack, no filler values shall be used for (unknown) higher priority elements." (`specs/src/ST0903.6.txt:2091`)

**R-NESTED-ENCODE-111** Location pack: latitude IMAPB(-90, 90, 4), longitude IMAPB(-180, 180, 4), hae IMAPB(-900, 19000, 2) (always present), then optionally sigEast, sigNorth, sigUp IMAPB(0, 650, 2), then optionally rhoEastNorth, rhoEastUp, rhoNorthUp IMAPB(-1, 1, 2): 10, 16 or 22 bytes. The rho group is only sent with the sigma group.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-66; section 10.10.1; Table 18
- Quote: "ST 0903.4-66 The Geospatial Coordinates triplet of a Location Pack shall always be present." (`specs/src/ST0903.6.txt:2149`)
- Quote: "when not included truncate the correlation coefficients group first followed by the standard deviations group." (`specs/src/ST0903.6.txt:2119`)
- Quote: "N/A latitude ° IMAPB(-90, 90, 4) 4 Latitude in degrees of a point with respect" (`specs/src/ST0903.6.txt:2126`)
- Quote: "N/A longitude ° IMAPB(-180, 180, 4) 4 Longitude in degrees of a point with" (`specs/src/ST0903.6.txt:2128`)
- Quote: "N/A hae m IMAPB(-900, 19000, 2) 2 Height of a point in meters above the" (`specs/src/ST0903.6.txt:2130`)
- Quote: "N/A sigEast m IMAPB(0, 650, 2) 2 point with respect to the ENU coordinate" (`specs/src/ST0903.6.txt:2133`)
- Quote: "N/A rhoEastNorth N/A IMAPB(-1, 1, 2) 2 Correlation coefficient between the East" (`specs/src/ST0903.6.txt:2141`)

**R-NESTED-ENCODE-112** Velocity pack: east, north, up IMAPB(-900, 900, 2) m/s (always present), optional sigma and rho groups as in Location: 6, 12 or 18 bytes. Only sent with an associated Location (Decision D-19).
- Who: misb::encode; conformance checker
- Source: ST 0903.4-75, -82; Table 19
- Quote: "ST 0903.4-75 The Velocity Components triplet of the Velocity pack shall be present." (`specs/src/ST0903.6.txt:2188`)
- Quote: "ST 0903.4-82 The Velocity pack shall be present only if there is an associated Location pack." (`specs/src/ST0903.6.txt:2189`)
- Quote: "N/A east m/s IMAPB(-900, 900, 2) 2 Velocity along the East axis of the East-" (`specs/src/ST0903.6.txt:2172`)

**R-NESTED-ENCODE-113** Acceleration pack: as Velocity, units m/s^2: 6, 12 or 18 bytes. Only sent with an associated Location.
- Who: misb::encode; conformance checker
- Source: ST 0903.4-85, -92; Table 20
- Quote: "ST 0903.4-85 The Acceleration Components triplet of the Acceleration pack shall always be present." (`specs/src/ST0903.6.txt:2229`)
- Quote: "ST 0903.4-92 The Acceleration pack shall be present only if there is an associated Location pack." (`specs/src/ST0903.6.txt:2233`)

**R-NESTED-ENCODE-114** BoundarySeries (VTarget 18, VTracker 5): a Series of Location packs, each with its BER length; at least two vertices; exactly two means opposite corners of a latitude-longitude aligned box; the normalised contour has one interior area.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.11, ST 0903.4-93, -94, ST 0903.6-141
- Quote: "The BoundarySeries structure includes the BER-encoded Length for each value. Each vertex is of type Location." (`specs/src/ST0903.6.txt:2302`)
- Quote: "ST 0903.4-93 A BoundarySeries shall contain at least two vertices." (`specs/src/ST0903.6.txt:2305`)
- Quote: "ST 0903.4-94 Where a BoundarySeries contains only two vertices, the vertices shall be opposite corners of a simple, geospatial bounding box, aligned with the Latitude-Longitude grid." (`specs/src/ST0903.6.txt:2306`)
- Quote: "ST 0903.6-141 A BoundarySeries’ normalized contour shall contain only one interior area." (`specs/src/ST0903.6.txt:2283`)

### G. VMask, VObject, VFeature, VTracker, VChip, Algorithm and Ontology Local Sets

**R-NESTED-ENCODE-120** VMask item 1 pixelContour: an Array (VLP) of at least three pixel numbers in clockwise order, each a BER length plus the pixel number in the fewest bytes, none above frameWidth * frameHeight.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.3.1, ST 0903.4-40, ST 0903.5-100
- Quote: "ST 0903.4-40 The VMask LS pixelContour (Item 1) shall list the contour points in clockwise order." (`specs/src/ST0903.6.txt:1680`)
- Quote: "ST 0903.5-100 A pixelContour pixel number shall be no greater than the number of pixels in a VMTI-MI frame." (`specs/src/ST0903.6.txt:1682`)
- Quote: "A pixelContour item is an Array type of three or more points representing the vertices of a polygon within a Motion Imagery frame listed in clockwise order." (`specs/src/ST0903.6.txt:1661`)

**R-NESTED-ENCODE-121** VMask item 2 bitMaskSeries: a Series of pixel runs; each run is [BER length of pixel number][pixel number, fewest bytes][run length as a BER length]. A run does not pass the end of its image row (Decision D-24).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.3.2, ST 0903.5-101
- Quote: "Encode pixel numbers using the Length-Value (i.e., “L | pixel” in Figure 19) construct of a Variable Length Pack. Encode the length of each run using BER-Length encoding." (`specs/src/ST0903.6.txt:1696`)
- Quote: "ST 0903.5-101 A bitMaskSeries pixel-run starting pixel number plus run-length shall be less than the line length of the VMTI-MI image." (`specs/src/ST0903.6.txt:1722`)

**R-NESTED-ENCODE-122** VObject: item 3 ontologyId (uint V8) equals an ontologyId of the ontologySeries of the same VMTI LS; item 4 confidence is IMAPB(0, 100, L) with L = item length, 1 to 3; item 5 vFeatureSeries; items 1 and 2 are deprecated and never written.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.4, ST 0903.6-131, Table 12
- Quote: "ST 0903.6-131 The value of a VObjects LS ontologyId (Item 3) shall be equal to one of the Ontology LS’s ids in the VMTI LS’s ontologySeries." (`specs/src/ST0903.6.txt:1752`)
- Quote: "The confidence value is IMAPB(0.0, 100.0, length) with the length defined by the tag’s length value. Increasing the length provides more accuracy. The minimum length is 1." (`specs/src/ST0903.6.txt:1759`)
- Quote: "4 confidence N/A IMAP V3 The amount of confidence in the label of" (`specs/src/ST0903.6.txt:1735`)
- Quote: "3 ontologyId N/A uint V8 VMTI’s Ontology Series represents this" (`specs/src/ST0903.6.txt:1733`)

**R-NESTED-ENCODE-123** VFeature: item 3 ontologyId (uint V8) equals an ontologyId of the ontologySeries; item 4 confidence as VObject 4; items 1 and 2 are deprecated and never written.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.5, ST 0903.6-132, Table 13
- Quote: "ST 0903.6-132 The value of VFeature LS’s ontologyId shall be equal to one of the Ontology LS’s ids in the VMTI LS’s ontologySeries." (`specs/src/ST0903.6.txt:1793`)

**R-NESTED-ENCODE-124** Each object prediction carries a label and a confidence; the encoder requires VObject items 3 and 4 and VFeature items 3 and 4 (Decision D-22).
- Who: misb::encode
- Source: ST 0903.6 section 7.3
- Quote: "Each object- prediction includes an object-label (i.e., what the type of the object is), an object-confidence value (i.e., the certainty the label is correct), and optional feature-labels" (`specs/src/ST0903.6.txt:444`)

**R-NESTED-ENCODE-125** VTracker: item 1 trackId is a 16-byte UUID; items 3, 4 are 8-byte MISP times; item 5 trackBoundarySeries is a BoundarySeries; item 7 confidenceLevel uint8 0 to 100; item 9 trackHistorySeries is in chronological order; items 10, 11 are Velocity / Acceleration packs; item 12 algorithmId (uint V, written with the fewest bytes, at most 8) refers to the algorithmSeries. Items 2, 6, 8 are deprecated and never written.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.6, Table 14, ST 0903.4-56, ST 0903.6-133
- Quote: "Uniquely identifies a track, using a 128-bit (16-byte) Universal Unique Identification (UUID) as standardized by the Open Software Foundation according to ISO/IEC 9834-8 [11]." (`specs/src/ST0903.6.txt:1833`)
- Quote: "ST 0903.4-56 The VTracker LS trackHistorySeries item (Item 9) shall contain the points in chronological order from start to end of the VMTI detections." (`specs/src/ST0903.6.txt:1882`)
- Quote: "ST 0903.6-133 The VTracker LS algorithmId (Item 12) value shall refer to the algorithmId of one of the elements in the VMTI LS algorithmSeries (Item 102)." (`specs/src/ST0903.6.txt:1898`)
- Quote: "Valid values: The set of all integers from 0 to 100 inclusive." (`specs/src/ST0903.6.txt:1869`)
- Quote: "12 algorithmId N/A uint V Identifier indicating which algorithm in the" (`specs/src/ST0903.6.txt:1830`)
- Quote: "1 trackId N/A UUID 16 A unique identifier (UUID) for the track" (`specs/src/ST0903.6.txt:1811`)
- Quote: "3 firstObsvTime µs uint 8 Time of the first observation of the entity" (`specs/src/ST0903.6.txt:1813`)

**R-NESTED-ENCODE-126** VChip: item 1 imageType is in every VChip and is exactly "jpeg" or "png", the type of the image in item 2 (IRI) and item 3 (embedded bytes).
- Who: misb::encode; conformance checker
- Source: ST 0903.6-134, -135, -136, ST 0903.4-59
- Quote: "ST 0903.6-134 Every VChip LS instance shall include the imageType (Item 1)." (`specs/src/ST0903.6.txt:1928`)
- Quote: "ST 0903.6-135 The VChip LS imageType (Item 1) shall state the type of VChip LS embeddedImage (Item 3)." (`specs/src/ST0903.6.txt:1931`)
- Quote: "ST 0903.6-136 The VChip LS imageType (Item 1) shall be either “jpeg” or “png”." (`specs/src/ST0903.6.txt:1933`)
- Quote: "ST 0903.4-59 The VChip LS imageType (Item 1) shall state the type of image referred to by VChip LS imageIRI (Item 2)." (`specs/src/ST0903.6.txt:1929`)

**R-NESTED-ENCODE-127** Algorithm LS: items 1 algorithmId (uint V8), 2 name and 3 version are in every instance; algorithmIds are unique within the series; item 4 class (utf8) and item 5 nFrames (uint V8) are optional.
- Who: misb::encode; conformance checker
- Source: ST 0903.5-102, -103, -104, ST 0903.6-137, Table 16
- Quote: "ST 0903.5-102 All instances of the Algorithm LS shall contain an algorithmId (Item 1)." (`specs/src/ST0903.6.txt:1970`)
- Quote: "ST 0903.6-137 All Algorithm LSs in an Algorithm LS series shall have unique algorithmIds (Item 1)." (`specs/src/ST0903.6.txt:1971`)
- Quote: "ST 0903.5-103 All instances of the Algorithm LS shall contain a name (Item 2)." (`specs/src/ST0903.6.txt:1982`)
- Quote: "ST 0903.5-104 All instances of the Algorithm LS shall contain version (Item 3)." (`specs/src/ST0903.6.txt:1991`)
- Quote: "1 algorithmId N/A uint V8 Identifier for the algorithm used" (`specs/src/ST0903.6.txt:1956`)
- Quote: "5 nFrames N/A uint V8 Number of frames the algorithm operates over" (`specs/src/ST0903.6.txt:1960`)

**R-NESTED-ENCODE-128** Ontology LS: items 1 ontologyId (uint V8), 3 ontologyIRI (an OWL ontology) and 4 entityIRI (an entity of that ontology) are in every instance; ontologyIds are unique within the series; item 6 label, when written, matches the ontology's rdfs:label or skos:prefLabel exactly.
- Who: misb::encode; conformance checker
- Source: ST 0903.5-105, -107, -108, ST 0903.6-138, -139, -140, Table 17
- Quote: "ST 0903.5-105 All instances of the Ontology LS shall contain an ontologyId (Item 1)." (`specs/src/ST0903.6.txt:2040`)
- Quote: "ST 0903.6-138 All Ontology LSs in an Ontology LS series shall have unique ontologyIds (Item 1)." (`specs/src/ST0903.6.txt:2041`)
- Quote: "ST 0903.5-107 All instances of the Ontology LS shall contain an ontologyIRI (Item 3)." (`specs/src/ST0903.6.txt:2062`)
- Quote: "ST 0903.5-108 All instances of the Ontology LS shall contain entityIRI (Item 4)." (`specs/src/ST0903.6.txt:2066`)
- Quote: "ST 0903.6-139 All instances of entityIRI (Item 4) shall have a value taken from the ontologyIRI (Item 3) specified in the Ontology LS." (`specs/src/ST0903.6.txt:2067`)
- Quote: "ST 0903.6-140 Where the Ontology LS includes a label (Item 6), the label shall exactly match the rdfs:label or skos:prefLabel in the defining ontologyIRI (Item 3)." (`specs/src/ST0903.6.txt:2081`)
- Quote: "1 ontologyId N/A uint V8 Identifier for the ontology used 2 parentId N/A uint V8" (`specs/src/ST0903.6.txt:2022`)

**R-NESTED-ENCODE-129** Ontology item 2 parentId (uint V8) is discouraged since ST 0903.6; when a caller supplies it, it equals the ontologyId of another element of the same series.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.9.2
- Quote: "However, this information is duplicative to the ontology hierarchy; therefore starting with ST0903.6 the MISP suggests not using this item." (`specs/src/ST0903.6.txt:2049`)
- Quote: "the parentId defines the link by the child defining its parentId equal to the parent ontology object’s ontologyId." (`specs/src/ST0903.6.txt:2051`)

**R-NESTED-ENCODE-130** Algorithm and ontology identifiers are only meaningful inside one VMTI LS instance, so every reference (VTarget 22, VTracker 12, VObject 3, VFeature 3) is resolved against the series of the same tag 74 value (Decision D-25).
- Who: misb::encode; conformance checker
- Source: ST 0903.6 sections 10.8.1, 10.9.1
- Quote: "Systems may reuse algorithmIds from VMTI LS to VMTI LS (i.e., two sequential VMTI packets) so receivers should not assume an identifier value is static for an entire VMTI stream." (`specs/src/ST0903.6.txt:1964`)

**R-NESTED-ENCODE-131** The Ontology LS requires items 1, 3 and 4.
- Who: misb::encode; conformance checker
- Source: ST 0903.6 section 10.9
- Quote: "The Ontology LS requires ontologyId - Item 1, ontologyIRI - Item 3, and entityIRI - Item 4 to be present." (`specs/src/ST0903.6.txt:2015`)

### H. ST 1201.5 IMAPB forward mapping

**R-NESTED-ENCODE-140** Forward mapping: (1) +inf, -inf and NaN map to their special patterns; (2) x < a maps to IMAP_BELOW_MINIMUM; (3) x > b maps to IMAP_ABOVE_MAXIMUM, in both cases only where the invoking standard uses those signals (rule 146); (4) otherwise y = truncate(sF * (x - a) + Zoffset).
- Who: misb::encode
- Source: ST 1201.5 section 7.2.1
- Quote: "1. If x is a special value, then: y = Table Lookup to map to specified bit pattern (see Section 7.2.3)" (`specs/src/ST1201.5.txt:225`)
- Quote: "2. If x<a then: y = Special bit pattern IMAP_BELOW_MINIMUM (see Section 7.2.3.1) 3. If x>b then: y = Special bit pattern IMAP_ABOVE_MAXIMUM" (`specs/src/ST1201.5.txt:227`)
- Quote: "a. y=truncate(sF*(x-a)+Zoffset)" (`specs/src/ST1201.5.txt:232`)

**R-NESTED-ENCODE-141** Constants from a, b and L: bPow = ceiling(log2(b - a)), dPow = 8L - 1, sF = 2^(dPow - bPow), sR = 2^(bPow - dPow), Zoffset = sF*a - floor(sF*a) when a < 0 < b, else 0. bPow is computed exactly from the f64 exponent bits, never with a floating log2 (Decision D-27).
- Who: misb::encode
- Source: ST 1201.5 section 7.1.2
- Quote: "1. bPow = ceiling(log2(b-a)) 2. dPow = 8*L-1 3. sF = 2^( dPow -bPow) 4. sR = 2^(bPow- dPow) 5. Zoffset = 0.0 6. if (a<0 and b>0) then Zoffset = sF*a-floor(sF*a)" (`specs/src/ST1201.5.txt:203`)

**R-NESTED-ENCODE-142** y is written as an L-byte big-endian unsigned integer (the low L bytes).
- Who: misb::encode
- Source: ST 1201.5 section 7.2.1
- Quote: "Note: Convert y into L number of bytes values (i.e., the lower L number of bytes is the “value” to send)" (`specs/src/ST1201.5.txt:235`)

**R-NESTED-ENCODE-143** Length for a required precision g (IMAPA): Lbits = ceiling(log2(b - a)) - floor(log2(g)) + 1, L = ceiling(Lbits / 8), with exact exponents; no rounding up to 4 or 8 bytes.
- Who: misb::encode
- Source: ST 1201.5 section 7.1.1
- Quote: "1. Lbits = ceiling(log2(b-a))-floor(log2(g)) + 1" (`specs/src/ST1201.5.txt:189`)
- Quote: "2. L = ceiling( Lbits/8)" (`specs/src/ST1201.5.txt:190`)

**R-NESTED-ENCODE-144** Special values (first byte, the other L - 1 bytes 0x00): +infinity 0xC8, -infinity 0xE8, NaN 0xD0 (positive quiet NaN, NaN identifier 0). -QNaN 0xF0, +SNaN 0xD8, -SNaN 0xF8 and user-defined 0xC0 to 0xC7 only through an explicit special-value API (Decision D-16).
- Who: misb::encode
- Source: ST 1201.5 section 7.2.3, Table 2
- Quote: "+Infinity 1 1 0 0 1 Zero Positive Infinity (+∞)" (`specs/src/ST1201.5.txt:305`)
- Quote: "*This standard defines only one NaN Identifier, i.e., fill bits b - b with zeros." (`specs/src/ST1201.5.txt:321`)

**R-NESTED-ENCODE-145** IMAP_BELOW_MINIMUM is first byte 0xE0, IMAP_ABOVE_MAXIMUM is 0xE1, other bytes 0x00; one byte is enough, so they exist for every L from 1.
- Who: misb::encode
- Source: ST 1201.5 section 7.2.3.1, Table 3
- Quote: "IMAP_BELOW_MINIMUM 1 1 1 0 0 0 0 0 Zero Filled IMAP_ABOVE_MAXIMUM 1 1 1 0 0 0 0 1 Zero Filled" (`specs/src/ST1201.5.txt:354`)
- Quote: "Currently, the defined and RESERVED values need only one byte." (`specs/src/ST1201.5.txt:344`)

**R-NESTED-ENCODE-146** Whether the below-minimum and above-maximum signals may be sent is decided by the invoking standard; ST 0903.6 uses them (rule 072). Without such permission an out-of-range input is an error.
- Who: misb::encode
- Source: ST 1201.5 section 7.2.3.1
- Quote: "Invoking standards define if and how to use the IMAP_BELOW_MINIMUM or IMAP_ABOVE_MAXIMUM on a case-by-case basis" (`specs/src/ST1201.5.txt:376`)

**R-NESTED-ENCODE-147** -0.0 is encoded as +0.0 (a normal value).
- Who: misb::encode
- Source: ST 1201.1-12
- Quote: "ST 1201.1-12 All negative zero values shall be mapped to a positive zero and sent as a normal (non-special) value." (`specs/src/ST1201.5.txt:332`)

**R-NESTED-ENCODE-148** x = b encodes as 0x80 followed by zeros only when b - a is an exact power of two (for example IMAPB(-1, 1, 2): 1.0 -> 80 00); otherwise the msb of every normal value is 0. This is a normal value, not a special one.
- Who: misb::encode
- Source: ST 1201.5 section 7.2.3, Table 1
- Quote: "The msb is zero for all normal mapped values except for the maximum floating-point value, b, but only if (b-a), as specified by the user, is a power of 2." (`specs/src/ST1201.5.txt:278`)

**R-NESTED-ENCODE-149** When an item is written with a length other than the nominal one, the constants are computed from the length actually written.
- Who: misb::encode
- Source: ST 1201.5 section 7.4
- Quote: "When using a different length, it is important to compute the constants needed to do the forward and reverse mapping based on the KLV supplied length." (`specs/src/ST1201.5.txt:440`)

**R-NESTED-ENCODE-150** The mapping truncates (floor of a non-negative number); it never rounds to nearest, so decode(encode(x)) lies in (x - sR, x] up to f64 rounding (Decision D-28).
- Who: misb::encode
- Source: ST 1201.5 section 8.3 (informative)
- Quote: "However, to support the zero matching requirements a truncation must be used instead" (`specs/src/ST1201.5.txt:592`)

### I. ST 1204.3 MIIS Core Identifier (VMTI item 13)

**R-NESTED-ENCODE-160** Binary Core Identifier = Version, Usage Value, then the FCID UUIDs or the MCID UUID. Version is a BER-OID and is 1 (one byte 0x01).
- Who: misb::encode; conformance checker
- Source: ST 1204.3 sections 7.1, 7.2, Table 5
- Quote: "Core Identifier = Version, Usage Value, FCID | MCID;" (`specs/src/ST1204.3.txt:521`)
- Quote: "Version is a BER-OID (see [6]) encoded value for the version number" (`specs/src/ST1204.3.txt:610`)
- Quote: "Currently, the Core Identifier Version is 1." (`specs/src/ST1204.3.txt:540`)

**R-NESTED-ENCODE-161** Usage Value is one byte: bit 7 = 0; bits 6-5 Sensor ID type and bits 4-3 Platform ID type (11 Physical, 10 Virtual, 01 Managed, 00 None); bit 2 Window ID included; bit 1 Minor ID included; bit 0 = 0.
- Who: misb::encode; conformance checker
- Source: ST 1204.3 section 7.3.1, Table 3
- Quote: "7 - MSB Reserved Always Zero 6,5 Sensor-ID-Type 11 = Physical, 10=Virtual, 01=Managed, 00=None 4,3 Platform-ID-Type 11 = Physical, 10=Virtual, 01=Managed, 00=None 2 Window-ID-Type 1=Included, 0=None 1 Minor-ID-Type 1=Included, 0=None 0 - LSB Reserved Always Zero" (`specs/src/ST1204.3.txt:571`)

**R-NESTED-ENCODE-162** Allowed combinations: Sensor [+ Platform] [+ Window], Platform [+ Window], Window alone, or Minor alone; never no identifier at all.
- Who: misb::encode; conformance checker
- Source: ST 1204.3 section 7.1
- Quote: "FCID = (Sensor ID, [Platform ID], [Window ID]) | (Platform ID, [Window ID]) | Window ID;" (`specs/src/ST1204.3.txt:529`)

**R-NESTED-ENCODE-163** Each identifier is a 16-byte UUID; FCID UUIDs follow in the order Sensor, Platform, Window, each only when its usage bits say it is present. Total length 18, 34 or 50 bytes.
- Who: misb::encode; conformance checker
- Source: ST 1204.3 Table 5
- Quote: "Each UUID value is 16 bytes so valid lengths are 16, 32 or 48 bytes. The order of the Sensor ID, Platform ID and Window ID is important and should follow the EBNF in Section 7.1" (`specs/src/ST1204.3.txt:613`)
- Quote: "UUID = 16 byte Universally Unique Identifiers (UUIDs) created following the" (`specs/src/ST1204.3.txt:534`)

**R-NESTED-ENCODE-164** A Minor ID is never combined with a Foundational ID.
- Who: misb::encode; conformance checker
- Source: ST 1204.1-28
- Quote: "ST 1204.1-28 When Motion Imagery Data includes a Foundational Core Identifier then a Minor Core Identifier shall NOT be used, generated, or inserted into the Motion Imagery Data." (`specs/src/ST1204.3.txt:474`)

**R-NESTED-ENCODE-165** UUIDs are version 1, 4 or 5 (Decision D-29).
- Who: misb::encode; conformance checker
- Source: ST 1204.1-42
- Quote: "ST 1204.1-42 UUIDs shall be generated using only UUID versions 1, 4 and 5 as stated in" (`specs/src/ST1204.3.txt:982`)

**R-NESTED-ENCODE-166** No temporary (nil) identifiers leave the platform: an injector never writes the all-zero pre-fill UUID.
- Who: misb::encode; conformance checker
- Source: ST 1204.1-32 (with ST 1204.1-31)
- Quote: "ST 1204.1-32 When Foundational Core Identifiers within Motion Imagery data leave the platform or are stored on the platform, they shall be fully formed with no temporary Identifiers." (`specs/src/ST1204.3.txt:450`)

**R-NESTED-ENCODE-167** The binary form carries no check value; the check value belongs to the text format only.
- Who: misb::encode; conformance checker
- Source: ST 1204.3 Table 5, Table 8
- Quote: "Core Identifier Block of data, which is the combination of Version, Usage Value and FCID or MCID." (`specs/src/ST1204.3.txt:608`)
- Quote: "After the complete string of hex characters, append a check hex value." (`specs/src/ST1204.3.txt:755`)

**R-NESTED-ENCODE-168** A sensor identifier built from several sensors is a hashed combination made by the caller (Appendix A.1); the encoder takes the resulting UUID as given.
- Who: misb::encode (caller input)
- Source: ST 1204.1-18
- Quote: "ST 1204.1-18 When a MIIS conformant multiple sensor system is used to form a single Motion" (`specs/src/ST1204.3.txt:370`)

## 3. Exact byte layouts and encoder tables

Notation: `M` mandatory in every instance, `C` conditional (condition given), `O` optional, `N` never written by the builder (deprecated or deleted; re-encoding a decoded packet copies such items from `Item::raw`, D-33). "fewest" = big-endian unsigned integer with no leading zero byte (rule 015). Lengths are BER (rule 012).

### 3.1 ST 0601 wrapper

| Field | Bytes | Value written |
|---|---|---|
| Tag | 1 | `30` (tag 48) or `4A` (tag 74) |
| Length | 1 to 9 | BER, fewest bytes: number of value bytes |
| Value | n | the nested set's items (tables below); no 16-byte key, no inner length, no checksum (rules 001, 002) |

Position inside the ST 0601 packet is set by the ST 0601 encoder (tag 2 first, tag 1 last, everything else in between, rule 022 and the ST 0601 topic). A packet with tag 74 also carries tags 23 and 24 (rule 008, D-31).

For comparison, the standalone forms this phase does not write: ST 0102 Local Set = key `06 0E 2B 34 02 03 01 01 0E 01 03 03 02 00 00 00`, BER length, the same items, still no checksum. ST 0903 standalone = key `06 0E 2B 34 02 0B 01 01 0E 01 03 03 06 00 00 00`, BER length, items, and differs from the nested form as follows:

| Point | Nested in tag 74 (this phase) | Standalone (not written now) |
|---|---|---|
| checkSum, item 1 | omitted (ST 0903.6-120) | required, last item, ST 0601 algorithm over key..checksum length (ST 0903.4-15, -17, ST 0903.6-119) |
| precisionTimeStamp, item 2 | optional when equal to ST 0601 tag 2, else required (ST 0903.6-118) | required (ST 0903.6-117) |
| FOV items 11, 12 | only when VMTI-MI differs from user-MI (ST 0903.4-26, -27) | required (ST 0903.6-122, -123) |
| miisId, item 13 | only when VMTI-MI differs (ST 0903.6-124) | required (ST 0903.6-125) |
| VTarget offsets 10, 11, 13 to 16 | allowed (ST 0903.4-35) | forbidden (ST 0903.6-116) |
| VTarget targetLocation 17 | optional, preferred | required for Active-* targets (ST 0903.6-130) |

### 3.2 ST 0102 Security Local Set (value of tag 48), encoder table

One-byte tags, BER lengths (rule 023). Items in ascending tag order (D-01). Every instance is complete (D-07): there is no delta or partial update of tag 48.

| Tag | Name | Pres. | Format | Length | Encoder rule | Example TLV (verified) |
|---|---|---|---|---|---|---|
| 1 | Security Classification | M | uint8 enum | 1 | `01`..`05` only (3.3) | `01 01 01` (UNCLASSIFIED//) |
| 2 | Classifying Country and Releasing Instructions Country Coding Method | M | uint8 enum | 1 | tag 2 column of 3.3; never `08`, `09`; no GENC AdminSub | `02 01 0E` (GENC Three Letter) |
| 3 | Classifying Country | M | ISO 646 | var | `//` + code in the tag 2 method (D-09) | `03 05 2F 2F 55 53 41` (`//USA`) |
| 4 | Security-SCI/SHI Information | C: SCI/SHI applies | ISO 646 | var | entries separated by `/`, ends with `//` | `04 09 41 42 43 2F 44 45 46 2F 2F` (`ABC/DEF//`) |
| 5 | Caveats | C: caveats apply (FOUO goes here) | ISO 646 | var | free text | `05 06 52 45 4C 20 54 4F` (`REL TO`) |
| 6 | Releasing Instructions | C: releasability applies | ISO 646 | var | codes (tag 2 method) separated by one `0x20` | `06 0B 55 53 41 20 43 41 4E 20 47 42 52` (`USA CAN GBR`) |
| 7 | Classified By | C (security guidance) | ISO 646 | var | free text | `07 06 53 43 47 20 30 31` |
| 8 | Derived From | C | ISO 646 | var | free text | `08 10 4D 75 6C ...` (`Multiple Sources`) |
| 9 | Classification Reason | C | ISO 646 | var | free text | `09 06 31 2E 34 28 63 29` (`1.4(c)`) |
| 10 | Declassification Date | C | ISO 646 | 8 | `YYYYMMDD`, valid date | `0A 08 32 30 34 35 31 32 33 31` (`20451231`) |
| 11 | Classification and Marking System | C | ISO 646 | var | free text | `0B 16 45 78 61 ...` |
| 12 | Object Country Coding Method | M | uint8 enum | 1 | tag 12 column of 3.3; never `08`..`0C` | `0C 01 0E`; `0C 01 40` (GENC AdminSub) |
| 13 | Object Country Codes | M | UTF-16BE, no BOM | var, even | codes (tag 12 method) separated by `;`, no spaces; frame-centre country included | `0D 06 00 55 00 53 00 41` (`USA`); `0D 0E 00 43 00 41 00 4E 00 3B 00 55 00 53 00 41` (`CAN;USA`) |
| 14 | Classification Comments | O | ISO 646 | var | non-essential text | `0E 13 53 79 6E ...` |
| 15..21 | UMID, UMID Audio/Data/System, Stream ID, Transport Stream ID, Item Designator ID | N | - | - | deleted in 0102.10 / 0102.12 | - |
| 22 | Version | M | uint16 | 2 | `00 0C` (D-03) | `16 02 00 0C` |
| 23 | Classifying Country and Releasing Instructions Country Coding Method Version Date | O | ISO 646 | 10 | `YYYY-MM-DD` | `17 0A 32 30 31 36 2D 30 37 2D 30 38` (`2016-07-08`) |
| 24 | Object Country Coding Method Version Date | O | ISO 646 | 10 | `YYYY-MM-DD` | `18 0A 32 30 31 36 2D 30 37 2D 30 38` |

"C" items are written when the security content requires them and left out (not zero-length) otherwise (rules 018, 031, 033, 034). What may be omitted: every C item that does not apply, and every O item. Nothing marked M may be omitted in strict mode (D-07). ISO 646 items accept printable ASCII `0x20`..`0x7E` only (D-05). There are no tags above 24.

### 3.3 ST 0102 enumerations (tags 1, 2, 12)

| Code | Tag 1 Classification | Tag 2 method | Tag 12 method |
|---|---|---|---|
| `00` | never | never | never |
| `01` | UNCLASSIFIED// | ISO-3166 Two Letter | ISO-3166 Two Letter |
| `02` | RESTRICTED// | ISO-3166 Three Letter | ISO-3166 Three Letter |
| `03` | CONFIDENTIAL// | FIPS 10-4 Two Letter (legacy, warn) | ISO-3166 Numeric |
| `04` | SECRET// | FIPS 10-4 Four Letter (legacy, warn) | FIPS 10-4 Two Letter (legacy, warn) |
| `05` | TOP SECRET// | ISO-3166 Numeric | FIPS 10-4 Four Letter (legacy, warn) |
| `06` | never | 1059 Two Letter | 1059 Two Letter |
| `07` | never | 1059 Three Letter | 1059 Three Letter |
| `08`, `09` | never | Omitted Value: never | Omitted Value: never |
| `0A` | never | FIPS 10-4 Mixed (legacy, warn) | Omitted Value: never |
| `0B` | never | ISO 3166 Mixed | Omitted Value: never |
| `0C` | never | STANAG 1059 Mixed | Omitted Value: never |
| `0D` | never | GENC Two Letter | GENC Two Letter |
| `0E` | never | GENC Three Letter | GENC Three Letter |
| `0F` | never | GENC Numeric | GENC Numeric |
| `10` | never | GENC Mixed | never |
| `40` | never | never (GENC AdminSub not applicable) | GENC AdminSub |
| other | never | never | never |

### 3.4 Country code shape per method (D-09; lint level unless noted)

| Method | Shape of one code | Tag 3 | Tag 6 / tag 13 separator |
|---|---|---|---|
| ISO-3166 / GENC / 1059 Two Letter | `[A-Z]{2}` | `//` + code (strict: prefix required) | tag 6: one `0x20`; tag 13: `;` (strict) |
| ISO-3166 / GENC / 1059 Three Letter | `[A-Z]{3}` | same | same |
| ISO-3166 / GENC Numeric | `[0-9]{3}` | same | same |
| FIPS 10-4 Two Letter | `[A-Z]{2}` | same | same |
| FIPS 10-4 Four Letter | `[A-Z0-9]{4}` | same | same |
| Mixed (tag 2 only) | all di-graphs or all tri-graphs of the source, plus `[A-Z]{4}` tetragraphs | same | tag 6: one `0x20` |
| GENC AdminSub (tag 12 only) | ISO 3166-2 form `[A-Z]{2}-[A-Z0-9]{1,3}` | n/a | tag 13: `;` |

### 3.5 VMTI Local Set (value of tag 74), encoder table

BER-OID tags (all one byte), BER lengths (rule 050). Order: item 2 first when present, then ascending tag (D-01). No item twice (rule 051).

| Item | Name | Pres. in tag 74 | Format | Length written | Encoder rule | Example TLV (verified) |
|---|---|---|---|---|---|---|
| 1 | checkSum | N | uint16 | - | never inside tag 74 (rule 052) | - |
| 2 | precisionTimeStamp | C: VMTI-MI time differs from ST 0601 tag 2 (D-11) | uint64 MISP us | 8 | first item | `02 08 00 03 82 44 30 F6 CE 40` (987654321000000) |
| 3 | vmtiSystemName | O | utf8 | 1..128 bytes, at most 32 chars | rules 019 to 021 | `03 0E 44 53 54 4F 5F 41 44 53 53 5F 56 4D 54 49` (`DSTO_ADSS_VMTI`) |
| 4 | vmtiLsVersionNum | M | uint V2 | fewest (1) | value 6 (D-10) | `04 01 06` |
| 5 | totalNumTargetsDetected | C: differs from item 6 (D-12) | uint V3 | fewest | 0..16,777,215, never below item 6 | `05 01 1C` (28) |
| 6 | numTargetsReported | M | uint V3 | fewest | = number of VTarget Packs in item 101 (D-12) | `06 01 02`; `06 01 00` (no targets) |
| 7 | motionImageryFrameNumber | N | - | - | deprecated (rule 061) | - |
| 8 | frameWidth | C: any pixel-number item present (rule 062) | uint V3 | fewest | 1..16,777,215 | `08 02 07 80` (1920) |
| 9 | frameHeight | O | uint V3 | fewest | 1..16,777,215 | `09 02 04 38` (1080) |
| 10 | vmtiSourceSensor | O (recommended when VMTI-MI differs) | utf8 | at most 128 chars, 512 bytes | rules 019 to 021 | `0A 07 45 4F 20 4E 6F 73 65` (`EO Nose`) |
| 11 | vmtiHorizontalFov | C: VMTI-MI differs from user-MI | IMAPB(0, 180, 2) | 2 | 0..180 deg | `0B 02 06 40` (12.5) |
| 12 | vmtiVerticalFov | C: VMTI-MI differs | IMAPB(0, 180, 2) | 2 | 0..180 deg | `0C 02 05 00` (10.0) |
| 13 | miisId | C: VMTI-MI differs | ST 1204 binary (3.11) | 18, 34 or 50 | group I | `0D 22 01 70 F5 92 ... 36 45` |
| 101 | vTargetSeries | C: at least one target | Series of VTarget Pack | var | ascending targetId (D-02); left out when no targets (D-13) | see 3.12 |
| 102 | algorithmSeries | C: referenced by VTarget 22 or VTracker 12, or caller supplies | Series of Algorithm LS | var | at least one element when present | `66 2C 2B 01 01 09 ...` |
| 103 | ontologySeries | C: referenced by VObject 3 / VFeature 3, or caller supplies | Series of Ontology LS | var | at least one element when present | `67 81 C1 5F 01 01 0A ...` |

Minimal valid tag 74 value: `04 01 06 06 01 00` (version 6, no targets reported).

### 3.6 VTarget Series element and VTarget Pack

```
Series element:  <BER length n> <targetId: BER-OID, 1..9 bytes> <TLV items, one-byte tags, BER lengths>
                 \________________________ n bytes _____________________________/
```

| Item | Name | Pres. | Format | Length written | Range / encoder rule | Example TLV (verified) |
|---|---|---|---|---|---|---|
| - | targetId | M | BER-OID | 1..9 | 0..2^63-1, fewest bytes, unique in the series, never reused (rules 082, 083, D-20) | `01`; `89 52` (1234); `FF FF FF FF FF FF FF FF 7F` (2^63-1) |
| 1 | targetCentroid | C (rule 085) | uint V6 | fewest | 1..2^48-1 | `01 03 06 40 00` (409600) |
| 2 | boundingBoxTopLeft | C: with 3 (D-17) | uint V6 | fewest | 1..2^48-1 | `02 03 06 40 00` |
| 3 | boundingBoxBottomRight | C: with 2 | uint V6 | fewest | 1..2^48-1, row and column not before item 2's | `03 03 06 D6 1E` (448030) |
| 4 | targetPriority | O | uint8 | 1 | 1..255 | `04 01 1B` (27) |
| 5 | targetConfidenceLevel | O | uint8 | 1 | 0..100 | `05 01 50` (80) |
| 6 | targetHistory | O | uint V2 | fewest | 0..65535 | `06 02 0A CD` (2765) |
| 7 | percentageOfTargetPixels | O | uint8 | 1 | 1..100 | `07 01 32` (50) |
| 8 | targetColor | O | 3 x uint8 | 3 | R, G, B; never shortened | `08 03 DA A5 20` |
| 9 | targetIntensity | O | uint V3 | fewest | 0..2^24-1 | `09 02 33 54` (13140) |
| 10 | targetLocationOffsetLat | O: with 11 (D-17) | IMAPB(-19.2, 19.2, 3) | 3 | target lat - parent frame-centre lat (D-18) | `0A 03 3A 66 67` (10.0) |
| 11 | targetLocationOffsetLon | O: with 10 | IMAPB(-19.2, 19.2, 3) | 3 | wrapped lon difference (D-18) | `0B 03 3E 66 67` (12.0) |
| 12 | targetHae | O | IMAPB(-900, 19000, 2) | 2 | metres HAE | `0C 02 2A 94` (10000) |
| 13..16 | boundingBox{TopLeft,BottomRight}{Lat,Lon}Offset | O: all four together (D-17) | IMAPB(-19.2, 19.2, 3) | 3 each | as 10, 11 | `0D 03 3A 66 67` ... `10 03 3A 66 67` |
| 17 | targetLocation | O (preferred over 10, 11) | Location pack (3.7) | 10, 16, 22 | full triplet always (rule 111) | `11 16 40 66 66 66 19 C0 00 00 03 A2 01 40 01 40 02 80 60 00 40 00 40 00` |
| 18 | geospatialContourSeries | O | BoundarySeries (3.8) | var | at least 2 vertices | `12 16 0A <10 bytes> 0A <10 bytes>` |
| 19 | centroidPixRow | C: with 20 | uint V4 | fewest | 1..2^32-1 | `13 02 03 68` (872) |
| 20 | centroidPixCol | C: with 19 | uint V4 | fewest | 1..2^32-1 | `14 02 04 71` (1137) |
| 21 | FPA index | N | - | - | deprecated | - |
| 22 | algorithmId | O | uint V3 | fewest | 0..2^24-1, present in item 102 of the same LS | `16 01 09` |
| 23 | detectionStatus | O (recommended, D-39) | uint8 | 1 | 0..4 (Table 5) | `17 01 01` (Active-Moving) |
| 101 | vMask | O | LS (3.9) | var | not empty | `65 19 01 09 ... 02 0C ...` |
| 102, 103 | single VObject / VFeature | N | - | - | deprecated; use 107 | - |
| 104 | vTracker | O | LS (3.9) | var | not empty | `68 34 01 10 ...` |
| 105 | vChip | O: exactly one chip (D-21) | LS (3.9) | var | never with 106 | `69 29 01 03 70 6E 67 02 22 ...` |
| 106 | vChipSeries | O: two or more chips | Series of VChip LS | var | first chip from the VMTI-MI frame | `6A 81 FD 81 D0 ...` |
| 107 | vObjectSeries | O | Series of VObject LS | var | caller order | `6B 12 11 03 01 0A 04 02 5A 00 05 08 07 03 01 0B 04 02 50 00` |

Required per target: the targetId and at least one TLV (rule 081). Conditionally: a centroid representation when detectionStatus is 1 or 3 (rule 085); 19 with 20 (rule 086); strict-mode pairs 2+3, 10+11, 13..16 (D-17); offsets only with tags 23/24 in the packet and timestamps within two frames (rules 008, 056).

### 3.7 Location, Velocity and Acceleration packs (fixed IMAPB lengths)

Location (VTarget 17, every vertex of a BoundarySeries, VTracker 9 points):

| Offset | Field | Mapping | Bytes | Group |
|---|---|---|---|---|
| 0 | latitude (deg, WGS84) | IMAPB(-90, 90, 4) | 4 | 1, always |
| 4 | longitude (deg) | IMAPB(-180, 180, 4) | 4 | 1, always |
| 8 | hae (m) | IMAPB(-900, 19000, 2) | 2 | 1, always |
| 10 | sigEast (m) | IMAPB(0, 650, 2) | 2 | 2, optional |
| 12 | sigNorth (m) | IMAPB(0, 650, 2) | 2 | 2 |
| 14 | sigUp (m) | IMAPB(0, 650, 2) | 2 | 2 |
| 16 | rhoEastNorth | IMAPB(-1, 1, 2) | 2 | 3, optional, only with group 2 |
| 18 | rhoEastUp | IMAPB(-1, 1, 2) | 2 | 3 |
| 20 | rhoNorthUp | IMAPB(-1, 1, 2) | 2 | 3 |

Total 10, 16 or 22 bytes. Velocity (VTracker 10, m/s) and Acceleration (VTracker 11, m/s^2): east, north, up IMAPB(-900, 900, 2) each (group 1, always), then sigEast, sigNorth, sigUp IMAPB(0, 650, 2) (group 2), then the three rho IMAPB(-1, 1, 2) (group 3): 6, 12 or 18 bytes. A group is sent only when all three of its values are known (rule 110); an unknown value is never replaced by a filler, NaN or the Invalid signal (D-38). The Invalid signal is for an illegal computed value only (rule 073).

IMAPB constants for every ST 0903 mapping (computed by ST 1201.5 7.1.2; `y(a)` is 0 for every row):

| Mapping | Used by | bPow | dPow | sF | Zoffset | y(0) | y(b) | One LSB |
|---|---|---|---|---|---|---|---|---|
| IMAPB(0, 180, 2) | VMTI 11, 12 | 8 | 15 | 2^7 | 0 | `0000` | `5A00` | 0.0078125 deg |
| IMAPB(-19.2, 19.2, 3) | VTarget 10, 11, 13..16 | 6 | 23 | 2^17 | 0.6000000000931323 | `266667` | `4CCCCD` | 7.62939453125e-6 deg |
| IMAPB(-900, 19000, 2) | VTarget 12, Location hae | 15 | 15 | 1 | 0 | `0384` | `4DBC` | 1 m |
| IMAPB(-90, 90, 4) | Location lat | 8 | 31 | 2^23 | 0 | `2D000000` | `5A000000` | 1.1920928955078125e-7 deg |
| IMAPB(-180, 180, 4) | Location lon | 9 | 31 | 2^22 | 0 | `2D000000` | `5A000000` | 2.384185791015625e-7 deg |
| IMAPB(0, 650, 2) | all sigma fields | 10 | 15 | 2^5 | 0 | `0000` | `5140` | 0.03125 |
| IMAPB(-1, 1, 2) | all rho fields | 1 | 15 | 2^14 | 0 | `4000` | `8000` (b - a is 2^1: msb set, rule 148) | 6.103515625e-5 |
| IMAPB(-900, 900, 2) | Velocity, Acceleration components | 11 | 15 | 2^4 | 0 | `3840` | `7080` | 0.0625 |
| IMAPB(0, 100, 1) | VObject 4, VFeature 4 with L = 1 | 7 | 7 | 1 | 0 | `00` | `64` | 1 percent |
| IMAPB(0, 100, 2) | same, L = 2 (default, D-14) | 7 | 15 | 2^8 | 0 | `0000` | `6400` | 0.00390625 percent |
| IMAPB(0, 100, 3) | same, L = 3 | 7 | 23 | 2^16 | 0 | `000000` | `640000` | 1.52587890625e-5 percent |

### 3.8 BoundarySeries (VTarget 18, VTracker 5) and Location series (VTracker 9)

```
<item tag> <BER total>  { <BER len = 10|16|22> <Location pack> }  repeated
```
BoundarySeries: at least 2 elements; 2 elements = opposite corners of a lat/lon-aligned box; vertex order as given by the caller (D-02). trackHistorySeries: at least 1 element (D-23), oldest first.

### 3.9 Sets inside a VTarget Pack (one-byte tags, BER lengths, ascending tag order)

VMask (VTarget 101):

| Item | Name | Format | Element layout | Rule |
|---|---|---|---|---|
| 1 | pixelContour | Array (VLP) | `<BER len k> <pixel number, k = fewest bytes, 1..6>` per point | at least 3 points, clockwise, each at most frameWidth * frameHeight when the height is known |
| 2 | bitMaskSeries | Series | `<BER len of element> <BER len k> <pixel number, k bytes> <run length, BER length form>` | run stays in its row (D-24) |

Verified: `01 09 02 39 AA 02 39 BF 02 3B 0B` (14762, 14783, 15115); `02 0C 03 01 4A 02 03 01 59 04 03 01 6A 02` ((74,2), (89,4), (106,2)).

VObject (elements of VTarget 107):

| Item | Name | Pres. | Format | Length | Rule |
|---|---|---|---|---|---|
| 1, 2 | ontology, ontologyClass | N | - | - | deprecated |
| 3 | ontologyId | M (D-22) | uint V8 | fewest | in item 103 of the same LS |
| 4 | confidence | M (D-22) | IMAPB(0, 100, L) | L = 1..3, default 2 (D-14) | 0.0..100.0 percent |
| 5 | vFeatureSeries | O | Series of VFeature LS | var | - |

VFeature (elements of VObject 5): 1, 2 N (deprecated); 3 ontologyId M (uint V8, fewest, in item 103); 4 confidence M (as VObject 4). Verified VObject element: `11 03 01 0A 04 02 5A 00 05 08 07 03 01 0B 04 02 50 00` (ontology 10, 90.0 percent, one feature: ontology 11, 80.0 percent).

VTracker (VTarget 104):

| Item | Name | Pres. | Format | Length | Rule |
|---|---|---|---|---|---|
| 1 | trackId | O | UUID | 16 | ISO/IEC 9834-8 bytes in network order |
| 2 | detectionStatus | N | - | - | deprecated (use VTarget 23) |
| 3 | firstObsvTime | O | uint64 MISP us | 8 | not after item 4 (D-37) |
| 4 | latestObsvTime | O | uint64 MISP us | 8 | - |
| 5 | trackBoundarySeries | O | BoundarySeries | var | at least 2 vertices |
| 6 | algorithm (text) | N | - | - | deprecated (use 12) |
| 7 | confidenceLevel | O | uint8 | 1 | 0..100 |
| 8 | numTrackPoints | N | - | - | deprecated (count of item 9) |
| 9 | trackHistorySeries | O | Series of Location | var | chronological |
| 10 | velocity | O: needs an associated Location (D-19) | Velocity pack | 6, 12, 18 | group truncation |
| 11 | acceleration | O: same | Acceleration pack | 6, 12, 18 | group truncation |
| 12 | algorithmId | O | uint V (written fewest, at most 8 bytes, U-02) | fewest | in item 102 of the same LS |

VChip (VTarget 105, elements of VTarget 106):

| Item | Name | Pres. | Format | Rule |
|---|---|---|---|---|
| 1 | imageType | M | utf8 | exactly `jpeg` or `png` (lower case) |
| 2 | imageIRI | C: item 3 absent (D-21) | utf8 | RFC 3987 IRI, image of the type in item 1 |
| 3 | embeddedImage | C: item 2 absent | bytes | the image file; magic number must match item 1 (D-21) |

Algorithm LS (elements of VMTI 102): 1 algorithmId M (uint V8, fewest, unique in the series); 2 name M (utf8, not empty); 3 version M (utf8, not empty); 4 class O (utf8); 5 nFrames O (uint V8, fewest). Verified: `2B 01 01 09 02 14 6B 36 5F 79 6F 6C 6F 5F 39 30 30 30 5F 74 72 61 63 6B 65 72 03 04 32 2E 36 61 04 07 6B 61 6C 6D 61 6E 6E 05 01 0A`.

Ontology LS (elements of VMTI 103): 1 ontologyId M (uint V8, fewest, unique); 2 parentId O, discouraged (uint V8, an ontologyId of this series); 3 ontologyIRI M (utf8, OWL ontology IRI); 4 entityIRI M (utf8); 5 versionIRI O (utf8); 6 label O (utf8, exact rdfs:label or skos:prefLabel).

### 3.10 ST 1201 IMAPB special patterns (first byte; the remaining L - 1 bytes are `00`)

| Meaning | First byte | L = 1 | L = 2 | L = 3 | L = 4 | When the encoder writes it |
|---|---|---|---|---|---|---|
| +infinity | `C8` | `C8` | `C8 00` | `C8 00 00` | `C8 00 00 00` | f64 +inf in lenient mode, or explicit special (D-15, D-16) |
| -infinity | `E8` | `E8` | `E8 00` | `E8 00 00` | `E8 00 00 00` | same |
| NaN (+quiet, id 0) | `D0` | `D0` | `D0 00` | `D0 00 00` | `D0 00 00 00` | any NaN in lenient mode, or explicit special |
| IMAP_BELOW_MINIMUM | `E0` | `E0` | `E0 00` | `E0 00 00` | `E0 00 00 00` | measured value below range, ST 0903 items only (rule 072) |
| IMAP_ABOVE_MAXIMUM | `E1` | `E1` | `E1 00` | `E1 00 00` | `E1 00 00 00` | measured value above range, ST 0903 items only |
| ST 0903 "Invalid" (user defined) | `C1` | `C1` | `C1 00` | `C1 00 00` | `C1 00 00 00` | explicit Invalid (rule 073) |
| -QNaN, +SNaN, -SNaN | `F0`, `D8`, `F8` | | | | | explicit special only |
| x = b with b - a a power of two | `80` | `80` | `80 00` | `80 00 00` | `80 00 00 00` | normal value, not special (rule 148) |

Forward mapping in code form (ST 1201.5 7.1.2 and 7.2.1; f64 throughout, D-28):

```
bPow = ceil_log2_exact(b - a)            // from the f64 bits, D-27
dPow = 8*L - 1
sF   = 2^(dPow - bPow)                   // exact power of two
Z    = (a < 0 && b > 0) ? sF*a - floor(sF*a) : 0
encode(x):
  if x is NaN or +-inf  -> special (strict: error unless passed as an explicit special)
  if x == -0.0          -> x = +0.0
  if x < a              -> E0 00.. (if the item allows it, else error)
  if x > b              -> E1 00.. (if the item allows it, else error)
  y = floor(sF*(x - a) + Z)              // = truncate, argument >= 0
  write y as L big-endian bytes          // y <= 2^dPow by construction
```

Length from precision (IMAPA, ST 1201.5 7.1.1): `Lbits = ceil_log2(b - a) - floor_log2(g) + 1`, `L = ceil(Lbits / 8)`, exact exponents. Verified values: IMAPA(-900, 19000, 0.5) = 3; IMAPA(0, 100, 1e-5) = 4; IMAPA(0, 1, 1e-5) = 3; IMAPA(0, 100, 0.1) = 2; IMAPA(0, 100, 1) = 1; IMAPA(0, 100, 0.001) = 3; IMAPA(-1, 1, 1e-4) = 2; IMAPA(0, 180, 0.01) = 2; IMAPA(0, 1e6, 1e-6) = 6.

### 3.11 ST 1204 MIIS Core Identifier, binary form (VMTI item 13)

| Offset | Field | Bytes | Value written |
|---|---|---|---|
| 0 | Version | 1 (BER-OID of 1) | `01` |
| 1 | Usage Value | 1 | `0 SS PP W M 0` (bit 7 to bit 0), see below |
| 2 | Sensor ID | 16 | present iff SS != 00 |
| next | Platform ID | 16 | present iff PP != 00 |
| next | Window ID | 16 | present iff W = 1 |
| 2 | Minor ID | 16 | present iff M = 1, and then nothing else |

SS, PP: `11` Physical, `10` Virtual, `01` Managed, `00` None. The encoder computes the usage byte from the identifiers it is given and never accepts a usage byte and identifiers separately (D-29). No check value in the binary form.

| Combination | Usage | Length | Verified example (ST 1204.3) |
|---|---|---|---|
| Physical sensor + Virtual platform | `70` | 34 | `01 70 F592F02373364AF8AA9162C00F2EB2DA 16B74341000841A0BE365B5AB96A3645` -> `0170:F592-...-3645:D3` |
| Physical + Physical | `78` | 34 | Appendix E4 |
| Virtual + Virtual + Window | `54` | 50 | Appendix E1 |
| Virtual sensor only | `40` | 18 | Appendix E6 |
| Window only | `04` | 18 | Appendix E9 |
| Minor only | `02` | 18 | `01 02 03DD9DEEFB48477B8204B0506F6B2A33` -> `0102:03DD-...-2A33:25` |

VMTI item 13 TLVs (verified through the decoder): `0D 22 01 70 F5 92 F0 23 73 36 4A F8 AA 91 62 C0 0F 2E B2 DA 16 B7 43 41 00 08 41 A0 BE 36 5B 5A B9 6A 36 45` and `0D 12 01 02 03 DD 9D EE FB 48 47 7B 82 04 B0 50 6F 6B 2A 33`.

### 3.12 Verified examples

All of these were built by the reference encoder of Appendix B, wrapped in a complete ST 0601 packet (key, BER length, tag 2 = 1700000000000000, the items, tag 65 = 19, checksum), decoded with `misb::decode`, and every decoded value was asserted; every packet decoded with `Packet::is_ok()` true and no `Invalid` or `OutOfRange` value except where noted.

**A. Minimal security set (tag 48 value, 28 bytes)**: UNCLASSIFIED//, GENC Three Letter, `//USA`, object `USA`, version 12.
```
01 01 01  02 01 0E  03 05 2F 2F 55 53 41  0C 01 0E  0D 06 00 55 00 53 00 41  16 02 00 0C
```
As a full ST 0601 packet (64 bytes):
```
06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 2F 02 08 00 06 0A 24 18 1E 40 00
30 1C 01 01 01 02 01 0E 03 05 2F 2F 55 53 41 0C 01 0E 0D 06 00 55 00 53 00 41 16 02 00 0C
41 01 13 01 02 94 29
```
The same encoder reproduces the published ST 0902.8 Annex C tag 48 byte for byte (1059 Three Letter, version 10): `30 1C 01 01 01 02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00 55 00 53 00 41 16 02 00 0A`.

**B. Security set with context and optional items (99 bytes)**: SECRET//, caveats `REL TO`, releasing `USA CAN GBR`, classified by, declassification 20451231, objects `CAN;USA`, version dates.
```
01 01 04 02 01 0E 03 05 2F 2F 55 53 41 05 06 52 45 4C 20 54 4F 06 0B 55 53 41 20 43 41 4E
20 47 42 52 07 06 53 43 47 20 30 31 0A 08 32 30 34 35 31 32 33 31 0C 01 0E 0D 0E 00 43 00
41 00 4E 00 3B 00 55 00 53 00 41 16 02 00 0C 17 0A 32 30 31 36 2D 30 37 2D 30 38 18 0A 32
30 31 36 2D 30 37 2D 30 38
```

**B2. Security set with tags 4, 8, 9, 11, 14 and GENC AdminSub objects (125 bytes)**:
```
01 01 03 02 01 0D 03 04 2F 2F 47 42 04 09 41 42 43 2F 44 45 46 2F 2F 08 10 4D 75 6C 74 69
70 6C 65 20 53 6F 75 72 63 65 73 09 06 31 2E 34 28 63 29 0B 16 45 78 61 6D 70 6C 65 20 4D
61 72 6B 69 6E 67 20 53 79 73 74 65 6D 0C 01 40 0D 16 00 55 00 53 00 2D 00 56 00 41 00 3B
00 55 00 53 00 2D 00 4D 00 44 0E 13 53 79 6E 74 68 65 74 69 63 20 74 65 73 74 20 64 61 74
61 16 02 00 0C
```

**C. Minimal VMTI with one target (tag 74 value, 22 bytes)**: version 6, one reported target, frame width 1920, target 1 with centroid 409600 and Active-Moving.
```
04 01 06  06 01 01  08 02 07 80  65 0A | 09 01 | 01 03 06 40 00 | 17 01 01
```
Full ST 0601 packet with tags 23, 24 (from ST 0902.8), the tag 48 of example A and this tag 74 (100 bytes):
```
06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 53 02 08 00 06 0A 24 18 1E 40 00 17 04 F1
01 A2 29 18 04 14 BC 08 2B 30 1C 01 01 01 02 01 0E 03 05 2F 2F 55 53 41 0C 01 0E 0D 06 00
55 00 53 00 41 16 02 00 0C 4A 16 04 01 06 06 01 01 08 02 07 80 65 0A 09 01 01 03 06 40 00
17 01 01 41 01 13 01 02 D9 E1
```

**D. Full VMTI (552 bytes)**, VMTI-MI different from user-MI (so items 10 to 13 present), two targets, one algorithm, two ontologies. Breakdown:

| Bytes | Meaning |
|---|---|
| `03 0E 44 53 54 4F 5F 41 44 53 53 5F 56 4D 54 49` | item 3 `DSTO_ADSS_VMTI` (ST 0903.6 example) |
| `04 01 06` `05 01 1C` `06 01 02` | version 6, total 28, reported 2 |
| `08 02 07 80` `09 02 04 38` | 1920 x 1080 |
| `0A 07 45 4F 20 4E 6F 73 65` | item 10 `EO Nose` |
| `0B 02 06 40` `0C 02 05 00` | FOV 12.5 x 10.0 deg |
| `0D 22 01 70 F5 ... 36 45` | item 13, ST 1204.3 section 7.4.1 example |
| `65 81 DD` | item 101, 221 bytes (BER long form) |
| `39 01` | element 1: 57 bytes, targetId 1 |
| `01 03 06 40 00` `04 01 01` `05 01 50` `08 03 DA A5 20` | centroid 409600, priority 1, confidence 80, colour goldenrod |
| `0A 03 3A 66 67` `0B 03 3E 66 67` `0C 02 2A 94` | offsets 10.0, 12.0 deg, HAE 10000 m |
| `16 01 09` `17 01 01` | algorithmId 9, Active-Moving |
| `6B 12 11 03 01 0A 04 02 5A 00 05 08 07 03 01 0B 04 02 50 00` | vObjectSeries: ontology 10 at 90.0 %, feature ontology 11 at 80.0 % |
| `81 A1 89 52` | element 2: 161 bytes, targetId 1234 |
| `11 16 40 66 66 66 19 C0 00 00 03 A2 01 40 01 40 02 80 60 00 40 00 40 00` | targetLocation 38.8, -77.0, 30 m, sigma 10, 10, 20 m, rho 0.5, 0, 0 |
| `13 02 03 68` `14 02 04 71` `17 01 03` | centroid row 872, column 1137, Active-Stopped |
| `65 19 01 09 02 39 AA 02 39 BF 02 3B 0B 02 0C 03 01 4A 02 03 01 59 04 03 01 6A 02` | vMask: contour and bit mask (ST 0903.6 examples) |
| `68 34 01 10 F8 1D 4F AE 7D EC 11 D0 A7 65 00 A0 C9 1E 6B F6 03 08 00 03 82 44 30 F6 CE 40 04 08 00 03 82 44 31 15 52 C0 07 01 32 0A 06 38 E0 37 F0 38 40 0C 01 09` | vTracker: trackId, first and latest time, confidence 50, velocity (10, -5, 0) m/s, algorithmId 9 |
| `69 29 01 03 70 6E 67 02 22 68 74 ... 70 6E 67` | vChip: `png`, IRI `https://example.com/chips/1234.png` |
| `66 2C 2B 01 01 09 02 14 6B 36 ... 05 01 0A` | algorithmSeries: id 9, `k6_yolo_9000_tracker`, `2.6a`, `kalmann`, 10 frames (ST 0903.6 examples) |
| `67 81 C1 5F 01 01 0A 03 27 ... 06 03 63 61 72 60 01 01 0B ...` | ontologySeries: id 10 envo `car`; id 11 feature ontology `Antenna` |

**E. Out-of-range and Invalid signals (32 bytes)**: target 5 with lat offset Invalid, lon offset above maximum, Location latitude Invalid.
```
04 01 06 06 01 01 65 18 17 05 0A 03 C1 00 00 0B 03 E1 00 00 11 0A C1 00 00 00 2D 40 00 00 03 84
```
The decoder reports all three as `Value::OutOfRange` (it does not tell the Invalid signal from the range signals, U-08).

**F. Coverage of the remaining VTarget, VTracker, VChip and Ontology items (785 bytes)**: VMTI item 2 present and first (time differs from the parent); target 7 with bounding box 2 and 3, history 2765, percentage 50, intensity 13140, bounding box offsets 13 to 16, geospatialContourSeries of two vertices, Active-Coasting, a VTracker with trackBoundarySeries, trackHistorySeries (10-byte and 16-byte Location elements), velocity with sigmas (12 bytes) and acceleration with sigmas and rhos (18 bytes), and a vChipSeries of an embedded 200-byte PNG (item 3 with BER long length `81 C8`) and a JPEG IRI; target 8 with a 10-byte targetLocation and Inactive; an Ontology LS with parentId and versionIRI. All decoded as written. It also shows truncation: an acceleration east of 0.1 m/s^2 decodes as 0.0625 and north of -0.2 as -0.25 (LSB 1/16).

**G. No targets (6 bytes)**: `04 01 06 06 01 00`.

**Item-level ST 0903.6 examples reproduced exactly**: `06 02 0A CD`, `07 01 32`, `09 02 33 54`, `13 02 03 68`, `14 02 04 71`, `01 03 06 40 00`, `04 01 1B`, `05 01 50`, VMTI `05 01 1C`, `06 01 0E`, `04 01 06`, `02 08 00 03 82 44 30 F6 CE 40`, Algorithm `01 01 09`, `05 01 0A`, VChip `01 04 6A 70 65 67`, VMask `01 09 02 39 AA 02 39 BF 02 3B 0B`, `0C 02 2A 94`.

**IMAPB vectors (forward mapped, then decoded by `misb::imapb::decode`)**:

| Mapping | x | y | decodes to |
|---|---|---|---|
| IMAPB(0, 180, 2) | 12.5 / 10.0 / 180.0 | `0640` / `0500` / `5A00` | 12.5 / 10.0 / 180.0 |
| IMAPB(-19.2, 19.2, 3) | 10.0 / 12.0 / 0.0 | `3A6667` / `3E6667` / `266667` | 10.0 / 12.0 / 0.0 |
| IMAPB(-19.2, 19.2, 3) | 19.2 / -19.2 | `4CCCCD` / `000000` | 19.199996948242188 / -19.20000457763672 |
| IMAPB(-900, 19000, 2) | 10000 / 19000 | `2A94` / `4DBC` | exact |
| IMAPB(-90, 90, 4) | 90 / 38.8 | `5A000000` / `40666666` | 90 / 38.799999952316284 |
| IMAPB(-180, 180, 4) | 180 / -77 | `5A000000` / `19C00000` | exact |
| IMAPB(0, 650, 2) | 650 | `5140` | 650 |
| IMAPB(-1, 1, 2) | 1.0 / 0.5 | `8000` / `6000` | exact |
| IMAPB(-900, 900, 2) | 900 / 0 | `7080` / `3840` | exact |
| IMAPB(0, 100, 1) | 100 / 37.5 | `64` / `25` | 100 / 37 |
| IMAPB(0, 100, 2) | 100 / 90 | `6400` / `5A00` | exact |
| IMAPB(0, 100, 3) | 100 | `640000` | 100 |
| ST 1201.5 Example 3, IMAPB(-900, 19000, 3) | 10 / 0 | `038E00` / `038400` | exact |
| ST 1201.5 Example 4, IMAPB(0.1, 0.9, 2) | 0.5 / 0.9 | `3333` / `6666` | 0.499993896484375 / 0.89998779296875 |
| ST 1201.5 Test 1, IMAPB(0, 100, 4) | 10.1 / 100 | `0A199999` / `64000000` | 10.099999964237213 / 100 |
| ST 1201.5 Test 2, IMAPB(0, 100, 3) | 20.2 | `143333` | 20.199996948242188 |
| ST 1201.5 Test 3, IMAPB(-9.9, 110, 3) | -9.9 / 0 / 0.225 / 101.475 / 110 | `000000` / `09E667` / `0A2000` / `6F6000` / `77E667` | -9.900009155273438 / 0 / 0.2249908447265625 / 101.47499084472656 / 110 |

-0.0 encodes exactly as +0.0 (checked for IMAPB(-19.2, 19.2, 3) and IMAPB(0, 180, 2)). Every special pattern of 3.10 with L = 1 to 4 is classified by `misb::imapb::special` as the intended kind; `E1 00` decodes as `OutOfRange` and `C8 00` as +infinity.

## 4. Decisions

Each decision states what the encoder does, why, and the source. "Standard silent" marks a choice the official texts do not make.

**D-01 Item order inside every nested set: ascending tag number.** Standard silent beyond VMTI item 2 first (rule 054): SMPTE ST 336 section 7.4 lets items come in any order (rule 022), ST 0102.12 and ST 0903.6 say nothing, and ST 0903.6 Figure 13 itself places item 4 after item 103. Ascending order is deterministic (property tests compare bytes), matches the published ST 0902.8 Annex C tag 48 (tags 1, 2, 3, 12, 13, 22) and jMISB (TreeMap by tag in every set). Applies to the ST 0102 set, the VMTI LS (2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 101, 102, 103), every VTarget Pack and every nested set. Re-encoding a decoded packet keeps the received order and bytes (D-33).

**D-02 Order of Series elements.** vTargetSeries: ascending targetId; algorithmSeries: ascending algorithmId; ontologySeries: ascending ontologyId (standard silent, "element order is not important", rule 068; deterministic output). vObjectSeries, vFeatureSeries, vChipSeries: caller order, except that the chip from the VMTI-MI frame is first in a vChipSeries (rule 103). trackHistorySeries: chronological (rule 125). BoundarySeries and pixelContour: the caller's vertex order, unchanged, because the order defines the polygon (pixelContour must be clockwise, rule 120; ST 0903.6 dropped the old vertex-order rule ST 0903.4-54 for BoundarySeries, so the encoder only checks the count and, for two vertices, the box rule).

**D-03 ST 0102 Version (tag 22) = 12.** The builder always writes `16 02 00 0C`, because it implements ST 0102.12 and Table 2 defines the value as the document version (rule 042). jMISB writes 12 too. Strict mode rejects a caller-supplied other value (the content rules of other versions differ, e.g. tag 13 was 8-bit text before 0102.10); re-encoding a decoded packet keeps its received version bytes.

**D-04 Tag 13 is UTF-16BE without a byte order mark.** ST 0102.12 only says "RFC 2781" (rule 040); RFC 2781 reads unlabelled UTF-16 without a BOM as big-endian (RFC not in `specs/src`), the published ST 0902.8 example writes `00 55 00 53 00 41` for `USA`, and jMISB writes UTF-16BE without BOM. Characters outside the BMP are written as surrogate pairs (never needed for code lists). The misb-rs decoder also accepts a BOM, little-endian and legacy 8-bit text; the encoder never produces them.

**D-05 ISO/IEC 646 text = printable ASCII.** Standard gives the type (ISO/IEC 646, rule 045) but no repertoire detail. The encoder accepts `0x20` to `0x7E` and rejects anything else in every mode (no silent replacement in security markings; jMISB silently turns non-ASCII into `?`). Leading or trailing blanks are rejected too (they would change how automated screening parses tag 6).

**D-06 Zero-length items.** Inside the ST 0102 set and inside the VMTI LS the encoder never writes a ZLI: neither standard declares Report-on-Change (rule 018), every tag 48 instance is complete (D-07), and an absent VMTI item already means "not reported". Mandatory items can never be ZLI (rule 017). At the ST 0601 level, ST 0601.19 6.5 permits a ZLI for tags 48 and 74 and ST 0107 discourages it (rule 007): the encoder refuses a ZLI for tag 48 in every mode (a security marking that becomes "unknown" helps nobody, ST 0102.10-55 asks for every frame to be marked, and section 6.5 says absence does not mean unclassified); for tag 74 it writes `4A 00` only on an explicit `unknown(VmtiLocalSet)` call. To say "no targets now", send a VMTI LS with numTargetsReported = 0 (D-13) rather than a ZLI.

**D-07 Completeness of tag 48 and no content defaults.** Every tag 48 value carries all six Required items (1, 2, 3, 12, 13, 22) plus every Context item that applies; there is no partial or delta update (ST 0601 Report-on-Change works per ST 0601 item, and tag 48 is one item). The builder has no defaults for classification, countries or coding methods (jMISB silently defaults tags 2 and 12 to GENC Two Letter; a wrong default in a security marking is worse than an error); only tag 22 is filled in automatically. ST 0102.12 section 6.4 lets a security official waive elements (rule 048): an explicit `allow_partial_security` option then permits leaving out tags 2, 3, 12 and 13 with a warning, but tag 1 (classification) and tag 22 are still required.

**D-08 Security repetition default: tag 48 in every ST 0601 packet.** ST 0102 requires at least every 30 s and on every change (rule 046) and notes that short clips may need it in every frame; ST 0902.8 Annex A (informative) recommends every 10 s; ST 0601 receivers forget an item after 30 s (ST 0601.19 6.5). A minimal set costs 30 bytes. `misb::mux` therefore puts tag 48 in every packet by default; a configurable period is accepted only up to 30 s (larger is rejected), and any change of the security content forces tag 48 into the next packet. The conformance checker flags gaps above 30 s.

**D-09 Validation of country codes.** Structural rules are errors in strict mode: tag 3 starts with `//` and has at least one code character after it; tag 6 uses single `0x20` separators with no leading, trailing or doubled blanks; tag 13 uses `;` with no spaces and no empty entries; tag 4 ends with `//` and has no empty `/` entries; dates are real calendar dates in the exact format. The shape of each code per method (section 3.4) is a warning only: the code lists themselves (ISO 3166, GENC, STANAG 1059, FIPS 10-4 / GEC) are not in `specs/src` and the standard defers to them (standard silent on exact syntax, U-05). Under a Mixed method, tag 6 (and tag 3) may mix one width of di/tri-graphs with tetragraphs (rule 035); the encoder warns when both widths appear.

**D-10 VMTI version item = 6.** The builder writes `04 01 06` in every VMTI LS (rule 058; the ST 0903.6 example is `0x06`). jMISB writes 5 (it implements 0903.5), which is a known deviation (Appendix A). Version 0 to 5 are never written by the builder.

**D-11 VMTI item 2 (precisionTimeStamp).** The builder takes the VMTI-MI timestamp as input. If it equals ST 0601 tag 2 of the packet (exact microseconds) the item is left out by default, as section 8.4 allows (rule 053), saving 10 bytes; an option `always_write_vmti_time` writes it anyway. If it differs, item 2 is written, first. If the difference exceeds two VMTI-MI frame periods, offset items are refused (rule 056); the builder needs the frame period for that test and, when the caller does not give one, refuses offset items whenever the times differ at all (conservative).

**D-12 Items 5 and 6.** Item 6 = number of VTarget Packs written in item 101 (rule 060; section 10.1.5 contrasts item 5 with "the number of elements in the vTargetSeries", which identifies item 6 with that count). A caller-supplied item 6 that differs is rejected in strict mode. Item 5 (size of the full target list) is written only when the caller supplies it and it differs from item 6 (rule 059); it must not be smaller than item 6 (strict error, standard silent but a reported subset cannot exceed the list). Standard silent on writing item 5 when equal; leaving it out saves bytes and loses nothing because ST 0903.4-18 only requires it when different.

**D-13 No targets.** A VMTI LS without targets is `04 01 06 06 01 00` (plus any other items the caller sets); item 101 is left out, never written empty or as a ZLI. Standard silent on an empty Series; a zero-length item 101 would read as "unknown" under ST 0107.

**D-14 Lengths.** Integers: fewest bytes (rule 015); fixed-length integers at their size (targetColor 3, uint8 items 1, times 8, version of ST 0102 2). IMAPB items with a single table length (VMTI 11, 12: 2; VTarget 10, 11, 13 to 16: 3; VTarget 12: 2; every Location, Velocity, Acceleration field) are always written at that length (rule 076): ST 1201.5 7.4 would allow another length, but the packs are Defined Length Packs and receivers such as jMISB reject other lengths for the fixed items (`specs/tables/st0903.md` 5.4). VObject and VFeature confidence ("IMAP V3", minimum 1): length from IMAPA(0, 100, g) with a configurable precision g, default g = 0.1 percent (the "0.0% to 100.0%" notation of sections 10.4.4 and 10.5.4), giving L = 2 (one LSB = 0.0039 percent); g must give L = 1 to 3, else error. Standard silent on the default precision.

**D-15 Out-of-range values and special values in the API.** ST 0903 IMAPB fields take a value of type `Imap` = `Value(f64)` | `BelowMinimum` | `AboveMaximum` | `Invalid` | `Special(kind)`. A plain `f64` outside the range is an error in strict mode (it usually means a units bug); with the option `out_of_range = Signal` it becomes `E0`/`E1` as ST 0903.6 section 9.1.1 prescribes (rule 072). The encoder never clamps a VMTI value into range: clamping would report a measured value as in range, the opposite of 9.1.1. A plain `f64` NaN or infinity is an error in strict mode and maps to `D0`/`C8`/`E8` in lenient mode; `Special` writes any Table 2 pattern explicitly. For other standards' IMAPB items (not in this topic) the invoking standard decides (rule 146).

**D-16 NaN pattern.** Any NaN, whatever its sign or payload, is written as `D0 00..` (positive quiet NaN, identifier 0), the only NaN identifier ST 1201.5 defines and the value of its test vectors; Rust f64 operations do not preserve signalling NaNs reliably. jMISB does the same; cbrl/klv keeps the sign (`F0` for negative NaN). Other NaN patterns only through `Special`.

**D-17 Pairs and groups inside a VTarget (strict mode).** Required together: 19 and 20 (rule 086, normative); 2 and 3 (a pixel bounding box needs both corners, rule 088); 10 and 11 (an offset location is a latitude-longitude pair, section 10.2.2.11); 13, 14, 15 and 16 (the four values of one geospatial box). Only 19/20 is a "shall"; the others are standard silent and enforced because a receiver cannot use half of them. Lenient mode warns instead.

**D-18 Computing offsets.** Offsets are relative to the frame centre value the receiver will decode from tags 23 and 24 of the same packet, i.e. the quantised ST 0601 value, not the unquantised input; otherwise the tag 23/24 quantisation error (one LSB is about 4.2e-8 deg of latitude, 8.4e-8 deg of longitude) would be added to the offset error. Longitude offsets are normalised to (-180, 180] so a target across the antimeridian from the frame centre gets a small offset; receivers wrap the sum (standard silent). An offset outside [-19.2, 19.2] follows D-15 (error, or `E0`/`E1` with the Signal option); the builder suggests targetLocation instead (rule 097).

**D-19 "Associated Location" for Velocity and Acceleration.** ST 0903.4-82 and -92 require one (rules 112, 113) but do not say where. The encoder accepts either VTarget item 17 (targetLocation) in the same VTarget Pack or a non-empty trackHistorySeries (VTracker 9) in the same VTracker, whose last point is the latest observation. Standard silent on which (U-07).

**D-20 targetId range.** 0 to 2^63 - 1 (BER-OID of at most 9 bytes, rule 082). 0 is allowed (standard silent; jMISB allows 0) but the state layer starts new ids at 1 and counts up, never reusing an id (rule 083), including across restarts when the caller persists the counter. With 63 bits an id counter never wraps in practice.

**D-21 VChip.** One chip -> item 105; two or more -> item 106; never both (rule 103). Each VChip carries imageType (`jpeg` or `png`, exact lower case) and at least one of imageIRI and embeddedImage (standard silent on requiring one, but a chip with neither carries no image). Strict mode checks that embedded bytes start with the JPEG (`FF D8 FF`) or PNG (`89 50 4E 47 0D 0A 1A 0A`) signature matching imageType (rule 126) and that imageIRI is a syntactically valid absolute IRI (scheme, no spaces or control characters). The image bytes are written as given, never re-encoded (jMISB re-encodes every chip as PNG regardless of imageType).

**D-22 VObject and VFeature carry both label and confidence.** Section 7.3 describes every object prediction as a label plus a confidence and every feature as a label with a confidence (rule 124); the tables mark neither item mandatory. Strict mode requires items 3 and 4 in each VObject and each VFeature; lenient mode warns.

**D-23 No empty nested sets or series.** The encoder refuses an empty VMask, VTracker, VObject, VFeature, VChip, Algorithm LS or Ontology LS, an empty trackHistorySeries, and any Series without elements (standard silent; an empty element is not a value; misb-rs reports an empty Series element as Invalid).

**D-24 Bit mask runs.** ST 0903.5-101 literally says "starting pixel number plus run-length shall be less than the line length", which cannot hold for pixel numbers past the first row (pixel numbers are row-major over the whole frame). The encoder reads it as "a run does not cross the end of its row": with column = ((pixel - 1) mod frameWidth) + 1, require column + run - 1 <= frameWidth, and run >= 1. Recorded as U-04.

**D-25 References are resolved inside one VMTI LS.** Ids may be reused differently in the next packet (rule 130), so a reference only means something against the series of the same tag 74 value. Strict mode rejects a VTarget 22, VTracker 12, VObject 3 or VFeature 3 value with no matching element in item 102 or 103 of the same VMTI LS, and an Ontology parentId with no matching ontologyId. The state layer re-sends the referenced Algorithm and Ontology LSs in every VMTI LS that refers to them.

**D-26 Size limits.** ST 0601 sets no maximum for tags 48 and 74 and ST 0903 none for any item (rule 006, ST 0903.6 9.2). The encoder by default keeps every packet decodable by misb-rs with its default `Config`: whole ST 0601 packet at most 1,048,576 bytes (`max_packet_bytes`), at most 65,536 items in total across all nested sets (`max_total_items`) and at most 65,536 per set or Series (`max_items`); nesting depth is fixed by the structure (deepest set at level 4 with ST 0601 at 0, below the default `max_depth` 8). These limits are configurable. Fixed limits from the standards: strings (item 3 at most 32 characters, item 10 at most 128 characters), counts (items 5 and 6 at most 16,777,215, so at most that many VTarget Packs), ids (targetId 9 bytes, algorithm and ontology ids 8 bytes, VTarget 22 3 bytes), pixel numbers 6 bytes, row/column 4 bytes. MPEG-TS carriage of a large packet (AU cell fragmentation above 65,535 bytes) belongs to the carriage topic. Bandwidth guidance (ST 0903.6 Appendix B.1) is the caller's concern.

**D-27 Exact base-2 exponents.** bPow = ceil(log2(b - a)) and the IMAPA exponents are computed from the f64 exponent and mantissa bits (as `misb::imapb::ceil_log2` already does), never with `f64::log2`. jMISB uses `Math.log(x)/Math.log(2)` and gets bPow wrong for spans that are exact powers of two such as 2^29 (Appendix A); none of the ST 0903 ranges is affected, but other standards' ranges might be.

**D-28 Arithmetic, and the round-trip tolerance.** The forward mapping is evaluated in f64 exactly as ST 1201.5 writes it, `floor(sF * (x - a) + Zoffset)`; this reproduces every ST 1201.5 and ST 0903.6 vector, including Test 3 (110.0 -> `77E667`), and `misb::imapb::Imapb::real_to_int` already implements it. Because the mapping truncates (rule 150), decode(encode(x)) lies in (x - sR, x], so the property test bound in the muxing plan, section 6.1 ("within half an LSB") is wrong for IMAPB fields: use 0 <= x - decode(encode(x)) < sR, plus a few ulps of f64 slack (the range minimum itself decodes up to one LSB below a when Zoffset is not 0, e.g. -19.2 -> -19.20000457763672). For L of 7 or 8 bytes f64 has fewer significant bits than the integer; this does not affect ST 0903 (at most 4 bytes) and is what the formula gives.

**D-29 ST 1204 encoding.** The builder takes the identifiers (sensor with type, platform with type, window, or minor) and derives the usage byte and the UUID order itself (rules 161, 163); a usage byte is never accepted separately (jMISB derives bits and bytes independently and can emit bytes that the usage byte does not announce). Version byte `01` always (jMISB defaults to 0). Strict mode rejects: no identifier; minor with any foundational identifier (rule 164); a nil UUID (rule 166); a UUID whose version nibble (high nibble of byte 6) is not 1, 4 or 5 or whose variant bits (top two bits of byte 8) are not `10` (rule 165). Lenient mode warns on the version and variant checks only.

**D-30 VMTI-MI versus user-MI.** The VMTI builder takes `vmti_mi_is_user_mi: bool`. When false, items 11, 12 and 13 are required (rules 065, 066) and item 10 is recommended (warning when absent). When true they may be left out and the parent's tags 16, 17 and 94 are the reference.

**D-31 Frame centre in the parent packet.** Strict mode requires tags 23 and 24 in every ST 0601 packet that carries tag 74 (ST 0903.6 Table 6 marks them Required, rule 008) and always when any VTarget uses an offset item; lenient mode requires them only for offsets. This check belongs to the ST 0601 packet builder, which sees both levels.

**D-32 utf8 cleaning.** Strict mode rejects utf8 values that break rules 020 and 021 (leading/trailing whitespace or forbidden control characters); lenient mode trims and removes them and records a warning. Limits are counted in Unicode scalar values (characters), and the byte length follows (at most 4 bytes per character).

**D-33 Re-encoding decoded packets.** `encode_packet` copies items whose value was not changed from `Item::raw`, so deprecated items, legacy versions, padding and the order of a received set survive byte for byte. Builders never create deprecated items (VMTI 7, VTarget 21, 102, 103, VObject 1, 2, VFeature 1, 2, VTracker 2, 6, 8; ST 0102 tags 15 to 21). Note for the property tests: the decoder turns the Invalid signal (`C1..`) and both range signals (`E0..`, `E1..`) into the same `Value::OutOfRange` (U-08), so a value-level round trip of those three must compare raw bytes.

**D-34 Classifying country under a Mixed method.** Tag 3 may hold a di/tri-graph of the method's source or an approved tetragraph (rule 035). The encoder accepts either shape (warning only, D-09).

**D-35 GENC AdminSub.** Allowed in tag 12 only (`40`). Consumers are only required to understand the country part of such codes (ST 0102.10-62), so the builder warns when tag 13 contains only AdminSub codes and suggests also including the plain country code under the frame centre (rule 039).

**D-36 Standalone sets.** Out of scope for this phase (section 3.1 lists what would differ). The builders are written so a later `standalone` mode adds the key, the length and, for VMTI, the checksum and the standalone presence rules (rule 104).

**D-37 VTracker consistency.** firstObsvTime must not be after latestObsvTime (strict error; standard silent). No VTracker item is mandatory; trackId is recommended.

**D-38 Location packs need a full coordinate triplet.** Latitude, longitude and HAE are all required (rule 111); an unknown HAE cannot be filled with NaN, zero or the Invalid signal (rule 110). If the caller has no HAE the targetLocation is not written (offsets or pixel items can still describe the target).

**D-39 Dropped targets.** ST 0903.6 says the target list does not contain Dropped targets (rule 106), yet Table 5 defines the value 2. By default `misb::state` stops reporting a target when it is dropped and retires its id; an option `report_drop_once` sends one last VTarget with detectionStatus = 2 so receivers can discard it at once, and then retires the id (U-10). detectionStatus itself is optional in the KLV but `misb::state` writes it for every reported target, because the 0903.6 lifecycle and rule 085 depend on it.

**D-40 Where each check runs.** Every strict check of this document is in `misb::encode` at build time (errors name the rule id). The conformance checker re-runs the stream-level ones on any input: rules 006, 012, 015, 017, 025 to 030, 038, 039, 042, 046, 050 to 054, 058, 060, 062, 067, 081, 082, 085, 086, 110 to 114, 126, 127, 128, 160 to 164.

## 5. Unresolved

| Id | Item | Why it is open | What the encoder does meanwhile |
|---|---|---|---|
| U-01 | ST 0903.6 section 9.2 says the VMTI LS uses "byte 6 = 0x2B", which SMPTE ST 336 Table 5 defines as a 1-byte length field with BER-OID tags. | Contradicts the VMTI key printed in section 10.1 (byte 6 = `0x0B`: BER length, BER-OID tags) and the sentence's own "BER short/long lengths". Looks like a typo; no erratum found. | BER lengths, as the key says (rule 050). No effect on bytes for items shorter than 128 bytes; long items need BER long form, which only `0x0B` allows. |
| U-02 | VTracker item 12 algorithmId is "uint V" with no maximum. | Table 14 gives no bound; the Algorithm LS ids it refers to are V8. | Fewest bytes, at most 8 (u64). |
| U-03 | Maximum size of one VMask pixelContour point. | Table 11 says "Array ... unsigned integer numbers" without a size. | Same as targetCentroid: at most 6 bytes (1 to 2^48 - 1), the decoder's limit too. |
| U-04 | ST 0903.5-101 wording (pixel + run < line length). | Literal reading is impossible beyond the first row. | D-24 (run must not cross its row end). |
| U-05 | Exact syntax of codes per coding method (FIPS 10-4 four-letter codes, GENC AdminSub codes, CAPCO tetragraph list). | Defined by external registers that are not in `specs/src` (FIPS 10-4 / GEC, GENC, ISO 3166-2, CAPCO Annex F). | Shape checks are warnings only (D-09, section 3.4). |
| U-06 | ST 0903.6 Appendix C invokes ST 0107.5; only ST 0107.4 is available. | ST 0107.5 (21 October 2021) could not be obtained (`specs/tables/misc.md`). | Rules 012 to 021 are taken from ST 0107.4; the "fewest bytes" requirement Appendix C attributes to ST 0107.5 is the same as ST 0107.3-10 in 0107.4. Re-check when 0107.5 is available. |
| U-07 | What "associated Location pack" means for Velocity and Acceleration (ST 0903.4-82, -92). | Not defined in ST 0903.6. | D-19 (VTarget 17 or a non-empty trackHistorySeries in the same VTarget Pack). |
| U-08 | The misb-rs decoder maps the ST 0903 Invalid signal (`C1 00..`), IMAP_BELOW_MINIMUM and IMAP_ABOVE_MAXIMUM all to `Value::OutOfRange`. | Read-side design choice; distinguishing them needs a decoder change (out of scope here, misb-rs is read-only for phase 0). | Property tests compare raw bytes for these three (D-33). Phase 1 may add distinct `Value` variants additively. |
| U-09 | Scope of "Required" for Frame Center Latitude/Longitude in ST 0903.6 Table 6. | The table says Required for embedded VMTI, but only offset items need the frame centre. | D-31: strict requires tags 23, 24 whenever tag 74 is present; lenient only with offsets. |
| U-10 | Whether a VTarget with detectionStatus Dropped (2) may be reported. | Section 6 says the target list excludes Dropped targets; Table 5 still defines the value. | D-39: not reported by default; one final report on request. |
| U-11 | targetId 0. | Not forbidden or mentioned. | Allowed; the state layer starts at 1 (D-20). |
| U-12 | Content correctness of security markings (CAPCO, DoD Manual 5200.01, releasability rules ST 0102.11-63, -64). | Outside ST 0102; decided by security officials. | The encoder checks structure and syntax only; the caller supplies the content. |
| U-13 | ST 0903.6 Figures 13 and 14 are not parseable byte streams (Figure 13: "L = 2 0x03 11" for a count that fits one byte, a VTarget series length that does not add up; Figure 14 uses item 5 as the count of packs). | Illustrations, not test vectors. | Not used as vectors; ST 0903.6 per-item examples are used instead (section 3.12). |

## Appendix A. jMISB cross-check (commit ede21c1)

Facts gathered from the jMISB encoders (file:line under `api/src/main/java/org/jmisb/api/klv/`); the official text wins in every case and this document follows it.

| Area | jMISB behaviour | Official text | This document |
|---|---|---|---|
| ST 0102 nested framing | `SecurityMetadataLocalSet.frameMessage(true)` writes only the TLVs, 1-byte tags, minimal BER lengths, ascending tag (`st0102/localset/SecurityMetadataLocalSet.java:81-122`); ST 0601 tag 48 wraps it (`st0601/NestedSecurityMetadata.java:61-62`) | ST 0601.19 6.3.3 | Same (rules 001, 023; D-01) |
| ST 0102 version | Builder defaults tag 22 to 12, 2 bytes (`ST0102Version.java:41-43`) | Table 2 | Same (D-03) |
| ST 0102 defaults | Builder defaults tags 2 and 12 to GENC Two Letter `0x0D` and checks only tags 3 and 13 | Table 2 Required | No content defaults; all six Required items enforced (D-07) |
| ST 0102 empty values | Items with empty bytes are silently dropped (`SecurityMetadataLocalSet.java:91`), so a "required" empty tag 3 disappears | ST 0107.4-16 | Empty required items are errors (rule 017) |
| ST 0102 tag 1 | Can encode `0x00` UNKNOWN (`Classification.java:13-32`) | Table 2: `01` to `05` | Never `00` (rule 025) |
| ST 0102 deleted tags | Tags 19 to 21 still re-emitted after a decode | Deleted in 0102.12 | Builder never writes them (rule 044) |
| ST 0102 strings | `getBytes(US_ASCII)`, non-ASCII silently becomes `?` | ISO/IEC 646 | Rejected (D-05) |
| ST 0102 tag 13 | UTF-16BE, no BOM (`ObjectCountryCodeString.java:48-51`) | RFC 2781 | Same (D-04) |
| VMTI version | Inserts or keeps version 5 (`st0903/VmtiMetadataConstants.java:11`, `VmtiLocalSet.java:261-269`); implements 0903.5 | 0903.6: value 6 (`04 01 06`) | 6 (D-10) |
| VMTI nested framing | Checksum skipped when nested, ascending tag order, item 2 first only because it is the lowest tag (`VmtiLocalSet.java:173-224`) | ST 0903.6-120, ST 0903.4-14 | Same (rules 052, 054) |
| VMTI item 6 | Not computed or added automatically | ST 0903.4-19 | Computed from the series (D-12) |
| VMTI item 7, VTarget 21, 102, 103, VTracker 2, 6, 8, VObject 1, 2, VFeature 1, 2 | Still writable | Deprecated in 0903.6 | Never written by builders (rules 061, 099, 122, 123, 125) |
| VTarget 23, VObject 5, VFeature 3 and 4, Ontology 5 and 6 | Not implemented | 0903.6 items | Implemented |
| VTarget series | `HashMap` by targetId: duplicates overwrite silently, output order is hash order (`VTargetSeries.java:36-48`) | ST 0903.6-126; order free | Duplicates rejected; ascending targetId (D-02) |
| VTarget Pack | No "at least one TLV" check; targetId limited to a Java int (5 BER-OID bytes) | ST 0903.4-10; V9 | Checked; 9 bytes (rules 081, 082) |
| Ids | Algorithm, ontology, parent ids and nFrames limited to 3 bytes (`VmtiV3Value`) | uint V8 | Up to 8 bytes (rules 127, 128) |
| VObject confidence | Always IMAPB(0, 100, 2) (`vobject/Confidence2.java:47-51`) | IMAP V3, length = item length | L from precision, default 2 (D-14) |
| Location / Velocity / Acceleration | Lengths 10/16/22 and 6/12/18 with group truncation, but writes a zero-length TLV when lat/lon/hae is missing; no range check, out-of-range becomes `E0`/`E1` | ST 0903.4-62, -63, -66 | Full triplet required; out-of-range per D-15 |
| bitMaskSeries | Run written as BER length (correct), but jMISB's decoder reads it as BER-OID | Section 10.3.2: BER-Length | BER length (rule 121) |
| VChip | No `jpeg`/`png` check; embedded image always re-encoded as PNG (`vchip/EmbeddedImage.java:49-78`) | ST 0903.6-134 to -136 | Checked; bytes written as given (D-21) |
| Algorithm / Ontology LS | Required items and id uniqueness not checked | ST 0903.5-102 to -108, ST 0903.6-137, -138 | Checked (rules 127, 128) |
| IMAPB forward mapping | `Math.floor(sF*(val - a) + zOffset)` (`st1201/FpEncoder.java:199`) | truncate (7.2.1) | Same (rule 140); identical for in-range input |
| IMAPB bPow | `ceil(Math.log(b-a)/Math.log(2))`; wrong for exact power-of-two spans such as 2^29 | ceiling(log2(b - a)) | Exact exponents (D-27) |
| IMAPA length | `ceil(log2((max-min)/precision) + 1)` bits, then rounds 3 up to 4 and 5..7 up to 8 bytes (`FpEncoder.java:137-152`); IMAPA(0, 1, 1e-5) = 4, spec 3 | ceiling(log2(b-a)) - floor(log2 g) + 1, L = ceiling(Lbits/8) | Spec formula (rule 143) |
| IMAPB specials | +inf `C8`, -inf `E8`, any NaN `D0`, below `E0`, above `E1` (`FpEncoder.java:175-196`); ReservedKind1 with id 0 yields `80 00..`, which is the normal maximum pattern | Tables 2, 3 | Same patterns (rules 144, 145); `80 00..` never written as a special |
| ST 1204 version | Raw byte, defaults to 0 unless set (`st1204/CoreIdentifier.java:61, 447`) | BER-OID, value 1 | `01` always (D-29) |
| ST 1204 usage vs bytes | Usage bits from the declared type, UUID bytes from non-null fields, decided independently; a minor UUID is written even when the usage byte does not announce it (`CoreIdentifier.java:428-466`) | Table 3, EBNF | Usage derived from the identifiers (D-29) |
| ST 1204 check value | Not in the binary form; text form uses the Appendix B P/Q algorithm | Table 5, Appendix B | Same (rule 167) |

cbrl/klv (`include/klv/codecs/imapb.hpp`, `misb1204/core_id_codec.hpp`) agrees with the official text on the points it implements: exact bPow, floor mapping (with clamping to 0..2^dPow), version `01`, usage derived from the identifiers, no binary check value; it keeps the NaN sign (`F0` for negative NaN), unlike D-16.

## Appendix B. Probe used to verify the examples

A throwaway probe project used during phase 0 (not kept): a Cargo project that depends on `misb` by path (`default-features = false`, misb-rs unmodified) and contains a reference encoder of about 150 lines written from this document (BER length, BER-OID, fewest-byte unsigned integers, one-byte-tag TLVs, Series framing, IMAPB via `Imapb::real_to_int`, IMAPA length from exact exponents, UTF-16BE, ST 0601 framing with `misb::checksum::st0601_checksum`). `cargo run` builds examples A to H of section 3.12, decodes each complete ST 0601 packet with `misb::decode`, asserts every decoded value, the IMAPB vectors and specials, the IMAPA lengths, the ST 1204 canonical strings and the target id forms, and ends with `ALL CHECKS PASSED`. The quote list was checked mechanically by `q/locate.py` in the same directory (each quote found within 5 lines of its line number after collapsing whitespace, at most 40 words, no en or em dashes).
