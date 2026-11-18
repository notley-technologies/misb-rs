# Phase 0: MISB ST 0601 encoder rules (`st0601-encode`)

> Phase 0 record. Where this document and [DECISIONS.md](DECISIONS.md) disagree (sections 1 and 3 there), DECISIONS.md wins. Source paths `specs/src/...` refer to the workspace copy of the official documents, which are not redistributed here.

Scope: every rule an ST 0601.19 packet producer (`misb::encode`, the stateful layer in `misb::mux`, and the conformance checker) must follow, with exact byte layouts for every item, the ST 0902 minimum set as the default content profile, and the decisions where the standards are silent. Nested ST 0102 / ST 0903 content, ST 1204 identifiers, ST 0603 time conversion and TS carriage are covered by their own phase 0 documents; this one only fixes how they are framed inside an ST 0601 packet.

## 1. Sources

| Document | Revision, date | Where obtained | Used for |
|---|---|---|---|
| MISB ST 0601 UAS Datalink Local Set | ST 0601.19, 02 March 2023, with the 05/10/2024 and 06/11/2025 corrections listed in its revision history | `specs/src/ST0601.19.txt` (+ `.pdf`); provenance in `specs/tables/st0601-a.md` (Internet Archive capture of the NGA registry S3 object) | Primary source: sections 6, 7, 8 and Appendix A |
| MISB ST 0107 KLV Metadata in Motion Imagery | ST 0107.4, 28 February 2019 | `specs/src/ST0107.4.txt` (+ `.pdf`); provenance in `specs/tables/misc.md` S5 (gwg.nga.mil via Wayback 20200111025555) | Baseline KLV rules (requirements 0107.2-01 to 0107.4-19). ST 0601.19 cites ST 0107.5 (Oct 2021), which could not be obtained (see Unresolved U-01) |
| MISB ST 0902 Motion Imagery Sensor Minimum Metadata Set | ST 0902.8, 1 November 2018 | `specs/src/ST0902.8.txt`; provenance in `specs/tables/st0601-example.md` | Minimum set, rates (Annex A), complete example packets (Annex C) |
| MISB ST 1607 Constructs to Amend/Segment KLV Metadata | ST 1607.2, 2025-06-11 | `specs/src/ST1607.2.txt` (+ `.pdf`); provenance `specs/tables/misc.md` S8 | Segment / Amend rules |
| SMPTE ST 336 Data Encoding Protocol Using KLV | ST 336:2017 | `specs/src/SMPTE-ST336-2017.txt`; provenance `specs/tables/misc.md` S1 (pub.smpte.org) | Key structure, BER length, BER-OID (Annexes I and J quote ISO/IEC 8825-1) |
| MISB ST 1201 Floating Point to Integer Mapping | ST 1201.5, 24 June 2021 | `specs/src/ST1201.5.txt` | IMAPB forward mapping (truncation, out-of-range flags) invoked by ST 0601 |
| Verified tag tables | 2026-11 | `specs/tables/st0601-a.md`, `st0601-b.md`, `st0601-c.md`, `st0601-example.md`, `misc.md` | Cross-check; `st0601-c.md` (tags 95-143) was never checked against the PDF, so every tag 95-143 value below was re-read from `ST0601.19.txt` |
| Decoder | working tree, 2026-11-17 | `misb-rs/src/st0601.rs`, `imapb.rs`, `checksum.rs` | The encoder inverts its `DESCS` table; its spec-example tests are the round-trip oracle |
| Reference implementations (cross-check only) | upstream sources | jMISB (`UasDatalinkAngle.java` etc.), cbrl/klv (`include/klv/codecs/mapped.hpp`) | Rounding behaviour of other encoders |

Line numbers below refer to the `.txt` files in `specs/src/`. All quotes are in `st0601-encode.quotes.json` and pass `specs/phase0/check_quotes.py`.

## 2. Rules

Implementers: `misb::encode` = packet/item builder; `misb::mux` = stateful layer (MetadataState, scheduler, Report-on-Change); `checker` = conformance checker (whoever hosts the ST 0601 content checks).

### 2.1 Packet framing

**R-ST0601-ENCODE-01** Write the 16-byte key `06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00` exactly, at the start of every packet. Implements: misb::encode, checker. Source: ST 0601.19 section 6.2. Quote: "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00 (CRC 56773)". Location: `specs/src/ST0601.19.txt:146`.

**R-ST0601-ENCODE-02** Never write any historical ST 0601 key (e.g. the 2005 `06 0E 2B 34 01 01 01 01 0F 00 ..` experimental key). Implements: misb::encode, checker. Source: ST 0601.19 section 6.2, ST 0601.8-19. Quote: "Historical 16-byte Universal Label Keys shall be forbidden in future developments." Location: `specs/src/ST0601.19.txt:149`.

**R-ST0601-ENCODE-03** Byte 8 of the key (the register version number) is written as registered, `0x01`, and is never varied. Decoders may ignore it (misb-rs does), but the encoder emits the registered key only. Implements: misb::encode. Source: SMPTE ST 336:2017 section 5.2.3. Quotes: "For items registered by SMPTE, byte 8 shall define the version number of the given register, which first defines the item specified by the Item Designator" (`specs/src/SMPTE-ST336-2017.txt:495`); "Decoders may ignore the version number or use the version number as an additional guide and consistency check in the process of parsing a Key." (`specs/src/SMPTE-ST336-2017.txt:512`).

**R-ST0601-ENCODE-04** Key byte 6 = `0x0B` fixes the syntax of the set: item lengths are BER short or long form and tags are BER-OID. The encoder uses exactly this syntax for every item (no fixed-size tags or lengths). Implements: misb::encode. Source: ST 336:2017 Table 5. Quote: "0x0B ASN.1 BER short or long ASN.1 OID BER". Location: `specs/src/SMPTE-ST336-2017.txt:827`.

**R-ST0601-ENCODE-05** A packet is key + BER length of the value + value, where the value is the sequence of TLV items (tag, length, value). Implements: misb::encode. Source: ST 0601.19 section 6.3, Figure 1. Quote: "A packet is a combination of a UL Key, the Length of the Value, and the Value." Location: `specs/src/ST0601.19.txt:151`.

**R-ST0601-ENCODE-06** The packet length is a definite BER length in its minimal form: one byte `0x00`-`0x7F` for values up to 127 bytes, otherwise `0x80 | n` followed by the n bytes of the length with no leading zero byte. Never write `0x80` (indefinite: ST 0601 defines no alternative end-of-value method) or `0xFF` (reserved). Implements: misb::encode, checker. Source: ST 336:2017 section 5.3 and Annex I (ISO/IEC 8825-1 8.1.3.5); ST 0902.8 Annex C. Quotes: "the value of the Length field shall be encoded using the Basic Encoding Rules (BER) for either the short form or long form encoding of length bytes" (`specs/src/SMPTE-ST336-2017.txt:529`); "It is suggested that the short form of ASN.1 BER be used for all Value fields smaller than or equal to 127 (0x7f)." (`specs/src/SMPTE-ST336-2017.txt:543`); "Any application document which allows the length of the Value field to be undefined shall define an alternative method of locating the end of the Value field." (`specs/src/SMPTE-ST336-2017.txt:550`); "c) the value 11111111 2 s hall not be used." (`specs/src/SMPTE-ST336-2017.txt:1256`); "Lengths up to 127 bytes are encoded in BER short form. Lengths of 128 bytes or greater are encoded in BER long form." (`specs/src/ST0902.8.txt:497`).

**R-ST0601-ENCODE-07** Every item length field (top level, inside nested sets and inside packs) uses BER short or long form with the fewest possible bytes. Implements: misb::encode, checker. Source: ST 0107.3-05 (section 6.3.2). Quote: "All instances of item Length fields within a MISB defined KLV Universal or Local Set shall be BER Short form or BER Long form encoded using the fewest possible bytes." Location: `specs/src/ST0107.4.txt:128`.

**R-ST0601-ENCODE-08** Tags are minimal BER-OID: tags 1-127 are one byte equal to the tag, tags 128-143 are two bytes `0x81 0x00` to `0x81 0x0F`; a first byte `0x80` is never written. Implements: misb::encode, checker. Source: ST 0601.19 section 7.1; ST 336:2017 Annex J (ISO/IEC 8825-1 8.19.2); ST 0107.4 section 6.3.1. Quotes: "The tag is a BER-OID encoded integer value. Single-byte tags represent tag numbers from 1 through 127. Tag numbers greater than 127 use two-bytes (or more)." (`specs/src/ST0601.19.txt:468`); "The subidentifier shall be encoded in the fewest possible octets" (`specs/src/SMPTE-ST336-2017.txt:1279`).

**R-ST0601-ENCODE-09** All multi-byte integers (fixed and variable length, IMAPB, pack fields, the checksum) are big-endian, most significant bit first. Implements: misb::encode. Source: ST 0107.2-01, ST 0107.2-02. Quote: "Byte order shall be big -endian or MSB." Location: `specs/src/ST0107.4.txt:66`.

**R-ST0601-ENCODE-10** Packets conform to SMPTE ST 336 and to every ST 0107 rule (the remaining rules in this document are those rules made concrete). Implements: misb::encode, checker. Source: ST 0107.3-03; ST 0601.8-03. Quotes: "All Local Set KLV metadata shall be formatted in compliance with SMPTE ST 336" (`specs/src/ST0107.4.txt:75`); "All UAS Datalink LS metadata shall be expressed in accordance with MISB ST 0107." (`specs/src/ST0601.19.txt:199`).

**R-ST0601-ENCODE-86** Only tags defined by ST 0601.19 (1-143, minus 66) are generated. Unknown tags (above 143) are written only when passing through recorded bytes (`set_raw`), never invented. Implements: misb::encode. Source: ST 0601.19 section 5. Quote: "Registration of new metadata items in the proper metadata dictionary (public or private) is a pre-requisite for using the metadata items in the UAS Datalink LS." Location: `specs/src/ST0601.19.txt:104`.

### 2.2 Presence, order, multiplicity

**R-ST0601-ENCODE-11** Item 2 (Precision Time Stamp) is the first item of every packet. Implements: misb::encode, checker. Source: ST 0601.8-09. Quote: "All instances of a UAS Datalink LS shall contain Item 2, Precision Time Stamp, as the first item of the LS." Location: `specs/src/ST0601.19.txt:327`.

**R-ST0601-ENCODE-12** Item 1 (Checksum) is the last item of every packet. Implements: misb::encode, checker. Source: ST 0601.8-11. Quote: "All instances of the UAS Datalink LS shall contain as the final item Item 1, Checksum." Location: `specs/src/ST0601.19.txt:446`.

**R-ST0601-ENCODE-13** Item 65 (UAS Datalink LS Version Number) is present in every packet (position free). The mandatory set is exactly {1, 2, 65}; every other item is "Optional" in its summary table. Implements: misb::encode, checker. Source: ST 0601.8-12; section 6.3; "Required in LS?" row of every section 8 table. Quotes: "All instances of the UAS Datalink LS shall contain Item 65, UAS Datalink LS Version Number." (`specs/src/ST0601.19.txt:448`); "UAS Datalink LS packets require the following items: Precision Time Stamp (Item 2), UAS Datalink LS Version Number (Item 65) and Checksum (Item 1)." (`specs/src/ST0601.19.txt:152`).

**R-ST0601-ENCODE-14** Between item 2 and item 1, any item order is valid (the encoder's default order is decision D-01). Implements: misb::encode. Source: ST 0601.13-23. Quote: "any order of other items within the LS instance shall be valid." Location: `specs/src/ST0601.19.txt:123`.

**R-ST0601-ENCODE-15** Exception to free order: when an SDCC-FLP (item 102) is written, the items it describes (its Refined Source List) are written immediately before it, in the order of the matrix rows. Implements: misb::encode (phase 7 SDCC support; until then item 102 is only passed through raw together with its preceding items). Source: ST 0601.19 section 6.3, section 8.102.1. Quotes: "the order of items within a UAS Datalink LS packet is arbitrary, unless dictated by use of any Standard Deviation Correlation Coefficient Floating Length Pack (SDCC-FLP)." (`specs/src/ST0601.19.txt:165`); "The Refined Source List values are written into the UAS Datalink Local Set immediately followed by the SDCC-FLP" (`specs/src/ST0601.19.txt:5590`).

**R-ST0601-ENCODE-16** Each item appears at most once per packet, except the four "Multiples Allowed = Yes" items 100 (Segment LS), 101 (Amend LS), 102 (SDCC-FLP) and 115 (Control Command). Implements: misb::encode, checker. Source: ST 0601.13-24; Table 1 MUL column; summary tables 8.100, 8.101, 8.102, 8.115. Quotes: "all items within an instance of a UAS Datalink LS shall be included only once." (`specs/src/ST0601.19.txt:125`); "Required in LS? Optional Allowed in SDCC Pack? No Multiples Allowed? Yes" (`specs/src/ST0601.19.txt:5478`, item 100).

**R-ST0601-ENCODE-17** Inside item 100 or 101 the child may repeat items that also appear in the parent (this is not a duplicate in the sense of R-16). Implements: misb::encode, checker. Source: ST 0601.14-35. Quote: "Child-items within Item 100 (Segment Local Set) or Item 101 (Amend Local Set), shall be allowed to duplicate items of their parent." Location: `specs/src/ST0601.19.txt:127`.

**R-ST0601-ENCODE-18** Every item is used with the meaning and units of its ST 0601.19 description (e.g. item 2 is MISP time, item 42 is MSL or HAE depending on items 25/78, item 47 bit meanings are the 0601.19 ones). Implements: misb::encode, misb::mux. Source: ST 0601.8-14. Quote: "The usage of all Tags within the UAS Datalink LS shall be consistent with the descriptions and clarifications contained within MISB ST 0601." Location: `specs/src/ST0601.19.txt:129`.

**R-ST0601-ENCODE-19** Where a restricted and a preferred representation exist, a single representation is preferred: full range (90, 91, 92, 93, 82-89) over restricted (6, 7, 50, 52, 26-33), extended (96, 103, 104, 105) over restricted (22, 38), HAE (75 or 104, 78, 76 or 105) over MSL (15, 25, 69). Decoders that understand the preferred item ignore the other (ST 0601.8-16, 8-17, 9-20, 9-21), so the encoder writes the preferred one by default (D-13). Implements: misb::encode. Source: ST 0601.19 sections 8.6.1, 8.15.1 and the matching "Details" of each pair. Quotes: "A single representation is preferred favoring the full-range version (Item 90) as per Section 6.1." (`specs/src/ST0601.19.txt:1542`); "For legacy systems, Item 15 and Item 75 | Item 104 are allowed with preference for Item 75 | Item 104." (`specs/src/ST0601.19.txt:1910`).

### 2.3 Checksum

**R-ST0601-ENCODE-20** The checksum covers every byte of the packet from the first key byte up to and including the checksum item's length byte: key, packet BER length, all items, then `01 02`. Only the two checksum value bytes are excluded. Implements: misb::encode, checker. Source: ST 0601.19 section 6.6, Figure 8. Quote: "The checksum is a running 16-bit summation through the entire packet beginning with the 16-byte Local Set Key and ending with the length field of the checksum LS item" Location: `specs/src/ST0601.19.txt:408`.

**R-ST0601-ENCODE-21** Algorithm: the byte at 0-based offset i (counted from the first key byte) is added shifted left by 8 when i is even and unshifted when i is odd; the sum is kept modulo 2^16. Use a `usize` index and a wrapping `u16` (the reference code's `unsigned short` index would overflow on packets of 65,536 bytes or more). `misb::checksum::st0601_checksum` already implements it. Implements: misb::encode, checker. Source: ST 0601.19 sections 6.6 and 8.1. Quotes: "bcc += buff[i] << (8 * ((i + 1) % 2));" (`specs/src/ST0601.19.txt:432`); "Lower 16-bits of summation" (`specs/src/ST0601.19.txt:1335`).

**R-ST0601-ENCODE-22** Item 1 is written as tag `01`, length `02`, then the 16-bit sum big-endian. It is computed last, after the packet length and every item are final. Implements: misb::encode. Source: ST 0601.19 section 8.1. Quote: "Performed on entire LS packet, including 16-byte US key and 1-byte checksum length" Location: `specs/src/ST0601.19.txt:1336`.

**R-ST0601-ENCODE-23** Receivers discard packets whose checksum does not match, so a single wrong byte loses the whole packet: the checker recomputes the checksum of every produced packet. Implements: checker. Source: ST 0601.8-08. Quote: "All instances of a UAS Datalink LS where the computed checksum is not identical to the included checksum shall be discarded." Location: `specs/src/ST0601.19.txt:444`.

### 2.4 Version and time

**R-ST0601-ENCODE-24** Item 65 carries the major version of ST 0601 the producer implements: `41 01 13` (19) for this encoder. Implements: misb::encode. Source: ST 0601.19 section 8.65. Quotes: "Indicates the major version of MISB ST 0601 used as the source standard when encoding the metadata into KLV" (`specs/src/ST0601.19.txt:3990`); "1..255 corresponds to document revisions MISB ST 0601.1 thru MISB ST 0601.255" (`specs/src/ST0601.19.txt:3993`).

**R-ST0601-ENCODE-25** Item 2 is an 8-byte unsigned count of microseconds of MISP time (ST 0603, no leap seconds, not UTC and not POSIX time) and is the time of birth of every item in the packet. Implements: misb::encode, misb::mux. Source: ST 0601.8-10; section 8.2. Quotes: "The value assigned to Item 2, Precision Time Stamp, shall represent the time of birth of the metadata of all the items contained in that instance of the UAS Datalink LS." (`specs/src/ST0601.19.txt:329`); "not including leap seconds. See MISB ST 0603" (`specs/src/ST0601.19.txt:1380`).

**R-ST0601-ENCODE-26** Changing item 2 of recorded packets breaks their synchronisation with the ST 0604 time stamps in the video; the standard offers item 137 (Correction Offset) for time corrections instead (D-22). Implements: misb::mux. Source: ST 0601.19 section 6.4 (informative). Quote: "Any modifications to the metadata Precision Time Stamp will break the synchronization between the metadata and Motion Imagery frames." Location: `specs/src/ST0601.19.txt:342`.

### 2.5 Value lengths

**R-ST0601-ENCODE-27** An item with a numeric Required Length is written with exactly that many bytes, never shortened (no dropping of leading zero bytes) and never padded. Implements: misb::encode, checker. Source: ST 0601.13-29; ST 0107.3-06. Quotes: "the KLV encoded value for the item shall use exactly the number of bytes specified by the Required Length." (`specs/src/ST0601.19.txt:1301`); "the encoded Value shall match the number of bytes defined by the required Length." (`specs/src/ST0107.4.txt:140`).

**R-ST0601-ENCODE-28** An item's value never exceeds its Max Length (127 for most strings, 32 for item 129, 50 for 94, 20 for 81, 16 for 127, 24 for 130, 17 for 143, and the IMAPB / variable integer maxima of 3.6). ST 0601 calls Max Length "recommended" but ST 0107.3-07, imported by ST 0601.8-03, makes it binding; the encoder enforces it. Implements: misb::encode, checker. Source: ST 0107.3-07; ST 0601.19 section 8 introduction. Quotes: "the encoded Value shall not exceed the number of bytes defined by the maximum Length." (`specs/src/ST0107.4.txt:143`); "specifies the recommended maximum length." (`specs/src/ST0601.19.txt:1257`).

**R-ST0601-ENCODE-29** Variable-length `uint` items (110, 111, 131, 133) and `int` items (136, 137) use the fewest bytes: no leading `00` bytes for uint, no redundant sign-extension bytes (`00` or `FF`) for int. The value 0 is the single byte `00` (a zero-length item would mean "unknown"). Implements: misb::encode, checker. Source: ST 0107.3-10. Quote: "the encoded value shall remove leading zero or leading sign extension bytes." Location: `specs/src/ST0107.4.txt:184`.

**R-ST0601-ENCODE-30** IMAPB items use the fewest bytes that still meet the system's precision, between 1 and the item's Max Length. Items 103, 104, 105 need at least 3 bytes for a resolution better than 1 m; item 96 is recommended at 3 bytes. Implements: misb::encode. Source: ST 0107.3-09; ST 0601.19 sections 8.96, 8.103-8.105. Quotes: "the encoded Value shall use the fewest number of bytes , while maintaining system precision" (`specs/src/ST0107.4.txt:181`); "For resolution < 1.0m, a length of >= 3 bytes is required" (`specs/src/ST0601.19.txt:5664`); "To be consistent with Item 22 Target Width, recommend a length of 3 bytes" (`specs/src/ST0601.19.txt:5354`).

**R-ST0601-ENCODE-31** BER and BER-OID values inside packs (command IDs, wavelength IDs, record lengths, string lengths, MSID local id, frame rate terms) use the fewest bytes. Implements: misb::encode. Source: ST 0107.3-11; ISO/IEC 8825-1 8.19.2 (R-08). Quote: "the encoded Value shall use the fewest number of bytes." Location: `specs/src/ST0107.4.txt:187`.

**R-ST0601-ENCODE-32** Values typed `float` (only inside the ST 1010 SDCC-FLP, item 102) are IEEE 754-2008 binary32/binary64, big-endian. No top-level ST 0601.19 item is a float. Implements: misb::encode (phase 7). Source: ST 0107.3-08. Quote: "the encoded Value shall use the IEEE 754 -2008 standard to encode the value." Location: `specs/src/ST0107.4.txt:178`.

### 2.6 Mapping and special values

**R-ST0601-ENCODE-33** Linearly mapped integer items are encoded with `KLV = round(Soft * span / range)` (offset items: `round((Soft - offset) * span / range)`), round half away from zero. ST 0601 gives the forward formula without a rounding rule except items 43/44 (`round`) and the item 81 example ("rounded to the nearest unit percentage"); its examples print full-precision values. Round-to-nearest reproduces all 64 published mapped-integer examples; truncation reproduces only 44 (section 3.11, D-06). Implements: misb::encode. Source: ST 0601.19 sections 8.43, 8.81.2, 8 introduction; ST 1201.5 section 4 (definition of round). Quotes: "KLV = round" (`specs/src/ST0601.19.txt:3089`); "A rounding function which, for this standard, means" (`specs/src/ST1201.5.txt:58`); "resolution, so programmers can verify they are using the right formulas." (`specs/src/ST0601.19.txt:1304`); "rounded to the nearest unit percentage" (`specs/src/ST0601.19.txt:4581`).

**R-ST0601-ENCODE-34** IMAPB items are encoded with the ST 1201 forward mapping, which truncates: `y = trunc(sF * (x - a) + zOffset)` with `bPow = ceil(log2(b - a))`, `dPow = 8L - 1`, `sF = 2^(dPow - bPow)`, `zOffset = sF*a - floor(sF*a)` when `a < 0 < b`, else 0; `y` is written as L big-endian bytes. `misb::imapb::Imapb::real_to_int` already implements this. Implements: misb::encode. Source: ST 1201.5 sections 7.1.2, 7.2.1, 8.3. Quotes: "y=truncate(sF*(x-a)+Zoffset)" (`specs/src/ST1201.5.txt:232`); "However, to support the zero matching requirements a truncation must be used instead" (`specs/src/ST1201.5.txt:592`).

**R-ST0601-ENCODE-35** An IMAPB input below the range minimum encodes as IMAP_BELOW_MINIMUM (`E0` followed by L-1 `00` bytes) and above the maximum as IMAP_ABOVE_MAXIMUM (`E1` then `00`s); this is part of the forward algorithm ST 0601 invokes (see D-07 for the policy and U-05). Implements: misb::encode. Source: ST 1201.5 section 7.2.1 steps 2-3, Table 3. Quotes: "y = Special bit pattern IMAP_BELOW_MINIMUM (see Section 7.2.3.1)" (`specs/src/ST1201.5.txt:228`); "y = Special bit pattern IMAP_ABOVE_MAXIMUM (see Section 7.2.3.1)" (`specs/src/ST1201.5.txt:230`).

**R-ST0601-ENCODE-36** Negative zero is encoded as positive zero (never as a special value). Implements: misb::encode. Source: ST 1201.1-12. Quote: "All negative zero values shall be mapped to a positive zero and sent as a normal (non-special) value." Location: `specs/src/ST1201.5.txt:332`.

**R-ST0601-ENCODE-37** For items that define an "Out of Range" indicator (6, 7, 50, 51, 52, 79, 80: `80 00`; 90, 91, 92, 93: `80 00 00 00`), a value outside the mapped range is written as that indicator, never clamped and never rejected. Implements: misb::encode. Source: ST 0601.13-27 (section 7.5). Quote: "When a value recedes below its minimum or exceeds its maximum range and the item allows an" Location: `specs/src/ST0601.19.txt:1106`.

**R-ST0601-ENCODE-38** For latitude/longitude items that define "N/A (Off-Earth)" (23, 24, 40, 41, 82-89: `80 00 00 00`; 26-33: `80 00`), a point not on the earth (above the horizon) is written as that indicator. It is a state the caller sets explicitly, not inferred from range. Implements: misb::encode. Source: ST 0601.13-28 (section 7.5). Quote: "When a position consisting of a latitude/longitude moves beyond the surface of the earth and the item allows an" Location: `specs/src/ST0601.19.txt:1114`.

**R-ST0601-ENCODE-39** "Reserved" codes are never written: `80 00 00 00` in items 13, 14, 19, 67, 68, and every enumeration code marked Reserved (63: 9-255, 77: 6-255, 121 wavelength IDs 7-20, 125: 13-255, 126: 7-255, 140 general status 12-127, 47 bits 6-7). Implements: misb::encode, checker. Source: ST 0601.19 section 7.5 and the item tables. Quote: "value maintains backward compatibility with older versions of MISB ST 0601." Location: `specs/src/ST0601.19.txt:1121`.

**R-ST0601-ENCODE-40** If a corner offset (26-33) falls outside +/-0.075 deg, do not report offsets; report the full corner points 82-89 instead. `N/A (Off-Earth)` is not a substitute for "out of range". Implements: misb::encode (builder rejects; the profile layer switches to 82-89). Source: ST 0601.19 sections 8.26.1-8.33.1. Quote: "When any corner point offsets are outside of the mapped range, the MISB recommends not reporting corner point offsets and instead using the full precision corner points (Items 82 through 89)." Location: `specs/src/ST0601.19.txt:2385`.

**R-ST0601-ENCODE-41** When item 81 (Image Horizon Pixel Pack) is in a packet, every corner on the sky side of the horizon vector is written as `N/A (Off-Earth)` and no other invalid corner coordinates appear. Implements: misb::encode (consistency check), checker. Source: ST 0601.19 section 8.81.1. Quote: "No invalid corner coordinates are allowed when the Image Horizon Pixel Pack is included in the same MISB ST 0601 packet." Location: `specs/src/ST0601.19.txt:4525`.

**R-ST0601-ENCODE-42** Coded items take only defined values: 34 in 0..2; 47 bits 6 and 7 zero; 62 a three- or four-digit number whose digits are all 1..8; 63 in 0..8; 77 in 0..5; 124 non-zero; 125 in 0..12; 126 in 0..6; 138 payload type in 0..4; 140 general status in 0..11. Implements: misb::encode. Source: ST 0601.19 sections 8.34, 8.47.1 (Table 3), 8.62, 8.63.1 (Table 4), 8.77.1 (Table 5), 8.124, 8.125, 8.126, 8.138.1, 8.140.1. Quotes: "A value with all bits set to zero does not have meaning and is not allowed" (`specs/src/ST0601.19.txt:6467`, item 124); "Only the values 111..8888 can be used without 0's or 9's" (`specs/src/ST0601.19.txt:3882`, item 62).

### 2.7 Strings

**R-ST0601-ENCODE-43** String items (3, 4, 10, 11, 12, 59, 70, 106, 107, 108, 129, 135, and the strings inside 115, 122, 128, 138, 140) are UTF-8 bytes with no terminator, at most 127 bytes (item 129: 32 bytes; item 115 command string: 127). Implements: misb::encode. Source: ST 0601.19 Table 1 (format `utf8`), sections 8.3, 8.115.1, 8.129. Quotes: "Suggested maximum: 127 characters" (`specs/src/ST0601.19.txt:1415`); "This string has a maximum length of 127 characters." (`specs/src/ST0601.19.txt:6085`).

**R-ST0601-ENCODE-44** The empty string is written as the single byte `00` (length 1); an unknown string is a zero-length item. Implements: misb::encode (and decoder change D-23). Source: ST 0107.4 section 6.3.3.2. Quotes: "The empty string uses a single null character (0x00) with no other characters to indicate the string is blank" (`specs/src/ST0107.4.txt:196`); "A string item with a length of zero (0) signifies an" (`specs/src/ST0107.4.txt:201`).

**R-ST0601-ENCODE-45** A non-empty string is written without leading or trailing `00`, `09`, `0A`, `0D`, `20`. Implements: misb::encode. Source: ST 0107.3-12. Quote: "the encoded value shall have all leading and trailing, null (0x00), tab (0x09), line feed (0x0A), carriage return (0x0D), and space (0x20)" Location: `specs/src/ST0107.4.txt:214`.

**R-ST0601-ENCODE-46** A non-empty string contains none of `00`-`08`, `0B`, `0C`, `0E`-`1F`, `7F` (no ST 0601 item allows them). Implements: misb::encode. Source: ST 0107.3-13. Quote: "ranges (inclusive) of 0x00 through 0x0 8, 0x0B , 0x0C, 0x0E through 0x1F, and character 0x7F removed" Location: `specs/src/ST0107.4.txt:219`.

**R-ST0601-ENCODE-47** ST 0902.8 Table 1 types items 3, 10, 11, 12 as ISO 646 (ST 0902.8 cites ST 0601.14); ASCII text is both ISO 646 IRV and UTF-8, so the profile warns on non-ASCII text in these items (D-10). Implements: misb::encode (profile). Source: ST 0902.8 Table 1. Quote: "3 Mission ID None ISO 646 variable" Location: `specs/src/ST0902.8.txt:115`.

### 2.8 Zero-length items (ZLI)

**R-ST0601-ENCODE-48** A ZLI (tag, length `00`, no value) may be written for any item except the mandatory items 1, 2, 65 and the multi-use items 100, 101, 102, 115. Implements: misb::encode, checker. Source: ST 0601.19 section 6.5; ST 0107.4-19. Quotes: "all items within the UAS Datalink Local Set may use Zero Length Items (ZLI)." (`specs/src/ST0601.19.txt:369`); "only single -use Local Set items within an instance shall be allowed to specify a Zero -Length Item (ZLI)." (`specs/src/ST0107.4.txt:273`).

**R-ST0601-ENCODE-49** Required items always have a positive length: 1, 2, 65 at the root, and item 143 inside every 100/101 (required there by ST 0601.19-41/-42). Implements: misb::encode, checker. Source: ST 0107.4-16 (and retired ST 0601.14-32). Quote: "Required or mandatory items of a Local Set shall always be reported with positive lengths" Location: `specs/src/ST0107.4.txt:267`.

**R-ST0601-ENCODE-50** A ZLI means "the value is now unknown" and is intended only for an item that was previously reported with a value (retired ST 0601.14-34 said the same). Implements: misb::mux (only the stateful layer knows the history). Source: ST 0107.4-17, section 6.3.4. Quotes: "Where a Local Set item has a length of zero, consumers shall interpret the value of the item as" (`specs/src/ST0107.4.txt:269`); "The intended use of a ZLI comes only after a value has been in the Known state" (`specs/src/ST0107.4.txt:246`).

**R-ST0601-ENCODE-51** ZLIs for nested sets and packs are discouraged unless the standard allows them; ST 0601 section 6.5 does allow them, so they are legal but the encoder never generates them on its own (D-11). Implements: misb::encode, misb::mux. Source: ST 0107.4 section 6.3.4. Quote: "Unless a standard allows it, the use of ZLI for a child Local Set is discouraged." Location: `specs/src/ST0107.4.txt:251`.

**R-ST0601-ENCODE-52** In the ST 0902 profile a ZLI never counts as reporting a minimum-set item. Implements: misb::mux, checker. Source: ST 0902.8-05. Quote: "No Zero-Length items (ZLI) shall be used to meet minimum reporting requirements." Location: `specs/src/ST0902.8.txt:83`.

### 2.9 Report-on-Change, refresh and rates

**R-ST0601-ENCODE-53** ST 0601 uses Report-on-Change: apart from 1, 2, 65 (in every packet), an item is sent when its value changes and in any case again within the Metadata Refresh Period, whose maximum is 30 s. Implements: misb::mux, checker. Source: ST 0601.19 section 6.5, ST 0601.15-36; ST 0107.4-14, ST 0107.4-18. Quotes: "additional items update when their value changes or if a Metadata Refresh Period (i.e., 30-second period) has elapsed since the last item update." (`specs/src/ST0601.19.txt:360`); "UAS Data-link LS items implemented using Report-on-Change shall adhere to the requirements for usage stated in MISB ST 0107." (`specs/src/ST0601.19.txt:366`); "items shall be reported no less than once every Metadata Refresh Period" (`specs/src/ST0107.4.txt:263`); "the maximum value for the Metadata Refresh Period shall be 30 seconds." (`specs/src/ST0107.4.txt:271`).

**R-ST0601-ENCODE-54** Receivers treat an item not refreshed within the period as Unknown, so a still-known value that the producer stops repeating silently disappears at the receiver; the stateful layer must keep refreshing every known item. Implements: misb::mux. Source: ST 0107.4-15. Quote: "metadata items which have not been updated within a Metadata Refresh Period shall be consid ered Unknown" Location: `specs/src/ST0107.4.txt:265`.

**R-ST0601-ENCODE-55** Known-Static items should be spread over the refresh period rather than all sent in one packet. Implements: misb::mux. Source: ST 0601.19 section 6.5.1 (recommendation; same text in ST 0107.4 6.3.5). Quote: "the MISB recommends distributing the Known-Static metadata items over a 30-second refresh period." Location: `specs/src/ST0601.19.txt:374`.

**R-ST0601-ENCODE-56** List items whose elements may be distributed over packets (128, 138, 140, 141) must re-send every element within 30 s, or the element drops out of the receiver's list. Implements: misb::mux. Source: ST 0601.19 section 6.5.1.1. Quote: "not including list elements in a 30 second time frame, means the list element is no longer part of the list." Location: `specs/src/ST0601.19.txt:388`.

**R-ST0601-ENCODE-57** Item-specific 30 s duties: item 115 is repeated (about every 30 s) until item 116 acknowledges it, then no longer repeated; custom wavelength records (item 128, IDs 21 and up) are sent at least every 30 s; IDs in item 121 and bits in item 139 must refer to records sent within the last 30 s. Implements: misb::mux, checker. Source: ST 0601.19 sections 8.115.1, 8.128.1; ST 0601.17-37, ST 0601.17-39. Quotes: "Item 115 is repeatable to meet Report-on-Change requirements (i.e., updates every 30 seconds) before item 116 acknowledges the Command." (`specs/src/ST0601.19.txt:6088`); "Any custom Wavelengths List records are sent at a minimum of once every 30 seconds." (`specs/src/ST0601.19.txt:6646`); "A Wavelength ID in Item 121 shall be one of the current values" (`specs/src/ST0601.19.txt:6307`); "A bit position value set to one (1) in Item 139 shall be one of the current Payload ID values" (`specs/src/ST0601.19.txt:7160`).

**R-ST0601-ENCODE-58** No standard in scope sets a packet rate, a minimum rate or a maximum rate for ST 0601 packets. ST 0601 only recommends adjusting repetition rates to the timing needs; ST 0902 Annex A (informative) recommends items 3, 10, 11, 12, the item 48 sub-items and 94 every 10 s and all other minimum-set items as often as bandwidth allows, up to the frame rate, and says not every packet must carry every item. Implements: misb::mux (rate policy defaults, D-16, D-17). Source: ST 0601.19 section 6.4; ST 0902.8 Annex A. Quotes: "A recommendation is for systems to adjust metadata repetition rates to meet timing criteria." (`specs/src/ST0601.19.txt:334`); "Include Tags 3, 10, 11, 12, 48 sub-tags & 94 once every 10 seconds" (`specs/src/ST0902.8.txt:174`); "Include all other items as often as possible, within the available bandwidth and up to the frame rate" (`specs/src/ST0902.8.txt:175`); "Note: It is not mandatory that each metadata packet contain every metadata item" (`specs/src/ST0902.8.txt:181`).

**R-ST0601-ENCODE-59** Section 6.6 says item 65 "updates at a minimum rate of once every 30 seconds"; the requirement ST 0601.8-12 (R-13) is stricter and wins: item 65 is in every packet. Implements: misb::encode. Source: ST 0601.19 section 6.6. Quote: "which updates at a minimum rate of once every 30 seconds, identifies the version used." Location: `specs/src/ST0601.19.txt:441`.

### 2.10 Nested sets and packs

**R-ST0601-ENCODE-60** A nested local set (48, 73, 74, 95, 97, 98, 99, 100, 101) is written as ST 0601 tag + BER length + the nested standard's TLV items. The value carries no 16-byte key, no inner length, and no checksum or CRC item even when the nested standard defines one when standalone (ST 0806 CRC-32 tag 1, ST 0903 checksum tag 1, ST 1002 CRC item 21). The outer item 1 covers the nested bytes. Implements: misb::encode. Source: ST 0601.19 section 6.3.3. Quotes: "The Value then contains a set of TLV triplets defined by another standard or document." (`specs/src/ST0601.19.txt:259`); "If the nested Local Set defines a checksum (or CRC) item, the Value does not include the checksum (or CRC) item." (`specs/src/ST0601.19.txt:260`).

**R-ST0601-ENCODE-61** The ST 0102 security metadata inside item 48 is always the ST 0102 Local Set form (never the Universal Set). Implements: misb::encode. Source: ST 0601.14-31 (section 8.48.1). Quote: "the ST 0102 format shall use the Local Set format." Location: `specs/src/ST0601.19.txt:3371`.

**R-ST0601-ENCODE-62** Pack rules: in a VLP an unknown element is written with length 0 and no value; trailing elements may be truncated, and the pack's total length always reflects what is written; a DLP never has undefined elements. Implements: misb::encode. Source: ST 0601.19 section 6.3.2. Quotes: "In this case the length for the value is zero (0) with the value omitted." (`specs/src/ST0601.19.txt:219`); "In both cases, the length (Total) of the VLP or DLP must reflect any truncation." (`specs/src/ST0601.19.txt:249`); "A DLP does not allow undefined values." (`specs/src/ST0601.19.txt:236`).

### 2.11 Segment and Amend (items 100, 101, 143; ST 1607.2)

**R-ST0601-ENCODE-63** Every Segment LS (100) and every Amend LS (101) contains an MSID item 143. Implements: misb::encode (phase 7), checker. Source: ST 0601.19-41, ST 0601.19-42. Quotes: "Where using the Segment LS (Item 100) the Segment LS shall include a Metadata Substream ID (MSID) (Item 143) to uniquely identify the" (`specs/src/ST0601.19.txt:1157`); "Where using the Amend LS (Item 101) the Amend LS shall include a Metadata Substream ID (MSID) (Item 143)" (`specs/src/ST0601.19.txt:1159`).

**R-ST0601-ENCODE-64** A child Segment/Amend LS is always written inside its parent (its lineage up to the root is kept in every packet that carries it). Implements: misb::encode, misb::mux. Source: ST 0601.19-43, ST 0601.19-44. Quotes: "the data producer shall include the child Segment LS within the parent LS." (`specs/src/ST0601.19.txt:1177`); "the data producer shall include the child Amend LS within the parent LS." (`specs/src/ST0601.19.txt:1180`).

**R-ST0601-ENCODE-65** Item 143 never appears at the root level. Implements: misb::encode, checker. Source: ST 0601.19-45. Quote: "No Metadata Substream ID (Item 143) shall be present at the root level UAS Datalink LS." Location: `specs/src/ST0601.19.txt:7604`.

**R-ST0601-ENCODE-66** Item 143 is a truncation pack: a local id greater than 0 is written alone; local id 0 is followed by the 16-byte UUID. Implements: misb::encode. Source: ST 0601.19-46, ST 0601.19-47. Quotes: "OID) greater than zero (0), the producer shall omit (truncate) the universal identifier (UUID)." (`specs/src/ST0601.19.txt:7623`); "OID) equal to zero, the producer shall provide the substream universal identifier (UUID)." (`specs/src/ST0601.19.txt:7626`).

**R-ST0601-ENCODE-67** At any one level only Amend LSs or only Segment LSs are present, never both; an Amend LS contains only Amend children (a Segment LS may contain Segment and Amend children). Implements: misb::encode, checker. Source: ST 1607.2-07, ST 1607.2-08, section 10. Quotes: "Within a given level only Amends LS(s) or Segments LS(s), but not both simultaneously, shall be allowed." (`specs/src/ST1607.2.txt:311`); "Where a parent Amend LS is instantiated, only child Amend LS(s) shall be allowed within the parent ." (`specs/src/ST1607.2.txt:313`).

**R-ST0601-ENCODE-68** The root security set (item 48) applies to all children; a child may carry its own item 48 only with ST 0102 items 12 and 13 (object country coding method and codes) and nothing else. Implements: misb::encode, checker. Source: ST 1607-01, ST 1607-02, ST 1607.2-09, ST 1607-04. Quotes: "the security metadata for the root KLV metadata set shall apply to all the metadata items in the metadata set, children and sub -children." (`specs/src/ST1607.2.txt:275`); "the Amend LS shall contain a MISB ST 0102 security metadata Local Set with only Item 12 and Item 13." (`specs/src/ST1607.2.txt:282`); "the Segment LS shall contain a MISB ST 0102 security metadata Local Set with only Item 12 and Item 13." (`specs/src/ST1607.2.txt:285`).

**R-ST0601-ENCODE-69** With an Amend LS, the root alone carries every MISP-required item (e.g. the ST 0902 set); with a Segment LS, the union of root and children does. Implements: misb::mux, checker. Source: ST 1607-05, ST 1607-06. Quotes: "the root metadata set shall contain all metadata items required to meet MISP conformance." (`specs/src/ST1607.2.txt:321`); "the union of root , child and sub-child metadata sets shall contain all metadata items required to meet MISP conformance." (`specs/src/ST1607.2.txt:323`).

### 2.12 Deprecated and replaced items

**R-ST0601-ENCODE-70** Item 66 is deprecated and has no format: never write it (its former content, the target location covariance, goes in an SDCC-FLP, item 102). Implements: misb::encode, checker. Source: ST 0601.19 Table 1, section 8.66. Quote: "This item has been deprecated." Location: `specs/src/ST0601.19.txt:582`.

**R-ST0601-ENCODE-71** Items 60 (Weapon Load) and 61 (Weapon Fired) are replaced by item 140 (Weapons Stores); new streams use 140. Implements: misb::encode (D-14). Source: ST 0601.19 sections 8.60.1, 8.61.1. Quote: "Note: the Weapon Stores (Item 140) replaces the Weapon Load (Item 60) and Weapon Fired (Item 61) for providing information about Weapons and their status." Location: `specs/src/ST0601.19.txt:3803`.

**R-ST0601-ENCODE-72** Extended items are favoured over their range-restricted forms (96 over 22, 103 over 38, 104/105 over the legacy heights), and a single representation is preferred (R-19). Implements: misb::encode. Source: ST 0601.19 sections 8.22.1, 8.96.1, 8.103.1. Quote: "A single representation is preferred, with the extended version (Item 96) being favored as per Section 6.1." Location: `specs/src/ST0601.19.txt:2217`.

**R-ST0601-ENCODE-73** Items 110 (Time Airborne) and 131 (Take-off Time) carry the same information; send one of them, not both (a suggestion: decoders accept both). Implements: misb::encode (warning). Source: ST 0601.19 section 8.110. Quote: "but not both in the same MISB ST" Location: `specs/src/ST0601.19.txt:5868`.

### 2.13 Other item-level requirements

**R-ST0601-ENCODE-74** Item 138 payload identifiers start at 0 and increase by 1 per payload. Implements: misb::encode. Source: ST 0601.13-30. Quote: "Identifier value shall start at zero (0) and increment by one (1) for each additional payload." Location: `specs/src/ST0601.19.txt:7066`.

**R-ST0601-ENCODE-75** A newly historical waypoint (item 141) gets a prosecution order below the most negative one in the list. Implements: misb::mux. Source: ST 0601.17-40. Quote: "Prosecution Order shall be less than the largest magnitude negative Prosecution Order of all waypoints in the waypoint list." Location: `specs/src/ST0601.19.txt:7441`.

**R-ST0601-ENCODE-76** An SDCC-FLP in ST 0601 uses only Mode 2 parse control. Implements: misb::encode (phase 7). Source: ST 0601.10-22. Quote: "The UAS Datalink Local Set shall only include SDCC-FLPs using Mode 2 Parse Control, as defined in MISB ST 1010." Location: `specs/src/ST0601.19.txt:5604`.

**R-ST0601-ENCODE-77** Wavelength ID 0 ("no active wavelengths") in item 121 is always alone. Implements: misb::encode. Source: ST 0601.17-38. Quote: "Where the Active Wavelength List includes Wavelength ID zero (0), the Active Wavelength List shall not contain any other Wavelength IDs." Location: `specs/src/ST0601.19.txt:6325`.

**R-ST0601-ENCODE-78** The preferred value of item 12 is `Geodetic WGS84` (it is the profile default). Implements: misb::encode (profile). Source: ST 0601.19 section 8.12.1. Quote: "is the preferred Image Coordinate System." Location: `specs/src/ST0601.19.txt:1797`.

### 2.14 ST 0902 minimum metadata set (default content profile)

**R-ST0601-ENCODE-79** MISMMS packets follow ST 0107 (same as R-10). Implements: misb::encode. Source: ST 0902.3-01. Quote: "All metadata shall be expressed in accordance with MISB ST 0107 [3]." Location: `specs/src/ST0902.8.txt:78`.

**R-ST0601-ENCODE-80** Minimum-set items are populated per ST 0601 (so ST 0601.19 formats and lengths govern where ST 0902 Table 1 shows older values; see U-03, U-09). Implements: misb::encode. Source: ST 0902.3-03. Quote: "The items of the MISMMS as defined in MISB ST 0902 Table 1 shall be populated in accordance with MISB ST 0601 requirements." Location: `specs/src/ST0902.8.txt:79`.

**R-ST0601-ENCODE-81** Every minimum-set item is reported at least every 30 s under all circumstances (and not by ZLI, R-52). Implements: misb::mux, checker. Source: ST 0902.3-04. Quote: "All metadata items contained in the MISMMS shall be reported no less than once every thirty (30) seconds under all circumstances." Location: `specs/src/ST0902.8.txt:81`.

**R-ST0601-ENCODE-82** The MISMMS is an ST 0601 profile (same key) in which every Table 1 item is mandatory unless conditional. Implements: misb::mux (profile). Source: ST 0902.8 section 6. Quote: "The MISMMS is a Local Set profile of MISB ST 0601 with all items mandatory unless conditionally dependent." Location: `specs/src/ST0902.8.txt:69`.

**R-ST0601-ENCODE-83** Conditional groups: 6 | 90, 7 | 91, 15 | 75 | 104, 25 | 78, 22 | 96 are "inclusive or" (at least one of each group), except that 75 and 104 are exclusive (never both). Implements: misb::encode, checker. Source: ST 0902.8 section 6, Note 1. Quote: "The use of Tag 75 and Tag 104 is governed by an" Location: `specs/src/ST0902.8.txt:95`.

**R-ST0601-ENCODE-84** Item 94 (MIIS Core Identifier) is required once the motion imagery leaves the system (platform plus ground control station). Implements: misb::mux (profile requires the caller to supply it). Source: ST 0902.8 section 6, Note 2. Quote: "A Motion Imagery Core Identifier (Tag 94) is required as the Motion Imagery data is disseminated from the" Location: `specs/src/ST0902.8.txt:96`.

### 2.15 Packet size

**R-ST0601-ENCODE-85** Neither ST 0601 nor ST 336 limits the packet size (set items have Max Length "Not Limited"); ST 336 lets the application limit it, and ST 0601's reference checksum code takes a 16-bit length. The encoder therefore applies a configurable limit (D-18). Implements: misb::encode. Source: ST 336:2017 section 5.3; ST 0601.19 section 6.6. Quotes: "Where appropriate, individual application ST / RPs may define the maximum byte-length of the Length field or may place limitations on the value range of the Length field" (`specs/src/SMPTE-ST336-2017.txt:536`); "unsigned short len ) // Length from 16-byte UL key up to 1-byte checksum length" (`specs/src/ST0601.19.txt:425`).

## 3. Byte layouts

### 3.1 Packet

| Offset | Field | Width | Value written |
|---|---|---|---|
| 0 | Universal Label key | 16 | `06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00` (R-01, R-03) |
| 16 | Value length | 1 to 3 (BER minimal; 3 = `82 hh ll` at the default 65,535-byte limit) | number of bytes from the first byte of item 2 through the last checksum byte (R-06) |
| 16 + n | Item 2 | 10 | `02 08` + 8-byte MISP time (R-11, R-25) |
| ... | Other items | variable | ascending tag order (D-01), each `tag length value` |
| end - 4 | Item 1 | 4 | `01 02 hi lo` (R-12, R-20 to R-22) |

Smallest valid packet (items 2, 65, 1; tag 2 = the ST 0601 example time `0004 59F4 A6AA 4AA8`), checksum computed and decoded `checksum ok` by the existing `klvdump`:

```
06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 11
02 08 00 04 59 F4 A6 AA 4A A8  41 01 13  01 02 AC F1
```

### 3.2 Item (TLV)

| Field | Width | Encoding |
|---|---|---|
| Tag | 1 (tags 1-127) or 2 (128-143) | minimal BER-OID (3.4) |
| Length | 1 (0-127), 2 (128-255), 3 (256-65535) | minimal BER (3.3); `00` only for a ZLI |
| Value | Length bytes | per tag (3.6) |

ZLI example (item 21 Slant Range unknown), decoded as `unknown` by `klvdump`:

```
06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00 13
02 08 00 04 59 F4 A6 AA 4A A8  15 00  41 01 13  01 02 AF 06
```

### 3.3 BER length (packet length, item lengths, lengths inside packs)

| Value | Bytes written | Never written |
|---|---|---|
| 0..127 | `LL` | `81 LL` (non-minimal) |
| 128..255 | `81 LL` | `82 00 LL` |
| 256..65,535 | `82 HH LL` | `83 00 HH LL` |
| 65,536..16,777,215 | `83 ..` (only if the size limit is raised) | |
| any | | `80` (indefinite), `FF` (reserved) |

`smpte_klv::ber::encode_length(len, BerForm::Minimal, sink)` produces exactly this.

### 3.4 BER-OID (tags and BER-OID pack fields)

| Value | Bytes |
|---|---|
| 0 | `00` (pack fields only; tag 0 is never written) |
| 1..127 | one byte = value |
| 128 | `81 00` |
| 129..143 | `81 01` .. `81 0F` (e.g. 131 = `81 03`, 143 = `81 0F`) |
| 16,383 | `FF 7F` |
| 16,384 | `81 80 00` |

Seven bits per byte, most significant group first, top bit set on every byte but the last, no leading `80` (`smpte_klv::ber::encode_oid`).

### 3.5 Checksum

```
sum: u16 = 0
for (i, b) in packet[0 .. len - 2].iter().enumerate():   // key .. "01 02"
    sum = sum.wrapping_add(if i % 2 == 0 { (b as u16) << 8 } else { b as u16 })
packet[len - 2 ..] = sum.to_be_bytes()
```

Test vectors (all recomputed for this document):

| Vector | Bytes summed | Checksum |
|---|---|---|
| ST 0601.19 8.1.1.2 sample `06 0E 2B 34 02 00 81 BB` | 8 | `B4 FD` |
| ST 0902.8 Annex C packet A ("Dynamic & Constant", 228 bytes, tag 65 = 6, nested item 48, item 94) | 226 | `3E 1E` (as published) |
| ST 0902.8 Annex C packet B ("Dynamic Only", 114 bytes, tag 65 = 6) | 112 | `5C 2B` (as published) |
| Packet B with `41 01 06` changed to `41 01 13` | 112 | `5C 38` (decodes `checksum ok`) |
| Smallest packet (3.1) | 32 | `AC F1` |
| ZLI packet (3.2) | 34 | `AF 06` |
| `specs/tables/st0601-a.md` synthetic (2, 65, 13) | 38 | `CB F7` |

Packets A and B are in `specs/tables/st0601-example.md` section 1. With D-01 (ascending order) and an explicit tag 65 override of 6, the encoder must reproduce A and B byte for byte from their decoded values: that is the main whole-packet acceptance test.

### 3.6 Per-tag encoder table (all 143 items of ST 0601.19)

Shared mappings (round = round half away from zero, D-06; BE = big-endian; "wrap" = a value outside the range is reduced modulo 360 into it, values inside it (both ends included) are unchanged, D-07):

| Name | Bytes | Formula | Software range |
|---|---|---|---|
| HDG | uint16 | round(x * 65535 / 360), wrap | 0..360 deg |
| FOV | uint16 | round(x * 65535 / 180) | 0..180 deg |
| ALT | uint16 | round((x + 900) * 65535 / 19900) | -900..19000 m |
| PRS | uint16 | round(x * 65535 / 5000) | 0..5000 mbar |
| TEN | uint16 | round(x * 65535 / 10000) | 0..10000 (m or kg) |
| ERR | uint16 | round(x * 65535 / 4095) | 0..4095 m |
| P8 | uint8 | round(x * 255 / 100) | 0..100 (m/s or %) |
| A32 | uint32 | round(x * 4294967295 / 360), wrap | 0..360 deg |
| RNG | uint32 | round(x * 4294967295 / 5000000) | 0..5,000,000 m |
| S20 | int16 | round(x * 65534 / 40) | -20..20 deg |
| OFS | int16 | round(x * 65534 / 0.15) | -0.075..0.075 deg |
| VEL | int16 | round(x * 65534 / 654) | -327..327 m/s |
| LAT | int32 | round(x * 4294967294 / 180) | -90..90 deg |
| LON | int32 | round(x * 4294967294 / 360) | -180..180 deg |
| IMAPB(a, b) | L bytes | ST 1201 forward mapping, truncation (R-34) | a..b |

Columns: "Req" = Required Length; "Write" = lengths the encoder may write (0 = ZLI excluded; see last column); "Unknown / special" = what to write for unknown, out of range or special states; "0902" = membership of the ST 0902 minimum set (M = always, a group such as "6/90" = one of the group, "-" = not in the set).

| Tag | Name | Encoder value bytes | Req | Write | Unknown / special | 0902 |
|---|---|---|---|---|---|---|
| 1 | Checksum | uint16 BE of 3.5 | 2 | 2 | mandatory, never ZLI | M |
| 2 | Precision Time Stamp | uint64 BE, MISP microseconds | 8 | 8 | mandatory, never ZLI | M |
| 3 | Mission ID | UTF-8 (3.10) | - | 1..127 | ZLI = unknown; "" = `00` | M |
| 4 | Platform Tail Number | UTF-8 | - | 1..127 | ZLI | - |
| 5 | Platform Heading Angle | HDG | 2 | 2 | ZLI; no special value | M |
| 6 | Platform Pitch Angle | S20 | 2 | 2 | ZLI; out of range `80 00` | 6/90 |
| 7 | Platform Roll Angle | int16 round(x * 65534 / 100), -50..50 deg | 2 | 2 | ZLI; out of range `80 00` | 7/91 |
| 8 | Platform True Airspeed | uint8 round(x), 0..255 m/s | 1 | 1 | ZLI | - |
| 9 | Platform Indicated Airspeed | uint8 round(x), 0..255 m/s | 1 | 1 | ZLI | - |
| 10 | Platform Designation | UTF-8 | - | 1..127 | ZLI | M |
| 11 | Image Source Sensor | UTF-8 | - | 1..127 | ZLI | M |
| 12 | Image Coordinate System | UTF-8; profile default `Geodetic WGS84` | - | 1..127 | ZLI | M |
| 13 | Sensor Latitude | LAT | 4 | 4 | ZLI; `80 00 00 00` (Reserved) never written | M |
| 14 | Sensor Longitude | LON | 4 | 4 | ZLI; Reserved never written | M |
| 15 | Sensor True Altitude | ALT (MSL) | 2 | 2 | ZLI | 15/75/104 |
| 16 | Sensor Horizontal Field of View | FOV | 2 | 2 | ZLI | M |
| 17 | Sensor Vertical Field of View | FOV | 2 | 2 | ZLI | M |
| 18 | Sensor Relative Azimuth Angle | A32 | 4 | 4 | ZLI | M |
| 19 | Sensor Relative Elevation Angle | LON formula (int32 round(x * 4294967294 / 360)), -180..180, wrap | 4 | 4 | ZLI; Reserved never written | M |
| 20 | Sensor Relative Roll Angle | A32 | 4 | 4 | ZLI | M |
| 21 | Slant Range | RNG | 4 | 4 | ZLI | M |
| 22 | Target Width | TEN (m) | 2 | 2 | ZLI | 22/96 |
| 23 | Frame Center Latitude | LAT | 4 | 4 | ZLI; Off-Earth `80 00 00 00` | M |
| 24 | Frame Center Longitude | LON | 4 | 4 | ZLI; Off-Earth `80 00 00 00` | M |
| 25 | Frame Center Elevation | ALT (MSL) | 2 | 2 | ZLI; not reported when frame center is off earth (8.25.1) | 25/78 |
| 26 | Offset Corner Latitude Point 1 | OFS of (corner lat - item 23) | 2 | 2 | ZLI; Off-Earth `80 00`; outside +/-0.075 not written (R-40) | - |
| 27 | Offset Corner Longitude Point 1 | OFS of (corner lon - item 24) | 2 | 2 | as 26 | - |
| 28 | Offset Corner Latitude Point 2 | OFS | 2 | 2 | as 26 | - |
| 29 | Offset Corner Longitude Point 2 | OFS | 2 | 2 | as 26 | - |
| 30 | Offset Corner Latitude Point 3 | OFS | 2 | 2 | as 26 | - |
| 31 | Offset Corner Longitude Point 3 | OFS | 2 | 2 | as 26 | - |
| 32 | Offset Corner Latitude Point 4 | OFS | 2 | 2 | as 26 | - |
| 33 | Offset Corner Longitude Point 4 | OFS | 2 | 2 | as 26 | - |
| 34 | Icing Detected | uint8 code 0 off, 1 no icing, 2 icing | 1 | 1 | ZLI | - |
| 35 | Wind Direction | HDG (direction wind comes from) | 2 | 2 | ZLI | - |
| 36 | Wind Speed | P8 (0..100 m/s) | 1 | 1 | ZLI | - |
| 37 | Static Pressure | PRS | 2 | 2 | ZLI | - |
| 38 | Density Altitude | ALT | 2 | 2 | ZLI | - |
| 39 | Outside Air Temperature | int8 round(x), -128..127 C | 1 | 1 | ZLI (-128 is an ordinary value) | - |
| 40 | Target Location Latitude | LAT | 4 | 4 | ZLI; Off-Earth `80 00 00 00` | - |
| 41 | Target Location Longitude | LON | 4 | 4 | ZLI; Off-Earth `80 00 00 00` | - |
| 42 | Target Location Elevation | ALT (MSL if only 25 known in the stream, HAE if 78 known) | 2 | 2 | ZLI; not reported when off earth | - |
| 43 | Target Track Gate Width | uint8 round(x / 2), 0..510 px | 1 | 1 | ZLI | - |
| 44 | Target Track Gate Height | uint8 round(x / 2), 0..510 px | 1 | 1 | ZLI | - |
| 45 | Target Error Estimate - CE90 | ERR | 2 | 2 | ZLI | - |
| 46 | Target Error Estimate - LE90 | ERR | 2 | 2 | ZLI | - |
| 47 | Generic Flag Data | uint8 bit field (3.7.2) | 1 | 1 | ZLI | - |
| 48 | Security Local Set | ST 0102 LS items (3.7.1) | - | 1..limit | ZLI legal, never generated (D-11) | M (48/1-6, 12, 13, 22) |
| 49 | Differential Pressure | PRS | 2 | 2 | ZLI | - |
| 50 | Platform Angle of Attack | S20 | 2 | 2 | ZLI; out of range `80 00` | - |
| 51 | Platform Vertical Speed | int16 round(x * 65534 / 360), -180..180 m/s | 2 | 2 | ZLI; out of range `80 00` | - |
| 52 | Platform Sideslip Angle | S20 | 2 | 2 | ZLI; out of range `80 00` | - |
| 53 | Airfield Barometric Pressure | PRS | 2 | 2 | ZLI | - |
| 54 | Airfield Elevation | ALT | 2 | 2 | ZLI | - |
| 55 | Relative Humidity | P8 (%) | 1 | 1 | ZLI | - |
| 56 | Platform Ground Speed | uint8 round(x), 0..255 m/s | 1 | 1 | ZLI | - |
| 57 | Ground Range | RNG | 4 | 4 | ZLI | - |
| 58 | Platform Fuel Remaining | TEN (kg) | 2 | 2 | ZLI | - |
| 59 | Platform Call Sign | UTF-8 | - | 1..127 | ZLI | - |
| 60 | Weapon Load | 3.7.3 (legacy) | 2 | 2 | ZLI; only with explicit legacy flag (D-14) | - |
| 61 | Weapon Fired | 3.7.3 (legacy) | 1 | 1 | as 60 | - |
| 62 | Laser PRF Code | uint16 = code (111..8888, digits 1-8) | 2 | 2 | ZLI | - |
| 63 | Sensor Field of View Name | uint8 code 0..8 (Table 4) | 1 | 1 | ZLI | - |
| 64 | Platform Magnetic Heading | HDG | 2 | 2 | ZLI | - |
| 65 | UAS Datalink LS Version Number | uint8 `13` (19) | 1 | 1 | mandatory, never ZLI | M |
| 66 | Deprecated | never written | - | - | - | - |
| 67 | Alternate Platform Latitude | LAT | 4 | 4 | ZLI; Reserved never written | - |
| 68 | Alternate Platform Longitude | LON | 4 | 4 | ZLI; Reserved never written | - |
| 69 | Alternate Platform Altitude | ALT (MSL; legacy, prefer 76/105) | 2 | 2 | ZLI | - |
| 70 | Alternate Platform Name | UTF-8 | - | 1..127 | ZLI | - |
| 71 | Alternate Platform Heading | HDG | 2 | 2 | ZLI | - |
| 72 | Event Start Time | uint64 BE, MISP microseconds | 8 | 8 | ZLI | - |
| 73 | RVT Local Set | ST 0806 LS items, no CRC item (3.7.1) | - | 1..limit | ZLI legal, never generated | - |
| 74 | VMTI Local Set | ST 0903 LS items, no checksum item (3.7.1) | - | 1..limit | ZLI legal, never generated | - |
| 75 | Sensor Ellipsoid Height | ALT (HAE) | 2 | 2 | ZLI | 15/75/104 (profile default) |
| 76 | Alternate Platform Ellipsoid Height | ALT (HAE) | 2 | 2 | ZLI | - |
| 77 | Operational Mode | uint8 code 0..5 (Table 5) | 1 | 1 | ZLI | - |
| 78 | Frame Center Height Above Ellipsoid | ALT (HAE) | 2 | 2 | ZLI; not reported when off earth | 25/78 (profile default) |
| 79 | Sensor North Velocity | VEL | 2 | 2 | ZLI; out of range `80 00` | - |
| 80 | Sensor East Velocity | VEL | 2 | 2 | ZLI; out of range `80 00` | - |
| 81 | Image Horizon Pixel Pack | 3.7.4 | - | 4 or 20 | ZLI; geo field "error" `80 00 00 00` | - |
| 82 | Corner Latitude Point 1 (Full) | LAT | 4 | 4 | ZLI; Off-Earth `80 00 00 00` | - |
| 83 | Corner Longitude Point 1 (Full) | LON | 4 | 4 | as 82 | - |
| 84 | Corner Latitude Point 2 (Full) | LAT | 4 | 4 | as 82 | - |
| 85 | Corner Longitude Point 2 (Full) | LON | 4 | 4 | as 82 | - |
| 86 | Corner Latitude Point 3 (Full) | LAT | 4 | 4 | as 82 | - |
| 87 | Corner Longitude Point 3 (Full) | LON | 4 | 4 | as 82 | - |
| 88 | Corner Latitude Point 4 (Full) | LAT | 4 | 4 | as 82 | - |
| 89 | Corner Longitude Point 4 (Full) | LON | 4 | 4 | as 82 | - |
| 90 | Platform Pitch Angle (Full) | LAT formula, -90..90 deg | 4 | 4 | ZLI; out of range `80 00 00 00` | 6/90 (profile default) |
| 91 | Platform Roll Angle (Full) | LAT formula, -90..90 deg | 4 | 4 | ZLI; out of range `80 00 00 00` | 7/91 (profile default) |
| 92 | Platform Angle of Attack (Full) | LAT formula, -90..90 deg | 4 | 4 | ZLI; out of range `80 00 00 00` | - |
| 93 | Platform Sideslip Angle (Full) | LON formula, -180..180 deg | 4 | 4 | ZLI; out of range `80 00 00 00` | - |
| 94 | MIIS Core Identifier | ST 1204 binary value without its key and length | - | 1..50 | ZLI | M |
| 95 | SAR Motion Imagery Local Set | ST 1206 LS items (raw until phase 7) | - | 1..limit | ZLI legal, never generated | - |
| 96 | Target Width Extended | IMAPB(0, 1500000), default 3 bytes | - | 1..8 | ZLI; below/above `E0`/`E1` + zeros | 22/96 (profile default, 3 bytes) |
| 97 | Range Image Local Set | ST 1002 LS items, CRC item 21 omitted | - | 1..limit | ZLI legal, never generated | - |
| 98 | Geo-Registration Local Set | ST 1601 LS items | - | 1..limit | ZLI legal, never generated | - |
| 99 | Composite Imaging Local Set | ST 1602 LS items | - | 1..limit | ZLI legal, never generated | - |
| 100 | Segment Local Set | ST 0601 items incl. 143 (3.7.5) | - | 1..limit | never ZLI; repeats allowed | - |
| 101 | Amend Local Set | ST 0601 items incl. 143 (3.7.5) | - | 1..limit | never ZLI; repeats allowed | - |
| 102 | SDCC-FLP | ST 1010 FLP, Mode 2, after its source items | - | 1..limit | never ZLI; repeats allowed | - |
| 103 | Density Altitude Extended | IMAPB(-900, 40000), default 3 | - | 1..8 | ZLI; `E0`/`E1` | - |
| 104 | Sensor Ellipsoid Height Extended | IMAPB(-900, 40000), default 3 | - | 1..8 | ZLI; `E0`/`E1` | 15/75/104 (never with 75) |
| 105 | Alternate Platform Ellipsoid Height Extended | IMAPB(-900, 40000), default 3 | - | 1..8 | ZLI; `E0`/`E1` | - |
| 106 | Stream Designator | UTF-8 | - | 1..127 | ZLI | - |
| 107 | Operational Base | UTF-8 | - | 1..127 | ZLI | - |
| 108 | Broadcast Source | UTF-8 | - | 1..127 | ZLI | - |
| 109 | Range To Recovery Location | IMAPB(0, 21000) km, default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 110 | Time Airborne | uint minimal, seconds | - | 1..4 | ZLI | - |
| 111 | Propulsion Unit Speed | uint minimal, rev/min | - | 1..4 | ZLI | - |
| 112 | Platform Course Angle | IMAPB(0, 360), default 2, wrap | - | 1..8 | ZLI | - |
| 113 | Altitude AGL | IMAPB(-900, 40000), default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 114 | Radar Altimeter | IMAPB(-900, 40000), default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 115 | Control Command | 3.7.6 | - | 2.. (string at most 127 bytes) | never ZLI; repeats allowed | - |
| 116 | Control Command Verification List | 3.7.7 | - | 1.. | ZLI | - |
| 117 | Sensor Azimuth Rate | IMAPB(-1000, 1000) deg/s, default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 118 | Sensor Elevation Rate | IMAPB(-1000, 1000), default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 119 | Sensor Roll Rate | IMAPB(-1000, 1000), default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 120 | On-board MI Storage Percent Full | IMAPB(0, 100), default 2 | - | 1..3 | ZLI; `E0`/`E1` | - |
| 121 | Active Wavelength List | 3.7.7 | - | 1.. | ZLI | - |
| 122 | Country Codes | 3.7.8 | - | 3.. | ZLI | - |
| 123 | Number of NAVSATs in View | uint8 count | 1 | 1 | ZLI | - |
| 124 | Positioning Method Source | uint8 flags (Table 10), non-zero | 1 | 1 | ZLI | - |
| 125 | Platform Status | uint8 code 0..12 (Table 11) | 1 | 1 | ZLI | - |
| 126 | Sensor Control Mode | uint8 code 0..6 (Table 12) | 1 | 1 | ZLI | - |
| 127 | Sensor Frame Rate Pack | 3.7.9 | - | 1..16 | ZLI | - |
| 128 | Wavelengths List | 3.7.10 | - | 11.. | ZLI | - |
| 129 | Target ID | UTF-8 | - | 1..32 | ZLI | - |
| 130 | Airbase Locations | 3.7.11 | - | 1..24 | ZLI | - |
| 131 | Take-off Time | uint minimal, MISP microseconds | - | 1..8 | ZLI | - |
| 132 | Transmission Frequency | IMAPB(1, 99999) MHz, default 3 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 133 | On-board MI Storage Capacity | uint minimal, GB | - | 1..4 | ZLI | - |
| 134 | Zoom Percentage | IMAPB(0, 100), default 2 | - | 1..4 | ZLI; `E0`/`E1` | - |
| 135 | Communications Method | UTF-8 | - | 1..127 | ZLI | - |
| 136 | Leap Seconds | int minimal (two's complement), seconds | - | 1..4 | ZLI | - |
| 137 | Correction Offset | int minimal, microseconds | - | 1..8 | ZLI | - |
| 138 | Payload List | 3.7.12 | - | 1.. | ZLI | - |
| 139 | Active Payloads | 3.7.13 | - | 1.. | ZLI | - |
| 140 | Weapons Stores | 3.7.14 | - | 1.. | ZLI | - |
| 141 | Waypoint List | 3.7.15 | - | 1.. | ZLI | - |
| 142 | View Domain | 3.7.16 | - | 1.. | ZLI | - |
| 143 | Metadata Substream ID Pack | 3.7.17; only inside 100/101 | - | 1..17 | never ZLI; never at root | - |

Required Length and Max Length were re-read for every row from the section 8 summary tables of `ST0601.19.txt` (mechanically extracted: "Length / Max Length / Required Length" row of each item). Fixed-length rows have Length = Max Length = Required Length; "Variable" rows have Required Length N/A. ST 0601.19 Table 1 lists item 143 as "byte 16", but its summary table gives Max Length 17 (1-byte local id 0 + UUID), which is what is used here.

### 3.7 Pack and nested layouts

#### 3.7.1 Nested local sets (48, 73, 74, 95, 97, 98, 99)

`[ST 0601 tag][BER length N][N bytes: child TLV items]`. Child items use BER-OID tags and minimal BER lengths of the child standard's tag table, in the child standard's own order rules. No child key, no child length, no child checksum/CRC item (R-60). Item 48 uses the ST 0102 Local Set (R-61). Example (ST 0902.8 Annex C): `30 1C 01 01 01 02 01 07 03 05 2F 2F 55 53 41 0C 01 07 0D 06 00 55 00 53 00 41 16 02 00 0A`.

#### 3.7.2 Item 47 Generic Flag Data (Table 3)

One byte, bit 0 = least significant: bit 0 Laser on (1) / off (0); bit 1 Auto-Track on / off; bit 2 IR polarity Black Hot (1) / White Hot (0); bit 3 Icing Detected / No Icing Detected; bit 4 Slant Range Measured (1) / Calculated (0); bit 5 Image Invalid (1) / Valid (0); bits 6 and 7 always 0. Example `2F 01 31`.

#### 3.7.3 Items 60 and 61 (legacy)

Item 60: byte 1 = `(station << 4) | substation`, byte 2 = `(weapon type << 4) | variant`, each nibble 0..15 (example `3C 02 AF D8`). Item 61: one byte = `(station << 4) | substation` (same as byte 1 of item 60 per 8.61.1; the summary table's "byte 2" is a spec error), example `3D 01 BA`.

#### 3.7.4 Item 81 Image Horizon Pixel Pack (Table 6)

| Field | Bytes | Encoding |
|---|---|---|
| Start x0, Start y0, End x1, End y1 | 1 each | uint8 = round(percent), 0..100 |
| Start Latitude, Start Longitude, End Latitude, End Longitude | 4 each, optional | LAT / LON; `80 00 00 00` = "error" |

Written as 4 bytes or 20 bytes only (D-24). Example `51 04 00 24 38 00`.

#### 3.7.5 Items 100 and 101 (Segment / Amend)

`[64 or 65][BER length][81 0F len MSID][child ST 0601 items...]`. Children may repeat parent items (R-17); never contain item 1 (R-60); contain exactly one 143, written first (D-21); nest only per R-67. Example (Amend with local MSID 5 and a corrected Sensor Latitude): `65 0A 81 0F 01 05 0D 04 55 95 B6 6D`.

#### 3.7.6 Item 115 Control Command (Table 7)

| Field | Bytes | Encoding |
|---|---|---|
| Command ID | 1+ | BER-OID, increasing and unique per command |
| Command String length | 1+ | BER minimal |
| Command String | 0..127 | UTF-8 (3.10) |
| Command Time | 0 or 8 | uint64 MISP microseconds; omitted on first use (defaults to the packet's item 2), included on repeats (D-25) |

Example `73 13 05 11 46 6C 79 20 74 6F 20 57 61 79 70 6F 69 6E 74 20 31` (ID 5, "Fly to Waypoint 1").

#### 3.7.7 Items 116 and 121 (BER-OID lists)

Concatenated minimal BER-OIDs, at least one, no per-element length. 116: acknowledged command IDs (example `74 02 03 07`). 121: wavelength IDs 1..6 (predefined, Table 14) or 21 and up (defined in item 128 within 30 s); 0 only alone; 7..20 never (example `79 02 01 03`).

#### 3.7.8 Item 122 Country Codes (Table 9)

`[L1][coding method, uint minimal, ST 0102 item 12 table][L2][overflight utf8][L3][operator utf8][L4][manufacture utf8]`, each L a minimal BER length. An unknown country is written with L = 0; trailing unknowns (manufacture, or operator and manufacture) are truncated (D-19). Example `7A 0B 01 0E 03 43 41 4E 00 03 46 52 41`.

#### 3.7.9 Item 127 Sensor Frame Rate Pack (Table 13)

`[numerator BER-OID][denominator BER-OID]`; the denominator is omitted when it is 1 and is never 0. Example `7F 05 83 D4 60 87 69` (60000/1001).

#### 3.7.10 Item 128 Wavelengths List (Table 15)

Repeated records `[record length BER][ID BER-OID][min IMAPB(0, 1e9, 4) nm][max IMAPB(0, 1e9, 4) nm][name utf8 = rest of record]`. Example `81 00 0E 0D 15 00 00 07 D0 00 00 0F A0 4E 4E 49 52`.

#### 3.7.11 Item 130 Airbase Locations (Table 16)

`[L][take-off location][L][recovery location]`; location = `[lat IMAPB(-90, 90, 4)][lon IMAPB(-180, 180, 4)][HAE IMAPB(-900, 9000, 3), optional]`, so L is 8, 11, or 0 (unknown). The recovery part is truncated when equal to take-off (D-19). Maximum 24 bytes.

#### 3.7.12 Item 138 Payload List (Tables 17-20)

`[payload count BER-OID]` then repeated `[record length BER][payload ID BER-OID][payload type BER-OID 0..4][name length BER][name utf8]`. IDs start at 0 and increase by 1 (R-74); the count is the total on board even when a packet carries only some records.

#### 3.7.13 Item 139 Active Payloads

Big-endian bit field, bit n (counted from the least significant bit of the last byte) = payload ID n active; the fewest bytes that hold the highest active ID; no active payload = `00`. Example `81 0B 01 0B` (payloads 0, 1, 3).

#### 3.7.14 Item 140 Weapons Stores (Tables 21-23)

Repeated records `[record length BER][station BER-OID][hardpoint BER-OID][carriage BER-OID][store BER-OID][status BER-OID = general status 0..11 | engagement bits 8..11][type length BER][weapon type utf8]`.

#### 3.7.15 Item 141 Waypoint List (Table 24)

Repeated records `[record length BER][waypoint ID BER-OID][prosecution order int16][info BER-OID: bit 0 manual, bit 1 ad hoc][location as 3.7.11, 8 or 11 bytes]`; info and location are optional only by truncation from the end; the encoder writes complete records when the data is known.

#### 3.7.16 Item 142 View Domain (Table 25)

Up to three pairs, azimuth, elevation, roll, each `[L = 2n][start IMAPB(range, n)][angular range IMAPB(0, 360, n)]`; start ranges azimuth 0..360, elevation -180..180, roll 0..360; L = 0 means that pair is unknown; trailing unknown pairs are truncated; default n = 3. Example `81 0E 0E 06 34 80 00 4B 00 00 06 1A 40 00 0C 80 00`.

#### 3.7.17 Item 143 Metadata Substream ID Pack

`[local id BER-OID]` alone when the local id is greater than 0 (`81 0F 01 05`), or `00` followed by the 16-byte UUID when it is 0 (`81 0F 11 00 B5 58 CD A5 5E 6B 51 AE 9C 62 06 9F C3 5F 5F 6A`).

### 3.8 IMAPB parameters (ST 0601.19 summary tables; LSB = sR)

| Tag | Range (a, b) | bPow | Max | Default L | LSB at L = 1 / 2 / 3 / 4 |
|---|---|---|---|---|---|
| 96 | 0, 1,500,000 m | 21 | 8 | 3 | 16384 / 64 / 0.25 / 2^-10 m |
| 103, 104, 105 | -900, 40,000 m | 16 | 8 | 3 | 512 (zOffset 0.2421875) / 2 / 2^-7 / 2^-15 m |
| 109 | 0, 21,000 km | 15 | 4 | 3 | 256 / 1 / 2^-8 / 2^-16 km |
| 112 | 0, 360 deg | 9 | 8 | 2 | 4 / 2^-6 / 2^-14 / 2^-22 deg |
| 113, 114 | -900, 40,000 m | 16 | 4 | 3 | as 103 |
| 117, 118, 119 | -1000, 1000 deg/s | 11 | 4 | 3 | 16 (zOffset 0.5) / 2^-4 / 2^-12 / 2^-20 |
| 120 | 0, 100 % | 7 | 3 | 2 | 1 / 2^-8 / 2^-16 % |
| 132 | 1, 99,999 MHz | 17 | 4 | 3 | 1024 / 4 / 2^-6 / 2^-14 MHz |
| 134 | 0, 100 % | 7 | 4 | 2 | 1 / 2^-8 / 2^-16 / 2^-24 % |
| 128 min/max | 0, 1e9 nm | 30 | fixed 4 | 4 | 0.5 nm at L = 4 |
| 130/141 lat, lon, HAE | -90..90, -180..180, -900..9000 | 8, 9, 14 | fixed 4, 4, 3 | 4, 4, 3 | 2^-23 deg, 2^-22 deg, 2^-9 m |
| 142 starts / ranges | 0..360, -180..180 / 0..360 | 9 | 8 | 3 | 2^-14 deg at L = 3 |

The resolution figures printed in some summary tables are inconsistent with the formula (104/105 "3 bytes = 78.125 mm" is 7.8125 mm; 112 "16.625 millidegrees" is 15.625; 113/114 "0.7 cm" is 0.78 cm): the formula governs.

### 3.9 Variable-length integers (R-29)

| Item type | Value | Bytes |
|---|---|---|
| uint (110, 111, 131, 133) | 0 / 255 / 256 / 19887 / 1,529,588,637,122,999 | `00` / `FF` / `01 00` / `4D AF` / `05 6F 27 1B 5E 41 B7` |
| int (136, 137) | 0 / 30 / 127 / 128 / -1 / -128 / -129 / 5,025,678,901 | `00` / `1E` / `7F` / `00 80` / `FF` / `80` / `FF 7F` / `01 2B 8D C6 35` |

Spec examples reproduced: 110 `6E 02 4DAF`, 111 `6F 02 0BB8`, 131 `8103 07 056F271B5E41B7`, 133 `8105 02 2710`, 136 `8108 01 1E`, 137 `8109 05 012B8DC635`.

### 3.10 Strings (R-43 to R-47)

1. Caller value "" (empty): write `00` (length 1).
2. Unknown: ZLI (length 0).
3. Otherwise: remove characters `00`-`08`, `0B`, `0C`, `0E`-`1F`, `7F`; trim leading and trailing `00`, `09`, `0A`, `0D`, `20`; if nothing is left write `00`; write the UTF-8 bytes; the result must be at most 127 bytes (32 for item 129; 127 for the item 115 command string; the maximum counts bytes, not characters).

### 3.11 Rounding verification (D-06)

All checks run with Python floats (IEEE binary64, as the encoder will use) during phase 0.

| Check | round half away from zero | truncate | floor |
|---|---|---|---|
| encode(printed example) == published bytes, 64 mapped-integer examples (the list in `misb-rs/src/st0601.rs` test `spec_examples_mapped_integers`) | 64 / 64 | 44 / 64 | 40 / 64 |
| decode then encode returns the same integer: every code of the 8- and 16-bit maps (HDG, ALT, S20, OFS, VEL, P8, ERR) and 800,000 random codes of LAT, LON, A32, RNG | 0 failures | 53,490 failures on 4 of the 16-bit maps alone | not run |

IMAPB (truncation, as ST 1201 mandates): all 14 published IMAPB examples (96, 103, 104, 105, 109, 112, 113, 114, 117, 118, 119, 120, 132, 134) reproduce; rounding fails for 103/104/105. Decode then encode returns the same integer for every code of L = 1..3 of every ST 0601 IMAPB range (68.6 million codes) except y = 0 at L = 1 for ranges spanning zero (it decodes below the minimum, so it re-encodes as `E0`); `encode_packet` must therefore reuse `Item::raw` for unchanged items (D-23).

### 3.12 ST 0902.8 Minimum Metadata Set (Tables 1 and 2)

Requirements: ST 0902.3-01 (ST 0107, R-79), ST 0902.3-03 (populate per ST 0601, R-80), ST 0902.3-04 (every item at least every 30 s, R-81), ST 0902.8-05 (no ZLI to meet the minimum, R-52); ST 0902.3-02 (use the ST 0601 key) is deprecated but still true. Notes 1 and 2 of section 6: the alternatives below are "inclusive or" except 75 and 104 (exclusive), and item 94 is required once imagery leaves the platform plus ground station system (R-83, R-84). "Interval" is the informative Annex A recommendation ("Fast" = as often as possible, up to the frame rate). ST 0902 types and lengths are as printed (ST 0601.14 era); the encoder uses the ST 0601.19 format of 3.6 (R-80).

| ST 0601 tag | Item (ST 0902 wording) | ST 0902 type, length | Interval | Profile (D-15) |
|---|---|---|---|---|
| 1 | Checksum | uint16, 2 | Fast | every packet |
| 2 | Precision Time Stamp | uint64, 8 | Fast | every packet |
| 3 | Mission ID | ISO 646, variable (max 127) | 10 s | yes |
| 5 | Platform Heading Angle | uint16, 2 | Fast | yes |
| 6 or 90 | Platform Pitch Angle (Short / Full) | int16, 2 / int32, 4 | Fast | 90 |
| 7 or 91 | Platform Roll Angle (Short / Full) | int16, 2 / int32, 4 | Fast | 91 |
| 10 | Platform Designation | ISO 646, variable (max 127) | 10 s | yes |
| 11 | Image Source Sensor | ISO 646, variable (max 127) | 10 s | yes |
| 12 | Image Coordinate System | ISO 646, variable (max 127) | 10 s | yes, `Geodetic WGS84` |
| 13 | Sensor Latitude | int32, 4 | Fast | yes |
| 14 | Sensor Longitude | int32, 4 | Fast | yes |
| 15 or 75 or 104 | Sensor True Altitude (MSL) / Sensor Ellipsoid Height (HAE) / Extended (HAE) | uint16, 2 / uint16, 2 / IMAPB, 2 | Fast | 75 (or 104 by configuration) |
| 16 | Sensor Horizontal FoV | uint16, 2 | Fast | yes |
| 17 | Sensor Vertical FoV | uint16, 2 | Fast | yes |
| 18 | Sensor Relative Azimuth Angle | uint32, 4 | Fast | yes |
| 19 | Sensor Relative Elevation Angle | int32, 4 | Fast | yes |
| 20 | Sensor Relative Roll Angle | uint32, 4 | Fast | yes |
| 21 | Slant Range | uint32, 4 | Fast | yes |
| 22 or 96 | Target Width / Target Width Extended | uint16, 2 / IMAPB, 3 | Fast | 96 (3 bytes) |
| 23 | Frame Center Latitude | int32, 4 | Fast | yes |
| 24 | Frame Center Longitude | int32, 4 | Fast | yes |
| 25 or 78 | Frame Center Elevation (MSL) / Frame Center Height Above Ellipsoid (HAE) | uint16, 2 / uint16, 2 | Fast | 78 |
| 48/1 | Security Classification | uint8, 1 | 10 s | caller |
| 48/2 | Classifying Country and Releasing Instructions Country Coding Method | uint8, 1 | 10 s | caller |
| 48/3 | Classifying Country | ISO 646, variable | 10 s | caller |
| 48/4 | Security-SCI/SHI Information | ISO 646, variable | 10 s | caller, if ST 0102 requires |
| 48/5 | Caveats | ISO 646, variable | 10 s | caller, if ST 0102 requires |
| 48/6 | Releasing Instructions | ISO 646, variable | 10 s | caller, if ST 0102 requires |
| 48/12 | Object Country Coding Method | uint8, 1 | 10 s | caller |
| 48/13 | Object Country Codes | UTF-16, variable | 10 s | caller |
| 48/22 | Security Metadata Version | uint16, 2 | 10 s | caller / ST 0102 encoder |
| 65 | UAS Local Set Version | uint8, 1 | Fast | every packet (19) |
| 94 | Motion Imagery Core Identifier | binary, 50 (maximum; the Annex C example is 34) | 10 s | caller |

ST 0902 Annex A also notes that some security items are conditional per ST 0102, and Note 3 that the starred string lengths of Table 2 are only representative.

## 4. Decisions

**D-01 Item order.** Item 2 first, then every other item in ascending tag number (item 65 in its numeric place), item 1 last. Exception: an SDCC-FLP is written right after its source items (R-15). `ItemOrder::Caller` keeps the caller's order (2 and 1 still forced) for re-encoding. Rationale: R-11, R-12, R-14; ascending order reproduces ST 0902.8 Annex C packets A and B byte for byte (their order is 2, 3, 5, 6, 7, 10..25, 48, 65, 94, 1). Standard silent on the order otherwise.

**D-02 Key.** Always the 16 registered bytes with byte 8 = `0x01`; no option to change it (R-01 to R-03).

**D-03 BER lengths.** Minimal form everywhere: packet length, item lengths, every length inside packs and nested sets (R-06, R-07, R-31). No fixed long-form lengths, not even for live use: the builder computes the value size before writing the header (sizes are known once all items are encoded), then writes the checksum last. `smpte_klv::ber::BerForm::Minimal`.

**D-04 Tags.** Minimal BER-OID (R-08); tag 0 and tags above 143 are rejected except in `set_raw` pass-through (R-86).

**D-05 Item 65.** Written as 19 by default. An explicit override exists for two uses only: re-encoding recorded packets whose items are passed through unchanged (keep their original version) and reproducing published vectors (ST 0902 Annex C uses 6). Re-encoding a decoded packet keeps its original item 65 unless the caller sets it.

**D-06 Rounding.** Standard silent for linear maps except items 43/44 (`round`) and the item 81 example (nearest percent). Decision: round half away from zero (`f64::round`, the ST 1201.5 definition of "round") for every linearly mapped item, items 43/44 and the item 81 percentages; IMAPB uses ST 1201 truncation (R-34). Evidence in 3.11: round-to-nearest reproduces all 64 published examples and is exact for decode-then-encode; truncation fails both. Reference implementations agree: jMISB uses `Math.round` (`UasDatalinkAngle.java:73`, `UasDatalinkLatitude.java:74`, `UasDatalinkAltitude.java:65`), cbrl/klv uses `std::round` (`include/klv/codecs/mapped.hpp:116`).

**D-07 Out-of-range and special inputs** (`EncodeOptions::policy`, default `Strict`):

| Input | Strict (default) | Clamp |
|---|---|---|
| Outside range, item has Out of Range indicator (6, 7, 50-52, 79, 80, 90-93) | write the indicator (R-37), report a warning | same |
| Outside range, IMAPB item | write `E0 00..` / `E1 00..` (R-35), warning | clamp to [a, b], warning |
| Full-circle angle outside its range (5, 18, 19, 20, 35, 64, 71, 112, and the 142 start angles; never the 142 angular ranges) | reduce modulo 360 into the range (same angle, no warning); values inside the range, both ends included, are unchanged | same |
| Outside range, any other numeric item (e.g. 13 latitude 91, 15 altitude 20000, 8 speed 300) | error | clamp to the nearest end, warning |
| Off-earth point | only by explicit `OffEarth` value on items that define it (R-38) | same |
| NaN, infinity | error | error |
| Invalid enumeration / reserved code / PRF code / zero flags (R-39, R-42) | error | error |
| Offsets 26-33 beyond +/-0.075 | error (the profile writes 82-89 instead, R-40) | same |

Standard silent on input validation; the rule is "never write a non-conformant value and never silently change a meaningful value".

**D-08 IMAPB lengths.** Per-tag defaults in 3.8: 3 bytes for 96 (spec recommendation), 103-105 (spec: at least 3 for better than 1 m), 109, 113, 114, 132 (spec example length), 117-119 (finer than the 0.0625 deg/s of 2 bytes; KWIVER default per `specs/tables/st0601-c.md`); 2 bytes for 112, 120, 134 (spec example length). The caller may set a length (1..Max) or a precision g, from which L = ceil((ceil(log2(b - a)) - floor(log2(g)) + 1) / 8) (ST 1201.5 7.1.1), capped at Max Length; never above Max Length (R-28, R-30).

**D-09 Strings.** Sanitising per R-45/R-46 is applied in both modes (ST 0107 prescribes the removal), with a warning when anything was removed. Over-long strings: strict = error, clamp = cut at the last UTF-8 character boundary within the limit, warning. Empty string = `00`; unknown = ZLI (R-44). The C ABI validates UTF-8 before encoding.

**D-10 ISO 646.** Write UTF-8 (ST 0601.19). Option `ascii_only` (default off) rejects non-ASCII text; the ST 0902 profile warns on non-ASCII in items 3, 10, 11, 12 (R-47).

**D-11 ZLI.** `unknown(tag)` is accepted for every tag except 1, 2, 65, 66, 100, 101, 102, 115, 143 (R-48, R-49). It is never generated automatically for nested sets or packs (R-51). `misb::mux` writes a ZLI only for an item it reported with a value earlier in the same stream (R-50), for example when a value goes stale (plan section 6.3) or when a stream switches representation, and never to satisfy ST 0902 reporting (R-52).

**D-12 Multiplicity.** A second instance of a single-use item is an error; 100, 101, 102, 115 append (R-16).

**D-13 Representations.** By default only the preferred representation is written (90, 91, 92, 93, 82-89, 96, 103, 75 or 104, 78, 76 or 105). Legacy items (6, 7, 50, 52, 26-33, 22, 38, 15, 25, 69) are written only when the caller sets them; when both forms are set the checker warns if they differ by more than one LSB of the coarser item. 75 and 104 together is an error (R-83); 110 and 131 together is a warning (R-73).

**D-14 Deprecated / replaced.** Item 66: error (R-70). Items 60/61: accepted only with `allow_legacy` (default off); item 140 is the replacement (R-71).

**D-15 Default content profile = ST 0902.8 MISMMS.** Items per packet and rate:

| ST 0902 item | Profile choice | Source of value | Rate (D-16) |
|---|---|---|---|
| 1, 2, 65 | always | encoder | every packet |
| 3 Mission ID | required | caller | every 10 s |
| 5 Platform Heading | required | caller | every packet |
| 6 / 90 | 90 (full range, ST 0902 typical case) | caller | every packet |
| 7 / 91 | 91 | caller | every packet |
| 10, 11 | required | caller | every 10 s |
| 12 | required, default `Geodetic WGS84` | encoder default | every 10 s |
| 13, 14 | required | caller | every packet |
| 15 / 75 / 104 | 75 (HAE, 2 bytes fixed); 104 instead when configured for platforms above 19,000 m (3 bytes, 2 on request); fixed per stream, never both | caller | every packet |
| 16, 17, 18, 19, 20, 21 | required | caller | every packet |
| 22 / 96 | 96, 3 bytes (matches ST 0902 Table 1) | caller | every packet |
| 23, 24 | required (Off-Earth when applicable) | caller | every packet |
| 25 / 78 | 78 (HAE) | caller | every packet |
| 48 (ST 0102 items 1, 2, 3, 4, 5, 6, 12, 13, 22 as ST 0102 requires) | required | caller (never defaulted: classification is not invented) | every 10 s |
| 94 | required | caller (ST 1204) | every 10 s |

A packet missing a required profile item at its due time is an error in profile mode (`Profile::St0902`), or a warning with `Profile::St0902Lenient`; `Profile::None` checks only R-11 to R-13.

**D-16 Refresh scheduling.** Dynamic items: every packet. Known-Static items: refresh period default 10 s (the ST 0902 recommendation for constant items), configurable 1-30 s, hard cap 30 s (R-53), staggered across the period (R-55). List items: every element within the period (R-56); item 115 repeated every refresh period until acknowledged (R-57).

**D-17 Packet rate.** Standard silent (R-58). Keep the plan defaults (sync: every video frame up to 30 Hz; async: 10 Hz); ST 0902 Annex A's "up to the frame rate" supports capping at the frame rate.

**D-18 Packet size.** Standard silent (R-85). Default maximum 65,535 bytes for the whole packet (key + length + value), so the checksum-covered range always fits the 16-bit `len` of the reference `bcc_16` that some receivers implement literally; configurable up to 1 MiB (the decoder's default `max_packet_bytes`). Exceeding it is an error (split content over packets, e.g. list distribution, R-56).

**D-19 Pack truncation.** Fewest bytes (ST 0107 6.3.3 "reduce variable length items to their smallest length"): 127 omits a denominator of 1; 122 truncates trailing unknown countries; 130 omits a recovery location equal to take-off; 142 truncates trailing unknown pairs; 141 writes complete records whenever data is known.

**D-20 Item 63 code 8.** Allowed: Table 4 defines 8 "Continuous Zoom" although the summary table's Max still says 7.

**D-21 Segment / Amend children.** Standard silent on child order: 143 first, then ascending tags. The encoder never writes item 1 in a child and does not copy 2 or 65 into children (allowed only if the caller sets them, R-17). Level rules R-67 and security rule R-68 are enforced by the builder.

**D-22 Re-stamping item 2.** Re-stamping recorded packets (plan section 5, anchor option 4) is allowed only when the output video has no ST 0604 time stamps or they are rewritten with the same anchor; otherwise the CLI offers writing item 137 instead (R-26). The CLI states it re-stamps (already in the plan).

**D-23 Round-trip consequences for the decoder (phase 1 work, repos untouched here).** (a) The decoder maps a string value of exactly `00` to the text "\u{0}"; per R-44 it must decode to "" so that decode then encode is the identity. (b) `Value::OutOfRange` merges below/above (IMAPB) and Out of Range / Reserved / error codes; `encode_packet` must write unchanged items from `Item::raw`, and the builder offers explicit `ImapBelowMinimum`, `ImapAboveMaximum` and `OffEarth` inputs. (c) The 1-byte IMAPB y = 0 case of 3.11 also requires raw pass-through.

**D-24 Item 81 length.** Written as 4 bytes, or 20 bytes when both geo points are known (a point that cannot be computed is written as the "error" code). Lengths 8, 12, 16 are legal per the "optional" marks but jMISB rejects them (`specs/tables/st0601-b.md`).

**D-25 Item 115 time.** Omitted on the first packet of a command ID, included (original time) on repeats.

**D-26 Checksum implementation.** `usize` index, wrapping `u16`, computed over the final bytes in the output buffer (R-21, R-22).

**D-27 Negative zero.** Mapped and IMAPB items: -0.0 encodes exactly as +0.0 (R-36); `f64::round(-0.0)` converts to integer 0 and the IMAPB formula yields the zero code.

## 5. Unresolved

**U-01 ST 0107.5 not available.** ST 0601.19 references ST 0107.5 (Oct 2021); only ST 0107.4 (2019) could be obtained (`specs/tables/misc.md` S5). Requirement IDs 0107.2-01 to 0107.4-19 are cited from 0107.4; 0107.5 may renumber or add requirements.

**U-02 Motion Imagery Handbook not available.** ST 0601 and ST 0107 defer to the Handbook for Report-on-Change details, the Metadata Refresh Period definition (ST 0107.4: default 30 s window), truncation-pack rules and BER/BER-OID illustrations. The rules here use only the ST 0601/0107/0902 text.

**U-03 ST 0902.8 item 104 length.** ST 0902.8 Tables 1/2 give item 104 as IMAPB 2 bytes ("number of bytes allowed"); ST 0601.19 allows 1..8 and requires at least 3 bytes for sub-metre resolution. ST 0902.3-03 makes ST 0601 govern, so 3 bytes is conformant to ST 0601, but a checker reading ST 0902 Table 1 literally could flag it. D-15 avoids the question by defaulting to item 75; when 104 is chosen the length is configurable (2 for a literal ST 0902 reading).

**U-04 Max Length force.** ST 0601 calls Max Length "recommended" and strings "Suggested maximum"; ST 0107.3-07 says "shall not exceed". We enforce (R-28); the decoder stays lenient.

**U-05 IMAPB out-of-range flags in ST 0601 items.** The IMAPB items' summary tables say Special Values "None" while the ST 1201 forward algorithm produces IMAP_BELOW_MINIMUM / IMAP_ABOVE_MAXIMUM. Whether an ST 0601 checker accepts `E0`/`E1` there is not stated; misb decodes them as `Value::OutOfRange`. Clamp mode avoids them.

**U-06 Item 81 lengths 8, 12, 16.** Allowed by Table 6's optional marks, rejected by jMISB; we never write them (D-24).

**U-07 Content of nested items.** ST 0102 item requirements for item 48, ST 1204 generation for item 94, ST 0903 for item 74: other phase 0 topics. This document only fixes their framing (R-60, R-61, 3.7.1).

**U-08 Item 136 sign and value.** How leap seconds relate item 2 to UTC (and the current count) belongs to the ST 0603 time topic. The decoder's doc comment on tag 136 ("tag 2 plus this many seconds is UTC") should be checked there.

**U-09 ISO 646 vs UTF-8.** ST 0902.8 (based on ST 0601.14) types items 3, 10, 11, 12 as ISO 646; ST 0601.19 says utf8 (D-10 handles it). Which ST 0601 revision changed the wording is still unknown (`specs/tables/st0601-a.md`).

**U-10 Item order inside Amend for ST 1601.** `specs/tables/misc.md` records ST 1601 Appendix A placing item 98 as the final element of an Amend LS; to be settled with the phase 7 Segment/Amend work.
