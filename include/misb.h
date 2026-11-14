/*
 * misb: MISB ST 0601 UAS Datalink Local Set decoder.
 *
 * Stable C ABI. Rules that hold for every function:
 *
 *  - Functions return a misb_status (0 on success, MISB_EMPTY when there is
 *    nothing to return, negative on error) unless documented otherwise.
 *    With panic unwinding enabled, an internal panic is reported as
 *    MISB_ERR_PANIC and a decoder is then unusable (MISB_ERR_POISONED) and
 *    must be freed.
 *  - Every pointer argument is checked for NULL. Pointers documented as
 *    optional may be NULL.
 *  - Structs that cross the boundary start with `struct_size`. Set it to
 *    sizeof(the struct) before passing it in. The library reads or writes
 *    only that many bytes, so newer libraries work with older headers and
 *    the other way round. On output, struct_size is set to the number of
 *    bytes written.
 *  - A decoder is not thread-safe: use each one from one thread at a time
 *    (it may move between threads). Separate decoders are independent. A
 *    packet never changes after it is created, so any number of threads may
 *    read one at once.
 *  - A packet owns everything it hands out. Every pointer in a misb_item or
 *    misb_packet_info filled from a packet (strings, data, raw bytes, the
 *    packet pointer itself) stays valid, and unchanged, until that packet
 *    is freed with misb_packet_free, and no longer. A packet does not
 *    depend on the decoder that produced it or on the input buffer it was
 *    decoded from. Strings returned by misb_version, misb_status_string and
 *    the misb_*_name functions are static.
 *  - Strings are NUL-terminated. Names and text are copied from the input
 *    or from the standards' tables as they are; a text value can contain a
 *    NUL byte, so use data_len for its full length.
 *
 * Compatibility: within one MISB_ABI_VERSION, functions, constants and
 * struct fields are only ever added (fields at the end), never changed.
 * Kind, standard, checksum and error codes are never reused. A newer
 * library can return codes this header does not list: treat an unknown
 * value kind as opaque (raw still holds the bytes of a set's items) and an
 * unknown error code as an error. The shared library's soname carries the
 * ABI version (libmisb.so.1). To detect a mismatched library at run time,
 * compare misb_abi_version() with MISB_ABI_VERSION.
 */
#ifndef MISB_H
#define MISB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MISB_ABI_VERSION 1

/* Version of the library this header came with. */
#define MISB_VERSION_MAJOR 0
#define MISB_VERSION_MINOR 1
#define MISB_VERSION_PATCH 0
#define MISB_VERSION_STRING "0.1.0"

/* ------------------------------------------------------------ status */

typedef int32_t misb_status;
#define MISB_OK 0
#define MISB_EMPTY 1            /* nothing to return: no packet waiting, no such item, no more cells */
#define MISB_ERR_NULL (-1)      /* a required pointer was NULL */
#define MISB_ERR_INVALID (-2)   /* an argument or struct field is invalid */
#define MISB_ERR_RANGE (-3)     /* an index or offset is out of range */
#define MISB_ERR_PARSE (-4)     /* not a complete ST 0601 packet (or AU cell) */
#define MISB_ERR_PANIC (-5)     /* internal error; a decoder is poisoned by it */
#define MISB_ERR_POISONED (-6)  /* the decoder failed earlier; free it */

/* ------------------------------------------------------------ codes */

/* Value kinds (misb_item.kind). Which misb_item fields a kind sets is
 * documented at misb_item. */
#define MISB_VALUE_UINT 1          /* unsigned integer */
#define MISB_VALUE_INT 2           /* signed integer */
#define MISB_VALUE_FLOAT 3         /* engineering value after the standard's mapping */
#define MISB_VALUE_TEXT 4          /* text (UTF-8; invalid sequences replaced) */
#define MISB_VALUE_BYTES 5         /* opaque bytes */
#define MISB_VALUE_TIME 6          /* MISP time, MISB ST 0603 */
#define MISB_VALUE_ENUM 7          /* enumerated code, with the standard's label when it has one */
#define MISB_VALUE_OUT_OF_RANGE 8  /* the standard's reserved "out of range" encoding */
#define MISB_VALUE_SET 9           /* nested local set (and the root of a packet) */
#define MISB_VALUE_LIST 10         /* ordered list of values */
#define MISB_VALUE_STRUCT 11       /* pack of named fields */
#define MISB_VALUE_INVALID 12      /* could not be decoded; see invalid_reason and raw */
#define MISB_VALUE_UNKNOWN 13      /* zero-length item: the producer says the value is not known */

/* Which standard a (possibly nested) local set follows. Top-level packets
 * are always ST 0601; the others appear nested inside it. */
#define MISB_STANDARD_ST0601 1  /* UAS Datalink Local Set */
#define MISB_STANDARD_ST0102 2  /* Security Metadata Local Set (ST 0601 tag 48) */
#define MISB_STANDARD_ST0806 3  /* Remote Video Terminal Local Set (ST 0601 tag 73) */
#define MISB_STANDARD_ST0903 4  /* Video Moving Target Indicator Local Set (ST 0601 tag 74) */

/* Outcome of the ST 0601 checksum check (tag 1, a 16-bit running sum over
 * the packet from the first key byte through the checksum's length byte).
 * MISSING counts as a failure, like MISMATCH: ST 0601 requires tag 1 as the
 * last item (ST 0601.8-11), so a top-level packet without it could not be
 * verified. With reject_bad_checksum a decoder drops both (counted in
 * checksum_errors and checksum_missing). */
#define MISB_CHECKSUM_NOT_APPLICABLE 0 /* nested sets, or checking turned off */
#define MISB_CHECKSUM_VALID 1
#define MISB_CHECKSUM_MISMATCH 2       /* see checksum_expected and checksum_computed */
#define MISB_CHECKSUM_MISSING 3        /* no 2-byte tag 1 as the last item: not verified, a failure */

/* Why a set stopped early, or why misb_decode_ex returned MISB_ERR_PARSE. */
#define MISB_ERROR_NONE 0
#define MISB_ERROR_TRUNCATED 1   /* input ended before the structure did */
#define MISB_ERROR_BAD_LENGTH 2  /* malformed BER length (reserved 0xFF, indefinite 0x80, too large) */
#define MISB_ERROR_BAD_TAG 3     /* malformed BER-OID tag */
#define MISB_ERROR_TOO_LARGE 4   /* packet value longer than max_packet_bytes */
#define MISB_ERROR_NOT_ST0601 5  /* the bytes do not start with the ST 0601 key */
#define MISB_ERROR_TOO_DEEP 6    /* sets nested deeper than max_depth */
#define MISB_ERROR_TOO_MANY_ITEMS 7 /* more items than max_items in a set, or max_total_items in a packet */
#define MISB_ERROR_INVALID_CONFIG 8 /* limits the library refuses (functions taking a config return MISB_ERR_INVALID) */

/* ------------------------------------------------------------ types */

typedef struct misb_decoder misb_decoder; /* opaque stream decoder */
typedef struct misb_packet misb_packet;   /* opaque decoded packet */

/* Limits and options; see the Rust `Config` docs. Fill with
 * misb_config_default, then change fields. Flags are 0 or 1. A function
 * that takes a config returns MISB_ERR_INVALID for a flag other than 0 or
 * 1, for max_packet_bytes, max_buffer_bytes, max_skip_bytes, max_items or
 * max_total_items of 0, and for max_depth above 32 (the hard ceiling that
 * keeps hostile nesting from exhausting the stack). A caller whose
 * struct_size ends before a field gets that field's default. */
typedef struct misb_config {
    uint32_t struct_size;
    uint32_t verify_checksum;     /* check the ST 0601 checksum, default 1 */
    uint32_t reject_bad_checksum; /* decoder drops packets that fail it or lack it, default 0 */
    uint32_t reserved;
    uint64_t max_packet_bytes;    /* largest packet value accepted, default 1 MiB */
    uint64_t max_buffer_bytes;    /* most bytes of complete packets queued, default 4 MiB */
    uint64_t max_depth;           /* deepest nesting of sets, 0 to 32, default 8 */
    uint64_t max_items;           /* most items decoded from one set, default 65536 */
    uint64_t max_skip_bytes;      /* longest KLV triplet skipped by its length, default 1 MiB */
    uint64_t max_total_items;     /* most items in one packet, nested sets included, default 65536 */
    uint32_t keep_raw;            /* keep raw bytes of validly decoded items, default 1 */
    uint32_t reserved2;
} misb_config;

/* Decoder counters since creation or the last reset; see the Rust `Stats`
 * docs. Byte counts are of input bytes. */
typedef struct misb_stats {
    uint32_t struct_size;
    uint32_t reserved;
    uint64_t packets;             /* packets returned by misb_decoder_next */
    uint64_t bytes;               /* bytes pushed */
    uint64_t bytes_skipped;       /* bytes not delivered in any packet */
    uint64_t resyncs;             /* runs of damaged bytes skipped to find the next key */
    uint64_t skipped_keys;        /* KLV packets skipped because their key is not ST 0601 */
    uint64_t oversized;           /* packets skipped for exceeding max_packet_bytes */
    uint64_t checksum_errors;     /* packets whose checksum did not match */
    uint64_t malformed;           /* packets returned with an error */
    uint64_t truncated_at_finish; /* incomplete packet cut off by misb_decoder_finish */
    uint64_t dropped;             /* complete packets dropped for exceeding max_buffer_bytes */
    uint64_t checksum_missing;    /* top-level packets without tag 1 as the last item */
    uint64_t nested_errors;       /* packets returned with a nested set that stopped early */
    uint64_t packet_bytes;        /* bytes of the packets returned; with bytes_skipped, all bytes once drained */
    uint64_t bad_lengths;         /* candidate keys followed by a malformed or unskippable length */
} misb_stats;

/* A packet, or a set nested inside one (misb_set_info_get). */
typedef struct misb_packet_info {
    uint32_t struct_size;
    uint32_t standard;           /* MISB_STANDARD_* */
    uint32_t checksum;           /* MISB_CHECKSUM_* */
    uint16_t checksum_expected;  /* with MISMATCH: value carried in tag 1; else 0 */
    uint16_t checksum_computed;  /* with MISMATCH: value computed over the packet; else 0 */
    uint32_t error;              /* MISB_ERROR_*: parsing stopped early; the items before are kept */
    uint32_t reserved;
    uint64_t item_count;         /* items decoded */
    const char *error_message;   /* says what went wrong; NULL with MISB_ERROR_NONE */
} misb_packet_info;

/*
 * One node of a packet's value tree. A packet's root is a SET whose
 * children are the packet's items; a nested set's children are its items;
 * a list's children are its elements; a struct's children are its fields.
 * Walk the tree with misb_item_child, or look children up with
 * misb_item_find and misb_item_field.
 *
 * Fields set for every kind:
 *   tag         items of a set: the local tag. List elements and struct
 *               fields: their index. The root: 0.
 *   name        items of a set: the standard's name for the tag, "Unknown"
 *               for tags it does not define. Struct fields: the field
 *               name. List elements: "". The root: the standard's title.
 *               Never NULL.
 *   units       items of a set: e.g. "deg", "m", "m/s"; "" when none, and
 *               for list elements and struct fields (the units of the
 *               enclosing item apply). Never NULL.
 *   raw         items of a set: the value bytes exactly as received, never
 *               NULL (raw_len 0 for an UNKNOWN item, and for validly decoded
 *               items when keep_raw is 0). Others: NULL with raw_len 0.
 *   child_count SET, LIST and STRUCT: number of children. Others: 0.
 *
 * Fields set by kind (all others are 0 or NULL):
 *   UINT         uint_value
 *   INT          int_value
 *   FLOAT        float_value. Can be NaN or infinite (for example an ST 1201
 *                IMAPB special value).
 *   TEXT         data, data_len: the text, also NUL-terminated
 *                (data[data_len] == 0). Never NULL.
 *   BYTES        data, data_len. Never NULL, even when data_len is 0.
 *   TIME         time_us: microseconds since 1970-01-01T00:00:00, every day
 *                86,400 seconds (MISP time, MISB ST 0603). Not UTC: MISP
 *                time has no leap seconds and is ahead of UTC by the leap
 *                seconds since 1972 less 8.000082 s (28.999918 s since
 *                2017), unless the producer wrote POSIX time; ST 0601 tag
 *                136 carries the offset. The library applies none.
 *   ENUM         enum_code; enum_label is the standard's name for the code,
 *                or NULL when it defines none.
 *   OUT_OF_RANGE nothing: the standard's reserved error encoding was
 *                received (e.g. 0x8000 for a mapped int16); see raw.
 *   SET          standard (MISB_STANDARD_*), child_count. Checksum and parse
 *                errors of the set: misb_set_info_get.
 *   LIST         child_count
 *   STRUCT       child_count
 *   INVALID      invalid_reason says why; raw keeps the bytes.
 *   UNKNOWN      nothing: a zero-length item, which ST 0601.19 section 6.5
 *                and MISB ST 0107 read as "the value is not known". Not an
 *                error. Only items a standard allows to be unknown decode
 *                to this; a zero-length mandatory or repeatable item is
 *                INVALID.
 *
 * packet and id identify the item for misb_item_child, misb_item_find,
 * misb_item_field and misb_set_info_get; do not change them.
 */
typedef struct misb_item {
    uint32_t struct_size;
    uint32_t kind;              /* MISB_VALUE_* */
    const misb_packet *packet;  /* the packet the item belongs to */
    uint64_t id;                /* the item's position in the packet */
    uint64_t tag;
    const char *name;
    const char *units;
    uint64_t child_count;
    uint64_t uint_value;
    int64_t int_value;
    double float_value;
    uint64_t time_us;
    uint64_t enum_code;
    const char *enum_label;
    const uint8_t *data;
    uint64_t data_len;
    const uint8_t *raw;
    uint64_t raw_len;
    const char *invalid_reason;
    uint32_t standard;
    uint32_t reserved;
} misb_item;

/* One metadata access unit cell (ISO/IEC 13818-1 section 2.12.4, Table
 * 2-97), as carried in synchronous KLV PES packets (MISB ST 1402). */
typedef struct misb_au_cell {
    uint32_t struct_size;
    uint8_t service_id;       /* metadata_service_id */
    uint8_t sequence_number;
    uint8_t fragment;         /* cell_fragment_indication: 3 complete, 2 first, 1 last, 0 middle */
    uint8_t decoder_config;   /* decoder_config_flag, 0 or 1 */
    uint8_t random_access;    /* random_access_indicator, 0 or 1 */
    uint8_t reserved[7];
    const uint8_t *data;      /* AU_cell_data_byte bytes: for KLV, whole KLV packets; never NULL */
    uint64_t data_len;
} misb_au_cell;

/* ------------------------------------------------------------ library */

uint32_t misb_abi_version(void);
const char *misb_version(void);                   /* e.g. "0.1.0" */
const char *misb_status_string(misb_status status);
const char *misb_value_kind_name(uint32_t kind);  /* e.g. "float"; NULL for unknown codes */
const char *misb_standard_name(uint32_t standard); /* e.g. "ST 0601"; NULL for unknown codes */
const char *misb_error_name(uint32_t error);      /* e.g. "truncated"; NULL for unknown codes */

/* ------------------------------------------------------------ decoder */

/* A decoder takes a stream of KLV, such as a .klv file or the payload of
 * an asynchronous KLV elementary stream (MISB ST 1402), in chunks of any
 * size, and returns the ST 0601 packets in it. Packets with other keys are
 * skipped by their declared length (counted in skipped_keys); damaged bytes
 * are skipped by scanning for the next key. Sets nested deeper than
 * max_depth (at most 32) stop with MISB_ERROR_TOO_DEEP.
 *
 * Drain with misb_decoder_next after every push. Complete packets wait in a
 * queue of at most max_buffer_bytes (each charged its size plus about 64
 * bytes); a packet that would overfill it is dropped and counted in
 * dropped, and one push can complete that many packets by itself, even if
 * the caller drains straight after it. So push large buffers, such as a
 * whole file, in slices: with the default limits, slices of up to 64 KiB
 * never drop a packet when the queue is drained after each one, and in
 * general slices of at most (max_buffer_bytes - max_packet_bytes - 1024) / 8
 * bytes do not. The packets found do not depend on how the input is split
 * as long as nothing is dropped. */

misb_status misb_config_default(misb_config *config);

/* `config` may be NULL for defaults; MISB_ERR_INVALID for a config the
 * library refuses (see misb_config). On error *out is set to NULL. */
misb_status misb_decoder_new(const misb_config *config, misb_decoder **out);
void misb_decoder_free(misb_decoder *decoder); /* NULL is ignored */

/* Feed bytes. `data` may be NULL when len is 0. Packets completed beyond
 * max_buffer_bytes are dropped (see above): drain after every push. */
misb_status misb_decoder_push(misb_decoder *decoder, const uint8_t *data, size_t len);
/* End of input: an incomplete trailing packet is dropped (counted in
 * truncated_at_finish). Complete packets stay available, and the decoder
 * can be fed again afterwards. */
misb_status misb_decoder_finish(misb_decoder *decoder);
/* Forget all buffered input, queued packets and counters. Packets already
 * returned are not affected. */
misb_status misb_decoder_reset(misb_decoder *decoder);

/* Take the oldest complete packet: *out receives a new packet that the
 * caller frees with misb_packet_free. Returns MISB_EMPTY, with *out set to
 * NULL, when none is waiting. */
misb_status misb_decoder_next(misb_decoder *decoder, misb_packet **out);
misb_status misb_decoder_stats(const misb_decoder *decoder, misb_stats *out);

/* ------------------------------------------------------------ packets */

/* Decode exactly one ST 0601 packet at the start of `data` with the
 * default config; trailing bytes are ignored. `data` may be NULL when len
 * is 0. Returns MISB_ERR_PARSE, with *out set to NULL, if `data` does not
 * start with a complete ST 0601 packet (16-byte key, BER length, value)
 * whose value fits max_packet_bytes. The key's version byte (byte 8, SMPTE
 * ST 336) is not compared. Problems inside the packet are not errors here:
 * misb_packet_info_get reports them. */
misb_status misb_decode(const uint8_t *data, size_t len, misb_packet **out);

/* As misb_decode, with a config (NULL for defaults) and two optional out
 * pointers: *consumed receives the bytes the packet occupies (key, length
 * and value; 0 on error), so the next packet of a buffer starts there, and
 * *error the MISB_ERROR_* reason for MISB_ERR_PARSE (MISB_ERROR_NONE
 * otherwise). A declared length over max_packet_bytes is
 * MISB_ERROR_TOO_LARGE even when the buffer is cut short, so a caller that
 * reads more input on MISB_ERROR_TRUNCATED is never asked for more than the
 * limit. A config the library refuses gives MISB_ERR_INVALID. Unlike a
 * decoder, this does not skip damaged bytes or other keys. */
misb_status misb_decode_ex(const uint8_t *data, size_t len, const misb_config *config,
                           misb_packet **out, size_t *consumed, uint32_t *error);

void misb_packet_free(misb_packet *packet); /* NULL is ignored */

/* Standard, checksum outcome, parse error and item count of the packet.
 * error_message stays valid until the packet is freed. */
misb_status misb_packet_info_get(const misb_packet *packet, misb_packet_info *out);

/* The root of the value tree: a SET (tag 0) whose children are the
 * packet's items. */
misb_status misb_packet_root(const misb_packet *packet, misb_item *out);
/* The packet's item at `index`, in the order received; MISB_ERR_RANGE
 * past the last. */
misb_status misb_packet_item(const misb_packet *packet, size_t index, misb_item *out);
/* The packet's first item with this tag; MISB_EMPTY if there is none. */
misb_status misb_packet_find(const misb_packet *packet, uint64_t tag, misb_item *out);

/* `parent` is an item the library filled in. `out` may be the same struct
 * as `parent`. A parent whose packet or id is not one the library wrote
 * gives MISB_ERR_INVALID. */

/* The child at `index`; MISB_ERR_RANGE past the last (always, for kinds
 * without children). */
misb_status misb_item_child(const misb_item *parent, size_t index, misb_item *out);
/* The first child with this tag (for a list or struct: this index);
 * MISB_EMPTY if there is none. */
misb_status misb_item_find(const misb_item *parent, uint64_t tag, misb_item *out);
/* The first child with this name (a struct field, or a set item by its
 * tag name); MISB_EMPTY if there is none. */
misb_status misb_item_field(const misb_item *parent, const char *name, misb_item *out);
/* Standard, parse error and item count of a SET item (checksum is
 * MISB_CHECKSUM_NOT_APPLICABLE for nested sets). MISB_ERR_INVALID for
 * other kinds. */
misb_status misb_set_info_get(const misb_item *set, misb_packet_info *out);

/* ------------------------------------------------------------ AU cells */

/* Split a synchronous metadata PES payload into its access unit cells.
 * Start with *offset = 0 and call until the status is not MISB_OK: each
 * MISB_OK fills `out` with the cell at *offset and moves *offset past it.
 * Returns MISB_EMPTY at the end of the data, MISB_ERR_PARSE (leaving
 * *offset unchanged) if the cell there is cut short, and MISB_ERR_RANGE if
 * *offset is beyond len. out->data points into `data` (or, when data_len is
 * 0, at a static byte), so it is valid as long as `data` is. `data` may be
 * NULL when len is 0. */
misb_status misb_au_cell_next(const uint8_t *data, size_t len, size_t *offset, misb_au_cell *out);

#ifdef __cplusplus
}
#endif

#endif /* MISB_H */
