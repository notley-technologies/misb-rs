/* ABI conformance and end-to-end check, driven by tests/c_abi.rs.
 *
 *   abi_test            print struct layout
 *   abi_test FILE.klv   also decode FILE.klv every way the API allows and
 *                       print what was found, one canonical line per item
 */
#include "misb.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S(s) printf("S %s %lu\n", #s, (unsigned long)sizeof(s));
#define F(s, f) printf("L %s.%s %lu\n", #s, #f, (unsigned long)offsetof(s, f));

static void layout(void) {
    S(misb_config)
    S(misb_stats)
    S(misb_packet_info)
    S(misb_item)
    S(misb_au_cell)
    S(misb_encode_options)
    S(misb_encode_error)
    S(misb_security)
    S(misb_utc)
    S(misb_st0604)
    F(misb_config, struct_size)
    F(misb_config, verify_checksum)
    F(misb_config, reject_bad_checksum)
    F(misb_config, reserved)
    F(misb_config, max_packet_bytes)
    F(misb_config, max_buffer_bytes)
    F(misb_config, max_depth)
    F(misb_config, max_items)
    F(misb_config, max_skip_bytes)
    F(misb_config, max_total_items)
    F(misb_config, keep_raw)
    F(misb_config, reserved2)
    F(misb_stats, struct_size)
    F(misb_stats, reserved)
    F(misb_stats, packets)
    F(misb_stats, bytes)
    F(misb_stats, bytes_skipped)
    F(misb_stats, resyncs)
    F(misb_stats, skipped_keys)
    F(misb_stats, oversized)
    F(misb_stats, checksum_errors)
    F(misb_stats, malformed)
    F(misb_stats, truncated_at_finish)
    F(misb_stats, dropped)
    F(misb_stats, checksum_missing)
    F(misb_stats, nested_errors)
    F(misb_stats, packet_bytes)
    F(misb_stats, bad_lengths)
    F(misb_packet_info, struct_size)
    F(misb_packet_info, standard)
    F(misb_packet_info, checksum)
    F(misb_packet_info, checksum_expected)
    F(misb_packet_info, checksum_computed)
    F(misb_packet_info, error)
    F(misb_packet_info, reserved)
    F(misb_packet_info, item_count)
    F(misb_packet_info, error_message)
    F(misb_item, struct_size)
    F(misb_item, kind)
    F(misb_item, packet)
    F(misb_item, id)
    F(misb_item, tag)
    F(misb_item, name)
    F(misb_item, units)
    F(misb_item, child_count)
    F(misb_item, uint_value)
    F(misb_item, int_value)
    F(misb_item, float_value)
    F(misb_item, time_us)
    F(misb_item, enum_code)
    F(misb_item, enum_label)
    F(misb_item, data)
    F(misb_item, data_len)
    F(misb_item, raw)
    F(misb_item, raw_len)
    F(misb_item, invalid_reason)
    F(misb_item, standard)
    F(misb_item, reserved)
    F(misb_au_cell, struct_size)
    F(misb_au_cell, service_id)
    F(misb_au_cell, sequence_number)
    F(misb_au_cell, fragment)
    F(misb_au_cell, decoder_config)
    F(misb_au_cell, random_access)
    F(misb_au_cell, reserved)
    F(misb_au_cell, data)
    F(misb_au_cell, data_len)
    F(misb_encode_options, struct_size)
    F(misb_encode_options, policy)
    F(misb_encode_options, order)
    F(misb_encode_options, allow_legacy)
    F(misb_encode_options, ascii_only)
    F(misb_encode_options, reserved)
    F(misb_encode_options, max_packet_bytes)
    F(misb_encode_error, struct_size)
    F(misb_encode_error, standard)
    F(misb_encode_error, tag)
    F(misb_encode_error, kind)
    F(misb_encode_error, reserved)
    F(misb_encode_error, reason)
    F(misb_security, struct_size)
    F(misb_security, classification)
    F(misb_security, country_coding_method)
    F(misb_security, object_country_coding_method)
    F(misb_security, version)
    F(misb_security, partial)
    F(misb_security, classifying_country)
    F(misb_security, sci_shi)
    F(misb_security, caveats)
    F(misb_security, releasing_instructions)
    F(misb_security, classified_by)
    F(misb_security, derived_from)
    F(misb_security, classification_reason)
    F(misb_security, declassification_date)
    F(misb_security, marking_system)
    F(misb_security, object_country_codes)
    F(misb_security, comments)
    F(misb_security, country_coding_method_date)
    F(misb_security, object_country_coding_method_date)
    F(misb_utc, struct_size)
    F(misb_utc, year)
    F(misb_utc, month)
    F(misb_utc, day)
    F(misb_utc, hour)
    F(misb_utc, minute)
    F(misb_utc, second)
    F(misb_utc, micros)
    F(misb_st0604, struct_size)
    F(misb_st0604, identifier)
    F(misb_st0604, status)
    F(misb_st0604, warnings)
    F(misb_st0604, value)
    F(misb_st0604, misp_us)
}

static misb_status check(const char *what, misb_status status) {
    if (status < 0) {
        fprintf(stderr, "%s: %s\n", what, misb_status_string(status));
        exit(1);
    }
    return status;
}

static void expect(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "failed: %s\n", what);
        exit(1);
    }
}

static void enc_check(const char *what, misb_status s) {
    if (s != MISB_OK) {
        fprintf(stderr, "%s returned %d (%s)\n", what, (int)s, misb_status_string(s));
        exit(1);
    }
}

static void hexline(const char *label, const uint8_t *b, size_t n) {
    size_t i;
    printf("ENC %s ", label);
    for (i = 0; i < n; i++) {
        printf("%02X", b[i]);
    }
    printf("\n");
}

/* The encoder: a packet built through every setter, compared by
 * tests/c_abi.rs with the Rust builder; errors, warnings, buffer sizes,
 * re-encoding and MISP time. */
static void encoder(void) {
    misb_encode_options opts;
    misb_encoder *e = NULL;
    misb_security sec;
    misb_encode_error err;
    misb_utc utc;
    misb_packet *p = NULL;
    uint8_t set[64], packet[512], again[512];
    size_t set_len = 0, len = 0, n = 0, count = 0;
    uint64_t misp = 0, leap = 0;

    memset(&opts, 0, sizeof opts);
    opts.struct_size = sizeof opts;
    enc_check("encode_options_default", misb_encode_options_default(&opts));
    printf("ENC OPTIONS policy=%u order=%u max=%llu\n", opts.policy, opts.order, (unsigned long long)opts.max_packet_bytes);

    memset(&sec, 0, sizeof sec);
    sec.struct_size = sizeof sec;
    sec.classification = 1;
    sec.country_coding_method = 0x0D;
    sec.classifying_country = "//US";
    sec.object_country_coding_method = 0x0D;
    sec.object_country_codes = "US";
    enc_check("security_encode", misb_security_encode(&sec, set, sizeof set, &set_len, NULL));
    hexline("SECURITY", set, set_len);
    sec.classifying_country = NULL;
    memset(&err, 0, sizeof err);
    err.struct_size = sizeof err;
    expect(misb_security_encode(&sec, set, sizeof set, &n, &err) == MISB_ERR_ENCODE, "a security set without tag 3");
    printf("ENC SECURITY_ERROR std=%u tag=%llu kind=%u\n", err.standard, (unsigned long long)err.tag, err.kind);
    sec.classifying_country = "//US";

    memset(&utc, 0, sizeof utc);
    utc.struct_size = sizeof utc;
    utc.year = 2022;
    utc.month = 7;
    utc.day = 12;
    utc.hour = 9;
    utc.minute = 5;
    utc.second = 3;
    utc.micros = 700;
    enc_check("misp_from_utc", misb_misp_from_utc(&utc, &misp));
    printf("ENC MISP %llu\n", (unsigned long long)misp);

    enc_check("encoder_new", misb_encoder_new(&opts, misp, &e));
    enc_check("set_text", misb_encoder_set_text(e, 3, "MISSION01", 9));
    enc_check("set_f64", misb_encoder_set_f64(e, 13, 60.176822966978335));
    enc_check("set_special", misb_encoder_set_special(e, 23, MISB_SPECIAL_OFF_EARTH));
    enc_check("set_code", misb_encoder_set_code(e, 34, 2));
    enc_check("set_imapb", misb_encoder_set_imapb(e, 117, 1.0, 2));
    enc_check("set_time", misb_encoder_set_time(e, 72, misp));
    enc_check("set_int", misb_encoder_set_int(e, 136, 29));
    enc_check("set_uint", misb_encoder_set_uint(e, 110, 19887));
    enc_check("unknown", misb_encoder_unknown(e, 21));
    enc_check("set_bytes", misb_encoder_set_bytes(e, 48, set, set_len));
    enc_check("set_raw", misb_encoder_set_raw(e, 200, (const uint8_t *)"private", 7));
    enc_check("set_f64 out of range indicator", misb_encoder_set_f64(e, 6, 25.0));
    /* Rejections add nothing and say why. */
    expect(misb_encoder_set_f64(e, 14, 181.0) == MISB_ERR_ENCODE, "longitude out of range");
    memset(&err, 0, sizeof err);
    err.struct_size = sizeof err;
    enc_check("last_error", misb_encoder_last_error(e, &err));
    printf("ENC ERROR std=%u tag=%llu kind=%u reason=%s\n", err.standard, (unsigned long long)err.tag, err.kind,
           err.reason);
    expect(misb_encoder_set_text(e, 4, "\xff", 1) == MISB_ERR_INVALID, "invalid UTF-8");
    expect(misb_encoder_set_f64(e, 9999, 1.0) == MISB_ERR_ENCODE, "an unknown tag");
    expect(misb_encoder_set_text(e, 3, "AGAIN", 5) == MISB_ERR_ENCODE, "a duplicate");
    err.struct_size = sizeof err;
    enc_check("last_error", misb_encoder_last_error(e, &err));
    printf("ENC DUPLICATE kind=%u\n", err.kind);
    expect(misb_encoder_set_special(e, 23, 99) == MISB_ERR_INVALID, "an unknown special");
    enc_check("warning_count", misb_encoder_warning_count(e, &count));
    printf("ENC WARNINGS %lu\n", (unsigned long)count);
    err.struct_size = sizeof err;
    enc_check("warning", misb_encoder_warning(e, 0, &err));
    printf("ENC WARNING tag=%llu kind=%u\n", (unsigned long long)err.tag, err.kind);
    expect(misb_encoder_warning(e, count, &err) == MISB_ERR_RANGE, "a warning past the last");
    expect(misb_encoder_finish(e, NULL, 0, &len) == MISB_ERR_TOO_SMALL && len > 0, "a size query");
    enc_check("finish", misb_encoder_finish(e, packet, sizeof packet, &len));
    hexline("PACKET", packet, len);
    expect(misb_encoder_last_error(e, &err) == MISB_EMPTY, "no error after a success");

    /* Re-encoding the decoded packet gives the same bytes. */
    enc_check("decode", misb_decode(packet, len, &p));
    enc_check("encode_packet", misb_encode_packet(p, NULL, again, sizeof again, &n, NULL));
    expect(n == len && memcmp(again, packet, n) == 0, "re-encoding");
    misb_packet_free(p);

    enc_check("reset", misb_encoder_reset(e, 1));
    enc_check("set_version", misb_encoder_set_version(e, 6));
    enc_check("finish", misb_encoder_finish(e, packet, sizeof packet, &len));
    hexline("EMPTY", packet, len);
    misb_encoder_free(e);
    misb_encoder_free(NULL);

    /* MISP time around the 2016 leap second. */
    utc.year = 2016;
    utc.month = 12;
    utc.day = 31;
    utc.hour = 23;
    utc.minute = 59;
    utc.second = 60;
    utc.micros = 500000;
    enc_check("misp_from_utc leap", misb_misp_from_utc(&utc, &leap));
    memset(&utc, 0, sizeof utc);
    utc.struct_size = sizeof utc;
    enc_check("misp_to_utc", misb_misp_to_utc(leap, &utc));
    printf("ENC LEAP %llu %04d-%02u-%02uT%02u:%02u:%02u.%06u\n", (unsigned long long)leap, utc.year, utc.month, utc.day,
           utc.hour, utc.minute, utc.second, utc.micros);
    enc_check("misp_from_posix_us", misb_misp_from_posix_us(1657616703000700LL, &misp));
    printf("ENC POSIX %llu\n", (unsigned long long)misp);
    printf("ENC VALID_UNTIL %lld\n", (long long)misb_leap_seconds_valid_until());
    printf("ENC STATUS %s|%s\n", misb_status_string(MISB_ERR_ENCODE), misb_status_string(MISB_ERR_TOO_SMALL));
}

static void t0604_hex(const char *label, const uint8_t *b, size_t n) {
    size_t i;
    printf("T0604 %s ", label);
    for (i = 0; i < n; i++) {
        printf("%02X", b[i]);
    }
    printf("\n");
}

/* ST 0604 timestamps: decoding the H.264 message of st1402-time.md section
 * 3.9, encoding it as H.265 nanoseconds, tolerated damage and refusals. */
static void st0604(void) {
    static const uint8_t h264[28] = {0x4D, 0x49, 0x53, 0x50, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73,
                                     0x65, 0x63, 0x74, 0x69, 0x6D, 0x65, 0x9F, 0x00, 0x05, 0xFF,
                                     0xE3, 0x97, 0xFF, 0xF8, 0x7C, 0xFF, 0x11, 0x6A};
    misb_st0604 ts, back;
    uint8_t buf[40], damaged[28];
    size_t len = 0;

    memset(&ts, 0, sizeof ts);
    ts.struct_size = sizeof ts;
    enc_check("st0604_decode", misb_st0604_decode(h264, sizeof h264, &ts));
    printf("T0604 DECODE id=%u status=%02X warnings=%u value=%llu misp=%llu\n", ts.identifier, ts.status, ts.warnings,
           (unsigned long long)ts.value, (unsigned long long)ts.misp_us);

    ts.identifier = MISB_ST0604_ID_HEVC_NANOSEC;
    ts.status = MISB_ST0604_STATUS_LOCKED;
    ts.value = ts.misp_us * 1000;
    expect(misb_st0604_encode(&ts, NULL, 0, &len) == MISB_ERR_TOO_SMALL && len == 28, "an ST 0604 size query");
    enc_check("st0604_encode", misb_st0604_encode(&ts, buf, sizeof buf, &len));
    t0604_hex("NANO", buf, len);
    memset(&back, 0, sizeof back);
    back.struct_size = sizeof back;
    enc_check("st0604_decode nano", misb_st0604_decode(buf, len, &back));
    enc_check("st0604_encode_payload", misb_st0604_encode_payload(&ts, buf, sizeof buf, &len));
    expect(len == 12, "a 12-byte payload");
    t0604_hex("PAYLOAD", buf, len);

    memcpy(damaged, h264, sizeof damaged);
    damaged[16] = 0x80;
    damaged[19] = 0x00;
    ts.struct_size = sizeof ts;
    enc_check("st0604_decode damaged", misb_st0604_decode(damaged, sizeof damaged, &ts));
    printf("T0604 TOLERATED status=%02X warnings=%u value=%llu\n", ts.status, ts.warnings, (unsigned long long)ts.value);
    printf("T0604 HEVC_NANO misp=%llu\n", (unsigned long long)back.misp_us);

    expect(misb_st0604_decode(h264 + 1, 27, &ts) == MISB_EMPTY, "not an ST 0604 identifier");
    expect(misb_st0604_decode(h264, 27, &ts) == MISB_ERR_PARSE, "an ST 0604 message cut short");
    expect(misb_st0604_decode(h264, 28, NULL) == MISB_ERR_NULL, "a NULL ST 0604 output");
    ts.status = 0x80;
    expect(misb_st0604_encode(&ts, buf, sizeof buf, &len) == MISB_ERR_INVALID, "an invalid Time Status");
    ts.status = MISB_ST0604_STATUS_LOCK_UNKNOWN;
    ts.identifier = 9;
    expect(misb_st0604_encode_payload(&ts, buf, sizeof buf, &len) == MISB_ERR_INVALID, "an unknown identifier");
}

static void hex(const uint8_t *p, uint64_t n) {
    uint64_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

static const char *or_dash(const char *s) {
    return s ? s : "-";
}

/* One line per item, children after their parent, depth first. */
static void item_line(const misb_item *it, int depth) {
    misb_item child;
    misb_packet_info info;
    uint64_t i, bits;

    expect(it->name != NULL && it->units != NULL, "name and units are never NULL");
    printf("ITEM %d tag=%llu kind=%u name=%s units=%s children=%llu raw=", depth, (unsigned long long)it->tag,
           it->kind, it->name, it->units, (unsigned long long)it->child_count);
    if (it->raw) {
        hex(it->raw, it->raw_len);
    } else {
        printf("-");
    }
    switch (it->kind) {
    case MISB_VALUE_UINT:
        printf(" u=%llu", (unsigned long long)it->uint_value);
        break;
    case MISB_VALUE_INT:
        printf(" i=%lld", (long long)it->int_value);
        break;
    case MISB_VALUE_FLOAT:
        memcpy(&bits, &it->float_value, sizeof bits);
        printf(" f=%016llx", (unsigned long long)bits);
        break;
    case MISB_VALUE_TEXT:
        printf(" text=");
        hex(it->data, it->data_len);
        printf(" nul=%d", it->data[it->data_len] == 0);
        break;
    case MISB_VALUE_BYTES:
        expect(it->data != NULL, "bytes are never NULL");
        printf(" bytes=");
        hex(it->data, it->data_len);
        break;
    case MISB_VALUE_TIME:
        printf(" time=%llu", (unsigned long long)it->time_us);
        break;
    case MISB_VALUE_ENUM:
        printf(" code=%llu label=%s", (unsigned long long)it->enum_code, or_dash(it->enum_label));
        break;
    case MISB_VALUE_SET:
        info.struct_size = sizeof info;
        check("set_info", misb_set_info_get(it, &info));
        expect(info.standard == it->standard && info.item_count == it->child_count, "set info agrees");
        printf(" std=%u (%s) checksum=%u error=%u msg=%s", it->standard, misb_standard_name(it->standard),
               info.checksum, info.error, or_dash(info.error_message));
        break;
    case MISB_VALUE_INVALID:
        printf(" reason=%s", it->invalid_reason);
        break;
    default:
        break;
    }
    printf("\n");
    for (i = 0; i < it->child_count; i++) {
        child.struct_size = sizeof child;
        check("child", misb_item_child(it, i, &child));
        item_line(&child, depth + 1);
    }
    child.struct_size = sizeof child;
    expect(misb_item_child(it, it->child_count, &child) == MISB_ERR_RANGE, "range error past the last child");
}

static void packet_lines(misb_packet *p) {
    misb_packet_info info;
    misb_item it, again;
    uint64_t i;

    info.struct_size = sizeof info;
    check("info", misb_packet_info_get(p, &info));
    printf("PACKET std=%u checksum=%u expected=%u computed=%u error=%u (%s) items=%llu msg=%s\n", info.standard,
           info.checksum, info.checksum_expected, info.checksum_computed, info.error, misb_error_name(info.error),
           (unsigned long long)info.item_count, or_dash(info.error_message));
    it.struct_size = sizeof it;
    check("root", misb_packet_root(p, &it));
    expect(it.kind == MISB_VALUE_SET && it.child_count == info.item_count && it.packet == p, "root");
    for (i = 0; i < info.item_count; i++) {
        it.struct_size = sizeof it;
        check("item", misb_packet_item(p, i, &it));
        again.struct_size = sizeof again;
        check("find", misb_packet_find(p, it.tag, &again));
        expect(again.tag == it.tag && again.id <= it.id, "find returns the first item with the tag");
        expect(misb_item_field(&it, "", &again) >= 0, "field lookup");
        item_line(&it, 1);
    }
    it.struct_size = sizeof it;
    expect(misb_packet_item(p, info.item_count, &it) == MISB_ERR_RANGE, "range error past the last item");
}

int main(int argc, char **argv) {
    misb_config config;
    misb_decoder *d = NULL;
    misb_packet *p = NULL;
    misb_stats stats;
    misb_au_cell cell;
    uint8_t *all = NULL, *pes;
    size_t total = 0, cap = 0, at, n, offset, used;
    uint32_t error;
    misb_status s;
    FILE *f;

    layout();
    printf("ABI %u VERSION %s\n", misb_abi_version(), misb_version());
    if (misb_abi_version() != MISB_ABI_VERSION || strcmp(misb_version(), MISB_VERSION_STRING) != 0) {
        fprintf(stderr, "library and header disagree\n");
        return 1;
    }
    if (argc < 2) {
        return 0;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 1;
    }
    for (;;) {
        if (total == cap) {
            cap = cap ? cap * 2 : 4096;
            all = realloc(all, cap);
            expect(all != NULL, "memory");
        }
        n = fread(all + total, 1, cap - total, f);
        if (n == 0) {
            break;
        }
        total += n;
    }
    fclose(f);

    /* The stream decoder, fed in awkward chunks. */
    config.struct_size = sizeof config;
    check("config_default", misb_config_default(&config));
    expect(config.verify_checksum == 1 && config.max_depth == 8, "defaults");
    expect(config.keep_raw == 1 && config.max_total_items == 65536, "new fields have defaults");
    config.verify_checksum = 2;
    expect(misb_decoder_new(&config, &d) == MISB_ERR_INVALID && d == NULL, "flags are 0 or 1");
    config.verify_checksum = 1;
    config.max_items = 0;
    expect(misb_decoder_new(&config, &d) == MISB_ERR_INVALID && d == NULL, "zero limits are refused");
    config.max_items = 65536;
    config.max_depth = 33;
    expect(misb_decoder_new(&config, &d) == MISB_ERR_INVALID && d == NULL, "depth above the ceiling is refused");
    config.max_depth = 8;
    check("new", misb_decoder_new(&config, &d));
    for (at = 0; at < total; at += n) {
        n = total - at < 7 ? total - at : 7;
        check("push", misb_decoder_push(d, all + at, n));
        while (check("next", misb_decoder_next(d, &p)) == MISB_OK) {
            packet_lines(p);
            misb_packet_free(p);
        }
        expect(p == NULL, "next clears out when empty");
    }
    check("finish", misb_decoder_finish(d));
    while (check("next", misb_decoder_next(d, &p)) == MISB_OK) {
        packet_lines(p);
        misb_packet_free(p);
    }
    stats.struct_size = sizeof stats;
    check("stats", misb_decoder_stats(d, &stats));
    printf("STATS packets=%llu bytes=%llu skipped=%llu resyncs=%llu keys=%llu oversized=%llu checksum_errors=%llu "
           "malformed=%llu truncated=%llu dropped=%llu missing=%llu nested=%llu packet_bytes=%llu bad_lengths=%llu\n",
           (unsigned long long)stats.packets, (unsigned long long)stats.bytes,
           (unsigned long long)stats.bytes_skipped, (unsigned long long)stats.resyncs,
           (unsigned long long)stats.skipped_keys, (unsigned long long)stats.oversized,
           (unsigned long long)stats.checksum_errors, (unsigned long long)stats.malformed,
           (unsigned long long)stats.truncated_at_finish, (unsigned long long)stats.dropped,
           (unsigned long long)stats.checksum_missing, (unsigned long long)stats.nested_errors,
           (unsigned long long)stats.packet_bytes, (unsigned long long)stats.bad_lengths);
    check("reset", misb_decoder_reset(d));
    misb_decoder_free(d);

    /* One packet at a time from the start of the buffer, until something
     * that is not an ST 0601 packet. */
    for (at = 0;;) {
        s = misb_decode_ex(all + at, total - at, NULL, &p, &used, &error);
        if (s != MISB_OK) {
            expect(p == NULL && used == 0, "nothing returned on error");
            printf("DECODE_END status=%d error=%u (%s) at=%lu\n", s, error, misb_error_name(error),
                   (unsigned long)at);
            break;
        }
        printf("DECODE at=%lu consumed=%lu\n", (unsigned long)at, (unsigned long)used);
        misb_packet_free(p);
        at += used;
    }
    check("decode", misb_decode(all, total, &p));
    misb_packet_free(p);
    expect(misb_decode(all, 3, &p) == MISB_ERR_PARSE && p == NULL, "a cut packet is a parse error");

    /* The first packet again, wrapped in a metadata AU cell. */
    check("decode", misb_decode_ex(all, total, NULL, &p, &used, NULL));
    misb_packet_free(p);
    pes = malloc(used + 5);
    expect(pes != NULL && used <= 0xFFFF, "memory");
    pes[0] = 0;
    pes[1] = 5;
    pes[2] = 0xD0; /* complete access unit, random access */
    pes[3] = (uint8_t)(used >> 8);
    pes[4] = (uint8_t)used;
    memcpy(pes + 5, all, used);
    offset = 0;
    for (;;) {
        cell.struct_size = sizeof cell;
        s = misb_au_cell_next(pes, used + 5, &offset, &cell);
        if (s != MISB_OK) {
            printf("CELL_END status=%d offset=%lu\n", s, (unsigned long)offset);
            break;
        }
        printf("CELL service=%u seq=%u fragment=%u config=%u random=%u len=%llu same=%d\n", cell.service_id,
               cell.sequence_number, cell.fragment, cell.decoder_config, cell.random_access,
               (unsigned long long)cell.data_len, memcmp(cell.data, all, used) == 0);
    }
    offset = 0;
    expect(misb_au_cell_next(pes, 4, &offset, &cell) == MISB_ERR_PARSE && offset == 0, "a cut cell");
    free(pes);
    free(all);

    expect(misb_value_kind_name(MISB_VALUE_INVALID) != NULL && misb_value_kind_name(0) == NULL, "kind names");
    expect(strcmp(misb_value_kind_name(MISB_VALUE_UNKNOWN), "unknown") == 0, "unknown kind name");
    expect(strcmp(misb_error_name(MISB_ERROR_TOO_MANY_ITEMS), "too many items") == 0 &&
               strcmp(misb_error_name(MISB_ERROR_INVALID_CONFIG), "invalid config") == 0,
           "new error names");
    expect(misb_decoder_push(NULL, NULL, 0) == MISB_ERR_NULL, "NULL decoder");
    printf("STATUS %s|%s\n", misb_status_string(MISB_ERR_PARSE), misb_status_string(42));
    encoder();
    st0604();
    printf("DONE\n");
    return 0;
}
