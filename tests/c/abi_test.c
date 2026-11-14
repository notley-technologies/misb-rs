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
    printf("DONE\n");
    return 0;
}
