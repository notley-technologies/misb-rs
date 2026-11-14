/* Print every MISB ST 0601 packet in a file of KLV as a tree of items.
 *
 * Against an installed library (`make install`):
 *
 *   cc misb_dump.c $(pkg-config --cflags --libs misb) -o misb_dump
 *
 * or with CMake, see CMakeLists.txt next to this file. Straight from the
 * build tree:
 *
 *   cargo build --release
 *   cc -I include examples/c/misb_dump.c -L target/release -lmisb -o misb_dump
 *   LD_LIBRARY_PATH=target/release ./misb_dump packets.klv
 *
 * With no file name, or "-", it reads standard input. A summary goes to
 * standard error.
 */
#include "misb.h"

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int fail(const char *what, misb_status status) {
    fprintf(stderr, "misb_dump: %s: %s\n", what, misb_status_string(status));
    return 1;
}

/* Display the continuous MISP time scale used by the Rust API. */
static void print_time(uint64_t us) {
    unsigned long long days = us / 86400000000ULL, rem = us % 86400000000ULL;
    unsigned long long z = days + 719468, era = z / 146097, doe = z % 146097;
    unsigned long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned long long mp = (5 * doy + 2) / 153;
    unsigned long long day = doy - (153 * mp + 2) / 5 + 1;
    unsigned long long month = mp < 10 ? mp + 3 : mp - 9;
    unsigned long long year = yoe + era * 400 + (month <= 2);
    unsigned long long secs = rem / 1000000;
    printf("%04llu-%02llu-%02lluT%02llu:%02llu:%02llu.%06llu MISP", year, month, day, secs / 3600, secs / 60 % 60,
           secs % 60, rem % 1000000);
}

/* Text in quotes, with anything unprintable escaped. data_len, not the
 * NUL terminator, gives the length: text can contain NUL bytes. */
static void print_text(const uint8_t *p, uint64_t n) {
    uint64_t i;
    putchar('"');
    for (i = 0; i < n; i++) {
        if (p[i] == '"' || p[i] == '\\') {
            printf("\\%c", p[i]);
        } else if (p[i] >= 0x20 && p[i] < 0x7F) {
            putchar(p[i]);
        } else {
            printf("\\x%02X", p[i]);
        }
    }
    putchar('"');
}

static void print_bytes(const uint8_t *p, uint64_t n) {
    uint64_t i;
    for (i = 0; i < n && i < 32; i++) {
        printf("%s%02X", i ? " " : "", p[i]);
    }
    if (n > 32) {
        printf(" ... (%llu bytes)", (unsigned long long)n);
    } else if (n == 0) {
        printf("(empty)");
    }
}

static misb_status print_item(const misb_item *it, int depth, uint32_t parent_kind) {
    misb_packet_info info;
    misb_item child;
    misb_status s;
    uint64_t i;

    /* Children start under their parent's name. */
    printf("%*s", 4 * depth - 2, "");
    if (parent_kind == MISB_VALUE_LIST) {
        printf("[%llu] ", (unsigned long long)it->tag);
    } else if (parent_kind == MISB_VALUE_STRUCT) {
        printf("%s: ", it->name);
    } else {
        printf("%3llu %s: ", (unsigned long long)it->tag, it->name);
    }
    switch (it->kind) {
    case MISB_VALUE_UINT:
        printf("%llu", (unsigned long long)it->uint_value);
        break;
    case MISB_VALUE_INT:
        printf("%lld", (long long)it->int_value);
        break;
    case MISB_VALUE_FLOAT:
        printf("%.15g", it->float_value);
        break;
    case MISB_VALUE_TEXT:
        print_text(it->data, it->data_len);
        break;
    case MISB_VALUE_BYTES:
        print_bytes(it->data, it->data_len);
        break;
    case MISB_VALUE_TIME:
        print_time(it->time_us);
        break;
    case MISB_VALUE_ENUM:
        if (it->enum_label) {
            printf("%s (%llu)", it->enum_label, (unsigned long long)it->enum_code);
        } else {
            printf("%llu", (unsigned long long)it->enum_code);
        }
        break;
    case MISB_VALUE_OUT_OF_RANGE:
        printf("out of range");
        break;
    case MISB_VALUE_SET:
        info.struct_size = sizeof info;
        if ((s = misb_set_info_get(it, &info)) != MISB_OK) {
            return s;
        }
        printf("%s set, %llu items", misb_standard_name(it->standard), (unsigned long long)info.item_count);
        if (info.error_message) {
            printf(", error: %s", info.error_message);
        }
        break;
    case MISB_VALUE_LIST:
        printf("list of %llu", (unsigned long long)it->child_count);
        break;
    case MISB_VALUE_STRUCT:
        printf("%llu fields", (unsigned long long)it->child_count);
        break;
    case MISB_VALUE_INVALID:
        printf("invalid (%s): ", it->invalid_reason);
        print_bytes(it->raw, it->raw_len);
        break;
    case MISB_VALUE_UNKNOWN: /* a zero-length item */
        printf("unknown");
        break;
    default: /* a kind newer than this program */
        printf("kind %u", it->kind);
        break;
    }
    if (it->units[0] && (it->kind == MISB_VALUE_UINT || it->kind == MISB_VALUE_INT || it->kind == MISB_VALUE_FLOAT)) {
        printf(" %s", it->units);
    }
    printf("\n");
    for (i = 0; i < it->child_count; i++) {
        child.struct_size = sizeof child;
        if ((s = misb_item_child(it, (size_t)i, &child)) != MISB_OK || (s = print_item(&child, depth + 1, it->kind)) != MISB_OK) {
            return s;
        }
    }
    return MISB_OK;
}

static misb_status print_packet(misb_packet *p, unsigned long long number) {
    misb_packet_info info;
    misb_item root, it;
    misb_status s;
    uint64_t i;

    info.struct_size = sizeof info;
    root.struct_size = sizeof root;
    if ((s = misb_packet_info_get(p, &info)) != MISB_OK || (s = misb_packet_root(p, &root)) != MISB_OK) {
        return s;
    }
    printf("packet %llu: %s %s, ", number, misb_standard_name(info.standard), root.name);
    switch (info.checksum) {
    case MISB_CHECKSUM_VALID:
        printf("checksum ok");
        break;
    case MISB_CHECKSUM_MISMATCH:
        printf("checksum MISMATCH (carried %04X, computed %04X)", info.checksum_expected, info.checksum_computed);
        break;
    case MISB_CHECKSUM_MISSING:
        printf("checksum missing");
        break;
    default:
        printf("checksum not checked");
        break;
    }
    printf(", %llu items", (unsigned long long)info.item_count);
    if (info.error_message) {
        printf(", error: %s", info.error_message);
    }
    printf("\n");
    for (i = 0; i < info.item_count; i++) {
        it.struct_size = sizeof it;
        if ((s = misb_packet_item(p, (size_t)i, &it)) != MISB_OK || (s = print_item(&it, 1, MISB_VALUE_SET)) != MISB_OK) {
            return s;
        }
    }
    return MISB_OK;
}

/* Print and free every packet waiting in the decoder. */
static misb_status drain(misb_decoder *d, unsigned long long *count) {
    misb_packet *p;
    misb_status s;
    for (;;) {
        if ((s = misb_decoder_next(d, &p)) != MISB_OK) {
            return s == MISB_EMPTY ? MISB_OK : s;
        }
        s = print_packet(p, ++*count);
        misb_packet_free(p);
        if (s != MISB_OK) {
            return s;
        }
    }
}

int main(int argc, char **argv) {
    misb_decoder *d = NULL;
    misb_stats stats;
    unsigned char buf[4096];
    unsigned long long count = 0;
    size_t n;
    misb_status s;
    FILE *f = stdin;
    int status = 0;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [FILE.klv]\n", argv[0]);
        return 2;
    }
    if (misb_abi_version() != MISB_ABI_VERSION) {
        fprintf(stderr, "libmisb has ABI %u, this program needs %d\n", misb_abi_version(), MISB_ABI_VERSION);
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "-") != 0) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror(argv[1]);
            return 1;
        }
    }
#ifdef _WIN32
    else {
        _setmode(_fileno(stdin), _O_BINARY);
    }
#endif
    if ((s = misb_decoder_new(NULL, &d)) != MISB_OK) {
        return fail("new", s);
    }
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if ((s = misb_decoder_push(d, buf, n)) != MISB_OK || (s = drain(d, &count)) != MISB_OK) {
            status = fail("decode", s);
            break;
        }
    }
    if (ferror(f)) {
        perror("read");
        status = 1;
    }
    if (f != stdin) {
        fclose(f);
    }
    if (status == 0 && ((s = misb_decoder_finish(d)) != MISB_OK || (s = drain(d, &count)) != MISB_OK)) {
        status = fail("finish", s);
    }
    stats.struct_size = sizeof stats;
    if (status == 0 && (s = misb_decoder_stats(d, &stats)) == MISB_OK) {
        fprintf(stderr, "misb_dump: %llu packets, %llu bytes, %llu skipped, %llu checksum errors\n", count,
                (unsigned long long)stats.bytes, (unsigned long long)stats.bytes_skipped,
                (unsigned long long)stats.checksum_errors);
    }
    misb_decoder_free(d);
    return status;
}
