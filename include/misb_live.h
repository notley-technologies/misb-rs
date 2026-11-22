/*
 * misb_live.h - live MISB ST 0601 KLV injection into MPEG transport streams.
 *
 * Available in libraries built with the `capi` and `mux` features
 * (`make FEATURES=mux`), which also export the mpegts C API (mpegts.h).
 * The rules of misb.h apply: every function returns a misb_status, structs
 * start with struct_size (set it to sizeof before passing a struct in or
 * out), additions are appended, no function unwinds into C, and a panic
 * poisons the handle (MISB_ERR_POISONED from then on).
 *
 * A live injector copies a live transport stream through and, for each
 * video frame its rate admits, inserts one ST 0601 packet built from the
 * current values: tag 2 is the frame's MISP time and, for synchronous KLV,
 * the PES PTS is the frame's PTS, sent right before the frame. Change the
 * values at any time between pushes; each packet is one consistent
 * snapshot, and a change shows on the next frame. Nothing waits for a PCR:
 * with video timestamps off, every input packet is handed to the sink
 * before misb_live_push returns (zero added latency). There are no threads
 * and no clock inside: pass the wall-clock MISP time of each push
 * (microseconds since 1970 in MISP time, TAI - 8.000082 s; not POSIX time,
 * see misb_misp_from_utc).
 *
 * Not thread-safe: use one handle from one thread at a time.
 */
#ifndef MISB_LIVE_H
#define MISB_LIVE_H

#include "misb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The injector stopped (input it cannot pass through, no room in strict
 * CBR, ...): misb_live_error says why; further pushes fail the same way. */
#define MISB_ERR_STREAM (-9)

typedef struct misb_live misb_live; /* opaque */

/* misb_live_config.carriage */
#define MISB_LIVE_SYNC 1  /* stream_type 0x15, a PTS on every packet (default) */
#define MISB_LIVE_ASYNC 2 /* stream_type 0x06 (SMPTE RP 217), no PTS */

/* misb_live_config.rate */
#define MISB_LIVE_RATE_DEFAULT 0     /* sync: every frame up to 30 Hz; async: 10 Hz */
#define MISB_LIVE_RATE_EVERY_FRAME 1
#define MISB_LIVE_RATE_EVERY_NTH 2   /* every rate_value-th frame */
#define MISB_LIVE_RATE_HZ 3          /* at most rate_value packets per second */

/* misb_live_config.anchor: where MISP time meets the program clock */
#define MISB_LIVE_ANCHOR_WALL_CLOCK 0  /* the first frame is at the now_us of its push (default) */
#define MISB_LIVE_ANCHOR_FIRST_FRAME 1 /* the first frame is at anchor_misp_us */
#define MISB_LIVE_ANCHOR_PTS 2         /* PTS anchor_pts is at anchor_misp_us */

/* misb_live_config.timestamps: MISB ST 0604 timestamps in H.264/H.265 video */
#define MISB_LIVE_TIMESTAMPS_OFF 0     /* the video is never changed (default) */
#define MISB_LIVE_TIMESTAMPS_ADD 1     /* added to access units without one */
#define MISB_LIVE_TIMESTAMPS_REWRITE 2 /* every access unit; existing ones replaced */

/* misb_live_config.flags */
#define MISB_LIVE_VIDEO_ANCHOR 0x01   /* take MISP time from the video's ST 0604 timestamps */
#define MISB_LIVE_LOCKED 0x02         /* written timestamps assert lock to absolute time */
#define MISB_LIVE_NANOSECONDS 0x04    /* H.265: nanosecond timestamps */
#define MISB_LIVE_STALE_UNKNOWN 0x08  /* stale values are sent as unknown, not left out */
#define MISB_LIVE_CBR 0x10            /* strict CBR: KLV and tables replace null packets */
#define MISB_LIVE_CBR_DROP 0x20       /* with CBR, drop units without room instead of failing */
#define MISB_LIVE_HAS_PID 0x40        /* use pid for the KLV stream (else a free one) */
#define MISB_LIVE_HAS_SERVICE_ID 0x80 /* use service_id (else the lowest free one) */
#define MISB_LIVE_CELLS_PER_AU 0x100  /* number cells from 0 in each access unit, not per stream:
                                       * a workaround for receivers such as MediaMTX (X-8) */

/* Settings. Fill with misb_live_config_default, then change fields. */
typedef struct misb_live_config {
    uint32_t struct_size;
    uint32_t carriage;   /* MISB_LIVE_SYNC or _ASYNC */
    uint32_t flags;      /* MISB_LIVE_* flags */
    uint32_t rate;       /* MISB_LIVE_RATE_* */
    double rate_value;   /* N or Hz for the rates that take one */
    uint32_t anchor;     /* MISB_LIVE_ANCHOR_* */
    uint32_t timestamps; /* MISB_LIVE_TIMESTAMPS_* */
    uint64_t anchor_pts;     /* 90 kHz, below 2^33 */
    uint64_t anchor_misp_us; /* MISP microseconds */
    uint64_t max_age_us;     /* a value older than this is stale; 0: never */
    uint32_t program;        /* program_number, or 0: the first program with video */
    uint32_t existing_klv;   /* MPEGTS_EXISTING_KLV_* of mpegts.h: keep 0, replace 1, fail 2 */
    uint16_t pid;            /* with MISB_LIVE_HAS_PID */
    uint8_t service_id;      /* with MISB_LIVE_HAS_SERVICE_ID (sync only) */
    uint8_t reserved;
    uint32_t psi_interval_ms; /* longest gap between PAT/PMT copies; 0: 100 */
} misb_live_config;

/* Counters. */
typedef struct misb_live_counters {
    uint32_t struct_size;
    uint32_t reserved;
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t held_packets;    /* input packets waiting inside after the last call */
    uint64_t frames;          /* video frames seen */
    uint64_t units;           /* KLV packets handed to the injector */
    uint64_t emitted;         /* of those, sent on request (misb_live_emit) */
    uint64_t empty;           /* frames due while no value was set */
    uint64_t late;            /* not sent: the PTS would have gone back */
    uint64_t refused;         /* not sent: the injector's queue was full */
    uint64_t encode_errors;   /* snapshots that did not encode */
    uint64_t discontinuities; /* program clock discontinuities */
    uint64_t reanchors;       /* the anchor moved to the video's ST 0604 time */
    uint64_t timestamps_found;
    uint64_t timestamps_written;
    uint64_t klv_packets;     /* TS packets of KLV written */
    uint64_t psi_packets;     /* TS packets of PAT and PMT written */
} misb_live_counters;

/* Output: whole TS packets, len a multiple of 188, valid during the call. */
typedef void (*misb_live_packets_fn)(void *user, const uint8_t *packets, size_t len);

misb_status misb_live_config_default(misb_live_config *out);
/* config may be NULL for the defaults. MISB_ERR_INVALID for settings out of
 * range (an unknown code, an EVERY_NTH rate below 1, a Hz rate outside
 * (0, 1000], a PID outside 0x0010 to 0x1FFE, ...). */
misb_status misb_live_new(const misb_live_config *config, misb_live **out);
void misb_live_free(misb_live *live); /* NULL is ignored */

/* Input bytes as they arrived (any chunking) at wall-clock MISP time now_us.
 * What is ready goes to sink (may be NULL to discard) before the call
 * returns. MISB_ERR_STREAM when the injector stopped. */
misb_status misb_live_push(misb_live *live, const uint8_t *data, size_t len, uint64_t now_us,
                           misb_live_packets_fn sink, void *user);
/* The input has ended: the last frames get their metadata. */
misb_status misb_live_finish(misb_live *live, misb_live_packets_fn sink, void *user);

/* Change a value, stamped with now_us (what staleness counts from). Each is
 * checked against the item's rules at once: MISB_ERR_ENCODE (nothing
 * changes; misb_live_last_error tells why), MISB_ERR_INVALID for a tag that
 * is not an ST 0601 tag. Engineering units as in misb_encoder_set_*. */
misb_status misb_live_set_f64(misb_live *live, uint64_t tag, double value, uint64_t now_us);
misb_status misb_live_set_uint(misb_live *live, uint64_t tag, uint64_t value, uint64_t now_us);
misb_status misb_live_set_int(misb_live *live, uint64_t tag, int64_t value, uint64_t now_us);
misb_status misb_live_set_code(misb_live *live, uint64_t tag, uint64_t code, uint64_t now_us);
/* text: UTF-8, len bytes, no NUL needed. */
misb_status misb_live_set_text(misb_live *live, uint64_t tag, const char *text, size_t len, uint64_t now_us);
/* The items of an encoded nested set (tag 48: misb_security_encode). */
misb_status misb_live_set_set(misb_live *live, uint64_t tag, const uint8_t *data, size_t len, uint64_t now_us);
/* Send the item with zero length: "value unknown" (ST 0601.19 6.5). */
misb_status misb_live_unknown(misb_live *live, uint64_t tag, uint64_t now_us);
/* Stop sending an item (MISB_EMPTY when it was not set), or every item. */
misb_status misb_live_clear(misb_live *live, uint64_t tag);
misb_status misb_live_clear_all(misb_live *live);
/* Send a packet at the next opportunity whatever the rate says: the next
 * frame (sync), or before the next input packet (async). */
misb_status misb_live_emit(misb_live *live);

/* The error of the last setter that failed (MISB_EMPTY when the last one
 * succeeded). */
misb_status misb_live_last_error(const misb_live *live, misb_encode_error *out);
/* Why the injector stopped, NUL-terminated and truncated to message_len;
 * MISB_EMPTY when it has not. */
misb_status misb_live_error(const misb_live *live, char *message, size_t message_len);
misb_status misb_live_stats(const misb_live *live, misb_live_counters *out);

#ifdef __cplusplus
}
#endif

#endif /* MISB_LIVE_H */
