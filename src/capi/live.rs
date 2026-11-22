//! The live injection part of the C ABI (`include/misb_live.h`, libraries
//! built with `capi` and `mux`): a [`LiveMux`] behind an opaque handle.
//! Same rules as the rest of the ABI: status codes, NULL checks,
//! `struct_size` on every struct, no unwinding into C, a panic poisons the
//! handle.

use super::encode::{c_error, misb_encode_error, MISB_ERR_ENCODE};
use super::{check_out, input, read_in, write_out};
use super::{misb_status, MISB_EMPTY, MISB_ERR_INVALID, MISB_ERR_NULL, MISB_ERR_PANIC, MISB_ERR_POISONED, MISB_OK};
use crate::encode::{EncodeError, Input};
use crate::mux::{
    Carriage, LiveAnchor, LiveMux, LiveMuxConfig, Rate, VideoTimestampOptions, VideoTimestamps,
};
use crate::state::StalePolicy;
use crate::st0601::Tag;
use crate::MispTime;
use mpegts::mux::{CellNumbering, ExistingKlv, OnOverflow, ProgramSelect, RateMode};
use std::ffi::c_char;
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::time::Duration;

/// The injector stopped (bad input it cannot pass through, a full queue in
/// strict CBR, ...); `misb_live_error` says why. The handle refuses further
/// pushes.
pub const MISB_ERR_STREAM: i32 = -9;

/// Synchronous KLV (stream_type 0x15).
pub const MISB_LIVE_SYNC: u32 = 1;
/// Asynchronous KLV (stream_type 0x06).
pub const MISB_LIVE_ASYNC: u32 = 2;

/// The carriage's default rate (every frame up to 30 Hz sync, 10 Hz async).
pub const MISB_LIVE_RATE_DEFAULT: u32 = 0;
/// Every video frame.
pub const MISB_LIVE_RATE_EVERY_FRAME: u32 = 1;
/// Every `rate_value`th frame.
pub const MISB_LIVE_RATE_EVERY_NTH: u32 = 2;
/// At most `rate_value` packets per second.
pub const MISB_LIVE_RATE_HZ: u32 = 3;

/// The first frame is at the wall-clock time it arrived.
pub const MISB_LIVE_ANCHOR_WALL_CLOCK: u32 = 0;
/// The first frame is at `anchor_misp_us`.
pub const MISB_LIVE_ANCHOR_FIRST_FRAME: u32 = 1;
/// PTS `anchor_pts` is at `anchor_misp_us`.
pub const MISB_LIVE_ANCHOR_PTS: u32 = 2;

/// Video timestamps off.
pub const MISB_LIVE_TIMESTAMPS_OFF: u32 = 0;
/// ST 0604 timestamps added to access units without one.
pub const MISB_LIVE_TIMESTAMPS_ADD: u32 = 1;
/// ST 0604 timestamps in every access unit, existing ones replaced.
pub const MISB_LIVE_TIMESTAMPS_REWRITE: u32 = 2;

/// Take MISP time from the video's ST 0604 timestamps.
pub const MISB_LIVE_VIDEO_ANCHOR: u32 = 0x01;
/// Written timestamps assert lock to an absolute time reference.
pub const MISB_LIVE_LOCKED: u32 = 0x02;
/// H.265: nanosecond timestamps.
pub const MISB_LIVE_NANOSECONDS: u32 = 0x04;
/// Stale values are written as unknown instead of left out.
pub const MISB_LIVE_STALE_UNKNOWN: u32 = 0x08;
/// Strict CBR output: KLV and tables replace null packets.
pub const MISB_LIVE_CBR: u32 = 0x10;
/// With MISB_LIVE_CBR, drop units that find no room instead of failing.
pub const MISB_LIVE_CBR_DROP: u32 = 0x20;
/// Use `pid` for the KLV stream.
pub const MISB_LIVE_HAS_PID: u32 = 0x40;
/// Use `service_id`.
pub const MISB_LIVE_HAS_SERVICE_ID: u32 = 0x80;
/// Number metadata cells from 0 in each access unit instead of one counter
/// per stream: a workaround for receivers that require it, such as
/// MediaMTX (DECISIONS X-8).
pub const MISB_LIVE_CELLS_PER_AU: u32 = 0x100;

/// Settings of a live injector.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_live_config {
    pub struct_size: u32,
    /// `MISB_LIVE_SYNC` or `MISB_LIVE_ASYNC`.
    pub carriage: u32,
    /// `MISB_LIVE_*` flags.
    pub flags: u32,
    /// `MISB_LIVE_RATE_*`.
    pub rate: u32,
    /// N for `MISB_LIVE_RATE_EVERY_NTH`, Hz for `MISB_LIVE_RATE_HZ`.
    pub rate_value: f64,
    /// `MISB_LIVE_ANCHOR_*`.
    pub anchor: u32,
    /// `MISB_LIVE_TIMESTAMPS_*`.
    pub timestamps: u32,
    pub anchor_pts: u64,
    pub anchor_misp_us: u64,
    /// Values older than this are stale (left out, or unknown with
    /// `MISB_LIVE_STALE_UNKNOWN`); 0: never.
    pub max_age_us: u64,
    /// program_number to inject into; 0: the first program with video.
    pub program: u32,
    /// `MPEGTS_EXISTING_KLV_*` of mpegts.h (keep 0, replace 1, fail 2).
    pub existing_klv: u32,
    pub pid: u16,
    pub service_id: u8,
    pub reserved: u8,
    /// Longest gap between PAT and PMT copies, ms; 0: 100.
    pub psi_interval_ms: u32,
}

/// Counters of a live injector.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct misb_live_counters {
    pub struct_size: u32,
    pub reserved: u32,
    pub packets_in: u64,
    pub packets_out: u64,
    /// Input packets waiting inside the injector after the last call.
    pub held_packets: u64,
    pub frames: u64,
    pub units: u64,
    pub emitted: u64,
    pub empty: u64,
    pub late: u64,
    pub refused: u64,
    pub encode_errors: u64,
    pub discontinuities: u64,
    pub reanchors: u64,
    pub timestamps_found: u64,
    pub timestamps_written: u64,
    pub klv_packets: u64,
    pub psi_packets: u64,
}

/// Output: whole packets, len a multiple of 188, valid during the call.
pub type misb_live_packets_fn = Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, packets: *const u8, len: usize)>;

/// Opaque live injector handle.
#[derive(Debug)]
pub struct misb_live {
    mux: LiveMux,
    out: Vec<u8>,
    last_error: Option<EncodeError>,
    /// Why the injector stopped, NUL-free.
    failure: Option<String>,
    poisoned: bool,
}

fn default_config() -> misb_live_config {
    misb_live_config {
        struct_size: mem::size_of::<misb_live_config>() as u32,
        carriage: MISB_LIVE_SYNC,
        flags: 0,
        rate: MISB_LIVE_RATE_DEFAULT,
        rate_value: 0.0,
        anchor: MISB_LIVE_ANCHOR_WALL_CLOCK,
        timestamps: MISB_LIVE_TIMESTAMPS_OFF,
        anchor_pts: 0,
        anchor_misp_us: 0,
        max_age_us: 0,
        program: 0,
        existing_klv: 0,
        pid: 0,
        service_id: 0,
        reserved: 0,
        psi_interval_ms: 0,
    }
}

/// The Rust configuration of a C one, and the staleness settings.
fn config_of(c: &misb_live_config) -> Option<(LiveMuxConfig, Option<Duration>, StalePolicy)> {
    let carriage = match c.carriage {
        MISB_LIVE_SYNC => Carriage::Sync,
        MISB_LIVE_ASYNC => Carriage::Async,
        _ => return None,
    };
    let mut cfg = LiveMuxConfig::new(carriage);
    cfg.rate = match c.rate {
        MISB_LIVE_RATE_DEFAULT => cfg.rate,
        MISB_LIVE_RATE_EVERY_FRAME => Rate::EveryFrame,
        MISB_LIVE_RATE_EVERY_NTH if c.rate_value >= 1.0 && c.rate_value <= f64::from(u32::MAX) => {
            Rate::EveryNthFrame(c.rate_value as u32)
        }
        MISB_LIVE_RATE_HZ => Rate::Hz(c.rate_value),
        _ => return None,
    };
    cfg.anchor = match c.anchor {
        MISB_LIVE_ANCHOR_WALL_CLOCK => LiveAnchor::WallClock,
        MISB_LIVE_ANCHOR_FIRST_FRAME => LiveAnchor::FirstFrame(MispTime::from_micros(c.anchor_misp_us)),
        MISB_LIVE_ANCHOR_PTS if c.anchor_pts < 1 << 33 => {
            LiveAnchor::Pts { pts: c.anchor_pts, misp: MispTime::from_micros(c.anchor_misp_us) }
        }
        _ => return None,
    };
    let mode = match c.timestamps {
        MISB_LIVE_TIMESTAMPS_OFF => VideoTimestamps::Off,
        MISB_LIVE_TIMESTAMPS_ADD => VideoTimestamps::AddWhenMissing,
        MISB_LIVE_TIMESTAMPS_REWRITE => VideoTimestamps::Rewrite,
        _ => return None,
    };
    let mut ts = VideoTimestampOptions::new(mode);
    ts.locked = (c.flags & MISB_LIVE_LOCKED != 0).then_some(true);
    ts.nanoseconds = c.flags & MISB_LIVE_NANOSECONDS != 0;
    cfg.video_timestamps = ts;
    cfg.video_anchor = c.flags & MISB_LIVE_VIDEO_ANCHOR != 0;
    let mut inject = cfg.inject.clone();
    if c.program != 0 {
        inject = inject.with_program(ProgramSelect::Number(u16::try_from(c.program).ok()?));
    }
    inject = inject.with_existing_klv(match c.existing_klv {
        0 => ExistingKlv::Keep,
        1 => ExistingKlv::Replace,
        2 => ExistingKlv::Fail,
        _ => return None,
    });
    if c.flags & MISB_LIVE_HAS_PID != 0 {
        inject = inject.with_pid(c.pid);
    }
    if c.flags & MISB_LIVE_HAS_SERVICE_ID != 0 {
        inject = inject.with_service_id(c.service_id);
    }
    if c.flags & MISB_LIVE_CBR != 0 {
        let on_overflow = if c.flags & MISB_LIVE_CBR_DROP != 0 { OnOverflow::DropOldest } else { OnOverflow::Fail };
        inject = inject.with_rate(RateMode::Cbr { on_overflow });
    }
    if c.psi_interval_ms != 0 {
        inject = inject.with_psi_interval_ms(c.psi_interval_ms);
    }
    if c.flags & MISB_LIVE_CELLS_PER_AU != 0 {
        inject.sync.cell_numbering = CellNumbering::PerAccessUnit;
    }
    cfg.inject = inject;
    let max_age = (c.max_age_us != 0).then(|| Duration::from_micros(c.max_age_us));
    let policy = if c.flags & MISB_LIVE_STALE_UNKNOWN != 0 { StalePolicy::Unknown } else { StalePolicy::Omit };
    Some((cfg, max_age, policy))
}

unsafe fn live_mut<'a>(l: *mut misb_live) -> Result<&'a mut misb_live, i32> {
    let h = l.as_mut().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

unsafe fn live_ref<'a>(l: *const misb_live) -> Result<&'a misb_live, i32> {
    let h = l.as_ref().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

/// Run `f` on a handle; a panic poisons it.
unsafe fn with_live(l: *mut misb_live, f: impl FnOnce(&mut misb_live) -> misb_status) -> misb_status {
    let h = match live_mut(l) {
        Ok(h) => h,
        Err(status) => return status,
    };
    match catch_unwind(AssertUnwindSafe(|| f(&mut *h))) {
        Ok(status) => status,
        Err(_) => {
            h.poisoned = true;
            MISB_ERR_PANIC
        }
    }
}

/// Change the state: an encode error is kept as the last error.
unsafe fn set(l: *mut misb_live, tag: u64, now_us: u64, input: Option<Input>) -> misb_status {
    with_live(l, |h| {
        let Some(tag) = Tag::from_u64(tag) else { return MISB_ERR_INVALID };
        let at = MispTime::from_micros(now_us);
        let state = h.mux.state_mut();
        let r = match input {
            Some(v) => state.set(tag, v, at).map(|_| ()),
            None => state.unknown(tag, at).map(|_| ()),
        };
        match r {
            Ok(()) => {
                h.last_error = None;
                MISB_OK
            }
            Err(e) => {
                h.last_error = Some(e);
                MISB_ERR_ENCODE
            }
        }
    })
}

/// Hand what was written to the caller's sink.
unsafe fn deliver(h: &mut misb_live, sink: misb_live_packets_fn, user: *mut std::ffi::c_void) {
    if let (Some(f), false) = (sink, h.out.is_empty()) {
        f(user, h.out.as_ptr(), h.out.len());
    }
    h.out.clear();
}

/// The outcome of a push or finish.
fn status_of(h: &mut misb_live, r: Result<(), crate::mux::LiveMuxError>) -> misb_status {
    match r {
        Ok(()) => MISB_OK,
        Err(e) => {
            h.failure = Some(e.to_string().replace('\0', " "));
            MISB_ERR_STREAM
        }
    }
}

// ----------------------------------------------------------------- exports

#[no_mangle]
pub unsafe extern "C" fn misb_live_config_default(out: *mut misb_live_config) -> misb_status {
    catch_unwind(|| write_out(out, default_config())).unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_new(config: *const misb_live_config, out: *mut *mut misb_live) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    catch_unwind(AssertUnwindSafe(|| {
        let c = if config.is_null() {
            default_config()
        } else {
            match read_in(config, default_config()) {
                Ok((c, _)) => c,
                Err(status) => return status,
            }
        };
        let Some((cfg, max_age, policy)) = config_of(&c) else { return MISB_ERR_INVALID };
        let Ok(mut mux) = LiveMux::new(cfg) else { return MISB_ERR_INVALID };
        let staleness = mux.state_mut().staleness_mut();
        staleness.max_age = max_age;
        staleness.policy = policy;
        let h = Box::new(misb_live { mux, out: Vec::new(), last_error: None, failure: None, poisoned: false });
        out.write(Box::into_raw(h));
        MISB_OK
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_free(live: *mut misb_live) {
    if !live.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(live))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_push(
    live: *mut misb_live,
    data: *const u8,
    len: usize,
    now_us: u64,
    sink: misb_live_packets_fn,
    user: *mut std::ffi::c_void,
) -> misb_status {
    let bytes = match input(data, len) {
        Ok(b) => b,
        Err(status) => return status,
    };
    with_live(live, |h| {
        let mut out = mem::take(&mut h.out);
        let r = h.mux.push(bytes, MispTime::from_micros(now_us), &mut out);
        h.out = out;
        deliver(h, sink, user);
        status_of(h, r)
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_finish(
    live: *mut misb_live,
    sink: misb_live_packets_fn,
    user: *mut std::ffi::c_void,
) -> misb_status {
    with_live(live, |h| {
        let mut out = mem::take(&mut h.out);
        let r = h.mux.finish(&mut out).map(|_| ());
        h.out = out;
        deliver(h, sink, user);
        status_of(h, r)
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_f64(live: *mut misb_live, tag: u64, value: f64, now_us: u64) -> misb_status {
    set(live, tag, now_us, Some(Input::Float(value)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_uint(live: *mut misb_live, tag: u64, value: u64, now_us: u64) -> misb_status {
    set(live, tag, now_us, Some(Input::Uint(value)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_int(live: *mut misb_live, tag: u64, value: i64, now_us: u64) -> misb_status {
    set(live, tag, now_us, Some(Input::Int(value)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_code(live: *mut misb_live, tag: u64, code: u64, now_us: u64) -> misb_status {
    set(live, tag, now_us, Some(Input::Code(code)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_text(
    live: *mut misb_live,
    tag: u64,
    text: *const c_char,
    len: usize,
    now_us: u64,
) -> misb_status {
    let bytes = match input(text as *const u8, len) {
        Ok(b) => b,
        Err(status) => return status,
    };
    let Ok(s) = std::str::from_utf8(bytes) else { return MISB_ERR_INVALID };
    set(live, tag, now_us, Some(Input::Text(s.to_string())))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_set_set(
    live: *mut misb_live,
    tag: u64,
    data: *const u8,
    len: usize,
    now_us: u64,
) -> misb_status {
    let bytes = match input(data, len) {
        Ok(b) => b.to_vec(),
        Err(status) => return status,
    };
    set(live, tag, now_us, Some(Input::Set(bytes)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_unknown(live: *mut misb_live, tag: u64, now_us: u64) -> misb_status {
    set(live, tag, now_us, None)
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_clear(live: *mut misb_live, tag: u64) -> misb_status {
    with_live(live, |h| match Tag::from_u64(tag) {
        Some(tag) => {
            if h.mux.state_mut().clear(tag) {
                MISB_OK
            } else {
                MISB_EMPTY
            }
        }
        None => MISB_ERR_INVALID,
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_clear_all(live: *mut misb_live) -> misb_status {
    with_live(live, |h| {
        h.mux.state_mut().clear_all();
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_emit(live: *mut misb_live) -> misb_status {
    with_live(live, |h| {
        h.mux.emit();
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_last_error(live: *const misb_live, out: *mut misb_encode_error) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        let h = match live_ref(live) {
            Ok(h) => h,
            Err(status) => return status,
        };
        if let Err(status) = check_out(out) {
            return status;
        }
        match &h.last_error {
            Some(e) => write_out(out, c_error(e)),
            None => MISB_EMPTY,
        }
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_error(live: *const misb_live, message: *mut c_char, message_len: usize) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        let h = match live.as_ref() {
            Some(h) => h,
            None => return MISB_ERR_NULL,
        };
        let text = match (&h.failure, h.poisoned) {
            (Some(f), _) => f.as_str(),
            (None, true) => "a panic poisoned the injector",
            (None, false) => return MISB_EMPTY,
        };
        if message.is_null() || message_len == 0 {
            return if message.is_null() && message_len > 0 { MISB_ERR_NULL } else { MISB_OK };
        }
        let n = text.len().min(message_len - 1);
        ptr::copy_nonoverlapping(text.as_ptr(), message as *mut u8, n);
        message.add(n).write(0);
        MISB_OK
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_live_stats(live: *const misb_live, out: *mut misb_live_counters) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        let h = match live_ref(live) {
            Ok(h) => h,
            Err(status) => return status,
        };
        let s = h.mux.stats();
        write_out(
            out,
            misb_live_counters {
                struct_size: mem::size_of::<misb_live_counters>() as u32,
                reserved: 0,
                packets_in: s.inject.packets_in,
                packets_out: s.inject.packets_out,
                held_packets: s.inject.held_packets,
                frames: s.frames,
                units: s.units,
                emitted: s.emitted,
                empty: s.empty,
                late: s.late,
                refused: s.refused,
                encode_errors: s.encode_errors,
                discontinuities: s.discontinuities,
                reanchors: s.reanchors,
                timestamps_found: s.video.found,
                timestamps_written: s.video.written,
                klv_packets: s.inject.klv_packets,
                psi_packets: s.inject.psi_packets,
            },
        )
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn collect(user: *mut std::ffi::c_void, packets: *const u8, len: usize) {
        let out = &mut *(user as *mut Vec<u8>);
        out.extend_from_slice(std::slice::from_raw_parts(packets, len));
    }

    #[test]
    fn a_live_injector_through_the_c_abi() {
        unsafe {
            let mut cfg = misb_live_config { struct_size: mem::size_of::<misb_live_config>() as u32, rate: 99, ..default_config() };
            assert_eq!(misb_live_config_default(&mut cfg), MISB_OK);
            assert_eq!((cfg.struct_size as usize, cfg.rate), (mem::size_of::<misb_live_config>(), MISB_LIVE_RATE_DEFAULT));
            cfg.rate = MISB_LIVE_RATE_EVERY_FRAME;
            cfg.max_age_us = 2_000_000;
            let mut live = ptr::null_mut();
            assert_eq!(misb_live_new(&cfg, &mut live), MISB_OK);
            let now = 1_700_000_000_000_000;
            assert_eq!(misb_live_set_f64(live, 13, 38.5, now), MISB_OK);
            assert_eq!(misb_live_set_f64(live, 13, 1000.0, now), MISB_ERR_ENCODE);
            let mut e = misb_encode_error { struct_size: mem::size_of::<misb_encode_error>() as u32, ..mem::zeroed() };
            assert_eq!(misb_live_last_error(live, &mut e), MISB_OK);
            assert_eq!(e.tag, 13);
            let text = "C-ABI";
            assert_eq!(misb_live_set_text(live, 3, text.as_ptr() as *const c_char, text.len(), now), MISB_OK);
            assert_eq!(misb_live_set_f64(live, 999, 1.0, now), MISB_ERR_INVALID);
            assert_eq!(misb_live_clear(live, 5), MISB_EMPTY);
            let mut out: Vec<u8> = Vec::new();
            // Not a transport stream: nothing comes out, nothing fails.
            let user = &mut out as *mut Vec<u8> as *mut std::ffi::c_void;
            assert_eq!(misb_live_push(live, [0u8; 10].as_ptr(), 10, now, Some(collect), user), MISB_OK);
            assert_eq!(misb_live_emit(live), MISB_OK);
            let mut st = misb_live_counters { struct_size: mem::size_of::<misb_live_counters>() as u32, ..Default::default() };
            assert_eq!(misb_live_stats(live, &mut st), MISB_OK);
            assert_eq!(st.frames, 0);
            let mut msg = [0 as c_char; 64];
            assert_eq!(misb_live_error(live, msg.as_mut_ptr(), msg.len()), MISB_EMPTY);
            misb_live_free(live);
            let bad = misb_live_config { carriage: 9, ..default_config() };
            assert_eq!(misb_live_new(&bad, &mut live), MISB_ERR_INVALID);
            assert!(live.is_null());
            assert_eq!(misb_live_push(ptr::null_mut(), ptr::null(), 0, 0, None, ptr::null_mut()), MISB_ERR_NULL);
        }
    }

    #[test]
    fn cells_are_numbered_per_stream_unless_asked() {
        let (cfg, _, _) = config_of(&default_config()).unwrap();
        assert_eq!(cfg.inject.sync.cell_numbering, CellNumbering::PerStream);
        let per_au = misb_live_config { flags: MISB_LIVE_CELLS_PER_AU, ..default_config() };
        let (cfg, _, _) = config_of(&per_au).unwrap();
        assert_eq!(cfg.inject.sync.cell_numbering, CellNumbering::PerAccessUnit);
    }
}
