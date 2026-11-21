//! The encoder's C ABI (`include/misb.h`, section "encoder"): an opaque
//! `misb_encoder` that builds one ST 0601 packet at a time, the ST 0102
//! security set, re-encoding a decoded `misb_packet`, and MISP time
//! conversion. Same rules as the rest of the ABI: status codes, NULL
//! checks, `struct_size` on every struct, no unwinding into C, a handle
//! poisoned by an internal panic.

use super::{check_out, input, packet_ref, read_in, standard_code, write_out};
use super::{misb_packet, misb_status, MISB_EMPTY, MISB_ERR_INVALID, MISB_ERR_NULL, MISB_ERR_PANIC};
use super::{MISB_ERR_POISONED, MISB_ERR_RANGE, MISB_OK};
use crate::encode::{
    encode_packet, Classification, EncodeError, EncodeOptions, ErrorKind, Input, ItemOrder, Policy, Security,
    St0601Builder, Warning,
};
use crate::{st0601, LeapSeconds, MispTime, Standard, UtcDateTime};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};
use std::{mem, ptr};

/// The encoder rejected a value or packet; the details are in
/// `misb_encoder_last_error` or the `error` out-parameter.
pub const MISB_ERR_ENCODE: i32 = -7;
/// The output buffer is too small; `*len` holds the size needed.
pub const MISB_ERR_TOO_SMALL: i32 = -8;

/// [`Policy::Strict`] (the default, 0).
pub const MISB_POLICY_STRICT: u32 = 0;
/// [`Policy::Clamp`].
pub const MISB_POLICY_CLAMP: u32 = 1;
/// [`ItemOrder::Ascending`] (the default, 0).
pub const MISB_ORDER_ASCENDING: u32 = 0;
/// [`ItemOrder::Caller`].
pub const MISB_ORDER_CALLER: u32 = 1;

/// [`Input::OffEarth`].
pub const MISB_SPECIAL_OFF_EARTH: u32 = 1;
/// [`Input::OutOfRange`].
pub const MISB_SPECIAL_OUT_OF_RANGE: u32 = 2;
/// [`Input::BelowMinimum`].
pub const MISB_SPECIAL_BELOW_MINIMUM: u32 = 3;
/// [`Input::AboveMaximum`].
pub const MISB_SPECIAL_ABOVE_MAXIMUM: u32 = 4;

/// `misb_encode_error.kind` of a warning.
pub const MISB_ENCODE_WARNING: u32 = 0;
/// [`ErrorKind::UnknownTag`].
pub const MISB_ENCODE_ERR_UNKNOWN_TAG: u32 = 1;
/// [`ErrorKind::NotAllowed`].
pub const MISB_ENCODE_ERR_NOT_ALLOWED: u32 = 2;
/// [`ErrorKind::WrongType`].
pub const MISB_ENCODE_ERR_WRONG_TYPE: u32 = 3;
/// [`ErrorKind::OutOfRange`].
pub const MISB_ENCODE_ERR_OUT_OF_RANGE: u32 = 4;
/// [`ErrorKind::NotFinite`].
pub const MISB_ENCODE_ERR_NOT_FINITE: u32 = 5;
/// [`ErrorKind::InvalidCode`].
pub const MISB_ENCODE_ERR_INVALID_CODE: u32 = 6;
/// [`ErrorKind::TooLong`].
pub const MISB_ENCODE_ERR_TOO_LONG: u32 = 7;
/// [`ErrorKind::Duplicate`].
pub const MISB_ENCODE_ERR_DUPLICATE: u32 = 8;
/// [`ErrorKind::Missing`].
pub const MISB_ENCODE_ERR_MISSING: u32 = 9;
/// [`ErrorKind::TooLarge`].
pub const MISB_ENCODE_ERR_TOO_LARGE: u32 = 10;
/// [`ErrorKind::InvalidOptions`].
pub const MISB_ENCODE_ERR_INVALID_OPTIONS: u32 = 11;
/// [`ErrorKind::Unsupported`].
pub const MISB_ENCODE_ERR_UNSUPPORTED: u32 = 12;

/// [`EncodeOptions`] as C sees it. Zero-initialised fields mean the
/// defaults, except `max_packet_bytes` (0 also means the default).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_encode_options {
    pub struct_size: u32,
    pub policy: u32,
    pub order: u32,
    pub allow_legacy: u32,
    pub ascii_only: u32,
    pub reserved: u32,
    pub max_packet_bytes: u64,
}

/// An encoder error or warning.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_encode_error {
    pub struct_size: u32,
    /// `MISB_STANDARD_*` of the set the item belongs to.
    pub standard: u32,
    /// The item's tag, 0 when the error is about the packet.
    pub tag: u64,
    /// `MISB_ENCODE_ERR_*`, or `MISB_ENCODE_WARNING`.
    pub kind: u32,
    pub reserved: u32,
    /// What is wrong; static, never NULL.
    pub reason: *const c_char,
}

/// An ST 0102 Security Local Set. A 0 code or a NULL string leaves the
/// item out.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_security {
    pub struct_size: u32,
    pub classification: u32,
    pub country_coding_method: u32,
    pub object_country_coding_method: u32,
    /// Tag 22; 0 writes 12 (unless `partial`).
    pub version: u32,
    /// Nonzero allows a set without every Required item.
    pub partial: u32,
    pub classifying_country: *const c_char,
    pub sci_shi: *const c_char,
    pub caveats: *const c_char,
    pub releasing_instructions: *const c_char,
    pub classified_by: *const c_char,
    pub derived_from: *const c_char,
    pub classification_reason: *const c_char,
    pub declassification_date: *const c_char,
    pub marking_system: *const c_char,
    pub object_country_codes: *const c_char,
    pub comments: *const c_char,
    pub country_coding_method_date: *const c_char,
    pub object_country_coding_method_date: *const c_char,
}

/// A UTC calendar reading (second 60 during a leap second).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct misb_utc {
    pub struct_size: u32,
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub micros: u32,
}

/// One packet being built.
pub struct misb_encoder {
    builder: St0601Builder,
    last_error: Option<EncodeError>,
    poisoned: bool,
    out: Vec<u8>,
}

/// Error reasons are `&'static str` literals of this crate, so their
/// NUL-terminated copies are made once each and live for the whole run (a
/// bounded set: the literals in the binary).
fn static_cstr(s: &'static str) -> *const c_char {
    static CACHE: OnceLock<Mutex<HashMap<(usize, usize), &'static CStr>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let key = (s.as_ptr() as usize, s.len());
    let c = cache.entry(key).or_insert_with(|| {
        let owned = CString::new(s.replace('\0', "")).unwrap_or_default();
        Box::leak(owned.into_boxed_c_str())
    });
    c.as_ptr()
}

fn kind_code(k: ErrorKind) -> u32 {
    match k {
        ErrorKind::UnknownTag => MISB_ENCODE_ERR_UNKNOWN_TAG,
        ErrorKind::NotAllowed => MISB_ENCODE_ERR_NOT_ALLOWED,
        ErrorKind::WrongType => MISB_ENCODE_ERR_WRONG_TYPE,
        ErrorKind::OutOfRange => MISB_ENCODE_ERR_OUT_OF_RANGE,
        ErrorKind::NotFinite => MISB_ENCODE_ERR_NOT_FINITE,
        ErrorKind::InvalidCode => MISB_ENCODE_ERR_INVALID_CODE,
        ErrorKind::TooLong => MISB_ENCODE_ERR_TOO_LONG,
        ErrorKind::Duplicate => MISB_ENCODE_ERR_DUPLICATE,
        ErrorKind::Missing => MISB_ENCODE_ERR_MISSING,
        ErrorKind::TooLarge => MISB_ENCODE_ERR_TOO_LARGE,
        ErrorKind::InvalidOptions => MISB_ENCODE_ERR_INVALID_OPTIONS,
        _ => MISB_ENCODE_ERR_UNSUPPORTED,
    }
}

fn c_error(e: &EncodeError) -> misb_encode_error {
    misb_encode_error {
        struct_size: mem::size_of::<misb_encode_error>() as u32,
        standard: standard_code(e.standard),
        tag: e.tag.unwrap_or(0),
        kind: kind_code(e.kind),
        reserved: 0,
        reason: static_cstr(e.reason),
    }
}

fn c_warning(w: &Warning) -> misb_encode_error {
    misb_encode_error {
        struct_size: mem::size_of::<misb_encode_error>() as u32,
        standard: standard_code(w.standard),
        tag: w.tag.unwrap_or(0),
        kind: MISB_ENCODE_WARNING,
        reserved: 0,
        reason: static_cstr(w.reason),
    }
}

/// Write an error to an optional out-parameter and return MISB_ERR_ENCODE.
unsafe fn report(error: *mut misb_encode_error, e: &EncodeError) -> misb_status {
    if !error.is_null() && check_out(error).is_ok() {
        write_out(error, c_error(e));
    }
    MISB_ERR_ENCODE
}

fn default_options() -> misb_encode_options {
    let d = EncodeOptions::default();
    misb_encode_options {
        struct_size: mem::size_of::<misb_encode_options>() as u32,
        policy: MISB_POLICY_STRICT,
        order: MISB_ORDER_ASCENDING,
        allow_legacy: 0,
        ascii_only: 0,
        reserved: 0,
        max_packet_bytes: d.max_packet_bytes as u64,
    }
}

/// The caller's options (NULL for the defaults).
unsafe fn options_in(p: *const misb_encode_options) -> Result<EncodeOptions, i32> {
    if p.is_null() {
        return Ok(EncodeOptions::default());
    }
    let (o, _) = read_in(p, default_options())?;
    let mut opts = EncodeOptions::default();
    opts.policy = match o.policy {
        MISB_POLICY_STRICT => Policy::Strict,
        MISB_POLICY_CLAMP => Policy::Clamp,
        _ => return Err(MISB_ERR_INVALID),
    };
    opts.order = match o.order {
        MISB_ORDER_ASCENDING => ItemOrder::Ascending,
        MISB_ORDER_CALLER => ItemOrder::Caller,
        _ => return Err(MISB_ERR_INVALID),
    };
    opts.allow_legacy = o.allow_legacy != 0;
    opts.ascii_only = o.ascii_only != 0;
    if o.max_packet_bytes != 0 {
        opts.max_packet_bytes = usize::try_from(o.max_packet_bytes).map_err(|_| MISB_ERR_INVALID)?;
    }
    opts.validate().map_err(|_| MISB_ERR_INVALID)?;
    Ok(opts)
}

/// Copy `bytes` into a caller's buffer, or report the size needed.
unsafe fn copy_out(bytes: &[u8], buf: *mut u8, cap: usize, len: *mut usize) -> misb_status {
    if len.is_null() {
        return MISB_ERR_NULL;
    }
    len.write(bytes.len());
    if bytes.len() > cap {
        return MISB_ERR_TOO_SMALL;
    }
    if bytes.is_empty() {
        return MISB_OK;
    }
    if buf.is_null() {
        return MISB_ERR_NULL;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    MISB_OK
}

unsafe fn encoder_mut<'a>(e: *mut misb_encoder) -> Result<&'a mut misb_encoder, i32> {
    let h = e.as_mut().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

unsafe fn encoder_ref<'a>(e: *const misb_encoder) -> Result<&'a misb_encoder, i32> {
    let h = e.as_ref().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

/// Run `f` on an encoder: a panic poisons it; an encode error is kept as
/// the last error.
unsafe fn with_encoder(
    e: *mut misb_encoder,
    f: impl FnOnce(&mut St0601Builder) -> Result<(), EncodeError>,
) -> misb_status {
    let h = match encoder_mut(e) {
        Ok(h) => h,
        Err(status) => return status,
    };
    match catch_unwind(AssertUnwindSafe(|| f(&mut h.builder))) {
        Ok(Ok(())) => {
            h.last_error = None;
            MISB_OK
        }
        Ok(Err(err)) => {
            h.last_error = Some(err);
            MISB_ERR_ENCODE
        }
        Err(_) => {
            h.poisoned = true;
            MISB_ERR_PANIC
        }
    }
}

fn tag_of(tag: u64) -> Result<st0601::Tag, EncodeError> {
    st0601::Tag::from_u64(tag).ok_or(EncodeError::new(
        Standard::St0601,
        Some(tag),
        ErrorKind::UnknownTag,
        "not an ST 0601 tag (use misb_encoder_set_raw)",
    ))
}

/// A NUL-terminated UTF-8 string, or None for NULL.
unsafe fn opt_str(p: *const c_char) -> Result<Option<String>, i32> {
    if p.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(p).to_str().map(|s| Some(s.to_string())).map_err(|_| MISB_ERR_INVALID)
}

// ----------------------------------------------------------------- exports

#[no_mangle]
pub unsafe extern "C" fn misb_encode_options_default(out: *mut misb_encode_options) -> misb_status {
    catch_unwind(|| write_out(out, default_options())).unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_new(
    options: *const misb_encode_options,
    time_us: u64,
    out: *mut *mut misb_encoder,
) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    catch_unwind(AssertUnwindSafe(|| {
        let opts = match options_in(options) {
            Ok(o) => o,
            Err(status) => return status,
        };
        let h = Box::new(misb_encoder {
            builder: St0601Builder::with_options(MispTime::from_micros(time_us), opts),
            last_error: None,
            poisoned: false,
            out: Vec::new(),
        });
        out.write(Box::into_raw(h));
        MISB_OK
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_free(encoder: *mut misb_encoder) {
    if !encoder.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(encoder))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_reset(encoder: *mut misb_encoder, time_us: u64) -> misb_status {
    with_encoder(encoder, |b| {
        b.clear().time(MispTime::from_micros(time_us));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_version(encoder: *mut misb_encoder, version: u32) -> misb_status {
    let Ok(v) = u8::try_from(version) else { return MISB_ERR_INVALID };
    with_encoder(encoder, |b| {
        b.version(v);
        Ok(())
    })
}

unsafe fn set(encoder: *mut misb_encoder, tag: u64, input: Input) -> misb_status {
    with_encoder(encoder, |b| b.set(tag_of(tag)?, input).map(|_| ()))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_f64(encoder: *mut misb_encoder, tag: u64, value: f64) -> misb_status {
    set(encoder, tag, Input::Float(value))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_uint(encoder: *mut misb_encoder, tag: u64, value: u64) -> misb_status {
    set(encoder, tag, Input::Uint(value))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_int(encoder: *mut misb_encoder, tag: u64, value: i64) -> misb_status {
    set(encoder, tag, Input::Int(value))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_time(encoder: *mut misb_encoder, tag: u64, misp_us: u64) -> misb_status {
    set(encoder, tag, Input::Time(MispTime::from_micros(misp_us)))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_code(encoder: *mut misb_encoder, tag: u64, code: u64) -> misb_status {
    set(encoder, tag, Input::Code(code))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_text(
    encoder: *mut misb_encoder,
    tag: u64,
    text: *const c_char,
    len: usize,
) -> misb_status {
    // DECISIONS D-09: the C ABI checks UTF-8 before encoding.
    let bytes = match input(text as *const u8, len) {
        Ok(b) => b,
        Err(status) => return status,
    };
    let Ok(s) = std::str::from_utf8(bytes) else { return MISB_ERR_INVALID };
    set(encoder, tag, Input::Text(s.to_string()))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_special(encoder: *mut misb_encoder, tag: u64, special: u32) -> misb_status {
    let input = match special {
        MISB_SPECIAL_OFF_EARTH => Input::OffEarth,
        MISB_SPECIAL_OUT_OF_RANGE => Input::OutOfRange,
        MISB_SPECIAL_BELOW_MINIMUM => Input::BelowMinimum,
        MISB_SPECIAL_ABOVE_MAXIMUM => Input::AboveMaximum,
        _ => return MISB_ERR_INVALID,
    };
    set(encoder, tag, input)
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_imapb(
    encoder: *mut misb_encoder,
    tag: u64,
    value: f64,
    length: u32,
) -> misb_status {
    with_encoder(encoder, |b| b.set_imapb(tag_of(tag)?, value, length as usize).map(|_| ()))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_bytes(
    encoder: *mut misb_encoder,
    tag: u64,
    data: *const u8,
    len: usize,
) -> misb_status {
    let bytes = match input(data, len) {
        Ok(b) => b.to_vec(),
        Err(status) => return status,
    };
    set(encoder, tag, Input::Bytes(bytes))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_set_raw(
    encoder: *mut misb_encoder,
    tag: u64,
    data: *const u8,
    len: usize,
) -> misb_status {
    let bytes = match input(data, len) {
        Ok(b) => b,
        Err(status) => return status,
    };
    with_encoder(encoder, |b| b.set_raw(tag, bytes).map(|_| ()))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_unknown(encoder: *mut misb_encoder, tag: u64) -> misb_status {
    with_encoder(encoder, |b| b.unknown(tag_of(tag)?).map(|_| ()))
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_finish(
    encoder: *mut misb_encoder,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
) -> misb_status {
    if len.is_null() {
        return MISB_ERR_NULL;
    }
    let h = match encoder_mut(encoder) {
        Ok(h) => h,
        Err(status) => return status,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut out = mem::take(&mut h.out);
        let r = h.builder.finish_into(&mut out);
        let status = match r {
            Ok(_) => {
                h.last_error = None;
                copy_out(&out, buf, cap, len)
            }
            Err(e) => {
                h.last_error = Some(e);
                MISB_ERR_ENCODE
            }
        };
        h.out = out;
        status
    }));
    r.unwrap_or_else(|_| {
        h.poisoned = true;
        MISB_ERR_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_last_error(encoder: *const misb_encoder, out: *mut misb_encode_error) -> misb_status {
    let h = match encoder_ref(encoder) {
        Ok(h) => h,
        Err(status) => return status,
    };
    catch_unwind(AssertUnwindSafe(|| match &h.last_error {
        Some(e) => write_out(out, c_error(e)),
        None => match check_out(out) {
            Ok(()) => MISB_EMPTY,
            Err(status) => status,
        },
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_warning_count(encoder: *const misb_encoder, count: *mut usize) -> misb_status {
    let h = match encoder_ref(encoder) {
        Ok(h) => h,
        Err(status) => return status,
    };
    if count.is_null() {
        return MISB_ERR_NULL;
    }
    count.write(h.builder.warnings().len());
    MISB_OK
}

#[no_mangle]
pub unsafe extern "C" fn misb_encoder_warning(
    encoder: *const misb_encoder,
    index: usize,
    out: *mut misb_encode_error,
) -> misb_status {
    let h = match encoder_ref(encoder) {
        Ok(h) => h,
        Err(status) => return status,
    };
    catch_unwind(AssertUnwindSafe(|| match h.builder.warnings().get(index) {
        Some(w) => write_out(out, c_warning(w)),
        None => MISB_ERR_RANGE,
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_security_encode(
    security: *const misb_security,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
    error: *mut misb_encode_error,
) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        let base = misb_security {
            struct_size: 0,
            classification: 0,
            country_coding_method: 0,
            object_country_coding_method: 0,
            version: 0,
            partial: 0,
            classifying_country: ptr::null(),
            sci_shi: ptr::null(),
            caveats: ptr::null(),
            releasing_instructions: ptr::null(),
            classified_by: ptr::null(),
            derived_from: ptr::null(),
            classification_reason: ptr::null(),
            declassification_date: ptr::null(),
            marking_system: ptr::null(),
            object_country_codes: ptr::null(),
            comments: ptr::null(),
            country_coding_method_date: ptr::null(),
            object_country_coding_method_date: ptr::null(),
        };
        let (c, _) = match read_in(security, base) {
            Ok(v) => v,
            Err(status) => return status,
        };
        let code = |v: u32| if v == 0 { Ok(None) } else { u8::try_from(v).map(Some).map_err(|_| MISB_ERR_INVALID) };
        let built = (|| -> Result<Security, i32> {
            let mut s = Security::default();
            s.classification = match c.classification {
                0 => None,
                v => Some(u8::try_from(v).ok().and_then(Classification::from_code).ok_or(MISB_ERR_INVALID)?),
            };
            s.country_coding_method = code(c.country_coding_method)?;
            s.object_country_coding_method = code(c.object_country_coding_method)?;
            s.version = if c.version == 0 { None } else { Some(u16::try_from(c.version).map_err(|_| MISB_ERR_INVALID)?) };
            s.classifying_country = opt_str(c.classifying_country)?;
            s.sci_shi = opt_str(c.sci_shi)?;
            s.caveats = opt_str(c.caveats)?;
            s.releasing_instructions = opt_str(c.releasing_instructions)?;
            s.classified_by = opt_str(c.classified_by)?;
            s.derived_from = opt_str(c.derived_from)?;
            s.classification_reason = opt_str(c.classification_reason)?;
            s.declassification_date = opt_str(c.declassification_date)?;
            s.marking_system = opt_str(c.marking_system)?;
            s.object_country_codes = opt_str(c.object_country_codes)?;
            s.comments = opt_str(c.comments)?;
            s.country_coding_method_date = opt_str(c.country_coding_method_date)?;
            s.object_country_coding_method_date = opt_str(c.object_country_coding_method_date)?;
            Ok(s)
        })();
        let s = match built {
            Ok(s) => s,
            Err(status) => return status,
        };
        let encoded = if c.partial != 0 { s.encode_partial() } else { s.encode() };
        match encoded {
            Ok(bytes) => copy_out(&bytes, buf, cap, len),
            Err(e) => report(error, &e),
        }
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_encode_packet(
    packet: *const misb_packet,
    options: *const misb_encode_options,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
    error: *mut misb_encode_error,
) -> misb_status {
    let p = match packet_ref(packet) {
        Ok(p) => p,
        Err(status) => return status,
    };
    catch_unwind(AssertUnwindSafe(|| {
        let opts = match options_in(options) {
            Ok(o) => o,
            Err(status) => return status,
        };
        match encode_packet(&p.packet, &opts) {
            Ok(bytes) => copy_out(&bytes, buf, cap, len),
            Err(e) => report(error, &e),
        }
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_misp_from_utc(utc: *const misb_utc, misp_us: *mut u64) -> misb_status {
    if misp_us.is_null() {
        return MISB_ERR_NULL;
    }
    let (u, _) = match read_in(utc, misb_utc::default()) {
        Ok(v) => v,
        Err(status) => return status,
    };
    let field = |v: u32| u8::try_from(v).map_err(|_| MISB_ERR_INVALID);
    let t = match (|| -> Result<Option<UtcDateTime>, i32> {
        Ok(UtcDateTime::new(u.year, field(u.month)?, field(u.day)?, field(u.hour)?, field(u.minute)?, field(u.second)?, u.micros))
    })() {
        Ok(Some(t)) => t,
        Ok(None) => return MISB_ERR_INVALID,
        Err(status) => return status,
    };
    match catch_unwind(|| MispTime::from_utc(t, LeapSeconds::builtin())) {
        Ok(Some(m)) => {
            misp_us.write(m.as_micros());
            MISB_OK
        }
        Ok(None) => MISB_ERR_INVALID,
        Err(_) => MISB_ERR_PANIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_misp_from_posix_us(posix_us: i64, misp_us: *mut u64) -> misb_status {
    if misp_us.is_null() {
        return MISB_ERR_NULL;
    }
    match catch_unwind(|| MispTime::from_posix_utc_micros(posix_us, LeapSeconds::builtin())) {
        Ok(Some(m)) => {
            misp_us.write(m.as_micros());
            MISB_OK
        }
        Ok(None) => MISB_ERR_INVALID,
        Err(_) => MISB_ERR_PANIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_misp_to_utc(misp_us: u64, out: *mut misb_utc) -> misb_status {
    if let Err(status) = check_out(out) {
        return status;
    }
    match catch_unwind(|| MispTime::from_micros(misp_us).to_utc(LeapSeconds::builtin())) {
        Ok(Some(t)) => write_out(
            out,
            misb_utc {
                struct_size: mem::size_of::<misb_utc>() as u32,
                year: t.year,
                month: t.month.into(),
                day: t.day.into(),
                hour: t.hour.into(),
                minute: t.minute.into(),
                second: t.second.into(),
                micros: t.micros,
            },
        ),
        Ok(None) => MISB_ERR_INVALID,
        Err(_) => MISB_ERR_PANIC,
    }
}

#[no_mangle]
pub extern "C" fn misb_leap_seconds_valid_until() -> i64 {
    LeapSeconds::builtin().valid_until()
}
