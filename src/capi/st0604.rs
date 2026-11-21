//! The ST 0604 part of the C ABI (`include/misb.h`, section "ST 0604
//! timestamps"): reading and writing the 28 bytes of timestamp information
//! carried in video. Same rules as the rest of the ABI: status codes, NULL
//! checks, `struct_size` on the struct, no unwinding into C.

use super::encode::copy_out;
use super::{check_out, input, read_in, write_out};
use super::{misb_status, MISB_EMPTY, MISB_ERR_INVALID, MISB_ERR_NULL, MISB_ERR_PANIC, MISB_ERR_PARSE};
use crate::st0604::{self, Decoded, Identifier, St0604Error, TimeStatus, Timestamp};
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// [`Identifier::MispMicrosectime`]. Codes are never reused; 0 is never an
/// identifier.
pub const MISB_ST0604_ID_MICROSEC: u32 = 1;
/// [`Identifier::HevcMicroseconds`].
pub const MISB_ST0604_ID_HEVC_MICROSEC: u32 = 2;
/// [`Identifier::HevcNanoseconds`].
pub const MISB_ST0604_ID_HEVC_NANOSEC: u32 = 3;

/// [`TimeStatus::LOCKED`].
pub const MISB_ST0604_STATUS_LOCKED: u32 = 0x1F;
/// [`TimeStatus::LOCK_UNKNOWN`].
pub const MISB_ST0604_STATUS_LOCK_UNKNOWN: u32 = 0x9F;
/// [`TimeStatus::LOCKED_FORWARD_JUMP`].
pub const MISB_ST0604_STATUS_LOCKED_FORWARD_JUMP: u32 = 0x5F;
/// [`TimeStatus::LOCKED_BACKWARD_JUMP`].
pub const MISB_ST0604_STATUS_LOCKED_BACKWARD_JUMP: u32 = 0x7F;
/// [`TimeStatus::LOCK_UNKNOWN_FORWARD_JUMP`].
pub const MISB_ST0604_STATUS_LOCK_UNKNOWN_FORWARD_JUMP: u32 = 0xDF;
/// [`TimeStatus::LOCK_UNKNOWN_BACKWARD_JUMP`].
pub const MISB_ST0604_STATUS_LOCK_UNKNOWN_BACKWARD_JUMP: u32 = 0xFF;

/// A separator byte is not `FF` ([`st0604::Warnings::bad_separators`]).
pub const MISB_ST0604_WARN_SEPARATOR: u32 = 0x1;
/// Reserved status bits not all 1 ([`st0604::Warnings::reserved_bits`]).
pub const MISB_ST0604_WARN_RESERVED: u32 = 0x2;
/// Status bit 5 without bit 6
/// ([`st0604::Warnings::reverse_without_discontinuity`]).
pub const MISB_ST0604_WARN_REVERSE: u32 = 0x4;
/// Bytes after the 28 ([`st0604::Warnings::trailing_bytes`]).
pub const MISB_ST0604_WARN_TRAILING: u32 = 0x8;

/// An ST 0604 timestamp as C sees it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct misb_st0604 {
    pub struct_size: u32,
    /// `MISB_ST0604_ID_*`.
    pub identifier: u32,
    /// The Time Status byte.
    pub status: u32,
    /// `MISB_ST0604_WARN_*` bits (decoding only).
    pub warnings: u32,
    /// Microseconds, or nanoseconds for `MISB_ST0604_ID_HEVC_NANOSEC`.
    pub value: u64,
    /// The value in MISP microseconds (decoding only).
    pub misp_us: u64,
}

/// Bytes of `misb_st0604` an encoding caller must supply: up to and
/// including `value`.
const ENCODE_FIELDS: usize = 24;

fn id_code(id: Identifier) -> u32 {
    match id {
        Identifier::MispMicrosectime => MISB_ST0604_ID_MICROSEC,
        Identifier::HevcMicroseconds => MISB_ST0604_ID_HEVC_MICROSEC,
        Identifier::HevcNanoseconds => MISB_ST0604_ID_HEVC_NANOSEC,
    }
}

fn id_of(code: u32) -> Option<Identifier> {
    Some(match code {
        MISB_ST0604_ID_MICROSEC => Identifier::MispMicrosectime,
        MISB_ST0604_ID_HEVC_MICROSEC => Identifier::HevcMicroseconds,
        MISB_ST0604_ID_HEVC_NANOSEC => Identifier::HevcNanoseconds,
        _ => return None,
    })
}

fn c_timestamp(d: &Decoded) -> misb_st0604 {
    let w = &d.warnings;
    let mut warnings = 0;
    if w.bad_separators > 0 {
        warnings |= MISB_ST0604_WARN_SEPARATOR;
    }
    if w.reserved_bits {
        warnings |= MISB_ST0604_WARN_RESERVED;
    }
    if w.reverse_without_discontinuity {
        warnings |= MISB_ST0604_WARN_REVERSE;
    }
    if w.trailing_bytes > 0 {
        warnings |= MISB_ST0604_WARN_TRAILING;
    }
    misb_st0604 {
        struct_size: mem::size_of::<misb_st0604>() as u32,
        identifier: id_code(d.timestamp.identifier),
        status: u32::from(d.timestamp.status.byte()),
        warnings,
        value: d.timestamp.value,
        misp_us: d.timestamp.misp_time().as_micros(),
    }
}

/// The caller's timestamp: a known identifier and a status byte.
unsafe fn timestamp_in(p: *const misb_st0604) -> Result<Timestamp, i32> {
    let (t, n) = read_in(p, misb_st0604::default())?;
    if n < ENCODE_FIELDS {
        return Err(MISB_ERR_INVALID);
    }
    let id = id_of(t.identifier).ok_or(MISB_ERR_INVALID)?;
    let status = u8::try_from(t.status).map_err(|_| MISB_ERR_INVALID)?;
    Ok(Timestamp::new(id, TimeStatus::from_byte(status), t.value))
}

/// Encode with `f` and copy the bytes out.
unsafe fn encode_with<const N: usize>(
    timestamp: *const misb_st0604,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
    f: fn(&Timestamp) -> Result<[u8; N], St0604Error>,
) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        if len.is_null() {
            return MISB_ERR_NULL;
        }
        let t = match timestamp_in(timestamp) {
            Ok(t) => t,
            Err(status) => return status,
        };
        match f(&t) {
            Ok(bytes) => copy_out(&bytes, buf, cap, len),
            Err(_) => MISB_ERR_INVALID,
        }
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_st0604_decode(data: *const u8, len: usize, out: *mut misb_st0604) -> misb_status {
    catch_unwind(AssertUnwindSafe(|| {
        if let Err(status) = check_out(out) {
            return status;
        }
        let bytes = match input(data, len) {
            Ok(b) => b,
            Err(status) => return status,
        };
        match st0604::decode(bytes) {
            Ok(d) => write_out(out, c_timestamp(&d)),
            Err(St0604Error::UnknownIdentifier) => MISB_EMPTY,
            Err(_) => MISB_ERR_PARSE,
        }
    }))
    .unwrap_or(MISB_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn misb_st0604_encode(
    timestamp: *const misb_st0604,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
) -> misb_status {
    encode_with(timestamp, buf, cap, len, Timestamp::to_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn misb_st0604_encode_payload(
    timestamp: *const misb_st0604,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
) -> misb_status {
    encode_with(timestamp, buf, cap, len, Timestamp::payload)
}
