use super::*;
use misb::capi::*;
use std::ffi::CStr;
use std::mem;
use std::os::raw::c_char;
use std::ptr;

/// Most nodes of one packet's tree the C API walk visits.
const MAX_NODES: usize = 3000;

/// The C API: the first part of the input is a sequence of API calls, the
/// rest builds the stream they push.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    let ops_len = usize::from(input.u8()) * 2;
    let mut ops = Input::new(input.bytes(ops_len));
    let s = generate(&mut input);
    // SAFETY: every pointer handed to the API points at live, correctly
    // sized memory owned by this function, or at what the API returned.
    unsafe { capi_session(&mut ops, &s) }
}

fn expect(status: misb_status, allowed: &[misb_status], call: &str) {
    assert!(allowed.contains(&status), "{call} returned {status}");
}

/// Read every byte, so a bad pointer is caught (by a sanitizer, or a crash).
unsafe fn touch(data: *const u8, len: u64) {
    if len > 0 {
        assert!(!data.is_null(), "null data with length {len}");
        let s = std::slice::from_raw_parts(data, usize::try_from(len).unwrap());
        black_box(s.iter().fold(0u8, |a, &b| a ^ b));
    }
}

/// A string the library returned: not NULL, NUL-terminated.
unsafe fn cstr<'a>(p: *const c_char, what: &str) -> &'a [u8] {
    assert!(!p.is_null(), "{what} is NULL");
    CStr::from_ptr(p).to_bytes()
}

/// A `struct_size` for `T`: usually exact (always, once the input runs
/// out), sometimes an older (shorter) or newer (longer) struct, sometimes
/// invalid.
fn struct_size<T>(ops: &mut Input<'_>) -> u32 {
    let full = mem::size_of::<T>() as u32;
    match ops.u8() % 8 {
        1 => u32::from(ops.u8()) % full,
        2 => full + u32::from(ops.u8()),
        _ => full,
    }
}

const fn full<T>() -> u32 {
    mem::size_of::<T>() as u32
}

/// Bytes of `misb_item` up to and including `id`, which navigation needs.
fn item_ref_size() -> u32 {
    let v = mem::MaybeUninit::<misb_item>::uninit();
    let base = v.as_ptr();
    // SAFETY: only the address is computed; nothing is read.
    let at = unsafe { ptr::addr_of!((*base).id) } as usize - base as usize;
    (at + mem::size_of::<u64>()) as u32
}

fn kind_of(v: &Value) -> u32 {
    match v {
        Value::Uint(_) => MISB_VALUE_UINT,
        Value::Int(_) => MISB_VALUE_INT,
        Value::Float(_) => MISB_VALUE_FLOAT,
        Value::Text(_) => MISB_VALUE_TEXT,
        Value::Bytes(_) => MISB_VALUE_BYTES,
        Value::Time(_) => MISB_VALUE_TIME,
        Value::Enum { .. } => MISB_VALUE_ENUM,
        Value::OutOfRange => MISB_VALUE_OUT_OF_RANGE,
        Value::Set(_) => MISB_VALUE_SET,
        Value::List(_) => MISB_VALUE_LIST,
        Value::Struct(_) => MISB_VALUE_STRUCT,
        Value::Invalid(_) => MISB_VALUE_INVALID,
        Value::Unknown => MISB_VALUE_UNKNOWN,
        _ => panic!("a Value variant the harness does not know"),
    }
}

/// The C view of a config the library would build from `c`: the bytes up
/// to `struct_size` over the defaults, then the documented rules.
fn config_accepted(c: &misb_config) -> bool {
    let size = c.struct_size as usize;
    if size < 4 {
        return false;
    }
    let mut v = misb_config_defaults();
    let n = size.min(mem::size_of::<misb_config>());
    // SAFETY: both are plain repr(C) structs of the same type; n bytes fit.
    unsafe { ptr::copy_nonoverlapping(c as *const misb_config as *const u8, &mut v as *mut misb_config as *mut u8, n) };
    let flags_ok = [v.verify_checksum, v.reject_bad_checksum, v.keep_raw].iter().all(|&f| f <= 1);
    let limits_ok = [v.max_packet_bytes, v.max_buffer_bytes, v.max_skip_bytes, v.max_items, v.max_total_items]
        .iter()
        .all(|&l| l != 0 && usize::try_from(l).is_ok());
    flags_ok && limits_ok && v.max_depth <= Config::MAX_DEPTH_LIMIT as u64
}

fn misb_config_defaults() -> misb_config {
    // SAFETY: zeroed is a valid misb_config; the library fills it.
    let mut c: misb_config = unsafe { std::mem::zeroed() };
    c.struct_size = full::<misb_config>();
    // SAFETY: c is a live, correctly sized struct.
    assert_eq!(unsafe { misb_config_default(&mut c) }, MISB_OK);
    c
}

unsafe fn capi_session(ops: &mut Input<'_>, s: &[u8]) {
    const OK: &[i32] = &[MISB_OK];
    const NULL: &[i32] = &[MISB_ERR_NULL];

    let mut config = misb_config_defaults();
    match ops.u8() % 4 {
        0 => {}
        1 => {
            config.verify_checksum = u32::from(ops.bool());
            config.reject_bad_checksum = u32::from(ops.bool());
            config.keep_raw = u32::from(ops.bool());
            config.max_depth = u64::from(ops.u8() % 33);
            config.max_items = 1 + u64::from(ops.u8());
            config.max_total_items = 1 + u64::from(ops.u16());
            config.max_packet_bytes = 1 + u64::from(ops.u16());
            config.max_buffer_bytes = 1 + u64::from(ops.u16()) * 4;
            config.max_skip_bytes = 1 + u64::from(ops.u16());
        }
        2 => {
            // Anything, valid or not.
            config.verify_checksum = u32::from(ops.u8() % 3);
            config.reject_bad_checksum = u32::from(ops.u8() % 3);
            config.keep_raw = u32::from(ops.u8() % 3);
            config.reserved = ops.u32();
            config.max_depth = u64::from(ops.u8() % 40);
            config.max_items = u64::from(ops.u16() % 300);
            config.max_total_items = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_packet_bytes = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_buffer_bytes = [0, 1, u64::from(ops.u32() % (1 << 22)), u64::MAX][usize::from(ops.u8() % 4)];
            config.max_skip_bytes = [0, 1, u64::from(ops.u16()), u64::MAX][usize::from(ops.u8() % 4)];
        }
        _ => config.struct_size = struct_size::<misb_config>(ops),
    }
    let mut d: *mut misb_decoder = ptr::null_mut();
    let use_config = ops.u8() >= 32;
    let config_ptr: *const misb_config = if use_config { &config } else { ptr::null() };
    let status = misb_decoder_new(config_ptr, &mut d);
    expect(status, &[MISB_OK, MISB_ERR_INVALID], "decoder_new");
    assert_eq!(status == MISB_OK, !use_config || config_accepted(&config), "decoder_new accepted the wrong configs");
    if status != MISB_OK {
        assert!(d.is_null(), "failed decoder_new left a handle");
        expect(misb_decoder_new(ptr::null(), &mut d), OK, "decoder_new(defaults)");
    }
    assert!(!d.is_null());
    expect(misb_decoder_new(ptr::null(), ptr::null_mut()), NULL, "decoder_new(out=NULL)");

    let mut pos = 0usize;
    let mut kept: Vec<*mut misb_packet> = Vec::new();
    while !ops.is_empty() {
        match ops.u8() % 10 {
            0 => {
                let n = (1 + usize::from(ops.u16() % 4096)).min(s.len() - pos);
                expect(misb_decoder_push(d, s[pos..].as_ptr(), n), OK, "push");
                pos += n;
            }
            1 => {
                expect(misb_decoder_push(d, ptr::null(), 0), OK, "push(NULL, 0)");
                expect(misb_decoder_push(d, ptr::null(), 1), NULL, "push(NULL, 1)");
                expect(misb_decoder_push(ptr::null_mut(), s.as_ptr(), 0), NULL, "push(decoder=NULL)");
            }
            2 => expect(misb_decoder_finish(d), OK, "finish"),
            3 => {
                let mut p = ptr::null_mut();
                let status = misb_decoder_next(d, &mut p);
                expect(status, &[MISB_OK, MISB_EMPTY], "next");
                assert_eq!(status == MISB_OK, !p.is_null());
                if status == MISB_OK {
                    walk_packet(p, ops, None);
                    // Some packets outlive the decoder.
                    if ops.bool() {
                        kept.push(p);
                    } else {
                        misb_packet_free(p);
                    }
                }
            }
            4 => {
                let mut st: misb_stats = misb_stats::default();
                st.struct_size = struct_size::<misb_stats>(ops);
                let size = st.struct_size;
                let status = misb_decoder_stats(d, &mut st);
                expect(status, &[MISB_OK, MISB_ERR_INVALID], "stats");
                assert_eq!(status == MISB_ERR_INVALID, size < 4);
                if status == MISB_OK {
                    assert_eq!(st.struct_size, size.min(full::<misb_stats>()));
                    if st.struct_size == full::<misb_stats>() {
                        assert!(st.packet_bytes + st.bytes_skipped <= st.bytes);
                        assert!(st.bytes <= pos as u64);
                    }
                }
            }
            5 => {
                if ops.u8() < 40 {
                    expect(misb_decoder_reset(d), OK, "reset");
                }
            }
            6 => decode_ex_call(ops, s),
            7 => au_cell_calls(ops, s),
            8 => names(ops),
            _ => null_calls(ops, d, s),
        }
    }

    // Finish the stream and drain everything.
    if pos < s.len() {
        expect(misb_decoder_push(d, s[pos..].as_ptr(), s.len() - pos), OK, "push(rest)");
    }
    expect(misb_decoder_finish(d), OK, "finish");
    loop {
        let mut p = ptr::null_mut();
        let status = misb_decoder_next(d, &mut p);
        expect(status, &[MISB_OK, MISB_EMPTY], "next");
        if status != MISB_OK {
            assert!(p.is_null());
            break;
        }
        walk_packet(p, &mut Input::new(&[]), None);
        misb_packet_free(p);
    }
    let mut st = misb_stats::default();
    st.struct_size = full::<misb_stats>();
    expect(misb_decoder_stats(d, &mut st), OK, "stats");
    assert_eq!(st.bytes, st.packet_bytes + st.bytes_skipped, "bytes not accounted for after finish");
    misb_decoder_free(d);
    misb_decoder_free(ptr::null_mut());
    // A packet does not depend on its decoder.
    for p in kept {
        walk_packet(p, &mut Input::new(&[]), None);
        misb_packet_free(p);
    }
    misb_packet_free(ptr::null_mut());
}

/// misb_decode and misb_decode_ex on a slice of the stream, against
/// `decode_prefix`.
unsafe fn decode_ex_call(ops: &mut Input<'_>, s: &[u8]) {
    let at = if s.is_empty() { 0 } else { usize::from(ops.u16()) % s.len() };
    let n = usize::from(ops.u16()).min(s.len() - at);
    let data = &s[at..at + n];
    let mut config = misb_config_defaults();
    if ops.bool() {
        config.max_packet_bytes = 1 + u64::from(ops.u16());
        config.max_depth = u64::from(ops.u8() % 40);
        config.keep_raw = u32::from(ops.u8() % 3);
    }
    let use_config = ops.bool();
    let config_ptr: *const misb_config = if use_config { &config } else { ptr::null() };
    let (mut p, mut consumed, mut error) = (ptr::null_mut(), usize::MAX, u32::MAX);
    let with_outs = ops.bool();
    let status = misb_decode_ex(
        data.as_ptr(),
        data.len(),
        config_ptr,
        &mut p,
        if with_outs { &mut consumed } else { ptr::null_mut() },
        if with_outs { &mut error } else { ptr::null_mut() },
    );
    expect(status, &[MISB_OK, MISB_ERR_PARSE, MISB_ERR_INVALID], "decode_ex");
    assert_eq!(status == MISB_OK, !p.is_null());
    if use_config && !config_accepted(&config) {
        assert_eq!(status, MISB_ERR_INVALID);
        return;
    }
    let cfg = if use_config { rust_config(&config) } else { Config::default() };
    match misb::decode_prefix(data, &cfg) {
        Ok((packet, used)) => {
            assert_eq!(status, MISB_OK);
            if with_outs {
                assert_eq!((consumed, error), (used, MISB_ERROR_NONE));
            }
            walk_packet(p, ops, Some(&packet));
            misb_packet_free(p);
        }
        Err(e) => {
            assert_eq!(status, MISB_ERR_PARSE);
            if with_outs {
                assert_eq!(consumed, 0);
                let name = cstr(misb_error_name(error), "error name");
                assert!(!name.is_empty());
                assert_ne!(error, MISB_ERROR_NONE, "{e}");
            }
        }
    }
    // misb_decode is misb_decode_ex with the defaults.
    let mut q = ptr::null_mut();
    let status = misb_decode(data.as_ptr(), data.len(), &mut q);
    expect(status, &[MISB_OK, MISB_ERR_PARSE], "decode");
    assert_eq!(status == MISB_OK, misb::decode(data).is_ok());
    misb_packet_free(q);
}

/// The Rust config the C config stands for (already accepted).
fn rust_config(c: &misb_config) -> Config {
    let mut r = Config::default();
    r.verify_checksum = c.verify_checksum == 1;
    r.reject_bad_checksum = c.reject_bad_checksum == 1;
    r.keep_raw = c.keep_raw == 1;
    r.max_packet_bytes = c.max_packet_bytes as usize;
    r.max_buffer_bytes = c.max_buffer_bytes as usize;
    r.max_skip_bytes = c.max_skip_bytes as usize;
    r.max_depth = c.max_depth as usize;
    r.max_items = c.max_items as usize;
    r.max_total_items = c.max_total_items as usize;
    r
}

unsafe fn au_cell_calls(ops: &mut Input<'_>, s: &[u8]) {
    let at = if s.is_empty() { 0 } else { usize::from(ops.u16()) % s.len() };
    let data = &s[at..];
    let mut offset = 0usize;
    let mut steps = 0;
    loop {
        let mut cell: misb_au_cell = std::mem::zeroed();
        cell.struct_size = struct_size::<misb_au_cell>(ops);
        let size = cell.struct_size;
        let before = offset;
        let status = misb_au_cell_next(data.as_ptr(), data.len(), &mut offset, &mut cell);
        expect(status, &[MISB_OK, MISB_EMPTY, MISB_ERR_PARSE, MISB_ERR_INVALID], "au_cell_next");
        assert_eq!(status == MISB_ERR_INVALID, size < 4);
        steps += 1;
        if status != MISB_OK {
            assert_eq!(offset, before, "offset moved on {status}");
            if status == MISB_ERR_INVALID && steps < 1000 {
                continue;
            }
            break;
        }
        assert!(offset > before && offset <= data.len());
        if cell.struct_size == full::<misb_au_cell>() {
            assert_eq!(cell.data_len as usize + 5, offset - before);
            assert!(!cell.data.is_null());
            touch(cell.data, cell.data_len);
            assert!(cell.fragment <= 3 && cell.decoder_config <= 1 && cell.random_access <= 1);
        }
        if steps > 1000 {
            break;
        }
    }
    let mut cell: misb_au_cell = std::mem::zeroed();
    cell.struct_size = full::<misb_au_cell>();
    let mut past = data.len() + 1;
    expect(misb_au_cell_next(data.as_ptr(), data.len(), &mut past, &mut cell), &[MISB_ERR_RANGE], "au_cell_next(past end)");
    expect(misb_au_cell_next(data.as_ptr(), data.len(), ptr::null_mut(), &mut cell), &[MISB_ERR_NULL], "au_cell_next(offset=NULL)");
    let mut zero = 0usize;
    expect(misb_au_cell_next(ptr::null(), 0, &mut zero, &mut cell), &[MISB_EMPTY], "au_cell_next(NULL, 0)");
}

unsafe fn names(ops: &mut Input<'_>) {
    assert_eq!(misb_abi_version(), MISB_ABI_VERSION);
    assert_eq!(cstr(misb_version(), "version"), misb::VERSION.as_bytes());
    let kind = u32::from(ops.u8() % 20);
    assert_eq!(misb_value_kind_name(kind).is_null(), !(1..=13).contains(&kind), "kind {kind}");
    let standard = u32::from(ops.u8() % 8);
    assert_eq!(misb_standard_name(standard).is_null(), !(1..=4).contains(&standard), "standard {standard}");
    let error = u32::from(ops.u8() % 12);
    assert_eq!(misb_error_name(error).is_null(), error > 8, "error {error}");
    assert!(!cstr(misb_status_string(ops.u32() as i32), "status string").is_empty());
}

unsafe fn null_calls(ops: &mut Input<'_>, d: *mut misb_decoder, s: &[u8]) {
    const NULL: &[i32] = &[MISB_ERR_NULL];
    let mut p = 1 as *mut misb_packet;
    expect(misb_decoder_next(ptr::null_mut(), &mut p), NULL, "next(decoder=NULL)");
    assert!(p.is_null(), "next did not clear *out");
    expect(misb_decoder_next(d, ptr::null_mut()), NULL, "next(out=NULL)");
    let mut st = misb_stats::default();
    st.struct_size = full::<misb_stats>();
    expect(misb_decoder_stats(ptr::null(), &mut st), NULL, "stats(decoder=NULL)");
    expect(misb_decoder_stats(d, ptr::null_mut()), NULL, "stats(out=NULL)");
    expect(misb_decoder_finish(ptr::null_mut()), NULL, "finish(NULL)");
    expect(misb_decoder_reset(ptr::null_mut()), NULL, "reset(NULL)");
    expect(misb_config_default(ptr::null_mut()), NULL, "config_default(NULL)");
    let mut c: misb_config = std::mem::zeroed();
    expect(misb_config_default(&mut c), &[MISB_ERR_INVALID], "config_default(struct_size 0)");
    let mut q = 1 as *mut misb_packet;
    expect(misb_decode(ptr::null(), 5, &mut q), NULL, "decode(NULL, 5)");
    assert!(q.is_null());
    expect(misb_decode(s.as_ptr(), s.len(), ptr::null_mut()), NULL, "decode(out=NULL)");
    expect(misb_decode_ex(ptr::null(), 1, ptr::null(), &mut q, ptr::null_mut(), ptr::null_mut()), NULL, "decode_ex(NULL, 1)");
    let mut info: misb_packet_info = std::mem::zeroed();
    info.struct_size = full::<misb_packet_info>();
    expect(misb_packet_info_get(ptr::null(), &mut info), NULL, "packet_info_get(NULL)");
    let mut item: misb_item = std::mem::zeroed();
    item.struct_size = full::<misb_item>();
    expect(misb_packet_root(ptr::null(), &mut item), NULL, "packet_root(NULL)");
    expect(misb_packet_item(ptr::null(), 0, &mut item), NULL, "packet_item(NULL)");
    expect(misb_packet_find(ptr::null(), 1, &mut item), NULL, "packet_find(NULL)");
    expect(misb_item_child(ptr::null(), 0, &mut item), NULL, "item_child(NULL)");
    expect(misb_item_find(ptr::null(), 0, &mut item), NULL, "item_find(NULL)");
    expect(misb_item_field(ptr::null(), b"x\0".as_ptr() as *const c_char, &mut item), NULL, "item_field(NULL)");
    expect(misb_set_info_get(ptr::null(), &mut info), NULL, "set_info_get(NULL)");
    // An item the library did not fill in: no packet behind it.
    let mut blank: misb_item = std::mem::zeroed();
    blank.struct_size = full::<misb_item>();
    expect(misb_item_child(&blank, 0, &mut item), &[MISB_ERR_INVALID], "item_child(blank)");
    blank.struct_size = u32::from(ops.u8() % 4);
    expect(misb_item_child(&blank, 0, &mut item), &[MISB_ERR_INVALID], "item_child(struct_size < 4)");
}

/// Walk a packet's tree through the C API, checking every node and, when
/// `rust` is given, that it shows the same values as the Rust packet.
unsafe fn walk_packet(p: *const misb_packet, ops: &mut Input<'_>, rust: Option<&Packet>) {
    let mut info: misb_packet_info = std::mem::zeroed();
    info.struct_size = struct_size::<misb_packet_info>(ops);
    let size = info.struct_size;
    let status = misb_packet_info_get(p, &mut info);
    expect(status, &[MISB_OK, MISB_ERR_INVALID], "packet_info_get");
    assert_eq!(status == MISB_ERR_INVALID, size < 4);
    info.struct_size = full::<misb_packet_info>();
    expect(misb_packet_info_get(p, &mut info), &[MISB_OK], "packet_info_get");
    check_info(&info, rust);
    assert_eq!(info.standard, MISB_STANDARD_ST0601);
    assert!(info.checksum <= MISB_CHECKSUM_MISSING);

    let mut root: misb_item = std::mem::zeroed();
    root.struct_size = full::<misb_item>();
    expect(misb_packet_root(p, &mut root), &[MISB_OK], "packet_root");
    assert_eq!((root.kind, root.tag, root.child_count), (MISB_VALUE_SET, 0, info.item_count));
    assert!(root.raw.is_null() && root.raw_len == 0);
    assert!(!cstr(root.name, "root name").is_empty());
    let mut budget = MAX_NODES;
    let items: Option<Vec<&Value>> = rust.map(|r| r.items.iter().map(|i| &i.value).collect());
    walk_children(&root, ops, items.as_deref(), &mut budget);

    // misb_packet_item and misb_packet_find agree with the root's children.
    let mut a: misb_item = std::mem::zeroed();
    a.struct_size = full::<misb_item>();
    let index = usize::from(ops.u8());
    let status = misb_packet_item(p, index, &mut a);
    expect(status, &[MISB_OK, MISB_ERR_RANGE], "packet_item");
    assert_eq!(status == MISB_OK, (index as u64) < info.item_count);
    if status == MISB_OK {
        let mut b: misb_item = std::mem::zeroed();
        b.struct_size = full::<misb_item>();
        expect(misb_item_child(&root, index, &mut b), &[MISB_OK], "item_child(root)");
        assert_eq!((a.id, a.tag, a.kind), (b.id, b.tag, b.kind));
        let mut f: misb_item = std::mem::zeroed();
        f.struct_size = full::<misb_item>();
        expect(misb_packet_find(p, a.tag, &mut f), &[MISB_OK], "packet_find");
        assert_eq!(f.tag, a.tag);
        assert!(f.id <= a.id, "find returned a later item than the first");
    }
    let tag = u64::from(ops.u16());
    expect(misb_packet_find(p, tag, &mut a), &[MISB_OK, MISB_EMPTY], "packet_find");
}

unsafe fn check_info(info: &misb_packet_info, rust: Option<&Packet>) {
    assert!(info.error <= MISB_ERROR_INVALID_CONFIG);
    assert_eq!(info.error == MISB_ERROR_NONE, info.error_message.is_null());
    if !info.error_message.is_null() {
        assert!(!cstr(info.error_message, "error message").is_empty());
    }
    if info.checksum != MISB_CHECKSUM_MISMATCH {
        assert_eq!((info.checksum_expected, info.checksum_computed), (0, 0));
    }
    if let Some(r) = rust {
        assert_eq!(info.item_count, r.items.len() as u64);
        assert_eq!(info.error == MISB_ERROR_NONE, r.error.is_none());
        let code = match r.checksum {
            Checksum::NotApplicable => MISB_CHECKSUM_NOT_APPLICABLE,
            Checksum::Valid => MISB_CHECKSUM_VALID,
            Checksum::Mismatch { .. } => MISB_CHECKSUM_MISMATCH,
            Checksum::Missing => MISB_CHECKSUM_MISSING,
            _ => panic!("a Checksum variant the harness does not know"),
        };
        assert_eq!(info.checksum, code);
        if let Some(e) = &r.error {
            assert_eq!(cstr(info.error_message, "error message"), e.to_string().as_bytes());
        }
    }
}

/// Check the children of `parent` (filled in by the library), recursively
/// while the budget lasts. `rust` holds the values the children show.
unsafe fn walk_children(parent: &misb_item, ops: &mut Input<'_>, rust: Option<&[&Value]>, budget: &mut usize) {
    if let Some(r) = rust {
        assert_eq!(parent.child_count, r.len() as u64, "child count differs from the Rust value");
    }
    for i in 0..parent.child_count as usize {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let mut c: misb_item = std::mem::zeroed();
        // Sometimes an older, shorter struct.
        c.struct_size = if ops.u8() >= 240 { item_ref_size() + u32::from(ops.u8() % 16) } else { full::<misb_item>() };
        let size = c.struct_size;
        expect(misb_item_child(parent, i, &mut c), &[MISB_OK], "item_child");
        assert_eq!(c.struct_size, size.min(full::<misb_item>()));
        if c.struct_size < full::<misb_item>() {
            // Fill in the rest through the same item, as `out` may be the
            // same struct as `parent`.
            let mut whole = c;
            whole.struct_size = full::<misb_item>();
            let mut again: misb_item = whole;
            expect(misb_item_child(parent, i, &mut again), &[MISB_OK], "item_child");
            // Only the fields the short struct had room for were written.
            assert_eq!(again.id, c.id);
            c = again;
        }
        let value = rust.map(|r| r[i]);
        check_item(&c, parent.kind == MISB_VALUE_SET, value);
        // Out of range, and lookups.
        let mut x: misb_item = std::mem::zeroed();
        x.struct_size = full::<misb_item>();
        expect(misb_item_child(&c, c.child_count as usize, &mut x), &[MISB_ERR_RANGE], "item_child(past end)");
        expect(misb_item_find(parent, c.tag, &mut x), &[MISB_OK], "item_find(own tag)");
        assert_eq!(x.tag, c.tag);
        let name = cstr(c.name, "name").to_vec();
        let mut name_z = name.clone();
        name_z.push(0);
        expect(misb_item_field(parent, name_z.as_ptr() as *const c_char, &mut x), &[MISB_OK], "item_field(own name)");
        assert_eq!(cstr(x.name, "name"), &name[..]);
        let mut info: misb_packet_info = std::mem::zeroed();
        info.struct_size = full::<misb_packet_info>();
        let status = misb_set_info_get(&c, &mut info);
        if c.kind == MISB_VALUE_SET {
            expect(status, &[MISB_OK], "set_info_get");
            assert_eq!(info.item_count, c.child_count);
            assert_eq!(info.standard, c.standard);
            assert_eq!(info.checksum, MISB_CHECKSUM_NOT_APPLICABLE);
            check_info(&info, value.and_then(Value::as_set));
        } else {
            expect(status, &[MISB_ERR_INVALID], "set_info_get(not a set)");
        }
        let children: Option<Vec<&Value>> = value.map(|v| match v {
            Value::Set(p) => p.items.iter().map(|i| &i.value).collect(),
            Value::List(l) => l.iter().collect(),
            Value::Struct(f) => f.iter().map(|x| &x.value).collect(),
            _ => Vec::new(),
        });
        if c.child_count > 0 {
            // Navigate from a copy, then from the same struct as the output.
            walk_children(&c, ops, children.as_deref(), budget);
            let mut same = c;
            let both: *mut misb_item = &mut same;
            expect(misb_item_child(both, 0, both), &[MISB_OK], "item_child(out == parent)");
        }
    }
}

unsafe fn check_item(c: &misb_item, in_set: bool, rust: Option<&Value>) {
    assert!((MISB_VALUE_UINT..=MISB_VALUE_UNKNOWN).contains(&c.kind), "kind {}", c.kind);
    assert!(!misb_value_kind_name(c.kind).is_null());
    cstr(c.name, "name");
    cstr(c.units, "units");
    if in_set {
        assert!(!c.raw.is_null(), "a set item without raw");
        touch(c.raw, c.raw_len);
    } else {
        assert!(c.raw.is_null() && c.raw_len == 0);
    }
    match c.kind {
        MISB_VALUE_TEXT => {
            assert!(!c.data.is_null());
            touch(c.data, c.data_len + 1);
            assert_eq!(*c.data.add(c.data_len as usize), 0, "text not NUL-terminated");
        }
        MISB_VALUE_BYTES => {
            assert!(!c.data.is_null());
            touch(c.data, c.data_len);
        }
        MISB_VALUE_INVALID => {
            cstr(c.invalid_reason, "invalid reason");
        }
        MISB_VALUE_ENUM => {
            if !c.enum_label.is_null() {
                cstr(c.enum_label, "enum label");
            }
        }
        MISB_VALUE_SET => assert!((MISB_STANDARD_ST0601..=MISB_STANDARD_ST0903).contains(&c.standard)),
        MISB_VALUE_UNKNOWN => assert_eq!(c.raw_len, 0),
        _ => {}
    }
    if !matches!(c.kind, MISB_VALUE_SET | MISB_VALUE_LIST | MISB_VALUE_STRUCT) {
        assert_eq!(c.child_count, 0);
    }
    let Some(v) = rust else { return };
    assert_eq!(c.kind, kind_of(v), "kind differs from {v:?}");
    match v {
        Value::Uint(u) => assert_eq!(c.uint_value, *u),
        Value::Int(i) => assert_eq!(c.int_value, *i),
        Value::Float(f) => assert!(c.float_value == *f || (c.float_value.is_nan() && f.is_nan())),
        Value::Time(t) => assert_eq!(c.time_us, *t),
        Value::Text(t) => assert_eq!(std::slice::from_raw_parts(c.data, c.data_len as usize), t.as_bytes()),
        Value::Bytes(b) => assert_eq!(std::slice::from_raw_parts(c.data, c.data_len as usize), &b[..]),
        Value::Enum { code, label } => {
            assert_eq!(c.enum_code, *code);
            assert_eq!(c.enum_label.is_null(), label.is_none());
            if let Some(l) = label {
                assert_eq!(cstr(c.enum_label, "label"), l.as_bytes());
            }
        }
        Value::Invalid(why) => assert_eq!(cstr(c.invalid_reason, "reason"), why.as_bytes()),
        _ => {}
    }
}
