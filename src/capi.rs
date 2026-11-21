//! Stable C ABI. The contract is `include/misb.h`; read its header comment
//! for the rules every function follows.
//!
//! A decoded packet crosses the boundary as an opaque `misb_packet` handle
//! that owns the Rust [`Packet`] together with everything the C side is
//! handed: a flat table of the value tree (one node per item, list element
//! and struct field, children stored contiguously) and an arena of
//! NUL-terminated copies of every string. Rust's `&'static str` and
//! `String` are not NUL-terminated, so names, units, enum labels, invalid
//! reasons, text values and error messages are copied into the arena once,
//! when the handle is built. After that the handle never changes, so every
//! pointer it gives out stays valid, and identical, until
//! `misb_packet_free`, and any number of threads may read it at once.
#![allow(unsafe_code, non_camel_case_types, clippy::missing_safety_doc)]

use crate::au_cells;
use crate::{Checksum, Config, Decoder, Error, Field, Item, Packet, Standard, Value};
use std::collections::HashMap;
use std::ffi::CStr;
use std::hash::{BuildHasherDefault, Hasher};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{mem, ptr, slice};

/// `MISB_ABI_VERSION`: bumped only for incompatible changes.
pub const MISB_ABI_VERSION: u32 = 1;

/// Function result: 0 on success, positive for "nothing to return",
/// negative on error.
pub type misb_status = i32;
/// Success.
pub const MISB_OK: i32 = 0;
/// Nothing to return: no packet waiting, no matching item, no more cells.
pub const MISB_EMPTY: i32 = 1;
/// A required pointer was NULL.
pub const MISB_ERR_NULL: i32 = -1;
/// An argument or struct field is invalid.
pub const MISB_ERR_INVALID: i32 = -2;
/// An index or offset is out of range.
pub const MISB_ERR_RANGE: i32 = -3;
/// The bytes are not a complete ST 0601 packet (or AU cell).
pub const MISB_ERR_PARSE: i32 = -4;
/// Internal error; a decoder is poisoned by it.
pub const MISB_ERR_PANIC: i32 = -5;
/// The decoder failed earlier and must be freed.
pub const MISB_ERR_POISONED: i32 = -6;

/// Value kinds (`misb_item.kind`), one per [`Value`] variant. Codes are
/// never reused; 0 is never a kind.
pub const MISB_VALUE_UINT: u32 = 1;
/// [`Value::Int`].
pub const MISB_VALUE_INT: u32 = 2;
/// [`Value::Float`].
pub const MISB_VALUE_FLOAT: u32 = 3;
/// [`Value::Text`].
pub const MISB_VALUE_TEXT: u32 = 4;
/// [`Value::Bytes`].
pub const MISB_VALUE_BYTES: u32 = 5;
/// [`Value::Time`].
pub const MISB_VALUE_TIME: u32 = 6;
/// [`Value::Enum`].
pub const MISB_VALUE_ENUM: u32 = 7;
/// [`Value::OutOfRange`].
pub const MISB_VALUE_OUT_OF_RANGE: u32 = 8;
/// [`Value::Set`], and the root item of a packet.
pub const MISB_VALUE_SET: u32 = 9;
/// [`Value::List`].
pub const MISB_VALUE_LIST: u32 = 10;
/// [`Value::Struct`].
pub const MISB_VALUE_STRUCT: u32 = 11;
/// [`Value::Invalid`].
pub const MISB_VALUE_INVALID: u32 = 12;
/// [`Value::Unknown`].
pub const MISB_VALUE_UNKNOWN: u32 = 13;

/// [`Standard::St0601`]. Codes are never reused; 0 is never a standard.
pub const MISB_STANDARD_ST0601: u32 = 1;
/// [`Standard::St0102`].
pub const MISB_STANDARD_ST0102: u32 = 2;
/// [`Standard::St0806`].
pub const MISB_STANDARD_ST0806: u32 = 3;
/// [`Standard::St0903`].
pub const MISB_STANDARD_ST0903: u32 = 4;

/// [`Checksum::NotApplicable`].
pub const MISB_CHECKSUM_NOT_APPLICABLE: u32 = 0;
/// [`Checksum::Valid`].
pub const MISB_CHECKSUM_VALID: u32 = 1;
/// [`Checksum::Mismatch`].
pub const MISB_CHECKSUM_MISMATCH: u32 = 2;
/// [`Checksum::Missing`].
pub const MISB_CHECKSUM_MISSING: u32 = 3;

/// No error: the set was parsed to its end.
pub const MISB_ERROR_NONE: u32 = 0;
/// [`Error::Truncated`].
pub const MISB_ERROR_TRUNCATED: u32 = 1;
/// [`Error::BadLength`].
pub const MISB_ERROR_BAD_LENGTH: u32 = 2;
/// [`Error::BadTag`].
pub const MISB_ERROR_BAD_TAG: u32 = 3;
/// [`Error::TooLarge`].
pub const MISB_ERROR_TOO_LARGE: u32 = 4;
/// [`Error::NotSt0601`].
pub const MISB_ERROR_NOT_ST0601: u32 = 5;
/// [`Error::TooDeep`].
pub const MISB_ERROR_TOO_DEEP: u32 = 6;
/// [`Error::TooManyItems`].
pub const MISB_ERROR_TOO_MANY_ITEMS: u32 = 7;
/// [`Error::InvalidConfig`].
pub const MISB_ERROR_INVALID_CONFIG: u32 = 8;

// ---------------------------------------------------------------- structs

/// Decoder limits and options; see [`Config`]. Fields after `max_items`
/// were added later: a caller whose `struct_size` stops before them gets
/// the defaults.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_config {
    pub struct_size: u32,
    pub verify_checksum: u32,
    pub reject_bad_checksum: u32,
    pub reserved: u32,
    pub max_packet_bytes: u64,
    pub max_buffer_bytes: u64,
    pub max_depth: u64,
    pub max_items: u64,
    pub max_skip_bytes: u64,
    pub max_total_items: u64,
    pub keep_raw: u32,
    pub reserved2: u32,
}

/// Decoder counters; see [`crate::Stats`]. Fields after `dropped` were
/// added later.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct misb_stats {
    pub struct_size: u32,
    pub reserved: u32,
    pub packets: u64,
    pub bytes: u64,
    pub bytes_skipped: u64,
    pub resyncs: u64,
    pub skipped_keys: u64,
    pub oversized: u64,
    pub checksum_errors: u64,
    pub malformed: u64,
    pub truncated_at_finish: u64,
    pub dropped: u64,
    pub checksum_missing: u64,
    pub nested_errors: u64,
    pub packet_bytes: u64,
    pub bad_lengths: u64,
}

/// Summary of a packet or of a nested set.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_packet_info {
    pub struct_size: u32,
    pub standard: u32,
    pub checksum: u32,
    pub checksum_expected: u16,
    pub checksum_computed: u16,
    pub error: u32,
    pub reserved: u32,
    pub item_count: u64,
    pub error_message: *const c_char,
}

/// One node of a packet's value tree.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_item {
    pub struct_size: u32,
    pub kind: u32,
    pub packet: *const misb_packet,
    pub id: u64,
    pub tag: u64,
    pub name: *const c_char,
    pub units: *const c_char,
    pub child_count: u64,
    pub uint_value: u64,
    pub int_value: i64,
    pub float_value: f64,
    pub time_us: u64,
    pub enum_code: u64,
    pub enum_label: *const c_char,
    pub data: *const u8,
    pub data_len: u64,
    pub raw: *const u8,
    pub raw_len: u64,
    pub invalid_reason: *const c_char,
    pub standard: u32,
    pub reserved: u32,
}

/// One metadata access unit cell; see [`crate::AuCell`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct misb_au_cell {
    pub struct_size: u32,
    pub service_id: u8,
    pub sequence_number: u8,
    pub fragment: u8,
    pub decoder_config: u8,
    pub random_access: u8,
    pub reserved: [u8; 7],
    pub data: *const u8,
    pub data_len: u64,
}

/// Opaque decoder handle.
#[derive(Debug)]
pub struct misb_decoder {
    decoder: Decoder,
    /// A panic left the decoder in an unknown state.
    poisoned: bool,
}

/// Opaque packet handle: the packet and the C view of it. Immutable once
/// built.
#[derive(Debug)]
pub struct misb_packet {
    packet: Packet,
    /// The value tree, flattened. Node 0 is the root (the packet itself);
    /// the children of every node are contiguous.
    nodes: Vec<Node>,
    /// NUL-terminated strings the nodes point at. Offset 0 holds the empty
    /// string.
    arena: Vec<u8>,
}

/// Arena offset meaning "no string" (a NULL pointer in C).
const NONE: usize = usize::MAX;

/// What a `misb_item` shows, minus what can be read from the value itself.
#[derive(Debug)]
struct Node {
    /// The value, inside `misb_packet::packet`; null for the root.
    value: *const Value,
    /// The set item the node is; null for the root, list elements and
    /// struct fields, which have no bytes of their own.
    item: *const Item,
    /// Local tag; index for list elements and struct fields; 0 for the root.
    tag: u64,
    /// Arena offsets of the name and units (never `NONE`).
    name: usize,
    units: usize,
    /// Arena offset of the text of a TEXT value, the label of an ENUM, the
    /// reason of an INVALID or the error message of a SET; `NONE` otherwise.
    extra: usize,
    /// Node index of the first child (meaningless without children).
    first_child: usize,
}

/// Points at a NUL byte: the data of empty TEXT, BYTES and raw values, so
/// that `data` is never NULL for those kinds.
static EMPTY: [u8; 1] = [0];

// ---------------------------------------------------------------- helpers

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
}

/// Run `f`, turning a panic into a status code.
fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(MISB_ERR_PANIC)
}

/// Run `f` on a decoder; a panic poisons it.
fn guard_mut(h: &mut misb_decoder, f: impl FnOnce(&mut misb_decoder) -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| f(&mut *h))) {
        Ok(status) => status,
        Err(_) => {
            h.poisoned = true;
            MISB_ERR_PANIC
        }
    }
}

unsafe fn decoder_mut<'a>(d: *mut misb_decoder) -> Result<&'a mut misb_decoder, i32> {
    let h = d.as_mut().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

unsafe fn decoder_ref<'a>(d: *const misb_decoder) -> Result<&'a misb_decoder, i32> {
    let h = d.as_ref().ok_or(MISB_ERR_NULL)?;
    if h.poisoned {
        return Err(MISB_ERR_POISONED);
    }
    Ok(h)
}

unsafe fn packet_ref<'a>(p: *const misb_packet) -> Result<&'a misb_packet, i32> {
    p.as_ref().ok_or(MISB_ERR_NULL)
}

/// Read a caller's struct, honouring its `struct_size`: fields the caller
/// does not know about keep the values in `base`. Returns the struct and
/// the number of bytes read.
unsafe fn read_in<T: Copy>(p: *const T, base: T) -> Result<(T, usize), i32> {
    if p.is_null() {
        return Err(MISB_ERR_NULL);
    }
    let size = (p as *const u32).read() as usize;
    if size < mem::size_of::<u32>() {
        return Err(MISB_ERR_INVALID);
    }
    let n = size.min(mem::size_of::<T>());
    let mut v = base;
    ptr::copy_nonoverlapping(p as *const u8, ptr::addr_of_mut!(v) as *mut u8, n);
    Ok((v, n))
}

/// Check that a caller's output struct is usable: not NULL and with a
/// `struct_size` of at least 4.
unsafe fn check_out<T>(p: *mut T) -> Result<(), i32> {
    if p.is_null() {
        return Err(MISB_ERR_NULL);
    }
    if ((p as *const u32).read() as usize) < mem::size_of::<u32>() {
        return Err(MISB_ERR_INVALID);
    }
    Ok(())
}

/// Write `v` into a caller's struct, no further than its `struct_size`,
/// and set `struct_size` to the bytes written.
unsafe fn write_out<T: Copy>(p: *mut T, v: T) -> i32 {
    if let Err(status) = check_out(p) {
        return status;
    }
    let size = (p as *const u32).read() as usize;
    let n = size.min(mem::size_of::<T>());
    ptr::copy_nonoverlapping(ptr::addr_of!(v) as *const u8, p as *mut u8, n);
    (p as *mut u32).write(n as u32);
    MISB_OK
}

fn size_of_u32<T>() -> u32 {
    mem::size_of::<T>() as u32
}

/// The caller's bytes as a slice: `data` may be NULL only when `len` is 0.
unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len > isize::MAX as usize {
        return Err(MISB_ERR_INVALID);
    }
    match (data.is_null(), len) {
        (_, 0) => Ok(&[]),
        (true, _) => Err(MISB_ERR_NULL),
        (false, _) => Ok(slice::from_raw_parts(data, len)),
    }
}

/// Write through an optional out pointer.
unsafe fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        p.write(v);
    }
}

/// `MISB_VALUE_*` code of a value.
fn kind_code(v: &Value) -> u32 {
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
    }
}

/// `MISB_STANDARD_*` code of a standard.
fn standard_code(s: Standard) -> u32 {
    match s {
        Standard::St0601 => MISB_STANDARD_ST0601,
        Standard::St0102 => MISB_STANDARD_ST0102,
        Standard::St0806 => MISB_STANDARD_ST0806,
        Standard::St0903 => MISB_STANDARD_ST0903,
    }
}

/// `MISB_ERROR_*` code of an error. Exhaustive, with no wildcard, so that a
/// new variant cannot be added without a code.
fn error_code(e: &Error) -> u32 {
    match e {
        Error::Truncated { .. } => MISB_ERROR_TRUNCATED,
        Error::BadLength => MISB_ERROR_BAD_LENGTH,
        Error::BadTag => MISB_ERROR_BAD_TAG,
        Error::TooLarge { .. } => MISB_ERROR_TOO_LARGE,
        Error::NotSt0601 => MISB_ERROR_NOT_ST0601,
        Error::TooDeep => MISB_ERROR_TOO_DEEP,
        Error::TooManyItems { .. } => MISB_ERROR_TOO_MANY_ITEMS,
        Error::InvalidConfig(_) => MISB_ERROR_INVALID_CONFIG,
    }
}

impl From<&Config> for misb_config {
    fn from(c: &Config) -> Self {
        misb_config {
            struct_size: size_of_u32::<misb_config>(),
            verify_checksum: u32::from(c.verify_checksum),
            reject_bad_checksum: u32::from(c.reject_bad_checksum),
            reserved: 0,
            max_packet_bytes: c.max_packet_bytes as u64,
            max_buffer_bytes: c.max_buffer_bytes as u64,
            max_depth: c.max_depth as u64,
            max_items: c.max_items as u64,
            max_skip_bytes: c.max_skip_bytes as u64,
            max_total_items: c.max_total_items as u64,
            keep_raw: u32::from(c.keep_raw),
            reserved2: 0,
        }
    }
}

impl misb_config {
    /// The Rust config, or `MISB_ERR_INVALID` for a flag other than 0 or 1,
    /// a size that does not fit `size_t`, or limits [`Config::validate`]
    /// refuses.
    fn to_config(self) -> Result<Config, i32> {
        let size = |v: u64| usize::try_from(v).map_err(|_| MISB_ERR_INVALID);
        let flag = |v: u32| match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MISB_ERR_INVALID),
        };
        // Start from the defaults so that options this struct does not
        // carry keep their default values.
        let mut c = Config::default();
        c.verify_checksum = flag(self.verify_checksum)?;
        c.reject_bad_checksum = flag(self.reject_bad_checksum)?;
        c.max_packet_bytes = size(self.max_packet_bytes)?;
        c.max_buffer_bytes = size(self.max_buffer_bytes)?;
        c.max_depth = size(self.max_depth)?;
        c.max_items = size(self.max_items)?;
        c.max_skip_bytes = size(self.max_skip_bytes)?;
        c.max_total_items = size(self.max_total_items)?;
        c.keep_raw = flag(self.keep_raw)?;
        c.validate().map_err(|_| MISB_ERR_INVALID)?;
        Ok(c)
    }
}

/// The config a caller passed: NULL means the defaults.
unsafe fn config_in(config: *const misb_config) -> Result<Config, i32> {
    if config.is_null() {
        return Ok(Config::default());
    }
    let (c, _) = read_in(config, misb_config::from(&Config::default()))?;
    c.to_config()
}

// ---------------------------------------------------------------- packet handle

/// The children still to be laid out for a node.
#[derive(Clone, Copy)]
enum Children<'p> {
    Items(&'p [Item]),
    Values(&'p [Value]),
    Fields(&'p [Field]),
}

/// Hash for the interning table. Its keys are the addresses of static
/// strings in this library, a small fixed set that input cannot add to, so
/// a multiplicative hash is enough and much cheaper than SipHash.
#[derive(Default)]
struct AddressHasher(u64);

impl Hasher for AddressHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
}

/// Builds the node table and string arena of a packet handle. Iterative,
/// so the depth of the value tree cannot exhaust the stack.
struct Builder<'p> {
    nodes: Vec<Node>,
    arena: Vec<u8>,
    /// Arena offsets of the static strings copied so far, by address and
    /// length (a static string's bytes never change).
    interned: HashMap<(usize, usize), usize, BuildHasherDefault<AddressHasher>>,
    /// Nodes whose children are not laid out yet.
    pending: Vec<(usize, Children<'p>)>,
}

impl<'p> Builder<'p> {
    /// Lay out `packet`. Every pointer in the nodes points into heap memory
    /// owned by `packet` (item and value buffers, nested sets), never at
    /// the `Packet` struct itself, so the packet may move afterwards.
    fn build(packet: &'p Packet) -> (Vec<Node>, Vec<u8>) {
        // Room for the top level; nested values grow the vectors as needed.
        let mut arena = Vec::with_capacity(32 * (packet.items.len() + 1));
        arena.push(0);
        let mut b = Builder {
            nodes: Vec::with_capacity(packet.items.len() + 1),
            arena,
            // Each top-level item usually brings a name and units.
            interned: HashMap::with_capacity_and_hasher(2 * packet.items.len() + 2, Default::default()),
            pending: Vec::new(),
        };
        let name = b.intern(packet.standard.title());
        let extra = b.error_message(packet);
        b.nodes.push(Node {
            value: ptr::null(),
            item: ptr::null(),
            tag: 0,
            name,
            units: 0,
            extra,
            first_child: 0,
        });
        b.pending.push((0, Children::Items(&packet.items)));
        while let Some((parent, children)) = b.pending.pop() {
            let first = b.nodes.len();
            match children {
                Children::Items(items) => {
                    for item in items {
                        let name = b.intern(item.name);
                        let units = b.intern(item.units);
                        b.push(&item.value, item, item.tag, name, units);
                    }
                }
                Children::Values(values) => {
                    for (i, v) in values.iter().enumerate() {
                        b.push(v, ptr::null(), i as u64, 0, 0);
                    }
                }
                Children::Fields(fields) => {
                    for (i, f) in fields.iter().enumerate() {
                        let name = b.intern(f.name);
                        b.push(&f.value, ptr::null(), i as u64, name, 0);
                    }
                }
            }
            if let Some(node) = b.nodes.get_mut(parent) {
                node.first_child = first;
            }
        }
        (b.nodes, b.arena)
    }

    fn push(&mut self, value: &'p Value, item: *const Item, tag: u64, name: usize, units: usize) {
        let id = self.nodes.len();
        let extra = match value {
            Value::Text(s) => self.copy(s),
            Value::Enum { label: Some(l), .. } => self.intern(l),
            Value::Invalid(why) => self.intern(why),
            Value::Set(p) => self.error_message(p),
            _ => NONE,
        };
        self.nodes.push(Node { value, item, tag, name, units, extra, first_child: 0 });
        match value {
            Value::Set(p) => self.pending.push((id, Children::Items(&p.items))),
            Value::List(l) => self.pending.push((id, Children::Values(l))),
            Value::Struct(f) => self.pending.push((id, Children::Fields(f))),
            _ => {}
        }
    }

    /// A NUL-terminated copy of `s`; its offset.
    fn copy(&mut self, s: &str) -> usize {
        let at = self.arena.len();
        self.arena.extend_from_slice(s.as_bytes());
        self.arena.push(0);
        at
    }

    /// A static string, copied once per packet.
    fn intern(&mut self, s: &'static str) -> usize {
        if s.is_empty() {
            return 0;
        }
        let key = (s.as_ptr() as usize, s.len());
        if let Some(&at) = self.interned.get(&key) {
            return at;
        }
        let at = self.copy(s);
        self.interned.insert(key, at);
        at
    }

    fn error_message(&mut self, p: &Packet) -> usize {
        match &p.error {
            Some(e) => self.copy(&e.to_string()),
            None => NONE,
        }
    }
}

impl misb_packet {
    fn new(packet: Packet) -> Box<misb_packet> {
        let mut h = Box::new(misb_packet { packet, nodes: Vec::new(), arena: Vec::new() });
        let (nodes, arena) = Builder::build(&h.packet);
        h.nodes = nodes;
        h.arena = arena;
        h
    }

    /// The value a node shows; `None` for the root.
    fn value(&self, n: &Node) -> Option<&Value> {
        // SAFETY: a non-null `value` points into `self.packet`, which lives
        // as long as `self` and is never changed (see `Builder::build`).
        unsafe { n.value.as_ref() }
    }

    /// The set a node shows: the packet for the root, the nested set for a
    /// SET value.
    fn set_of(&self, n: &Node) -> Option<&Packet> {
        match self.value(n) {
            None => Some(&self.packet),
            Some(Value::Set(p)) => Some(p),
            Some(_) => None,
        }
    }

    fn child_count(&self, n: &Node) -> usize {
        match self.value(n) {
            None => self.packet.items.len(),
            Some(Value::Set(p)) => p.items.len(),
            Some(Value::List(l)) => l.len(),
            Some(Value::Struct(f)) => f.len(),
            Some(_) => 0,
        }
    }

    /// Node indices of the children of node `id`.
    fn children(&self, id: usize) -> std::ops::Range<usize> {
        match self.nodes.get(id) {
            Some(n) => {
                let count = self.child_count(n);
                let end = n.first_child.saturating_add(count).min(self.nodes.len());
                n.first_child.min(end)..end
            }
            None => 0..0,
        }
    }

    /// A C string in the arena; NULL for `NONE`.
    fn cstr(&self, at: usize) -> *const c_char {
        self.arena.get(at..).map_or(ptr::null(), |s| s.as_ptr() as *const c_char)
    }

    /// The bytes of an arena string, without its NUL.
    fn arena_bytes(&self, at: usize) -> &[u8] {
        let rest = self.arena.get(at..).unwrap_or(&[]);
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        rest.get(..end).unwrap_or(&[])
    }

    /// The C view of node `id`.
    fn item(&self, id: usize) -> Option<misb_item> {
        let n = self.nodes.get(id)?;
        let mut out = misb_item::empty();
        out.struct_size = size_of_u32::<misb_item>();
        out.packet = self;
        out.id = id as u64;
        out.tag = n.tag;
        out.name = self.cstr(n.name);
        out.units = self.cstr(n.units);
        out.child_count = self.child_count(n) as u64;
        // SAFETY: as for `value`.
        if let Some(item) = unsafe { n.item.as_ref() } {
            out.raw = bytes_ptr(&item.raw);
            out.raw_len = item.raw.len() as u64;
        }
        match self.value(n) {
            None => {
                out.kind = MISB_VALUE_SET;
                out.standard = standard_code(self.packet.standard);
            }
            Some(v) => {
                out.kind = kind_code(v);
                match v {
                    Value::Uint(u) => out.uint_value = *u,
                    Value::Int(i) => out.int_value = *i,
                    Value::Float(f) => out.float_value = *f,
                    Value::Text(s) => {
                        out.data = self.cstr(n.extra) as *const u8;
                        out.data_len = s.len() as u64;
                    }
                    Value::Bytes(b) => {
                        out.data = bytes_ptr(b);
                        out.data_len = b.len() as u64;
                    }
                    Value::Time(t) => out.time_us = *t,
                    Value::Enum { code, .. } => {
                        out.enum_code = *code;
                        out.enum_label = self.cstr(n.extra);
                    }
                    Value::Set(p) => out.standard = standard_code(p.standard),
                    Value::Invalid(_) => out.invalid_reason = self.cstr(n.extra),
                    Value::OutOfRange | Value::Unknown | Value::List(_) | Value::Struct(_) => {}
                }
            }
        }
        Some(out)
    }

    /// Summary of the set node `id` shows; `None` if it is not a set.
    fn set_info(&self, id: usize) -> Option<misb_packet_info> {
        let n = self.nodes.get(id)?;
        let p = self.set_of(n)?;
        let (checksum, checksum_expected, checksum_computed) = match p.checksum {
            Checksum::NotApplicable => (MISB_CHECKSUM_NOT_APPLICABLE, 0, 0),
            Checksum::Valid => (MISB_CHECKSUM_VALID, 0, 0),
            Checksum::Mismatch { expected, computed } => (MISB_CHECKSUM_MISMATCH, expected, computed),
            Checksum::Missing => (MISB_CHECKSUM_MISSING, 0, 0),
        };
        Some(misb_packet_info {
            struct_size: size_of_u32::<misb_packet_info>(),
            standard: standard_code(p.standard),
            checksum,
            checksum_expected,
            checksum_computed,
            error: p.error.as_ref().map_or(MISB_ERROR_NONE, error_code),
            reserved: 0,
            item_count: p.items.len() as u64,
            error_message: self.cstr(n.extra),
        })
    }

    /// Write the `index`th child of node `parent`.
    unsafe fn write_child(&self, parent: usize, index: usize, out: *mut misb_item) -> i32 {
        let child = self.children(parent).nth(index);
        match child.and_then(|c| self.item(c)) {
            Some(item) => write_out(out, item),
            None => MISB_ERR_RANGE,
        }
    }

    /// Write the first child of node `parent` that `matches`.
    unsafe fn write_first(&self, parent: usize, out: *mut misb_item, matches: impl Fn(&Node) -> bool) -> i32 {
        let found = self.children(parent).find(|&c| self.nodes.get(c).map_or(false, &matches));
        match found.and_then(|c| self.item(c)) {
            Some(item) => write_out(out, item),
            None => MISB_EMPTY,
        }
    }
}

/// Never NULL: empty buffers point at a NUL byte.
fn bytes_ptr(b: &[u8]) -> *const u8 {
    if b.is_empty() {
        EMPTY.as_ptr()
    } else {
        b.as_ptr()
    }
}

impl misb_item {
    /// All fields zero or NULL.
    fn empty() -> misb_item {
        misb_item {
            struct_size: 0,
            kind: 0,
            packet: ptr::null(),
            id: 0,
            tag: 0,
            name: ptr::null(),
            units: ptr::null(),
            child_count: 0,
            uint_value: 0,
            int_value: 0,
            float_value: 0.0,
            time_us: 0,
            enum_code: 0,
            enum_label: ptr::null(),
            data: ptr::null(),
            data_len: 0,
            raw: ptr::null(),
            raw_len: 0,
            invalid_reason: ptr::null(),
            standard: 0,
            reserved: 0,
        }
    }
}

/// Bytes of `misb_item` up to and including `id`: what a caller's item
/// must hold to be navigated from.
fn item_ref_size() -> usize {
    let v = mem::MaybeUninit::<misb_item>::uninit();
    let base = v.as_ptr();
    // SAFETY: only the address is computed; nothing is read.
    let at = unsafe { ptr::addr_of!((*base).id) } as usize - base as usize;
    at + mem::size_of::<u64>()
}

/// The packet and node an item filled in by the library refers to.
unsafe fn node_of<'a>(item: *const misb_item) -> Result<(&'a misb_packet, usize), i32> {
    let (v, n) = read_in(item, misb_item::empty())?;
    if n < item_ref_size() {
        return Err(MISB_ERR_INVALID);
    }
    let h = v.packet.as_ref().ok_or(MISB_ERR_INVALID)?;
    match usize::try_from(v.id) {
        Ok(id) if id < h.nodes.len() => Ok((h, id)),
        _ => Err(MISB_ERR_INVALID),
    }
}

/// Hand a new packet handle to C.
unsafe fn give(out: *mut *mut misb_packet, packet: Packet) {
    out.write(Box::into_raw(misb_packet::new(packet)));
}

// ---------------------------------------------------------------- library

// These return constants or static strings chosen by a `match` on an
// integer: nothing in them can panic, so they need no guard.

#[no_mangle]
pub extern "C" fn misb_abi_version() -> u32 {
    MISB_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn misb_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn misb_status_string(status: misb_status) -> *const c_char {
    let s: &'static str = match status {
        MISB_OK => "ok\0",
        MISB_EMPTY => "nothing to return\0",
        MISB_ERR_NULL => "null pointer\0",
        MISB_ERR_INVALID => "invalid argument\0",
        MISB_ERR_RANGE => "index out of range\0",
        MISB_ERR_PARSE => "not a complete ST 0601 packet\0",
        MISB_ERR_PANIC => "internal error\0",
        MISB_ERR_POISONED => "decoder unusable after an internal error\0",
        MISB_ERR_ENCODE => "value or packet rejected by the encoder\0",
        MISB_ERR_TOO_SMALL => "output buffer too small\0",
        _ => "unknown status\0",
    };
    s.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn misb_value_kind_name(kind: u32) -> *const c_char {
    let s: &'static str = match kind {
        MISB_VALUE_UINT => "uint\0",
        MISB_VALUE_INT => "int\0",
        MISB_VALUE_FLOAT => "float\0",
        MISB_VALUE_TEXT => "text\0",
        MISB_VALUE_BYTES => "bytes\0",
        MISB_VALUE_TIME => "time\0",
        MISB_VALUE_ENUM => "enum\0",
        MISB_VALUE_OUT_OF_RANGE => "out of range\0",
        MISB_VALUE_SET => "set\0",
        MISB_VALUE_LIST => "list\0",
        MISB_VALUE_STRUCT => "struct\0",
        MISB_VALUE_INVALID => "invalid\0",
        MISB_VALUE_UNKNOWN => "unknown\0",
        _ => return ptr::null(),
    };
    s.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn misb_standard_name(standard: u32) -> *const c_char {
    // The same text as `Standard::name`; tests.rs checks it.
    let s: &'static str = match standard {
        MISB_STANDARD_ST0601 => "ST 0601\0",
        MISB_STANDARD_ST0102 => "ST 0102\0",
        MISB_STANDARD_ST0806 => "ST 0806\0",
        MISB_STANDARD_ST0903 => "ST 0903\0",
        _ => return ptr::null(),
    };
    s.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn misb_error_name(error: u32) -> *const c_char {
    let s: &'static str = match error {
        MISB_ERROR_NONE => "no error\0",
        MISB_ERROR_TRUNCATED => "truncated\0",
        MISB_ERROR_BAD_LENGTH => "malformed BER length\0",
        MISB_ERROR_BAD_TAG => "malformed BER-OID tag\0",
        MISB_ERROR_TOO_LARGE => "too large\0",
        MISB_ERROR_NOT_ST0601 => "not an ST 0601 packet\0",
        MISB_ERROR_TOO_DEEP => "sets nested too deeply\0",
        MISB_ERROR_TOO_MANY_ITEMS => "too many items\0",
        MISB_ERROR_INVALID_CONFIG => "invalid config\0",
        _ => return ptr::null(),
    };
    s.as_ptr() as *const c_char
}

// ---------------------------------------------------------------- decoder

#[no_mangle]
pub unsafe extern "C" fn misb_config_default(config: *mut misb_config) -> misb_status {
    guard(|| write_out(config, misb_config::from(&Config::default())))
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_new(config: *const misb_config, out: *mut *mut misb_decoder) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    guard(|| {
        let config = check!(config_in(config));
        let decoder = check!(Decoder::with_config(config).map_err(|_| MISB_ERR_INVALID));
        let h = Box::new(misb_decoder { decoder, poisoned: false });
        out.write(Box::into_raw(h));
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_free(decoder: *mut misb_decoder) {
    if !decoder.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(decoder))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_push(decoder: *mut misb_decoder, data: *const u8, len: usize) -> misb_status {
    let h = check!(decoder_mut(decoder));
    let bytes = check!(input(data, len));
    guard_mut(h, |h| {
        h.decoder.push(bytes);
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_finish(decoder: *mut misb_decoder) -> misb_status {
    let h = check!(decoder_mut(decoder));
    guard_mut(h, |h| {
        h.decoder.finish();
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_reset(decoder: *mut misb_decoder) -> misb_status {
    let h = check!(decoder_mut(decoder));
    guard_mut(h, |h| {
        h.decoder.reset();
        MISB_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_next(decoder: *mut misb_decoder, out: *mut *mut misb_packet) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    let h = check!(decoder_mut(decoder));
    guard_mut(h, |h| match h.decoder.next_packet() {
        Some(packet) => {
            give(out, packet);
            MISB_OK
        }
        None => MISB_EMPTY,
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decoder_stats(decoder: *const misb_decoder, out: *mut misb_stats) -> misb_status {
    let h = check!(decoder_ref(decoder));
    guard(|| {
        let s = h.decoder.stats();
        write_out(
            out,
            misb_stats {
                struct_size: size_of_u32::<misb_stats>(),
                reserved: 0,
                packets: s.packets,
                bytes: s.bytes,
                bytes_skipped: s.bytes_skipped,
                resyncs: s.resyncs,
                skipped_keys: s.skipped_keys,
                oversized: s.oversized,
                checksum_errors: s.checksum_errors,
                malformed: s.malformed,
                truncated_at_finish: s.truncated_at_finish,
                dropped: s.dropped,
                checksum_missing: s.checksum_missing,
                nested_errors: s.nested_errors,
                packet_bytes: s.packet_bytes,
                bad_lengths: s.bad_lengths,
            },
        )
    })
}

// ---------------------------------------------------------------- packets

#[no_mangle]
pub unsafe extern "C" fn misb_decode(data: *const u8, len: usize, out: *mut *mut misb_packet) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    let bytes = check!(input(data, len));
    guard(|| match crate::decode(bytes) {
        Ok(packet) => {
            give(out, packet);
            MISB_OK
        }
        Err(_) => MISB_ERR_PARSE,
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_decode_ex(
    data: *const u8,
    len: usize,
    config: *const misb_config,
    out: *mut *mut misb_packet,
    consumed: *mut usize,
    error: *mut u32,
) -> misb_status {
    if out.is_null() {
        return MISB_ERR_NULL;
    }
    out.write(ptr::null_mut());
    put(consumed, 0);
    put(error, MISB_ERROR_NONE);
    let bytes = check!(input(data, len));
    guard(|| {
        let cfg = check!(config_in(config));
        match crate::decode_prefix(bytes, &cfg) {
            Ok((packet, used)) => {
                give(out, packet);
                put(consumed, used);
                MISB_OK
            }
            Err(e) => {
                put(error, error_code(&e));
                MISB_ERR_PARSE
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_packet_free(packet: *mut misb_packet) {
    if !packet.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(packet))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn misb_packet_info_get(packet: *const misb_packet, out: *mut misb_packet_info) -> misb_status {
    let h = check!(packet_ref(packet));
    guard(|| match h.set_info(0) {
        Some(info) => write_out(out, info),
        None => MISB_ERR_PANIC,
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_packet_root(packet: *const misb_packet, out: *mut misb_item) -> misb_status {
    let h = check!(packet_ref(packet));
    guard(|| match h.item(0) {
        Some(item) => write_out(out, item),
        None => MISB_ERR_PANIC,
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_packet_item(packet: *const misb_packet, index: usize, out: *mut misb_item) -> misb_status {
    let h = check!(packet_ref(packet));
    check!(check_out(out));
    guard(|| h.write_child(0, index, out))
}

#[no_mangle]
pub unsafe extern "C" fn misb_packet_find(packet: *const misb_packet, tag: u64, out: *mut misb_item) -> misb_status {
    let h = check!(packet_ref(packet));
    check!(check_out(out));
    guard(|| h.write_first(0, out, |n| n.tag == tag))
}

#[no_mangle]
pub unsafe extern "C" fn misb_item_child(parent: *const misb_item, index: usize, out: *mut misb_item) -> misb_status {
    let (h, id) = check!(node_of(parent));
    check!(check_out(out));
    guard(|| h.write_child(id, index, out))
}

#[no_mangle]
pub unsafe extern "C" fn misb_item_find(parent: *const misb_item, tag: u64, out: *mut misb_item) -> misb_status {
    let (h, id) = check!(node_of(parent));
    check!(check_out(out));
    guard(|| h.write_first(id, out, |n| n.tag == tag))
}

#[no_mangle]
pub unsafe extern "C" fn misb_item_field(
    parent: *const misb_item,
    name: *const c_char,
    out: *mut misb_item,
) -> misb_status {
    let (h, id) = check!(node_of(parent));
    if name.is_null() {
        return MISB_ERR_NULL;
    }
    check!(check_out(out));
    guard(|| {
        let want = CStr::from_ptr(name).to_bytes();
        h.write_first(id, out, |n| h.arena_bytes(n.name) == want)
    })
}

#[no_mangle]
pub unsafe extern "C" fn misb_set_info_get(set: *const misb_item, out: *mut misb_packet_info) -> misb_status {
    let (h, id) = check!(node_of(set));
    guard(|| match h.set_info(id) {
        Some(info) => write_out(out, info),
        None => MISB_ERR_INVALID,
    })
}

// ---------------------------------------------------------------- AU cells

#[no_mangle]
pub unsafe extern "C" fn misb_au_cell_next(
    data: *const u8,
    len: usize,
    offset: *mut usize,
    out: *mut misb_au_cell,
) -> misb_status {
    if offset.is_null() {
        return MISB_ERR_NULL;
    }
    let bytes = check!(input(data, len));
    check!(check_out(out));
    guard(|| {
        let at = offset.read();
        let Some(rest) = bytes.get(at..) else { return MISB_ERR_RANGE };
        match au_cells(rest).next() {
            None => MISB_EMPTY,
            Some(Err(_)) => MISB_ERR_PARSE,
            Some(Ok(cell)) => {
                let cell_len = cell.data.len() + 5;
                let status = write_out(
                    out,
                    misb_au_cell {
                        struct_size: size_of_u32::<misb_au_cell>(),
                        service_id: cell.service_id,
                        sequence_number: cell.sequence_number,
                        fragment: cell.fragment,
                        decoder_config: u8::from(cell.decoder_config),
                        random_access: u8::from(cell.random_access),
                        reserved: [0; 7],
                        data: bytes_ptr(cell.data),
                        data_len: cell.data.len() as u64,
                    },
                );
                if status == MISB_OK {
                    offset.write(at.saturating_add(cell_len));
                }
                status
            }
        }
    })
}

mod encode;
pub use encode::*;

#[cfg(test)]
mod tests;
