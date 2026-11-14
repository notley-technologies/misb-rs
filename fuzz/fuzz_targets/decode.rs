//! Raw bytes: key hunting, framing, and every set decoder behind it. The
//! first byte picks the settings. Works best with real KLV in the seed
//! corpus.
#![cfg_attr(not(feature = "capi"), forbid(unsafe_code))]
#![no_main]

#[path = "../../tests/harness/mod.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::decode(data));
