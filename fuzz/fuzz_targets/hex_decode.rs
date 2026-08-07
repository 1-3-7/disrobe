#![no_main]
use libfuzzer_sys::fuzz_target;

use disrobe_core::codec::hex::{OddTail, STRICT, TOKEN, TRUNCATING, WRAPPED_STREAM, decode_with};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 {
        return;
    }
    for options in [
        STRICT,
        TOKEN,
        TRUNCATING,
        WRAPPED_STREAM,
        STRICT.with_odd_tail(OddTail::PadHigh),
        STRICT.with_max_input_bytes(256),
    ] {
        if let Ok(decoded) = decode_with(data, options) {
            assert!(decoded.len() <= data.len());
        }
    }
});
