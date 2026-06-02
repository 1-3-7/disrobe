#![no_main]
#![cfg(feature = "chain")]

use libfuzzer_sys::fuzz_target;

use disrobe_core::chain::spec::ChainSpec;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ChainSpec::parse(text);
});
