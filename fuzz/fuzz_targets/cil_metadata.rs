#![no_main]

use disrobe_fuzz::cil_metadata;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    cil_metadata::run_fuzz_input(data, cil_metadata::exercise);
});
