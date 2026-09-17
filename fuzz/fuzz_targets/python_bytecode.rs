#![no_main]

use libfuzzer_sys::fuzz_target;

use disrobe_fuzz::python_bytecode;

fuzz_target!(|data: &[u8]| {
    if let Err(error) = python_bytecode::run_fuzz_input(data, python_bytecode::exercise) {
        panic!("{error}");
    }
});
