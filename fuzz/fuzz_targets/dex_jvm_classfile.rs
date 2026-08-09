#![no_main]

use libfuzzer_sys::fuzz_target;

use disrobe_fuzz::dex_jvm_classfile::{self, JvmExerciseOutcome};

fuzz_target!(|data: &[u8]| {
    let _: JvmExerciseOutcome =
        dex_jvm_classfile::run_fuzz_input(data, dex_jvm_classfile::exercise);
});
