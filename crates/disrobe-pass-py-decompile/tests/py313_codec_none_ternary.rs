#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::PathBuf;

use common::band::{
    BandInterpreter, CorpusMeasurement, band_scratch, find_interpreter, measure_corpus_file,
};
use common::stdlib_measure::interpreter_stdlib;

#[test]
fn codec_encoder_getstate_preserves_the_return_ternary() {
    let path: PathBuf = find_interpreter("3.13.14").expect("CPython 3.13.14");
    let lib: PathBuf = interpreter_stdlib(&path).expect("CPython 3.13.14 stdlib");
    let interpreter: BandInterpreter = BandInterpreter {
        alias: "3.13.14",
        path,
        is_prerelease: false,
    };

    for (module, label) in [
        ("encodings/utf_16.py", "py313-utf16-none-ternary"),
        ("encodings/utf_32.py", "py313-utf32-none-ternary"),
    ] {
        let scratch: PathBuf = band_scratch(label);
        let CorpusMeasurement::Measured(tally) =
            measure_corpus_file(&interpreter, &lib.join(module), label, &scratch)
        else {
            panic!("{module} was not measurable");
        };
        assert!(
            !tally
                .failures
                .iter()
                .any(|failure| failure.qualname == "<module>.IncrementalEncoder.getstate"),
            "{module} IncrementalEncoder.getstate is not recompile-equivalent: {:?}",
            tally.failures
        );
        let recovered: String =
            fs::read_to_string(scratch.join(format!("{label}.{}.dec.py", interpreter.alias)))
                .expect("recovered codec source");
        assert!(
            recovered.contains("return 2 if self.encoder is None else 0"),
            "{module} did not retain the return ternary"
        );
    }
}
