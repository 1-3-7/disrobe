#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyobfus::PyobfusPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "pyobfus";

const HELLO_SOURCE: &str = "print('hello world')\n";
const SAMPLE_SOURCE: &str = "import os\n\ndef greet(name):\n    return f'hello, {name}'\n\ndef main():\n    user = os.environ.get('USER', 'world')\n    print(greet(user))\n\nif __name__ == '__main__':\n    main()\n";

#[test]
fn pyobfus_real_hello_base64_reversed_recovers_exact_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        common::skip_absent_corpus(
            "pyobfus_real_hello_base64_reversed_recovers_exact_source",
            OBF,
        );
        return;
    };
    let text: &str = std::str::from_utf8(&fixture).expect("utf8");
    assert!(
        text.contains("lambda __ :") && text.contains("b64decode(__[::-1])"),
        "real fixture must be the htr-tech reversed base64 lambda wrapper"
    );
    let detect: DetectReport = PyobfusPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::Pyobfus);
    assert!(detect.matched, "real fixture must be detected: {detect:?}");

    let peel: PeelOutcome = PyobfusPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Full);
    assert_eq!(
        peel.recovered_source, HELLO_SOURCE,
        "base64-reversed peel must reproduce the exact original source"
    );
    assert_eq!(peel.stages_applied, vec!["reverse", "base64"]);
}

#[test]
fn pyobfus_real_sample_zlib_base64_recovers_exact_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "sample") else {
        common::skip_absent_corpus("pyobfus_real_sample_zlib_base64_recovers_exact_source", OBF);
        return;
    };
    let detect: DetectReport = PyobfusPass.detect(&fixture);
    assert!(detect.matched);

    let peel: PeelOutcome = PyobfusPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("sample peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Full);
    assert_eq!(
        peel.recovered_source, SAMPLE_SOURCE,
        "zlib+base64-reversed peel must reproduce the exact original source"
    );
    assert_eq!(peel.stages_applied, vec!["reverse", "base64", "zlib"]);
}

#[test]
fn pyobfus_real_marshal_chain_reaches_bytecode_handoff() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "marshal") else {
        common::skip_absent_corpus("pyobfus_real_marshal_chain_reaches_bytecode_handoff", OBF);
        return;
    };
    let detect: DetectReport = PyobfusPass.detect(&fixture);
    assert!(detect.matched);
    assert!(
        detect
            .markers
            .iter()
            .any(|m: &String| m == "decode-marshal")
    );

    let peel: PeelOutcome = PyobfusPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("marshal peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Partial,
        "marshal-terminated chain is an honest bytecode handoff, not source"
    );
    assert_eq!(
        peel.stages_applied,
        vec!["reverse", "base64", "zlib", "marshal"]
    );
    assert_eq!(
        peel.diagnostics
            .get("entry_code_object")
            .map(String::as_str),
        Some("<module>")
    );
}
