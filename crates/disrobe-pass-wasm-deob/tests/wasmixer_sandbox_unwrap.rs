#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{StubInfo, UnwrapReport, detect_decrypt_stubs, unwrap_decryption};

#[cfg(feature = "sandbox")]
const REAL_ONDEMAND_WAT: &str =
    include_str!("../../../corpus/wasm/obf/real/wasmixer_ondemand.obf.wat");

#[cfg(feature = "sandbox")]
const KNOWN_PLAINTEXT: &[u8] = b"disrobe/wasm/on-demand-decrypt";

#[cfg(feature = "sandbox")]
fn assemble(wat_text: &str) -> Vec<u8> {
    wat::parse_str(wat_text).expect("corpus wat must assemble")
}

#[cfg(feature = "sandbox")]
#[test]
fn real_compiler_ondemand_thunk_decrypts_to_known_plaintext() {
    let bytes: Vec<u8> = assemble(REAL_ONDEMAND_WAT);

    let stubs: Vec<StubInfo> = detect_decrypt_stubs(&bytes).expect("stub detection runs");
    assert!(
        !stubs.is_empty(),
        "the real rustc-emitted XOR byte-walk thunk must classify as a decrypt stub"
    );

    let report: UnwrapReport =
        unwrap_decryption(&bytes, &stubs).expect("sandbox unwrap runs on the real module");
    assert_eq!(
        report.recovered(),
        1,
        "exactly one stub decrypts its real data segment; failed={:?}",
        report.unresolved
    );
    assert_eq!(report.failed(), 0, "no stub should be unresolved");

    let recovered: &[u8] = &report.segments[0].decrypted;
    assert_eq!(
        recovered,
        KNOWN_PLAINTEXT,
        "sandbox-recovered plaintext must equal the known compiler input, got {:?}",
        core::str::from_utf8(recovered)
    );
    assert!(
        report.segments[0].len == KNOWN_PLAINTEXT.len() as i32,
        "recovered span length must match the real data-segment byte length"
    );
}

#[cfg(feature = "sandbox")]
#[test]
fn garbage_bytes_never_fabricate_plaintext() {
    let stub: StubInfo = StubInfo {
        fn_index: 0,
        key: Some(0x4b),
        op_histogram: std::collections::BTreeMap::new(),
        confidence: 1.0,
    };
    let junk: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x61, 0x73, 0x6d, 0xff, 0xff];
    let outcome: Result<UnwrapReport, _> = unwrap_decryption(&junk, &[stub]);
    if let Ok(report) = outcome {
        assert!(
            report.segments.is_empty(),
            "a non-wasm / malformed blob must never yield decrypted bytes"
        );
    }
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasmixer_sandbox_unwrap_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasmixer_sandbox_unwrap`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
