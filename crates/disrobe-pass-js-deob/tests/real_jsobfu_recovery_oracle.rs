#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{Detection, JsObfuRecovery, JsObfuscator, detect, recover_jsobfu};
use sha2::{Digest, Sha256};

#[path = "common/mod.rs"]
mod common;

const OBFUSCATED_SHA256: &str = "fb8a0fa445ef48d791834b971a7621c1e23a2f64480c8ee9aa07c4d33380e329";

struct AuthoredReference {
    source_sha256: &'static str,
    output: &'static str,
}

const AUTHORED_REFERENCE: AuthoredReference = AuthoredReference {
    source_sha256: "7576a69b3e0dd823087c56f5705d8b5c28d0c30a5a90a306e1b9ccca574aedfe",
    output: "{\"greeting\":\"hi world!\",\"sum\":3,\"product\":12,\"fib10\":55,\"factorial5\":120,\"count\":5,\"registered\":\"greet,add,mul,fib,factorial\"}",
};

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> String {
    let p: PathBuf = corpus(rel);
    fs::read_to_string(&p)
        .unwrap_or_else(|error| panic!("required corpus fixture {}: {error}", p.display()))
}

fn assert_sha256(label: &str, source: &str, expected: &str) {
    let actual: String = format!("{:x}", Sha256::digest(source.as_bytes()));
    assert_eq!(actual, expected, "{label} fixture hash changed");
}

fn eval_console_output(script: &str) -> Result<String, common::BoaWorkerError> {
    let executable: PathBuf = std::env::current_exe().map_err(|error: std::io::Error| {
        common::BoaWorkerError::HarnessFailure(error.to_string())
    })?;
    common::BoaWorker::new(executable)?.eval_capture(script, &[])
}

#[test]
fn real_jsobfu_classifies_as_jsobfu_family() {
    let src: String = load("jsobfu/obfuscated.js");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(
        det.family,
        JsObfuscator::JsObfu,
        "real jsobfu ES5 output must classify as the JsObfu family, not {:?}",
        det.family
    );
    assert!(det.confidence >= 0.5, "confidence floor: {det:?}");
}

#[test]
fn clean_source_not_misclassified_as_jsobfu() {
    let src: String = load("jsobfu/input.js");
    let det: Detection = detect(src.as_bytes());
    assert_ne!(
        det.family,
        JsObfuscator::JsObfu,
        "the clean ground-truth source must not be misdetected as jsobfu"
    );
}

#[test]
fn real_jsobfu_recovery_folds_fromcharcode_chains() {
    let src: String = load("jsobfu/obfuscated.js");
    let out: JsObfuRecovery = recover_jsobfu(&src);
    assert!(
        out.char_fold.from_char_code_calls_folded >= 20,
        "recovery must statically fold many String.fromCharCode chains; got {}",
        out.char_fold.from_char_code_calls_folded
    );
    assert!(
        !out.source.contains("String.fromCharCode"),
        "no String.fromCharCode chain may survive a full recovery"
    );
}

#[test]
fn recovered_jsobfu_is_behaviorally_identical_to_ground_truth() {
    let obf: String = load("jsobfu/obfuscated.js");
    let original: String = load("jsobfu/input.js");
    assert_sha256("obfuscated", &obf, OBFUSCATED_SHA256);
    assert_sha256(
        "authored input",
        &original,
        AUTHORED_REFERENCE.source_sha256,
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");

    assert_eq!(
        recovered_output, AUTHORED_REFERENCE.output,
        "recovered jsobfu must produce the pinned reference output"
    );
}

#[test]
fn recovered_jsobfu_output_mutation_is_rejected() {
    let obf: String = load("jsobfu/obfuscated.js");
    let authored: String = load("jsobfu/input.js");
    assert_sha256("obfuscated", &obf, OBFUSCATED_SHA256);
    assert_sha256(
        "authored input",
        &authored,
        AUTHORED_REFERENCE.source_sha256,
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");
    assert_eq!(recovered_output, AUTHORED_REFERENCE.output);

    let mutated: String = format!("{}\nconsole.log('mutation');", out.source);
    let mutated_output: String =
        eval_console_output(&mutated).expect("mutated recovered code must produce console output");
    assert_ne!(
        mutated_output, AUTHORED_REFERENCE.output,
        "mutation control must turn the grade red"
    );
}
