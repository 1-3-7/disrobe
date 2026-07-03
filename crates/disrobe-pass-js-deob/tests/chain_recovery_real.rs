#![cfg(feature = "chain")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_js_deob::chain_detector::{JS_OBF_PASS, JsObfDetector};

const JSCONFUSER_STATESUM: &str =
    include_str!("../../../corpus/js/jsconfuser/recovery/obf_statesum.real.js");
const JSCONFUSER_RGF: &str =
    include_str!("../../../corpus/js/jsconfuser/recovery/obf_tokenizer.rgf.js");
const JSCRAMBLER_BANNER: &str = include_str!("../../../corpus/js/jscrambler/obfuscated.banner.js");
const JAVASCRIPT_OBFUSCATOR: &str =
    include_str!("../../../corpus/js/javascript-obfuscator/obfuscated.js");
const PACKER_MEGAFILE: &str = include_str!("../../../corpus/js/packer/obfuscated.megafile.js");
const JSFUCK_BASIC: &str = include_str!("../corpus/esoteric/jsfuck-basic.fuck.js");
const SEA_BLOB: &[u8] = include_bytes!("../../../corpus/js/sea/sea-prep.blob");
const BYTENODE_JSC: &[u8] = include_bytes!("../../../corpus/v8/node-24/hello-24.jsc");

const fn ctx(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

fn run_chain(bytes: &[u8]) -> Artifact {
    let verdict: DetectVerdict = JsObfDetector
        .detect(&ctx(bytes))
        .expect("chain detector must produce a verdict for a real obfuscated sample");
    assert!(
        verdict.confidence >= 0.5,
        "verdict confidence below pick threshold: {verdict:?}"
    );
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    JS_OBF_PASS
        .run(&artifact)
        .expect("chain run path must recover, not error")
}

fn run_chain_text(bytes: &[u8]) -> String {
    let out: Artifact = run_chain(bytes);
    assert_eq!(out.rung, Rung::Surface);
    String::from_utf8(out.envelope).expect("recovered chain output must be utf-8")
}

#[test]
fn chain_recovers_jsconfuser_state_sum_to_plaintext() {
    let recovered: String = run_chain_text(JSCONFUSER_STATESUM.as_bytes());
    assert!(
        recovered.len() < JSCONFUSER_STATESUM.len(),
        "state-sum recovery must shrink the obfuscated machine: in={} out={}",
        JSCONFUSER_STATESUM.len(),
        recovered.len()
    );
    assert!(
        recovered.contains("43:220,13:200,34:214,88:250"),
        "linearized state machine must emit the known plaintext payload:\n{recovered}"
    );
    assert!(
        !recovered.contains("switch") || !recovered.contains("+ z7Y6ec"),
        "the state-sum dispatcher must be gone after linearization:\n{recovered}"
    );
}

#[test]
fn chain_recovers_jsconfuser_rgf_eval_to_real_function() {
    let recovered: String = run_chain_text(JSCONFUSER_RGF.as_bytes());
    assert!(
        recovered.len() < JSCONFUSER_RGF.len(),
        "rgf-eval recovery must shrink the wrapped payload: in={} out={}",
        JSCONFUSER_RGF.len(),
        recovered.len()
    );
    assert!(
        recovered.contains("function tokenize"),
        "the rgf-eval wrapper must be inlined to the real tokenizer source:\n{recovered}"
    );
    assert!(
        !recovered.contains("_rgf_eval") && !recovered.contains("_rgf=["),
        "the rgf-eval payload markers must be consumed:\n{recovered}"
    );
}

#[test]
fn chain_recovers_jscrambler_integrity_loop() {
    let detection: DetectVerdict = JsObfDetector
        .detect(&ctx(JSCRAMBLER_BANNER.as_bytes()))
        .expect("jscrambler banner must be detected");
    assert_eq!(detection.format_tag, "js-jscrambler");
    let recovered: String = run_chain_text(JSCRAMBLER_BANNER.as_bytes());
    assert!(
        !recovered.contains("while (!![])") && !recovered.contains("['constructor']"),
        "the jscrambler self-reference integrity loop must be stripped on the chain:\n{recovered}"
    );
    assert!(
        recovered.contains("console.log"),
        "business logic must survive the jscrambler chain recovery:\n{recovered}"
    );
}

#[test]
fn chain_recovers_javascript_obfuscator() {
    let recovered: String = run_chain_text(JAVASCRIPT_OBFUSCATOR.as_bytes());
    assert_ne!(
        recovered, JAVASCRIPT_OBFUSCATOR,
        "obfuscator.io chain run must transform, not pass through verbatim"
    );
    assert!(
        recovered.contains("\"source\""),
        "obfuscator.io chain output must carry a recovered source field:\n{}",
        &recovered[..recovered.len().min(200)]
    );
}

#[test]
fn chain_unpacks_dean_edwards_packer() {
    let detection: DetectVerdict = JsObfDetector
        .detect(&ctx(PACKER_MEGAFILE.as_bytes()))
        .expect("dean-edwards packer must be detected");
    assert_eq!(detection.format_tag, "js-dean-edwards-packer");
    let recovered: String = run_chain_text(PACKER_MEGAFILE.as_bytes());
    assert!(
        !recovered.starts_with("eval(function(p,a,c,k,e,"),
        "the p,a,c,k,e,r wrapper must be unpacked, not echoed:\n{}",
        &recovered[..recovered.len().min(120)]
    );
    assert!(
        recovered.contains("use strict") || recovered.contains("legacyVar"),
        "the unpacked payload must contain the real source tokens:\n{}",
        &recovered[..recovered.len().min(200)]
    );
}

#[test]
fn chain_decodes_jsfuck() {
    let detection: DetectVerdict = JsObfDetector
        .detect(&ctx(JSFUCK_BASIC.as_bytes()))
        .expect("jsfuck must be detected");
    assert_eq!(detection.format_tag, "js-jsfuck");
    let recovered: String = run_chain_text(JSFUCK_BASIC.as_bytes());
    assert!(
        !recovered.is_empty(),
        "jsfuck chain decode must produce a non-empty recovered string"
    );
    assert!(
        recovered != JSFUCK_BASIC,
        "jsfuck chain decode must transform the symbolic source"
    );
}

#[test]
fn chain_carves_node_sea_main_code() {
    let detection: DetectVerdict = JsObfDetector
        .detect(&ctx(SEA_BLOB))
        .expect("node sea blob must be detected");
    assert_eq!(detection.format_tag, "js-node-sea");
    let recovered: String = run_chain_text(SEA_BLOB);
    assert!(
        recovered.len() < SEA_BLOB.len(),
        "carved main code must be smaller than the whole blob: blob={} carved={}",
        SEA_BLOB.len(),
        recovered.len()
    );
    assert!(
        recovered.contains("use strict") || recovered.contains("edge_cases"),
        "carved SEA main code must be the embedded JavaScript source:\n{}",
        &recovered[..recovered.len().min(200)]
    );
}

#[test]
fn chain_disassembles_bytenode_jsc() {
    let detection: DetectVerdict = JsObfDetector
        .detect(&ctx(BYTENODE_JSC))
        .expect("bytenode .jsc must be detected");
    assert_eq!(detection.format_tag, "js-bytenode-jsc");
    let report: String = run_chain_text(BYTENODE_JSC);
    assert!(
        report.contains("\"function_count\""),
        "bytenode chain run must emit a disassembly report, not just a header:\n{}",
        &report[..report.len().min(200)]
    );
    assert!(
        report.contains("\"disassembly\"") && report.contains("\"instruction_count\""),
        "bytenode report must contain disassembled bytecode arrays:\n{}",
        &report[..report.len().min(400)]
    );
    let parsed: serde_json::Value = serde_json::from_str(&report).expect("report must be json");
    let fn_count: u64 = parsed
        .get("function_count")
        .and_then(serde_json::Value::as_u64)
        .expect("function_count present");
    assert!(
        fn_count >= 1,
        "at least one BytecodeArray must be recovered and disassembled, got {fn_count}"
    );
}
