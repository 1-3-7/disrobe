#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{Detection, JsObfuRecovery, JsObfuscator, detect, recover_jsobfu};
use sha2::{Digest, Sha256};

const INPUT_SHA256: &str = "7576a69b3e0dd823087c56f5705d8b5c28d0c30a5a90a306e1b9ccca574aedfe";
const OBFUSCATED_SHA256: &str = "fb8a0fa445ef48d791834b971a7621c1e23a2f64480c8ee9aa07c4d33380e329";
const AUTHORED_OUTPUT: &str = "{\"greeting\":\"hi world!\",\"sum\":3,\"product\":12,\"fib10\":55,\"factorial5\":120,\"count\":5,\"registered\":\"greet,add,mul,fib,factorial\"}";

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

const CAPTURE_HARNESS: &str = "\
var __dr_out=[];\
var console={log:function(){var a=Array.prototype.slice.call(arguments);__dr_out.push(a.join(' '));}};\
var window={console:console,JSON:JSON};\
";

fn eval_console_output(script: &str) -> Option<String> {
    let mut wrapped: String = String::with_capacity(script.len() + CAPTURE_HARNESS.len() + 64);
    wrapped.push_str(CAPTURE_HARNESS);
    wrapped.push_str("try{\n");
    wrapped.push_str(script);
    wrapped.push_str("\n}catch(e){}\n__dr_out.join('\\u0001');");
    let mut ctx: Context = Context::default();
    {
        let limits: &mut boa_engine::vm::RuntimeLimits = ctx.runtime_limits_mut();
        limits.set_recursion_limit(20_000);
        limits.set_loop_iteration_limit(50_000_000);
        limits.set_stack_size_limit(16 * 1024 * 1024);
    }
    let v: boa_engine::JsValue = ctx.eval(Source::from_bytes(wrapped.as_bytes())).ok()?;
    v.as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
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
    assert_sha256("authored input", &original, INPUT_SHA256);
    let ground_truth: String =
        eval_console_output(&original).expect("ground-truth source must run under boa");
    assert_eq!(
        ground_truth, AUTHORED_OUTPUT,
        "authored source output changed"
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");

    assert_eq!(
        recovered_output, AUTHORED_OUTPUT,
        "recovered jsobfu must produce the same program output as the original source"
    );
}

#[test]
fn recovered_jsobfu_output_mutation_is_rejected() {
    let obf: String = load("jsobfu/obfuscated.js");
    let authored: String = load("jsobfu/input.js");
    assert_sha256("obfuscated", &obf, OBFUSCATED_SHA256);
    assert_sha256("authored input", &authored, INPUT_SHA256);
    let authored_output: String =
        eval_console_output(&authored).expect("ground-truth source must run under boa");
    assert_eq!(
        authored_output, AUTHORED_OUTPUT,
        "authored source output changed"
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");
    assert_eq!(recovered_output, AUTHORED_OUTPUT);

    let mutated: String = format!("{}\nconsole.log('mutation');", out.source);
    let mutated_output: String =
        eval_console_output(&mutated).expect("mutated recovered code must produce console output");
    assert_ne!(
        mutated_output, AUTHORED_OUTPUT,
        "mutation control must turn the grade red"
    );
}
