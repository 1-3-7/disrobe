#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{Detection, JsObfuRecovery, JsObfuscator, detect, recover_jsobfu};

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
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
    let Some(src): Option<String> = load("jsobfu/obfuscated.js") else {
        eprintln!("SKIP: jsobfu/obfuscated.js fixture missing");
        return;
    };
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
    let Some(src): Option<String> = load("jsobfu/input.js") else {
        eprintln!("SKIP: jsobfu/input.js fixture missing");
        return;
    };
    let det: Detection = detect(src.as_bytes());
    assert_ne!(
        det.family,
        JsObfuscator::JsObfu,
        "the clean ground-truth source must not be misdetected as jsobfu"
    );
}

#[test]
fn real_jsobfu_recovery_folds_fromcharcode_chains() {
    let Some(src): Option<String> = load("jsobfu/obfuscated.js") else {
        eprintln!("SKIP: jsobfu/obfuscated.js fixture missing");
        return;
    };
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
    let Some(obf): Option<String> = load("jsobfu/obfuscated.js") else {
        eprintln!("SKIP: jsobfu/obfuscated.js fixture missing");
        return;
    };
    let Some(original): Option<String> = load("jsobfu/input.js") else {
        eprintln!("SKIP: jsobfu/input.js fixture missing");
        return;
    };
    let ground_truth: String =
        eval_console_output(&original).expect("ground-truth source must run under boa");
    assert!(
        !ground_truth.is_empty(),
        "ground-truth program must produce console output"
    );

    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: String =
        eval_console_output(&out.source).expect("recovered jsobfu must re-parse and run under boa");

    assert_eq!(
        recovered_output, ground_truth,
        "recovered jsobfu must produce the same program output as the original source"
    );
}

#[test]
fn raw_obfuscated_and_recovered_agree_under_boa() {
    let Some(obf): Option<String> = load("jsobfu/obfuscated.js") else {
        eprintln!("SKIP: jsobfu/obfuscated.js fixture missing");
        return;
    };
    let raw_output: Option<String> = eval_console_output(&obf);
    let out: JsObfuRecovery = recover_jsobfu(&obf);
    let recovered_output: Option<String> = eval_console_output(&out.source);
    if let (Some(raw), Some(rec)) = (raw_output.as_ref(), recovered_output.as_ref())
        && !raw.is_empty()
    {
        assert_eq!(
            rec, raw,
            "recovery must preserve the obfuscated program's runtime behavior"
        );
    }
}
