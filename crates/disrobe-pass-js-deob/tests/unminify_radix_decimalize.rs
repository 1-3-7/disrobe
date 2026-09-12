#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{
    ObfuscatorIoOptions, ObfuscatorIoOutput, RenameStats, UnminifyStats, obfuscator_io_deobfuscate,
    rename_hex_idents, unminify,
};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn assert_equivalent(label: &str, original: &str) -> UnminifyStats {
    let (recovered, stats): (String, UnminifyStats) = unminify(original);
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: radix decimalization changed behavior\noriginal:\n{original}\nrecovered:\n{recovered}"
    );
    stats
}

#[test]
fn decimalizes_radix_literals_behavior_preserving() {
    let stats: UnminifyStats = assert_equivalent(
        "mixed-radix",
        "var samples = [0x10, 0o17, 0b1010, 0xff];\n\
         var total = 0;\n\
         for (var i = 0x0; i < samples.length; i += 0x1) { total += samples[i]; }\n\
         print(total);\n\
         print(samples.slice(0x1, 0x3).join('-'));",
    );
    assert!(
        stats.radix_literals_decimalized >= 6,
        "every hex/octal/binary literal must be decimalized; got {}",
        stats.radix_literals_decimalized
    );
    let (recovered, _): (String, UnminifyStats) =
        unminify("var samples = [0x10, 0o17, 0b1010, 0xff]; print(samples.join(','));");
    assert!(
        !recovered.contains("0x") && !recovered.contains("0o") && !recovered.contains("0b1"),
        "no radix prefix may survive in numeric position; got:\n{recovered}"
    );
    assert!(
        recovered.contains("16")
            && recovered.contains("15")
            && recovered.contains("10")
            && recovered.contains("255"),
        "decimal values must be present; got:\n{recovered}"
    );
}

#[test]
fn radix_decimalize_never_touches_string_or_comment_contents() {
    let original: &str = "var obj = { '0x41': 65 };\n\
         var css = '0xFF0000 color', tag = \"0xdeadbeef\";\n\
         // keep 0x10 in this comment\n\
         /* and 0xAB here */\n\
         var hexInName = obj['0x41'];\n\
         print(css + '|' + tag + '|' + hexInName);";
    let (recovered, _stats): (String, UnminifyStats) = unminify(original);
    assert!(
        recovered.contains("'0xFF0000 color'") || recovered.contains("0xFF0000 color"),
        "a hex sequence inside a string literal must survive verbatim; got:\n{recovered}"
    );
    assert!(
        recovered.contains("0xdeadbeef"),
        "a hex sequence inside a double-quoted string must survive; got:\n{recovered}"
    );
    assert!(
        recovered.contains("'0x41'"),
        "a hex sequence used as a string property key must survive; got:\n{recovered}"
    );
    let want: String = eval_capture(original).expect("original evaluates");
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "string/comment safety changed behavior");
}

#[test]
fn radix_decimalize_preserves_member_and_dot_property_access() {
    let original: &str = "var n = 0xa, m = arr[0xb], k = x.slice(0x0, 0x2);\nprint(n);";
    let want: String = eval_capture("var arr=[1,2,3,4,5,6,7,8,9,10,11,12]; var x=arr; var n = 0xa, m = arr[0xb], k = x.slice(0x0, 0x2); print(n + '|' + m + '|' + k.join(','));").expect("orig");
    let inlined: String = format!(
        "var arr=[1,2,3,4,5,6,7,8,9,10,11,12]; var x=arr; {}",
        unminify(original).0
    );
    let got: String = eval_capture(&format!(
        "var arr=[1,2,3,4,5,6,7,8,9,10,11,12]; var x=arr; var n = {}, m = arr[{}], k = x.slice({}, {}); print(n + '|' + m + '|' + k.join(','));",
        "10", "11", "0", "2"
    ))
    .expect("decimal form");
    assert_eq!(want, got, "decimal member/slice indices must match");
    assert!(
        inlined.contains("arr[11]") || inlined.contains("arr[ 11 ]"),
        "computed member index 0xb must decimalize to 11; got:\n{inlined}"
    );
}

fn corpus(rel: &str) -> String {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p: PathBuf = manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn gauntlet_recovered_output_is_decimal_not_hex() {
    let src: String = corpus("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("pipeline must not error");
    assert!(
        out.unminify_stats.radix_literals_decimalized >= 8,
        "the real javascript-obfuscator output carries many hex literals; at least 8 must be decimalized, got {}",
        out.unminify_stats.radix_literals_decimalized
    );
    let (recovered, _): (String, RenameStats) = rename_hex_idents(&out.source);
    for hex in ["[0x1]", "[0x0]", "+=0x1", "slice(0x0", "top(0x5"] {
        assert!(
            !recovered.contains(hex),
            "hex numeric literal `{hex}` must be decimalized in the recovered source; got:\n{}",
            recovered.chars().take(700).collect::<String>()
        );
    }
    assert!(
        recovered.contains("+=1") && recovered.contains("slice(0,") && recovered.contains("top(5)"),
        "decimal forms must appear in the recovered source"
    );
}
