#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

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

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-written input is not behaviorally identical to the original BEFORE transform"
    );
}

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String = eval_capture(original).expect("orig evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ORIG_RADIX: &str = r"
var a = 255;
var b = 15;
var c = 5;
print(a);
print(b);
print(c);
print(a + b + c);
";

const INPUT_RADIX: &str = r"
var a = 0xff;
var b = 0o17;
var c = 0b101;
print(a);
print(b);
print(c);
print(a + b + c);
";

#[test]
fn hex_octal_binary_literals_normalize_to_decimal() {
    assert_faithful_input("radix", ORIG_RADIX, INPUT_RADIX);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_RADIX);
    assert!(
        stats.numeric_literals_normalized >= 3,
        "all three radix literals must normalize; got {}",
        stats.numeric_literals_normalized
    );
    assert!(
        recovered.contains("a = 255")
            && recovered.contains("b = 15")
            && recovered.contains("c = 5"),
        "decimal forms must appear:\n{recovered}"
    );
    assert!(
        !recovered.contains("0xff") && !recovered.contains("0o17") && !recovered.contains("0b101"),
        "no radix prefix may survive:\n{recovered}"
    );
    assert_recovered_equivalent("radix", ORIG_RADIX, &recovered);
}

const ORIG_EXP_SEP: &str = r"
var ms = 1000;
var big = 1000000;
print(ms);
print(big);
print(ms * 2);
";

const INPUT_EXP_SEP: &str = r"
var ms = 1e3;
var big = 1_000_000;
print(ms);
print(big);
print(ms * 2);
";

#[test]
fn exponential_and_separator_literals_normalize() {
    assert_faithful_input("exp_sep", ORIG_EXP_SEP, INPUT_EXP_SEP);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_EXP_SEP);
    assert!(
        stats.numeric_literals_normalized >= 2,
        "1e3 and 1_000_000 must normalize; got {}",
        stats.numeric_literals_normalized
    );
    assert!(
        recovered.contains("ms = 1000") && recovered.contains("big = 1000000"),
        "decimal forms must appear:\n{recovered}"
    );
    assert!(
        !recovered.contains("1e3") && !recovered.contains("1_000_000"),
        "exponential and underscore-separated forms must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("exp_sep", ORIG_EXP_SEP, &recovered);
}

const SAFETY_HEX_IN_STRING_AND_KEY: &str = r#"
var o = { "0xff": 7 };
var s = "color 0xFF0000 here";
print(o["0xff"]);
print(s);
"#;

#[test]
fn numeric_normalization_never_touches_strings_or_keys() {
    let want: String = eval_capture(SAFETY_HEX_IN_STRING_AND_KEY).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_HEX_IN_STRING_AND_KEY);
    assert_eq!(
        stats.numeric_literals_normalized, 0,
        "a `0xff` inside a string literal or quoted property key is text, not a numeric literal, and must be left untouched"
    );
    assert!(
        recovered.contains("\"0xff\"") && recovered.contains("color 0xFF0000 here"),
        "string and key contents must survive verbatim:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const SAFETY_FLOAT_AND_BIGINT: &str = r"
var pi = 3.14;
var big = 9007199254740993n;
print(pi);
print(big);
print(typeof big);
";

#[test]
fn float_and_bigint_literals_are_left_intact() {
    let want: String = eval_capture(SAFETY_FLOAT_AND_BIGINT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_FLOAT_AND_BIGINT);
    assert_eq!(
        stats.numeric_literals_normalized, 0,
        "a canonical float and a BigInt literal carry no obfuscated radix and must not be rewritten"
    );
    assert!(
        recovered.contains("3.14") && recovered.contains("9007199254740993n"),
        "the BigInt suffix and the float must survive exactly:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
