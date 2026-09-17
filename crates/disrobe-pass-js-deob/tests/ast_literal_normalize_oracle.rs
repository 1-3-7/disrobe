#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

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

const ORIG_BOOL: &str = r"
var a = true;
var b = false;
print(a);
print(b);
";

const INPUT_BOOL: &str = r"
var a = !0;
var b = !1;
print(a);
print(b);
";

#[test]
fn boolean_shorthand_folds_to_keywords() {
    assert_faithful_input("bool", ORIG_BOOL, INPUT_BOOL);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_BOOL);
    assert!(
        stats.boolean_shorthands_normalized >= 2,
        "both !0 and !1 must fold; got {}",
        stats.boolean_shorthands_normalized
    );
    assert!(recovered.contains("a = true"), "got: {recovered}");
    assert!(recovered.contains("b = false"), "got: {recovered}");
    assert_recovered_equivalent("bool", ORIG_BOOL, &recovered);
}

const SAFETY_BOOL_IN_STRING_AND_KEY: &str = r#"
var o = { "!0": 7, "x!1y": 9 };
var s = "literal !0 and !1 text";
print(o["!0"]);
print(o["x!1y"]);
print(s);
"#;

#[test]
fn boolean_shorthand_never_fires_inside_string_or_property_key() {
    let want: String = eval_capture(SAFETY_BOOL_IN_STRING_AND_KEY).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_BOOL_IN_STRING_AND_KEY);
    assert_eq!(
        stats.boolean_shorthands_normalized, 0,
        "a `!0`/`!1` that lives inside a string literal or a quoted property key is NOT an operator and must be left untouched"
    );
    assert!(
        recovered.contains("\"!0\"") && recovered.contains("literal !0 and !1 text"),
        "string-literal and key contents must survive verbatim:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_VOID: &str = r"
var x = undefined;
print(x);
print(typeof x);
";

const INPUT_VOID: &str = r"
var x = void 0;
print(x);
print(typeof x);
";

#[test]
fn void_literal_folds_to_undefined() {
    assert_faithful_input("void", ORIG_VOID, INPUT_VOID);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_VOID);
    assert!(
        stats.void_undefineds_normalized >= 1,
        "void 0 must fold; got {}",
        stats.void_undefineds_normalized
    );
    assert!(
        !recovered.contains("void 0"),
        "the void 0 form must be gone: {recovered}"
    );
    assert!(
        recovered.contains("const x = undefined"),
        "a const initializer must remain after folding: {recovered}"
    );
    assert_recovered_equivalent("void", ORIG_VOID, &recovered);
}

const SAFETY_VOID_SIDE_EFFECT: &str = r"
var hits = 0;
function f() { hits++; return 5; }
var y = void f();
print(y);
print(hits);
";

#[test]
fn void_with_side_effecting_operand_is_left_intact() {
    let want: String = eval_capture(SAFETY_VOID_SIDE_EFFECT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_VOID_SIDE_EFFECT);
    assert_eq!(
        stats.void_undefineds_normalized, 0,
        "void f() must NOT collapse to undefined: the call's side effect (hits++) must still run"
    );
    assert!(recovered.contains("void f()"), "got: {recovered}");
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior + side effect preserved");
}

const SAFETY_VOID_SHADOWED_UNDEFINED: &str = r"
function read(undefined) { return void 0; }
var marker = !0;
print(read(7));
print(marker);
";

#[test]
fn void_literal_does_not_become_a_shadowed_undefined_binding() {
    let want: String =
        eval_capture(SAFETY_VOID_SHADOWED_UNDEFINED).expect("shadowed input evaluates");
    assert_eq!(want, "undefined\u{1}true");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_VOID_SHADOWED_UNDEFINED);
    assert_eq!(stats.void_undefineds_normalized, 0, "{recovered}");
    assert!(recovered.contains("void 0"), "{recovered}");
    assert_eq!(stats.boolean_shorthands_normalized, 1, "{recovered}");
    assert!(recovered.contains("marker = true"), "{recovered}");
    let got: String = eval_capture(&recovered).expect("recovered shadowed input evaluates");
    assert_eq!(want, got, "{recovered}");
}

const SAFETY_VOID_DIRECT_EVAL: &str = r"
function read() {
  (eval)('var undefined = 7');
  return void 0;
}
process.stdout.write(String(read()));
";

#[test]
fn void_literal_does_not_become_a_direct_eval_binding() {
    let expected: String = node_capture(SAFETY_VOID_DIRECT_EVAL);
    assert_eq!(expected, "undefined");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_VOID_DIRECT_EVAL);
    assert_eq!(stats.void_undefineds_normalized, 0, "{recovered}");
    assert!(recovered.contains("void 0"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_COMMENT_BEARING_LITERALS: &str = r"
let numeric = 1 /* numeric */ + 2;
let string = 'a' /* string */ + 'b';
let voided = void /* void */ 0;
process.stdout.write(String(numeric) + '\u0001' + string + '\u0001' + String(voided));
";

#[test]
fn comment_bearing_literal_expressions_remain_byte_intact() {
    let expected: String = node_capture(SAFETY_COMMENT_BEARING_LITERALS);
    assert_eq!(expected, "3\u{1}ab\u{1}undefined");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_COMMENT_BEARING_LITERALS);
    assert_eq!(stats.numeric_constants_folded, 0, "{recovered}");
    assert_eq!(stats.string_concats_folded, 0, "{recovered}");
    assert_eq!(stats.void_undefineds_normalized, 0, "{recovered}");
    assert_eq!(recovered, SAFETY_COMMENT_BEARING_LITERALS, "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

fn node_capture(source: &str) -> String {
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the direct-eval semantic reference")
        .expect("direct-eval semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

const ORIG_DOUBLE_NOT: &str = r"
function truthy(v) { return Boolean(v); }
print(truthy(3));
print(truthy(0));
print(truthy(''));
print(truthy('x'));
";

const INPUT_DOUBLE_NOT: &str = r"
function truthy(v) { return !!v; }
print(truthy(3));
print(truthy(0));
print(truthy(''));
print(truthy('x'));
";

#[test]
fn double_not_preserves_the_operator() {
    assert_faithful_input("double_not", ORIG_DOUBLE_NOT, INPUT_DOUBLE_NOT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_DOUBLE_NOT);
    assert_eq!(stats.double_not_coercions_normalized, 0, "{recovered}");
    assert!(recovered.contains("!!v"), "{recovered}");
    assert!(!recovered.contains("Boolean(v)"), "{recovered}");
    assert_recovered_equivalent("double_not", ORIG_DOUBLE_NOT, &recovered);
}

const SAFETY_DOUBLE_NOT_SHADOWED_BOOLEAN: &str = r"
function read(Boolean, value) { return !!value; }
process.stdout.write(String(read(function () { return 42; }, 0)));
";

#[test]
fn double_not_does_not_call_a_shadowed_boolean_binding() {
    let expected: String = node_capture(SAFETY_DOUBLE_NOT_SHADOWED_BOOLEAN);
    assert_eq!(expected, "false");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_DOUBLE_NOT_SHADOWED_BOOLEAN);
    assert_eq!(stats.double_not_coercions_normalized, 0, "{recovered}");
    assert!(recovered.contains("!!value"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_DOUBLE_NOT_DROPS_COERCION: &str = r"
var v = 'truthy';
var b = !!v;
print(b === true);
print(typeof b);
";

#[test]
fn double_not_preserves_boolean_type_unlike_naive_strip() {
    let want: String = eval_capture(SAFETY_DOUBLE_NOT_DROPS_COERCION).expect("evaluates");
    let (recovered, _stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_DOUBLE_NOT_DROPS_COERCION);
    assert!(
        !recovered.contains("var b = v;"),
        "the regex bug stripped !! entirely (b would become the string, not a boolean); the AST port must keep the coercion:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "`b === true` and `typeof b` must stay boolean after the transform"
    );
}

const ORIG_CONCAT: &str = r"
var s = 'foobar';
print(s);
print(s.length);
";

const INPUT_CONCAT: &str = r"
var s = 'foo' + 'bar';
print(s);
print(s.length);
";

#[test]
fn adjacent_string_literals_fold() {
    assert_faithful_input("concat", ORIG_CONCAT, INPUT_CONCAT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_CONCAT);
    assert!(
        stats.string_concats_folded >= 1,
        "'foo' + 'bar' must fold; got {}",
        stats.string_concats_folded
    );
    assert!(recovered.contains("foobar"), "got: {recovered}");
    assert_recovered_equivalent("concat", ORIG_CONCAT, &recovered);
}

const SAFETY_CONCAT_DIRECTIVE: &str = r"
function read() {
  'use ' + 'strict';
  return this === undefined;
}
process.stdout.write(String(read()));
";

#[test]
fn string_concat_does_not_create_a_directive_prologue() {
    let expected: String = node_capture(SAFETY_CONCAT_DIRECTIVE);
    assert_eq!(expected, "false");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_CONCAT_DIRECTIVE);
    assert_eq!(stats.string_concats_folded, 0, "{recovered}");
    assert!(recovered.contains("'use ' + 'strict'"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_TOP_LEVEL_CONCAT_DIRECTIVE: &str = r"
'use ' + 'strict';
undeclared = 7;
process.stdout.write(String(undeclared));
";

#[test]
fn top_level_string_concat_does_not_create_a_directive_prologue() {
    let expected: String = node_capture(SAFETY_TOP_LEVEL_CONCAT_DIRECTIVE);
    assert_eq!(expected, "7");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_TOP_LEVEL_CONCAT_DIRECTIVE);
    assert_eq!(stats.string_concats_folded, 0, "{recovered}");
    assert!(recovered.contains("'use ' + 'strict'"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_NEGATIVE_ZERO: &str = r"
process.stdout.write(String(Object.is(0 * -1, -0)) + '\u0001' + String(1 / (0 * -1)));
";

#[test]
fn numeric_fold_preserves_negative_zero() {
    let expected: String = node_capture(SAFETY_NEGATIVE_ZERO);
    assert_eq!(expected, "true\u{1}-Infinity");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_NEGATIVE_ZERO);
    assert_eq!(stats.numeric_constants_folded, 2, "{recovered}");
    assert!(recovered.contains("-0"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_CONCAT_PLUS_IN_STRING: &str = r#"
var s = "a' + 'b is literal";
print(s);
"#;

#[test]
fn string_concat_never_misreads_plus_inside_a_string() {
    let want: String = eval_capture(SAFETY_CONCAT_PLUS_IN_STRING).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_CONCAT_PLUS_IN_STRING);
    assert_eq!(
        stats.string_concats_folded, 0,
        "the regex saw `' + '` inside one string literal and wrongly merged across the quote boundary; the AST port sees a single StringLiteral and does nothing"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "single string literal preserved verbatim");
}

const ORIG_NUMERIC: &str = r"
var i = 0;
print(i);
";

const INPUT_NUMERIC: &str = r"
var i = -0x1a70 + 0x93d + 0x275 * 0x7;
print(i);
";

#[test]
fn numeric_constants_fold_obfuscator_arithmetic() {
    assert_faithful_input("numeric", ORIG_NUMERIC, INPUT_NUMERIC);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_NUMERIC);
    assert!(
        stats.numeric_constants_folded >= 2,
        "obfuscator arithmetic must fold; got {}",
        stats.numeric_constants_folded
    );
    assert!(recovered.contains("i = 0"), "got: {recovered}");
    assert_recovered_equivalent("numeric", ORIG_NUMERIC, &recovered);
}

const SAFETY_NUMERIC_NON_INTEGER_DIV: &str = r"
var q = 7 / 2;
print(q);
";

#[test]
fn numeric_fold_skips_non_integer_division() {
    let want: String = eval_capture(SAFETY_NUMERIC_NON_INTEGER_DIV).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_NUMERIC_NON_INTEGER_DIV);
    assert_eq!(
        stats.numeric_constants_folded, 0,
        "7 / 2 = 3.5 is not an exact integer and must not be rewritten as an int"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "3.5 preserved");
}
