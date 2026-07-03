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
        recovered.contains("x;") && !recovered.contains("x = undefined"),
        "after folding to undefined the redundant initializer is dropped, leaving a bare declaration: {recovered}"
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
fn double_not_becomes_boolean_coercion() {
    assert_faithful_input("double_not", ORIG_DOUBLE_NOT, INPUT_DOUBLE_NOT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_DOUBLE_NOT);
    assert!(
        stats.double_not_coercions_normalized >= 1,
        "!!v must become Boolean(v); got {}",
        stats.double_not_coercions_normalized
    );
    assert!(recovered.contains("Boolean(v)"), "got: {recovered}");
    assert!(
        !recovered.contains("!!v"),
        "the doubled not must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("double_not", ORIG_DOUBLE_NOT, &recovered);
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
