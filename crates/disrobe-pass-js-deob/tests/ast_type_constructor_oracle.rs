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

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String = eval_capture(original).expect("orig evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ORIG_NUMBER: &str = r"
var s = '42';
var n = +s;
print(n);
print(typeof n);
print(n + 1);
";

#[test]
fn unary_plus_on_identifier_becomes_number_call() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_NUMBER);
    assert!(
        stats.number_coercions_named >= 1,
        "+s must become Number(s); got {}",
        stats.number_coercions_named
    );
    assert!(
        recovered.contains("Number(s)"),
        "the Number constructor call must appear:\n{recovered}"
    );
    assert_recovered_equivalent("number", ORIG_NUMBER, &recovered);
}

const ORIG_STRING: &str = r"
var n = 42;
var s = n + '';
print(s);
print(typeof s);
print(s.length);
";

#[test]
fn plus_empty_string_becomes_string_call() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_STRING);
    assert!(
        stats.string_coercions_named >= 1,
        "n + '' must become String(n); got {}",
        stats.string_coercions_named
    );
    assert!(
        recovered.contains("String(n)"),
        "the String constructor call must appear:\n{recovered}"
    );
    assert_recovered_equivalent("string", ORIG_STRING, &recovered);
}

const ORIG_ARRAY: &str = r"
var a = [,,,];
print(a.length);
print(typeof a[0]);
";

#[test]
fn all_holes_array_becomes_array_call() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_ARRAY);
    assert!(
        stats.array_holes_named >= 1,
        "[,,,] must become Array(3); got {}",
        stats.array_holes_named
    );
    assert!(
        recovered.contains("Array(3)"),
        "the Array constructor call must appear:\n{recovered}"
    );
    assert_recovered_equivalent("array", ORIG_ARRAY, &recovered);
}

const SAFETY_LITERAL_AND_SHADOW: &str = r"
function withShadow(Number) {
  return +Number;
}
var lit = +5;
var pop = [1, , 3];
print(withShadow(99));
print(lit);
print(pop.length);
";

#[test]
fn literal_plus_and_shadowed_builtin_and_populated_array_are_left_alone() {
    let want: String = eval_capture(SAFETY_LITERAL_AND_SHADOW).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_LITERAL_AND_SHADOW);
    assert_eq!(
        stats.number_coercions_named, 0,
        "Number is shadowed as a parameter, and +5 is a literal-fold not a coercion; neither may convert"
    );
    assert_eq!(
        stats.array_holes_named, 0,
        "[1, , 3] has real elements and is not an all-holes array"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
