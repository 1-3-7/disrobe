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

const ORIG_VALUE: &str = r"
function build(a, b) {
  return { a, b };
}
var o = build(1, 2);
print(o.a);
print(o.b);
";

const INPUT_VALUE: &str = r"
function build(a, b) {
  return { a: a, b: b };
}
var o = build(1, 2);
print(o.a);
print(o.b);
";

#[test]
fn key_equals_value_identifier_becomes_value_shorthand() {
    assert_faithful_input("value", ORIG_VALUE, INPUT_VALUE);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_VALUE);
    assert!(
        stats.object_value_shorthands >= 2,
        "both a:a and b:b must collapse; got {}",
        stats.object_value_shorthands
    );
    assert!(
        recovered.contains("{ a, b }"),
        "must produce `{{ a, b }}`:\n{recovered}"
    );
    assert!(
        !recovered.contains("a: a"),
        "the longhand must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("value", ORIG_VALUE, &recovered);
}

const ORIG_METHOD: &str = r"
var api = {
  greet(name) { return 'hi ' + name; }
};
print(api.greet('x'));
";

const INPUT_METHOD: &str = r"
var api = {
  greet: function (name) { return 'hi ' + name; }
};
print(api.greet('x'));
";

#[test]
fn function_value_becomes_method_shorthand() {
    assert_faithful_input("method", ORIG_METHOD, INPUT_METHOD);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_METHOD);
    assert!(
        stats.object_method_shorthands >= 1,
        "f: function() must collapse to method shorthand; got {}",
        stats.object_method_shorthands
    );
    assert!(
        !recovered.contains("function"),
        "the function keyword must be gone:\n{recovered}"
    );
    assert!(
        recovered.contains("greet(name)"),
        "must produce method header `greet(name)`:\n{recovered}"
    );
    assert_recovered_equivalent("method", ORIG_METHOD, &recovered);
}

const ORIG_GENERATOR: &str = r"
var it = {
  *nums() { yield 1; yield 2; }
};
var g = it.nums();
print(g.next().value);
print(g.next().value);
";

const INPUT_GENERATOR: &str = r"
var it = {
  nums: function* () { yield 1; yield 2; }
};
var g = it.nums();
print(g.next().value);
print(g.next().value);
";

#[test]
fn generator_function_value_becomes_generator_method() {
    assert_faithful_input("generator", ORIG_GENERATOR, INPUT_GENERATOR);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_GENERATOR);
    assert!(
        stats.object_method_shorthands >= 1,
        "f: function*() must collapse to *f(); got {}",
        stats.object_method_shorthands
    );
    assert!(
        recovered.contains("*nums()"),
        "must produce generator method `*nums()`:\n{recovered}"
    );
    assert_recovered_equivalent("generator", ORIG_GENERATOR, &recovered);
}

const NEG_KEY_MISMATCH: &str = r"
function build(a, b) {
  return { a: b, b: a };
}
var o = build(1, 2);
print(o.a);
print(o.b);
";

#[test]
fn key_not_matching_value_is_unchanged() {
    let want: String = eval_capture(NEG_KEY_MISMATCH).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_KEY_MISMATCH);
    assert_eq!(
        stats.object_value_shorthands, 0,
        "a:b is not a shorthand candidate (key != value)"
    );
    assert!(
        recovered.contains("a: b"),
        "the longhand must be preserved verbatim:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_GETTER: &str = r"
var o = {
  get x() { return 42; }
};
print(o.x);
";

#[test]
fn getter_is_not_collapsed() {
    let want: String = eval_capture(NEG_GETTER).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_GETTER);
    assert_eq!(
        stats.object_method_shorthands, 0,
        "an accessor must NOT be rewritten as a plain method"
    );
    assert!(
        recovered.contains("get x()"),
        "the getter must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_NAMED_FN: &str = r"
var o = {
  rec: function fact(n) { return n <= 1 ? 1 : n * fact(n - 1); }
};
print(o.rec(4));
";

#[test]
fn named_function_expression_is_not_collapsed() {
    let want: String = eval_capture(NEG_NAMED_FN).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_NAMED_FN);
    assert_eq!(
        stats.object_method_shorthands, 0,
        "a named function expression relies on its own name and must NOT collapse"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
