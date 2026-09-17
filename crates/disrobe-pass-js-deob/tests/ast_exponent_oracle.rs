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

const ORIG_SIMPLE: &str = r"
var a = 3, b = 4;
print(Math.pow(a, b));
print(Math.pow(2, 10));
print(Math.pow(a + 1, b - 1));
";

#[test]
fn math_pow_becomes_exponentiation_operator() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_SIMPLE);
    assert!(
        stats.math_pow_to_exponent >= 3,
        "all three Math.pow calls must convert; got {}",
        stats.math_pow_to_exponent
    );
    assert!(
        !recovered.contains("Math.pow"),
        "no Math.pow call may survive:\n{recovered}"
    );
    assert!(
        recovered.contains("a ** b") && recovered.contains("2 ** 10"),
        "the ** operator must appear:\n{recovered}"
    );
    assert!(
        recovered.contains("(a + 1) ** (b - 1)"),
        "binary operands must be parenthesized to preserve precedence:\n{recovered}"
    );
    assert_recovered_equivalent("simple", ORIG_SIMPLE, &recovered);
}

const ORIG_NESTED: &str = r"
var a = 2, b = 3, c = 2;
print(Math.pow(Math.pow(a, b), c));
print(Math.pow(a, Math.pow(b, c)));
";

#[test]
fn nested_math_pow_preserves_associativity() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_NESTED);
    assert!(
        stats.math_pow_to_exponent >= 4,
        "all four nested Math.pow calls must convert; got {}",
        stats.math_pow_to_exponent
    );
    assert!(
        !recovered.contains("Math.pow"),
        "no Math.pow may survive:\n{recovered}"
    );
    assert!(
        recovered.contains("(a ** b) ** c"),
        "a pow used as the base of an outer pow must be parenthesized (** is right-associative):\n{recovered}"
    );
    assert_recovered_equivalent("nested", ORIG_NESTED, &recovered);
}

const SAFETY_NOT_MATH_POW: &str = r"
var Math2 = { pow: function (x, y) { return x - y; } };
function pow(x, y) { return x * y; }
print(Math2.pow(7, 2));
print(pow(7, 2));
print(Math.sqrt(16));
";

#[test]
fn unrelated_pow_and_other_math_methods_are_untouched() {
    let want: String = eval_capture(SAFETY_NOT_MATH_POW).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_NOT_MATH_POW);
    assert_eq!(
        stats.math_pow_to_exponent, 0,
        "only the global Math.pow may convert; a user object's `.pow`, a free `pow` function, and Math.sqrt must all be left alone"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_NEGATIVE_BASE: &str = r"
print(Math.pow(-2, 2));
print(Math.pow(4, 0.5));
";

#[test]
fn negative_base_and_fractional_exponent_stay_correct() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_NEGATIVE_BASE);
    assert!(
        stats.math_pow_to_exponent >= 2,
        "both calls convert; got {}",
        stats.math_pow_to_exponent
    );
    assert_recovered_equivalent("neg_base", ORIG_NEGATIVE_BASE, &recovered);
}
