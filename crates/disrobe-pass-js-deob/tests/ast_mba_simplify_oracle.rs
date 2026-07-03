#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_mba::{Expr, Width, equivalent_exhaustive};
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

fn assert_reeval_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged behaviorally\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

fn count_binary_mixers(source: &str) -> usize {
    source
        .chars()
        .filter(|c: &char| matches!(c, '^' | '&' | '*'))
        .count()
}

const ADD_VIA_XOR_CARRY: &str = r"
function mix(a, b) {
  return ((a ^ b) + 2 * (a & b)) | 0;
}
print(mix(0, 0));
print(mix(1, 2));
print(mix(255, 1));
print(mix(123456, 654321));
print(mix(-7, 9));
";

#[test]
fn xor_plus_twice_and_collapses_to_add_int32_context() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ADD_VIA_XOR_CARRY);
    assert!(
        stats.mba_expressions_collapsed >= 1,
        "MBA add identity must collapse; stats={}",
        stats.mba_expressions_collapsed
    );
    assert!(
        count_binary_mixers(&recovered) < count_binary_mixers(ADD_VIA_XOR_CARRY),
        "the ^/&/* mixers of the MBA form must be gone after collapse:\n{recovered}"
    );
    assert_reeval_equivalent("xor_carry_add", ADD_VIA_XOR_CARRY, &recovered);

    let original: Expr = Expr::add(
        Expr::xor(Expr::var(0), Expr::var(1)),
        Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
    );
    let simplified: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert!(
        equivalent_exhaustive(&original, &simplified, Width::W8, 2),
        "disrobe-mba oracle must prove (x^y)+2*(x&y) == x+y"
    );
}

const OR_PLUS_AND: &str = r"
function f(p, q) {
  return ((p | q) + (p & q)) | 0;
}
print(f(0, 0));
print(f(6, 10));
print(f(1023, 1));
print(f(987654, 123));
";

#[test]
fn or_plus_and_collapses_to_add() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(OR_PLUS_AND);
    assert!(
        stats.mba_expressions_collapsed >= 1,
        "(p|q)+(p&q) must collapse; stats={}",
        stats.mba_expressions_collapsed
    );
    assert_reeval_equivalent("or_plus_and", OR_PLUS_AND, &recovered);

    let original: Expr = Expr::add(
        Expr::or(Expr::var(0), Expr::var(1)),
        Expr::and(Expr::var(0), Expr::var(1)),
    );
    let simplified: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert!(equivalent_exhaustive(&original, &simplified, Width::W8, 2));
}

const OR_MINUS_AND_IS_XOR: &str = r"
function g(m, n) {
  return ((m | n) - (m & n)) | 0;
}
print(g(0, 0));
print(g(12, 10));
print(g(255, 240));
print(g(424242, 99));
";

#[test]
fn or_minus_and_collapses_to_xor() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(OR_MINUS_AND_IS_XOR);
    assert!(
        stats.mba_expressions_collapsed >= 1,
        "(m|n)-(m&n) must collapse to m^n; stats={}",
        stats.mba_expressions_collapsed
    );
    assert_reeval_equivalent("or_minus_and", OR_MINUS_AND_IS_XOR, &recovered);

    let original: Expr = Expr::sub(
        Expr::or(Expr::var(0), Expr::var(1)),
        Expr::and(Expr::var(0), Expr::var(1)),
    );
    let simplified: Expr = Expr::xor(Expr::var(0), Expr::var(1));
    assert!(equivalent_exhaustive(&original, &simplified, Width::W8, 2));
}

const NOT_IDENTITY: &str = r"
function h(z) {
  return ((-z - 1) ^ 0) | 0;
}
print(h(0));
print(h(5));
print(h(255));
print(h(-9));
";

#[test]
fn neg_minus_one_collapses_to_bitwise_not() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NOT_IDENTITY);
    assert!(
        stats.mba_expressions_collapsed >= 1,
        "-z-1 must collapse to ~z; stats={}",
        stats.mba_expressions_collapsed
    );
    assert_reeval_equivalent("not_identity", NOT_IDENTITY, &recovered);

    let original: Expr = Expr::sub(Expr::neg(Expr::var(0)), Expr::konst(1));
    let simplified: Expr = Expr::not(Expr::var(0));
    assert!(equivalent_exhaustive(&original, &simplified, Width::W16, 1));
}

const OPAQUE_ALWAYS_TRUE: &str = r"
function route(x, y) {
  if (((x ^ y) | 0) === (((x | y) - (x & y)) | 0)) {
    return 'always';
  }
  return 'never';
}
print(route(0, 0));
print(route(3, 5));
print(route(200, 55));
print(route(40000, 1));
";

#[test]
fn opaque_equality_identity_folds_to_true_branch() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(OPAQUE_ALWAYS_TRUE);
    assert!(
        stats.mba_opaque_branches_folded >= 1,
        "x^y === (x|y)-(x&y) is a tautology and must fold; stats={}",
        stats.mba_opaque_branches_folded
    );
    assert!(
        !recovered.contains("==="),
        "the opaque MBA predicate must be removed by the always-true fold:\n{recovered}"
    );
    assert!(
        recovered.contains("'always'"),
        "the live branch must survive:\n{recovered}"
    );
    assert_reeval_equivalent("opaque_true", OPAQUE_ALWAYS_TRUE, &recovered);
}

const GENUINE_NOT_FOLDED: &str = r"
function real(a, b) {
  if (((a & b) | 0) === ((a | b) | 0)) {
    return 'equal-bits';
  }
  return 'differ';
}
print(real(0, 0));
print(real(5, 3));
print(real(7, 7));
print(real(8, 4));
";

#[test]
fn genuine_data_dependent_predicate_not_folded() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(GENUINE_NOT_FOLDED);
    assert_eq!(
        stats.mba_opaque_branches_folded, 0,
        "a&b === a|b is data-dependent (true only when a==b); must NOT fold"
    );
    assert_reeval_equivalent("genuine_pred", GENUINE_NOT_FOLDED, &recovered);
}

const SIDE_EFFECT_GUARD: &str = r"
var calls = [];
function tick(v) { calls.push(v); return v; }
function compute() {
  return ((tick(3) ^ tick(4)) + 2 * (tick(3) & tick(4))) | 0;
}
print(compute());
print(calls.join(','));
";

#[test]
fn side_effecting_operands_are_not_collapsed() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SIDE_EFFECT_GUARD);
    assert_eq!(
        stats.mba_expressions_collapsed, 0,
        "operands with calls have side effects (call count would change); must NOT collapse"
    );
    assert_reeval_equivalent("side_effect", SIDE_EFFECT_GUARD, &recovered);
}

const NON_INT32_CONTEXT: &str = r"
function plain(a, b) {
  return (a ^ b) + 2 * (a & b);
}
print(plain(1, 2));
";

#[test]
fn add_root_without_int32_coercion_is_left_alone() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NON_INT32_CONTEXT);
    assert_eq!(
        stats.mba_expressions_collapsed, 0,
        "no surrounding int32 coercion: a `| 0`-wrapped rewrite could change semantics for non-int32 operands; must NOT fire"
    );
    assert_reeval_equivalent("non_int32", NON_INT32_CONTEXT, &recovered);
}
