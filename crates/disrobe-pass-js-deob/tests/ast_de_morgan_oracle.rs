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

const ORIG_AND: &str = r"
function check(a, b) {
  if (!a || !b) { return 'missing'; }
  return 'both';
}
print(check(true, true));
print(check(true, false));
print(check(false, true));
print(check(false, false));
";

const INPUT_AND: &str = r"
function check(a, b) {
  if (!(a && b)) { return 'missing'; }
  return 'both';
}
print(check(true, true));
print(check(true, false));
print(check(false, true));
print(check(false, false));
";

#[test]
fn not_of_and_becomes_or_of_negations_reeval_equivalent() {
    assert_faithful_input("and", ORIG_AND, INPUT_AND);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_AND);
    assert!(
        stats.de_morgan_and_negations >= 1,
        "!(a && b) must distribute; got {}",
        stats.de_morgan_and_negations
    );
    assert!(
        recovered.contains("!a || !b"),
        "must produce `!a || !b`:\n{recovered}"
    );
    assert!(
        !recovered.contains("!(a && b)"),
        "the negated conjunction must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("and", ORIG_AND, &recovered);
}

const ORIG_OR: &str = r"
function gate(x, y) {
  if (!x && !y) { return 'none'; }
  return 'some';
}
print(gate(0, 0));
print(gate(1, 0));
print(gate(0, 1));
print(gate(1, 1));
";

const INPUT_OR: &str = r"
function gate(x, y) {
  if (!(x || y)) { return 'none'; }
  return 'some';
}
print(gate(0, 0));
print(gate(1, 0));
print(gate(0, 1));
print(gate(1, 1));
";

#[test]
fn not_of_or_becomes_and_of_negations_reeval_equivalent() {
    assert_faithful_input("or", ORIG_OR, INPUT_OR);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_OR);
    assert!(
        stats.de_morgan_or_negations >= 1,
        "!(x || y) must distribute; got {}",
        stats.de_morgan_or_negations
    );
    assert!(
        recovered.contains("!x && !y"),
        "must produce `!x && !y`:\n{recovered}"
    );
    assert!(
        !recovered.contains("!(x || y)"),
        "the negated disjunction must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("or", ORIG_OR, &recovered);
}

const ORIG_COMPARE: &str = r"
function band(n) {
  if (!(n >= 10 && n <= 20)) { return 'out'; }
  return 'in';
}
print(band(5));
print(band(15));
print(band(25));
";

const INPUT_COMPARE: &str = ORIG_COMPARE;

#[test]
fn not_of_and_with_comparisons_reeval_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_COMPARE);
    assert!(
        stats.de_morgan_and_negations >= 1,
        "comparison operands are side-effect-free and must distribute; got {}",
        stats.de_morgan_and_negations
    );
    assert!(
        !recovered.contains("!(n >= 10 && n <= 20)"),
        "the negated conjunction must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("compare", ORIG_COMPARE, &recovered);
}

const NEG_SIDE_EFFECT: &str = r"
var log = [];
function a() { log.push('a'); return true; }
function b() { log.push('b'); return false; }
function probe() {
  if (!(a() && b())) { return 'no'; }
  return 'yes';
}
print(probe());
print(log.join(','));
";

#[test]
fn negative_side_effectful_operands_unchanged() {
    let want: String = eval_capture(NEG_SIDE_EFFECT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_SIDE_EFFECT);
    assert_eq!(
        stats.de_morgan_and_negations, 0,
        "operands with calls must NOT distribute (short-circuit order and effects would change)"
    );
    assert_eq!(stats.de_morgan_or_negations, 0, "no or-distribution either");
    assert!(
        recovered.contains("!(a() && b())"),
        "the side-effectful negated conjunction must be preserved verbatim:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "distributing side-effectful operands would call b() unconditionally; must be preserved"
    );
}

const NEG_ASSIGN_OPERAND: &str = r"
var log = [];
function run() {
  var x = 0;
  var y = 0;
  if (!((x = 1) && (y = 1))) { log.push('a'); }
  log.push(String(x));
  log.push(String(y));
}
run();
print(log.join(','));
";

#[test]
fn negative_assignment_operands_unchanged() {
    let want: String = eval_capture(NEG_ASSIGN_OPERAND).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_ASSIGN_OPERAND);
    assert_eq!(
        stats.de_morgan_and_negations, 0,
        "assignment operands have side effects and must NOT distribute"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
