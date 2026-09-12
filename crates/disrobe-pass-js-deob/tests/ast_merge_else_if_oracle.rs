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

const ORIG_CHAIN: &str = r"
function grade(n) {
  if (n >= 90) {
    return 'A';
  } else if (n >= 80) {
    return 'B';
  } else if (n >= 70) {
    return 'C';
  } else {
    return 'F';
  }
}
print(grade(95));
print(grade(85));
print(grade(72));
print(grade(50));
";

const INPUT_CHAIN: &str = r"
function grade(n) {
  if (n >= 90) {
    return 'A';
  } else {
    if (n >= 80) {
      return 'B';
    } else {
      if (n >= 70) {
        return 'C';
      } else {
        return 'F';
      }
    }
  }
}
print(grade(95));
print(grade(85));
print(grade(72));
print(grade(50));
";

#[test]
fn nested_else_block_merges_to_else_if_reeval_equivalent() {
    assert_faithful_input("chain", ORIG_CHAIN, INPUT_CHAIN);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_CHAIN);
    assert!(
        stats.else_if_merges >= 2,
        "both nested else blocks must collapse into else-if; got {}",
        stats.else_if_merges
    );
    assert!(
        recovered.contains("else if (n >= 80)") && recovered.contains("else if (n >= 70)"),
        "the chain must become else-if:\n{recovered}"
    );
    assert!(
        !recovered.contains("else {\n    if"),
        "the wrapping else block must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("chain", ORIG_CHAIN, &recovered);
}

const NEG_ELSE_WITH_PREFIX: &str = r"
var log = [];
function note(v) { log.push(v); }
function run(x) {
  if (x > 0) {
    note('pos');
  } else {
    note('checking');
    if (x === 0) {
      note('zero');
    }
  }
}
run(5);
run(0);
run(-1);
print(log.join(','));
";

#[test]
fn negative_else_with_extra_statements_unchanged() {
    let want: String = eval_capture(NEG_ELSE_WITH_PREFIX).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_ELSE_WITH_PREFIX);
    assert_eq!(
        stats.else_if_merges, 0,
        "an else block whose if is NOT the sole statement must NOT merge"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "merging across a sibling statement would drop it; behavior must be preserved"
    );
}

const NEG_INNER_IF_HAS_ELSE_SIBLING: &str = r"
var log = [];
function note(v) { log.push(v); }
function run(x) {
  if (x > 10) {
    note('big');
  } else {
    if (x > 5) {
      note('mid');
    }
    note('after');
  }
}
run(20);
run(7);
run(1);
print(log.join(','));
";

#[test]
fn negative_inner_if_followed_by_statement_unchanged() {
    let want: String = eval_capture(NEG_INNER_IF_HAS_ELSE_SIBLING).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(NEG_INNER_IF_HAS_ELSE_SIBLING);
    assert_eq!(
        stats.else_if_merges, 0,
        "the inner if has a trailing sibling so the else block must not collapse"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_INVERTED: &str = r"
function pick(x) {
  if (x > 0) {
    return 'positive';
  } else {
    return 'nonpositive';
  }
}
print(pick(3));
print(pick(-2));
print(pick(0));
";

const INPUT_INVERTED: &str = r"
function pick(x) {
  if (!(x > 0)) {
    return 'nonpositive';
  } else {
    return 'positive';
  }
}
print(pick(3));
print(pick(-2));
print(pick(0));
";

#[test]
fn inverted_if_else_swaps_arms_reeval_equivalent() {
    assert_faithful_input("inverted", ORIG_INVERTED, INPUT_INVERTED);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_INVERTED);
    assert!(
        stats.if_else_inversions >= 1,
        "the negated test must be inverted; got {}",
        stats.if_else_inversions
    );
    assert!(
        recovered.contains("if (x > 0)"),
        "the test must be de-negated:\n{recovered}"
    );
    assert!(
        !recovered.contains("!(x > 0)"),
        "the leading negation must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("inverted", ORIG_INVERTED, &recovered);
}

const ORIG_INVERTED_DANGLING: &str = r"
var log = [];
function note(v) { log.push(v); }
function run(x) {
  if (!flag(x)) {
    note('A');
  } else {
    if (x > 5) {
      note('B');
    }
  }
}
var flag = function (x) { return x < 0; };
run(-1);
run(8);
run(2);
print(log.join(','));
";

const INPUT_INVERTED_DANGLING: &str = ORIG_INVERTED_DANGLING;

#[test]
fn inverted_if_with_bare_else_if_stays_sound() {
    let want: String = eval_capture(INPUT_INVERTED_DANGLING).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_INVERTED_DANGLING);
    assert!(
        stats.if_else_inversions >= 1,
        "the negated test must invert; got {}",
        stats.if_else_inversions
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "swapping a bare inner-if into the consequent must not create a dangling-else bug:\n{recovered}"
    );
}

const ORIG_INVERT_SIDE_EFFECT: &str = r"
var log = [];
function cond() { log.push('cond'); return false; }
function run() {
  if (!cond()) {
    log.push('then');
  } else {
    log.push('else');
  }
}
run();
print(log.join(','));
";

const INPUT_INVERT_SIDE_EFFECT: &str = ORIG_INVERT_SIDE_EFFECT;

#[test]
fn inverted_test_with_side_effecting_call_preserved() {
    let want: String = eval_capture(INPUT_INVERT_SIDE_EFFECT).expect("evaluates");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(INPUT_INVERT_SIDE_EFFECT);
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "the side-effecting test must still run exactly once:\n{recovered}"
    );
}
