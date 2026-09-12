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
var log = [];
function tick() { log.push('t'); return log.length; }
function build() {
  var a, b, c;
  a = tick();
  b = a;
  c = a;
  log.push(a);
  log.push(b);
  log.push(c);
}
build();
print(log.join(','));
";

const TERSER_CHAIN: &str = r"
var log = [];
function tick() { log.push('t'); return log.length; }
function build() {
  var a, b, c;
  c = b = a = tick();
  log.push(a);
  log.push(b);
  log.push(c);
}
build();
print(log.join(','));
";

#[test]
fn terser_chained_assignment_splits_and_preserves_behavior() {
    assert_faithful_input("chain", ORIG_CHAIN, TERSER_CHAIN);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_CHAIN);
    assert_eq!(
        stats.chained_assignments_split, 1,
        "the statement-position chained assignment must split once; got {}\n{recovered}",
        stats.chained_assignments_split
    );
    assert_eq!(
        stats.chained_assignments_emitted, 3,
        "a three-target chain emits three separate assignments; got {}",
        stats.chained_assignments_emitted
    );
    assert!(
        !recovered.contains("c = b = a = tick()") && !recovered.contains("= b = a ="),
        "the chained form must be gone:\n{recovered}"
    );
    assert!(
        recovered.contains("a = tick();"),
        "the value must be assigned to the innermost target once:\n{recovered}"
    );
    assert_recovered_equivalent("chain", ORIG_CHAIN, &recovered);
}

const ORIG_TWO: &str = r"
var log = [];
function make() { log.push('m'); return 42; }
function run() {
  var x, y;
  x = make();
  y = x;
  print(x + ':' + y);
}
run();
print(log.join(','));
";

const TERSER_TWO: &str = r"
var log = [];
function make() { log.push('m'); return 42; }
function run() {
  var x, y;
  y = x = make();
  print(x + ':' + y);
}
run();
print(log.join(','));
";

#[test]
fn two_target_chain_splits_and_preserves_behavior() {
    assert_faithful_input("two", ORIG_TWO, TERSER_TWO);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_TWO);
    assert_eq!(
        stats.chained_assignments_split, 1,
        "the two-target chain must split:\n{recovered}"
    );
    assert_eq!(stats.chained_assignments_emitted, 2);
    assert!(
        !recovered.contains("y = x = make()"),
        "the chain must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("two", ORIG_TWO, &recovered);
}

const NEG_VALUE_CHAIN: &str = r"
var log = [];
function seed() { log.push('s'); return 5; }
function compute() {
  var a, b;
  var total = (a = b = seed()) + a + b;
  return total;
}
print(compute());
print(log.join(','));
";

#[test]
fn value_position_chain_is_not_split() {
    let want: String = eval_capture(NEG_VALUE_CHAIN).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_VALUE_CHAIN);
    assert_eq!(
        stats.chained_assignments_split, 0,
        "a chain used as a value inside a larger expression must not be split:\n{recovered}"
    );
    assert!(
        recovered.contains("a = b = seed()"),
        "the value-position chain must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_COMPOUND: &str = r"
var log = [];
function run() {
  var a = 1, b = 10;
  a = b += 5;
  log.push(a);
  log.push(b);
}
run();
print(log.join(','));
";

#[test]
fn compound_inner_operator_is_not_split() {
    let want: String = eval_capture(NEG_COMPOUND).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_COMPOUND);
    assert_eq!(
        stats.chained_assignments_split, 0,
        "a chain whose inner operator is a compound assignment must not be split:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_MEMBER: &str = r"
var log = [];
function run() {
  var o = {};
  var b;
  o.x = b = 7;
  log.push(o.x);
  log.push(b);
}
run();
print(log.join(','));
";

#[test]
fn member_outer_target_is_not_split() {
    let want: String = eval_capture(NEG_MEMBER).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_MEMBER);
    assert_eq!(
        stats.chained_assignments_split, 0,
        "member outer targets are out of scope; the chain must be left alone:\n{recovered}"
    );
    assert!(
        recovered.contains("o.x = b = 7"),
        "the member chain must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
