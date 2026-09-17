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

const ORIG_STMT: &str = r"
var log = [];
function a() { log.push('a'); }
function b() { log.push('b'); }
function c() { log.push('c'); }
a();
b();
c();
print(log.join(','));
";

const INPUT_STMT: &str = r"
var log = [];
function a() { log.push('a'); }
function b() { log.push('b'); }
function c() { log.push('c'); }
a(), b(), c();
print(log.join(','));
";

#[test]
fn statement_sequence_split_reeval_equivalent() {
    assert_faithful_input("stmt", ORIG_STMT, INPUT_STMT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_STMT);
    assert!(
        stats.sequence_statement_splits >= 1,
        "the comma-sequence statement must split; got {}",
        stats.sequence_statement_splits
    );
    assert!(
        !recovered.contains("a(), b(), c()"),
        "the comma sequence must be gone:\n{recovered}"
    );
    assert!(
        recovered.contains("a();") && recovered.contains("b();") && recovered.contains("c();"),
        "each call must become its own statement:\n{recovered}"
    );
    assert_recovered_equivalent("stmt", ORIG_STMT, &recovered);
}

const ORIG_RETURN: &str = r"
var log = [];
function side() { log.push('s'); return 0; }
function f() {
  side();
  return 42;
}
print(f());
print(log.join(','));
";

const INPUT_RETURN: &str = r"
var log = [];
function side() { log.push('s'); return 0; }
function f() {
  return side(), 42;
}
print(f());
print(log.join(','));
";

#[test]
fn return_sequence_split_reeval_equivalent() {
    assert_faithful_input("return", ORIG_RETURN, INPUT_RETURN);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_RETURN);
    assert!(
        stats.sequence_return_splits >= 1,
        "the return-sequence must split; got {}",
        stats.sequence_return_splits
    );
    assert!(
        recovered.contains("side();") && recovered.contains("return 42;"),
        "the side effect must hoist out and the last value must stay in the return:\n{recovered}"
    );
    assert!(
        !recovered.contains("return side(), 42"),
        "the comma-in-return must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("return", ORIG_RETURN, &recovered);
}

const NEG_FOR_HEADER: &str = r"
var sum = 0;
for (var i = 0, j = 10; i < 3; i++, j--) { sum += i + j; }
print(sum);
";

#[test]
fn negative_for_header_sequence_unchanged() {
    let want: String = eval_capture(NEG_FOR_HEADER).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_FOR_HEADER);
    assert_eq!(
        stats.sequence_statement_splits, 0,
        "the for-header update sequence must NOT be split (position-critical)"
    );
    assert_eq!(
        stats.sequence_return_splits, 0,
        "the for-header init sequence must NOT be split"
    );
    assert!(
        recovered.contains("i++, j--"),
        "the for-header comma must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_BRACELESS_IF: &str = r"
var log = [];
function a() { log.push('a'); }
function b() { log.push('b'); }
function guard(flag) { if (flag) a(), b(); }
guard(false);
print(log.join(','));
guard(true);
print(log.join(','));
";

#[test]
fn negative_braceless_if_body_sequence_unchanged() {
    let want: String = eval_capture(NEG_BRACELESS_IF).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_BRACELESS_IF);
    assert_eq!(
        stats.sequence_statement_splits, 0,
        "the list-position sequence-split pass must never flatten a guarded brace-less body into bare statements"
    );
    assert_eq!(
        stats.branch_comma_bodies_split, 1,
        "the guarded comma body is instead recovered into a block by the loop/branch comma-body pass:\n{recovered}"
    );
    assert!(
        !recovered.contains("a(), b()") && !recovered.contains("a(),b()"),
        "the guarded comma sequence must be recovered, not left as a comma expression:\n{recovered}"
    );
    assert!(
        recovered.contains("a();") && recovered.contains("b();"),
        "each guarded call must become its own statement inside the block:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "wrapping the guarded sequence in a block keeps b() inside the guard; behavior must be preserved"
    );
}

const ORIG_IF_TEST: &str = r"
var log = [];
function side() { log.push('s'); }
var flag = true;
side();
if (flag) { log.push('then'); }
print(log.join(','));
";

const INPUT_IF_TEST: &str = r"
var log = [];
function side() { log.push('s'); }
var flag = true;
if (side(), flag) { log.push('then'); }
print(log.join(','));
";

#[test]
fn if_test_sequence_hoists_reeval_equivalent() {
    assert_faithful_input("if-test", ORIG_IF_TEST, INPUT_IF_TEST);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_IF_TEST);
    assert!(
        stats.sequence_if_test_hoists >= 1,
        "the if-test sequence must hoist; got {}",
        stats.sequence_if_test_hoists
    );
    assert!(
        recovered.contains("side();"),
        "the leading effect must hoist before the if:\n{recovered}"
    );
    assert!(
        !recovered.contains("if (side(), flag)") && !recovered.contains("side(), flag"),
        "the comma in the if-test must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("if-test", ORIG_IF_TEST, &recovered);
}

const NEG_VALUE_POSITION: &str = r"
var x = (1, 2, 3);
print(x);
";

#[test]
fn negative_value_position_sequence_unchanged() {
    let want: String = eval_capture(NEG_VALUE_POSITION).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_VALUE_POSITION);
    assert_eq!(
        stats.sequence_statement_splits, 0,
        "a value-position sequence assigned to a binding must NOT be split"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "value-position comma yields the last operand; preserved"
    );
}
