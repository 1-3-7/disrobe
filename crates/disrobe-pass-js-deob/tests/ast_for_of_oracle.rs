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

const ORIG_TS_INDEX_LOOP: &str = r"
var items = ['a', 'b', 'c'];
for (var _i = 0, _arr = items; _i < _arr.length; _i++) {
  var item = _arr[_i];
  print(item.toUpperCase());
}
";

#[test]
fn ts_index_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_TS_INDEX_LOOP);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the index loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains(" of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("_arr[_i]") && !recovered.contains(".length"),
        "the index scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("ts_index", ORIG_TS_INDEX_LOOP, &recovered);
}

const ORIG_REASSIGNED: &str = r"
var nums = [1, 2, 3];
var total = 0;
for (var _i = 0, _a = nums; _i < _a.length; _i++) {
  let n = _a[_i];
  n = n * 2;
  total += n;
}
print(total);
";

#[test]
fn reassigned_element_still_runs_correctly() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_REASSIGNED);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "must convert; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (let n of nums)"),
        "a reassigned element must use let, not const:\n{recovered}"
    );
    assert_recovered_equivalent("reassigned", ORIG_REASSIGNED, &recovered);
}

const SAFETY_INDEX_USED: &str = r"
var xs = ['x', 'y'];
for (var _i = 0, _a = xs; _i < _a.length; _i++) {
  var v = _a[_i];
  print(_i + ':' + v);
}
";

#[test]
fn loop_using_the_index_in_the_body_is_left_intact() {
    let want: String = eval_capture(SAFETY_INDEX_USED).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_INDEX_USED);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "the body reads the loop index `_i`, which for...of does not provide; the loop must be left as-is"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const SAFETY_PLAIN_COUNTER: &str = r"
var sum = 0;
for (var i = 0; i < 5; i++) { sum += i; }
print(sum);
";

#[test]
fn a_plain_counting_loop_is_not_a_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_PLAIN_COUNTER);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "a counting loop with no array-index element decl is not an iteration loop"
    );
    assert_recovered_equivalent("counter", SAFETY_PLAIN_COUNTER, &recovered);
}
