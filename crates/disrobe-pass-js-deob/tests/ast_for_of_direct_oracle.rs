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

const BABEL7_FORM_A: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (var _i2 = 0; _i2 < items.length; _i2++) {
  var item = items[_i2];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn babel7_direct_index_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BABEL7_FORM_A);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the direct index loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains(" of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("items[_i2]") && !recovered.contains("_i2 <"),
        "the index scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("babel7_form_a", BABEL7_FORM_A, &recovered);
}

const BABEL7_FORM_A_BLOCK_SCOPED: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (let _i = 0; _i < items.length; _i++) {
  const item = items[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn babel7_block_scoped_index_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BABEL7_FORM_A_BLOCK_SCOPED);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "must convert; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (const item of items)"),
        "a non-reassigned const element must stay const:\n{recovered}"
    );
    assert_recovered_equivalent(
        "babel7_form_a_block",
        BABEL7_FORM_A_BLOCK_SCOPED,
        &recovered,
    );
}

const LENGTH_CACHE_FORM_B: &str = r"
var arr = [1, 2, 3, 4];
var total = 0;
for (var _i = 0, _len = arr.length; _i < _len; _i++) {
  var n = arr[_i];
  total += n;
}
print(total);
";

#[test]
fn length_cache_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(LENGTH_CACHE_FORM_B);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the length-cache loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var n of arr)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("_len") && !recovered.contains("arr[_i]"),
        "the index and length-cache scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("form_b", LENGTH_CACHE_FORM_B, &recovered);
}

const SAFETY_INDEX_USED: &str = r"
var xs = ['x', 'y'];
for (var _i = 0; _i < xs.length; _i++) {
  var v = xs[_i];
  print(_i + ':' + v);
}
";

#[test]
fn direct_loop_using_the_index_is_left_intact() {
    let want: String = eval_capture(SAFETY_INDEX_USED).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_INDEX_USED);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "the body reads the loop index, which for...of does not provide; leave it as-is"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NESTED_DEFAULTED_BINDING: &str = r"
var rows = [[{ value: 2 }, undefined], [{ value: 4 }, 6]];
var total = 0;
for (var _i = 0; _i < rows.length; _i++) {
  let [{ value }, scale = 3] = rows[_i];
  value += 1;
  total += value * scale;
}
print(total);
";

#[test]
fn direct_index_loop_recovers_nested_defaulted_binding() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NESTED_DEFAULTED_BINDING);
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "the nested binding must recover exactly once"
    );
    assert!(
        recovered.contains("for (let [{ value }, scale = 3] of rows)"),
        "the exact nested/defaulted binding must move into the loop head:\n{recovered}"
    );
    assert!(
        !recovered.contains("rows[_i]") && !recovered.contains("_i <"),
        "the complete index scaffold must be removed:\n{recovered}"
    );
    assert_recovered_equivalent(
        "nested_defaulted_binding",
        NESTED_DEFAULTED_BINDING,
        &recovered,
    );
}

#[test]
fn snapshotted_iterable_recovers_object_binding_defaults() {
    let source: &str = r"
var rows = [{ value: 2 }, {}];
var total = 0;
for (var _i = 0, _rows = rows; _i < _rows.length; _i++) {
  const { value: current = 5 } = _rows[_i];
  total += current;
}
print(total);
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 1);
    assert!(
        recovered.contains("for (const { value: current = 5 } of rows)"),
        "the snapshotted iterable must retain its object binding:\n{recovered}"
    );
    assert_recovered_equivalent("snapshotted_object_binding", source, &recovered);
}

#[test]
fn destructuring_loop_with_observable_index_is_left_intact() {
    let source: &str = r"
var rows = [[1, 2], [3, 4]];
for (var _i = 0; _i < rows.length; _i++) {
  const [left, right] = rows[_i];
  print(_i + ':' + (left + right));
}
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "an observable index must preserve the original loop"
    );
    assert!(
        recovered.contains("rows[_i]") && recovered.contains("_i < rows.length"),
        "the original loop must remain intact:\n{recovered}"
    );
    assert_recovered_equivalent("observable_destructuring_index", source, &recovered);
}

#[test]
fn comment_inside_destructuring_scaffold_causes_byte_preserving_refusal() {
    let source: &str = r"for (var _i = 0; _i < rows.length; _i++) {
  let /* keep binding context */ [left, right] = rows[_i];
  print(left + right);
}";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 0);
    assert_eq!(recovered, source);
}

#[test]
fn binding_default_using_the_removed_index_is_left_intact() {
    let source: &str = r"
var rows = [[undefined], [9]];
var seen = [];
for (var _i = 0; _i < rows.length; _i++) {
  const [value = _i] = rows[_i];
  seen.push(value);
}
print(seen.join(','));
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 0);
    assert!(
        recovered.contains("const [value = _i] = rows[_i]")
            && recovered.contains("_i < rows.length"),
        "the index-dependent binding must retain its scaffold:\n{recovered}"
    );
    assert_recovered_equivalent("index_dependent_binding_default", source, &recovered);
}

#[test]
fn destructuring_reassignment_keeps_the_loop_binding_mutable() {
    let source: &str = r"
var rows = [[1, 2], [3, 4]];
var seen = [];
for (var _i = 0; _i < rows.length; _i++) {
  let [left, right] = rows[_i];
  [left, right] = [right, left];
  seen.push(left - right);
}
print(seen.join(','));
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 1);
    assert!(
        recovered.contains("for (let [left, right] of rows)"),
        "a destructuring assignment must prevent const recovery:\n{recovered}"
    );
    assert_recovered_equivalent("destructuring_reassignment", source, &recovered);
}

#[test]
fn member_mutation_preserves_a_const_destructuring_binding() {
    let source: &str = r"
var rows = [{ item: { value: 1 } }, { item: { value: 3 } }];
var seen = [];
for (var _i = 0; _i < rows.length; _i++) {
  const { item } = rows[_i];
  item.value++;
  seen.push(item.value);
}
print(seen.join(','));
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 1);
    assert!(
        recovered.contains("for (const { item } of rows)"),
        "mutating a member must not make the binding mutable:\n{recovered}"
    );
    assert_recovered_equivalent("const_member_mutation", source, &recovered);
}

#[test]
fn original_const_binding_preserves_assignment_failure() {
    let source: &str = r"
var rows = [[1]];
var result = 'no error';
try {
  for (var _i = 0; _i < rows.length; _i++) {
    const [value] = rows[_i];
    value = 7;
  }
} catch (error) {
  result = error.name;
}
print(result);
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 1);
    assert!(
        recovered.contains("for (const [value] of rows)"),
        "an original const binding must remain const:\n{recovered}"
    );
    assert_recovered_equivalent("const_assignment_failure", source, &recovered);
}

#[test]
fn computed_key_and_default_keep_their_evaluation_order() {
    let source: &str = r"
var trace = [];
function key() { trace.push('key'); return 'value'; }
function fallback() { trace.push('default'); return 5; }
var rows = [{}, { value: 3 }];
for (var _i = 0; _i < rows.length; _i++) {
  const { [key()]: current = fallback() } = rows[_i];
  trace.push('body:' + current);
}
print(trace.join(','));
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 1);
    assert!(
        recovered.contains("for (const { [key()]: current = fallback() } of rows)"),
        "the exact computed/defaulted binding must move into the loop head:\n{recovered}"
    );
    assert!(
        !recovered.contains("rows[_i]") && !recovered.contains("_i < rows.length"),
        "the complete index scaffold must be removed:\n{recovered}"
    );
    assert_recovered_equivalent("computed_key_default_order", source, &recovered);
}

#[test]
fn binding_default_using_the_removed_length_cache_is_left_intact() {
    let source: &str = r"
var rows = [[undefined], [9]];
var seen = [];
for (var _i = 0, _len = rows.length; _i < _len; _i++) {
  const [value = _len] = rows[_i];
  seen.push(value);
}
print(seen.join(','));
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.index_loops_to_for_of, 0);
    assert!(
        recovered.contains("const [value = _len] = rows[_i]") && recovered.contains("_i < _len"),
        "the cache-dependent binding must retain its scaffold:\n{recovered}"
    );
    assert_recovered_equivalent("length_cache_dependent_default", source, &recovered);
}

#[test]
fn binding_named_after_the_removed_index_preserves_tdz_failure() {
    let source: &str = r"
var rows = [[7]];
var result = 'completed';
try {
  for (var _i = 0; _i < rows.length; _i++) {
    const [_i] = rows[_i];
  }
} catch (error) {
  result = error.name;
}
print(result);
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "a binding that shadows the removed index must preserve the TDZ failure"
    );
    assert!(
        recovered.contains("const [_i] = rows[_i]") && recovered.contains("_i < rows.length"),
        "the shadowing loop must retain its scaffold:\n{recovered}"
    );
    assert_recovered_equivalent("index_binding_tdz", source, &recovered);
}

#[test]
fn snapshot_binding_named_after_the_iterable_preserves_rhs_scope() {
    let source: &str = r"
var items = [[7]];
var result = 'completed';
try {
  for (var _i = 0, _rows = items; _i < _rows.length; _i++) {
    const [items] = _rows[_i];
  }
} catch (error) {
  result = error.name;
}
print(result);
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "a binding that shadows the snapshot iterable must retain its original RHS scope"
    );
    assert!(
        recovered.contains("_rows = items") && recovered.contains("const [items] = _rows[_i]"),
        "the snapshot loop must retain its scaffold:\n{recovered}"
    );
    assert_recovered_equivalent("snapshot_iterable_binding_scope", source, &recovered);
}
