#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

const HELPERS: &str = r"
function _arrayLikeToArray(a, n) {
  if (n == null || n > a.length) n = a.length;
  for (var i = 0, r = new Array(n); i < n; i++) r[i] = a[i];
  return r;
}
function _arrayWithoutHoles(a) {
  if (Array.isArray(a)) return _arrayLikeToArray(a);
}
function _toConsumableArray(a) {
  return _arrayWithoutHoles(a) || Array.from(a);
}
";

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
    let want: String = eval_capture(original)
        .unwrap_or_else(|| panic!("{label}: original must evaluate; src=\n{original}"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged from the authored program\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const PLAIN_ARRAY_SNAPSHOT: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn a_spread_snapshot_of_a_proven_array_recovers_the_original_iterable() {
    let program: String = format!("{HELPERS}{PLAIN_ARRAY_SNAPSHOT}");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the snapshot loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var item of items)"),
        "the for...of head must name the authored iterable, not the lowering helper:\n{recovered}"
    );
    assert!(
        !recovered.contains("of _toConsumableArray("),
        "the materializing helper must not survive into the loop head:\n{recovered}"
    );
    assert_recovered_equivalent("plain_array_snapshot", &program, &recovered);
}

const ARRAY_FROM_SNAPSHOT: &str = r"
var items = [1, 2, 3];
var total = 0;
for (var _i = 0, _a = Array.from(items); _i < _a.length; _i++) {
  var n = _a[_i];
  total += n;
}
print(total);
";

#[test]
fn an_array_from_snapshot_of_a_proven_array_recovers_the_original_iterable() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ARRAY_FROM_SNAPSHOT);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the snapshot loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var n of items)"),
        "the for...of head must name the authored iterable:\n{recovered}"
    );
    assert_recovered_equivalent("array_from_snapshot", ARRAY_FROM_SNAPSHOT, &recovered);
}

const MUTATED_SUBJECT_SNAPSHOT: &str = r"
var items = ['a', 'b'];
var out = [];
for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
  var item = _a[_i];
  items.push(item + '!');
  out.push(item);
}
print(out.join(',') + '|' + items.length);
";

#[test]
fn a_snapshot_whose_body_grows_the_subject_keeps_the_copy() {
    let program: String = format!("{HELPERS}{MUTATED_SUBJECT_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "iterating the live array would never terminate here, so the copy must be preserved:\n{recovered}"
    );
    assert_recovered_equivalent("mutated_subject_snapshot", &program, &recovered);
}

const REASSIGNED_SUBJECT_SNAPSHOT: &str = r"
var items = ['a', 'b'];
var out = [];
for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
  var item = _a[_i];
  items = ['z'];
  out.push(item);
}
print(out.join(',') + '|' + items.join(','));
";

#[test]
fn a_snapshot_whose_body_reassigns_the_subject_keeps_the_copy() {
    let program: String = format!("{HELPERS}{REASSIGNED_SUBJECT_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "rebinding the subject mid-loop changes what a live iteration walks:\n{recovered}"
    );
    assert_recovered_equivalent("reassigned_subject_snapshot", &program, &recovered);
}

const LAZY_ITERABLE_SNAPSHOT: &str = r"
function* source() {
  print('produced 1');
  yield 1;
  print('produced 2');
  yield 2;
}
var stream = source();
for (var _i = 0, _a = _toConsumableArray(stream); _i < _a.length; _i++) {
  var value = _a[_i];
  print('consumed ' + value);
}
";

#[test]
fn a_snapshot_of_a_lazy_iterable_keeps_the_copy_so_side_effects_stay_ordered() {
    let program: String = format!("{HELPERS}{LAZY_ITERABLE_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var value of stream)"),
        "a generator is drained before the body runs, so unwrapping would interleave its prints:\n{recovered}"
    );
    assert_recovered_equivalent("lazy_iterable_snapshot", &program, &recovered);
}

const PARAMETER_SUBJECT_SNAPSHOT: &str = r"
function walk(items) {
  var out = [];
  for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
    var item = _a[_i];
    out.push(item);
  }
  return out.join(',');
}
print(walk(new Set(['a', 'b'])));
";

#[test]
fn a_snapshot_of_an_unproven_parameter_keeps_the_copy() {
    let program: String = format!("{HELPERS}{PARAMETER_SUBJECT_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "a parameter carries no array evidence, so the copy must be preserved:\n{recovered}"
    );
    assert_recovered_equivalent("parameter_subject_snapshot", &program, &recovered);
}

const SHADOWED_NAME_SNAPSHOT: &str = r"
var items = ['a', 'b'];
function walk(items) {
  var out = [];
  for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
    var item = _a[_i];
    out.push(item);
  }
  return out.join(',');
}
print(walk(new Set(['x', 'y'])));
";

#[test]
fn an_outer_array_binding_does_not_prove_a_shadowing_parameter_is_an_array() {
    let program: String = format!("{HELPERS}{SHADOWED_NAME_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "the array evidence belongs to the outer binding, not the shadowing parameter:\n{recovered}"
    );
    assert_recovered_equivalent("shadowed_name_snapshot", &program, &recovered);
}

const REDEFINED_HELPER: &str = r"
function _toConsumableArray(a) {
  return a.slice().reverse();
}
var items = ['a', 'b', 'c'];
var out = [];
for (var _i = 0, _a = _toConsumableArray(items); _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
}
print(out.join(','));
";

#[test]
fn a_helper_that_only_borrows_the_babel_name_is_not_trusted() {
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(REDEFINED_HELPER);
    assert!(
        !recovered.contains("for (var item of items)"),
        "this helper reverses rather than copies, so its name must not buy an unwrap:\n{recovered}"
    );
    assert_recovered_equivalent("redefined_helper", REDEFINED_HELPER, &recovered);
}

const REBOUND_ARRAY: &str = r"
var Array = { from: function (a) { return [a[a.length - 1]]; } };
var items = ['a', 'b', 'c'];
var out = [];
for (var _i = 0, _a = Array.from(items); _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
}
print(out.join(','));
";

#[test]
fn a_locally_rebound_array_global_is_not_trusted() {
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(REBOUND_ARRAY);
    assert!(
        !recovered.contains("for (var item of items)"),
        "Array.from is shadowed here and returns one element, so it must not be unwrapped:\n{recovered}"
    );
    assert_recovered_equivalent("rebound_array", REBOUND_ARRAY, &recovered);
}
