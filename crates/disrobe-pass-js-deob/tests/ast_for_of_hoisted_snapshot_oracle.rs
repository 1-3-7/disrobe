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

fn assert_restored(label: &str, input: &str, recovered: &str, needle: &str) {
    assert!(
        !input.contains(needle),
        "{label}: `{needle}` is already in the input, so finding it in the output proves nothing"
    );
    assert!(
        recovered.contains(needle),
        "{label}: `{needle}` was absent from the input and must be restored:\n{recovered}"
    );
}

fn assert_removed(label: &str, input: &str, recovered: &str, needle: &str) {
    assert!(
        input.contains(needle),
        "{label}: `{needle}` must be present in the input for its removal to mean anything"
    );
    assert!(
        !recovered.contains(needle),
        "{label}: `{needle}` must not survive the rewrite:\n{recovered}"
    );
}

const HOISTED_VAR_SNAPSHOT: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
var _a = _toConsumableArray(items);
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn a_hoisted_spread_snapshot_recovers_the_authored_iterable_and_drops_the_helper() {
    let program: String = format!("{HELPERS}{HOISTED_VAR_SNAPSHOT}");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the hoisted snapshot loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert_restored(
        "hoisted_var",
        &program,
        &recovered,
        "for (var item of items)",
    );
    assert_removed("hoisted_var", &program, &recovered, "_a =");
    assert!(
        !recovered.contains("of _a)"),
        "the loop must name the authored iterable, not the deleted copy:
{recovered}"
    );
    assert_recovered_equivalent("hoisted_var", &program, &recovered);
}

const HOISTED_ARRAY_FROM_SNAPSHOT: &str = r"
var items = [1, 2, 3];
var total = 0;
var _a = Array.from(items);
for (var _i = 0; _i < _a.length; _i++) {
  var n = _a[_i];
  total += n;
}
print(total);
";

#[test]
fn a_hoisted_array_from_snapshot_recovers_the_authored_iterable() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(HOISTED_ARRAY_FROM_SNAPSHOT);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the hoisted snapshot loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert_restored(
        "hoisted_array_from",
        HOISTED_ARRAY_FROM_SNAPSHOT,
        &recovered,
        "for (var n of items)",
    );
    assert_removed(
        "hoisted_array_from",
        HOISTED_ARRAY_FROM_SNAPSHOT,
        &recovered,
        "_a =",
    );
    assert_recovered_equivalent(
        "hoisted_array_from",
        HOISTED_ARRAY_FROM_SNAPSHOT,
        &recovered,
    );
}

const HOISTED_LET_SNAPSHOT: &str = r"
let items = ['x', 'y'];
let out = [];
let _a = _toConsumableArray(items);
for (let _i = 0; _i < _a.length; _i++) {
  let item = _a[_i];
  out.push(item);
}
print(out.join(','));
";

#[test]
fn a_hoisted_let_snapshot_recovers_the_authored_iterable() {
    let program: String = format!("{HELPERS}{HOISTED_LET_SNAPSHOT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert_restored(
        "hoisted_let",
        &program,
        &recovered,
        "for (const item of items)",
    );
    assert_recovered_equivalent("hoisted_let", &program, &recovered);
}

const TEMP_READ_AFTER_LOOP: &str = r"
var items = ['a', 'b'];
var out = [];
var _a = _toConsumableArray(items);
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
}
print(out.join(',') + '|' + _a.length);
";

#[test]
fn a_hoisted_snapshot_still_read_after_the_loop_keeps_its_binding() {
    let program: String = format!("{HELPERS}{TEMP_READ_AFTER_LOOP}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        recovered.contains("_a ="),
        "the temporary outlives the loop, so its binding must not be deleted:\n{recovered}"
    );
    assert!(
        recovered.contains("of _a)"),
        "the loop must keep iterating the copy while the copy is still read:\n{recovered}"
    );
    assert_recovered_equivalent("temp_read_after_loop", &program, &recovered);
}

const SUBJECT_MUTATED_BEFORE_LOOP: &str = r"
var items = ['a', 'b'];
var out = [];
var _a = _toConsumableArray(items);
items.push('c');
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
}
print(out.join(',') + '|' + items.join(','));
";

#[test]
fn a_subject_mutated_between_the_snapshot_and_the_loop_keeps_the_copy() {
    let program: String = format!("{HELPERS}{SUBJECT_MUTATED_BEFORE_LOOP}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "the snapshot predates the push, so a live iteration would walk one element too many:\n{recovered}"
    );
    assert_recovered_equivalent("subject_mutated_before_loop", &program, &recovered);
}

const SUBJECT_MUTATED_IN_BODY: &str = r"
var items = ['a', 'b'];
var out = [];
var _a = _toConsumableArray(items);
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  items.push(item + '!');
  out.push(item);
}
print(out.join(',') + '|' + items.length);
";

#[test]
fn a_hoisted_snapshot_whose_body_grows_the_subject_keeps_the_copy() {
    let program: String = format!("{HELPERS}{SUBJECT_MUTATED_IN_BODY}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "iterating the live array would never terminate here, so the copy must be preserved:\n{recovered}"
    );
    assert_recovered_equivalent("subject_mutated_in_body", &program, &recovered);
}

const HOISTED_REDEFINED_HELPER: &str = r"
function _toConsumableArray(a) {
  return a.slice().reverse();
}
var items = ['a', 'b', 'c'];
var out = [];
var _a = _toConsumableArray(items);
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
}
print(out.join(','));
";

#[test]
fn a_hoisted_helper_that_only_borrows_the_babel_name_is_not_trusted() {
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(HOISTED_REDEFINED_HELPER);
    assert!(
        !recovered.contains("for (var item of items)"),
        "this helper reverses rather than copies, so its name must not buy an unwrap:\n{recovered}"
    );
    assert_recovered_equivalent(
        "hoisted_redefined_helper",
        HOISTED_REDEFINED_HELPER,
        &recovered,
    );
}

const HOISTED_UNPROVEN_SUBJECT: &str = r"
function walk(items) {
  var out = [];
  var _a = _toConsumableArray(items);
  for (var _i = 0; _i < _a.length; _i++) {
    var item = _a[_i];
    out.push(item);
  }
  return out.join(',');
}
print(walk(new Set(['a', 'b'])));
";

#[test]
fn a_hoisted_snapshot_of_an_unproven_parameter_keeps_the_copy() {
    let program: String = format!("{HELPERS}{HOISTED_UNPROVEN_SUBJECT}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "a parameter carries no array evidence, so the copy must be preserved:\n{recovered}"
    );
    assert_recovered_equivalent("hoisted_unproven_subject", &program, &recovered);
}

const HOISTED_TEMP_REASSIGNED: &str = r"
var items = ['a', 'b'];
var out = [];
var _a = _toConsumableArray(items);
for (var _i = 0; _i < _a.length; _i++) {
  var item = _a[_i];
  out.push(item);
  if (_i === 0) _a = ['z'];
}
print(out.join(','));
";

#[test]
fn a_hoisted_snapshot_reassigned_inside_the_loop_keeps_its_binding() {
    let program: String = format!("{HELPERS}{HOISTED_TEMP_REASSIGNED}");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert!(
        !recovered.contains("for (var item of items)"),
        "the temporary is rebound mid-loop, so it is not a pure snapshot of the subject:\n{recovered}"
    );
    assert_recovered_equivalent("hoisted_temp_reassigned", &program, &recovered);
}

#[test]
fn the_hoisted_rewrite_is_byte_identical_across_two_runs() {
    let program: String = format!("{HELPERS}{HOISTED_VAR_SNAPSHOT}");
    let (first, _a): (String, AstUnminifyStats) = unminify_ast(&program);
    let (second, _b): (String, AstUnminifyStats) = unminify_ast(&program);
    assert_eq!(
        first, second,
        "two runs over the same input must produce byte-identical output"
    );
}
