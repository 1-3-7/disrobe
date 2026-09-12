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

const BABEL_LOOSE_HELPER: &str = r#"
function _createForOfIteratorHelperLoose(o) {
  var it = typeof Symbol !== "undefined" && o[Symbol.iterator] || o["@@iterator"];
  if (it) return (it = it.call(o)).next.bind(it);
  if (Array.isArray(o)) {
    var i = 0;
    return function () {
      if (i >= o.length) return { done: true };
      return { done: false, value: o[i++] };
    };
  }
  throw new TypeError("not iterable");
}
"#;

const ORIGINAL: &str = r#"
var values = new Set(["a", "b", "c"]);
var result = [];
for (var value of values) {
  result.push(value.toUpperCase());
}
print(result.join(","));
"#;

fn lowered() -> String {
    format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
var values = new Set(["a", "b", "c"]);
var result = [];
for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step = _iterator()).done;) {
  var value = _step.value;
  result.push(value.toUpperCase());
}
print(result.join(","));
"#
    )
}

#[test]
fn babel_loose_callable_iterator_recovers_to_for_of() {
    let input: String = lowered();
    let expected: String = eval_capture(ORIGINAL).expect("original must evaluate");
    assert_eq!(
        eval_capture(&input).expect("Babel loose lowering must evaluate"),
        expected,
        "the committed lowering must preserve the original behavior before recovery"
    );

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the Babel loose callable-iterator loop must become for...of; stats={stats:?}"
    );
    assert!(
        recovered.contains("for (var value of values)"),
        "the recovered loop must expose the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("_createForOfIteratorHelperLoose(values)")
            && !recovered.contains("_iterator()"),
        "the loose iterator scaffold must be removed:\n{recovered}"
    );
    assert_eq!(
        eval_capture(&recovered).expect("recovered source must evaluate"),
        expected,
        "recovery must preserve behavior"
    );
}

#[test]
fn callable_iterator_reused_in_body_is_left_intact() {
    let input: String = format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
var values = ["a", "b"];
for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step = _iterator()).done;) {
  print(_step.value);
  print(_iterator);
}
"#
    );
    let expected: String = eval_capture(&input).expect("input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "a callable iterator used by the body is not removable"
    );
    assert_eq!(
        eval_capture(&recovered).expect("unchanged source must evaluate"),
        expected,
        "refusal must preserve behavior"
    );
}

#[test]
fn same_named_nonstandard_helper_is_left_intact() {
    let input: &str = r#"
function _createForOfIteratorHelperLoose(values) {
  var index = 0;
  return function () {
    return index < values.length
      ? { done: false, value: values[index++] + "!" }
      : { done: true };
  };
}
var values = ["a", "b"];
for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step = _iterator()).done;) {
  print(_step.value);
}
"#;
    let expected: String = eval_capture(input).expect("input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "a same-named helper with different value semantics must not be recovered"
    );
    assert_eq!(
        eval_capture(&recovered).expect("unchanged source must evaluate"),
        expected,
        "refusal must preserve the helper's transformed values"
    );
}

#[test]
fn shadowed_same_named_nonstandard_helper_blocks_recovery() {
    let input: String = format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
function run(_createForOfIteratorHelperLoose, values) {
  for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step = _iterator()).done;) {
    print(_step.value);
  }
}
run(function (items) {
  var index = 0;
  return function () {
    return index < items.length
      ? { done: false, value: items[index++] + "!" }
      : { done: true };
  };
}, ["a", "b"]);
"#
    );
    let expected: String = eval_capture(&input).expect("input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "a shadowed helper with different value semantics must block recovery"
    );
    assert_eq!(
        eval_capture(&recovered).expect("unchanged source must evaluate"),
        expected,
        "refusal must preserve the shadowed helper's transformed values"
    );
}

#[test]
fn non_function_binding_and_fake_fingerprint_block_recovery() {
    let input: &str = r#"
function fake(values) {
  var index = 0;
  var markers = "Symbol.iterator @@iterator .next.bind Array.isArray";
  return function () {
    return index < values.length
      ? { done: false, value: values[index++] + markers.length }
      : { done: true };
  };
}
var _createForOfIteratorHelperLoose = fake;
for (var _iterator = _createForOfIteratorHelperLoose(["a"]), _step; !(_step = _iterator()).done;) {
  print(_step.value);
}
"#;
    let expected: String = eval_capture(input).expect("input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert_eq!(stats.helper_loops_to_for_of, 0);
    assert_eq!(eval_capture(&recovered), Some(expected));
}

#[test]
fn second_argument_and_tail_temp_use_block_recovery() {
    let input: String = format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
var values = [["a"]];
for (var _iterator = _createForOfIteratorHelperLoose(values, true), _step; !(_step = _iterator()).done;) {
  var value = _step.value;
  print(value[0]);
}
"#
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(stats.helper_loops_to_for_of, 0);
    assert!(recovered.contains("_createForOfIteratorHelperLoose(values, true)"));
}

#[test]
fn destructuring_temp_used_after_loop_blocks_recovery() {
    let input: String = format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
var values = [["a"]];
for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step = _iterator()).done;) {
  var _value = _slicedToArray(_step.value, 1), value = _value[0];
  print(value);
}
print(_value);
"#
    );
    let (_, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(stats.helper_loops_to_for_of, 0);
}

#[test]
fn compound_step_assignment_blocks_recovery() {
    let input: String = format!(
        "{BABEL_LOOSE_HELPER}{}",
        r#"
var values = ["a"];
for (var _iterator = _createForOfIteratorHelperLoose(values), _step; !(_step += _iterator()).done;) {
  var value = _step.value;
  print(value);
}
"#
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(stats.helper_loops_to_for_of, 0);
    assert!(recovered.contains("!(_step += _iterator()).done"));
}
