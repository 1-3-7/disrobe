#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};
use std::process::{Command, Output};

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

fn eval_capture_node(program: &str) -> Option<String> {
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\nprocess.stdout.write(__out.join('\\u0001'));"
    );
    let output: Output = Command::new("node").arg("-e").arg(harness).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: desugared input is not behaviorally identical to the original developer source BEFORE transform"
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

const ORIG_SHORTHAND: &str = r"
function area(_ref) {
  var w = _ref.w, h = _ref.h;
  return w * h;
}
print(area({ w: 4, h: 5 }));
print(area({ w: 2, h: 9 }));
";

const DEV_SHORTHAND: &str = r"
function area({ w, h }) {
  return w * h;
}
print(area({ w: 4, h: 5 }));
print(area({ w: 2, h: 9 }));
";

#[test]
fn babel_object_destructure_param_recovers_shorthand() {
    assert_faithful_input("shorthand", DEV_SHORTHAND, ORIG_SHORTHAND);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_SHORTHAND);
    assert!(
        stats.object_params_restructured >= 1,
        "the `var w = _ref.w` extraction must become a destructuring param; got {}",
        stats.object_params_restructured
    );
    assert!(
        recovered.contains("function area({ w, h })"),
        "the destructuring pattern must land on the signature:\n{recovered}"
    );
    assert!(
        !recovered.contains("_ref"),
        "the synthetic param and its extraction scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("shorthand", DEV_SHORTHAND, &recovered);
}

const ORIG_RENAMED: &str = r"
function delta(_ref) {
  var start = _ref.from, finish = _ref.to;
  return finish - start;
}
print(delta({ from: 3, to: 11 }));
print(delta({ from: 10, to: 4 }));
";

const DEV_RENAMED: &str = r"
function delta({ from: start, to: finish }) {
  return finish - start;
}
print(delta({ from: 3, to: 11 }));
print(delta({ from: 10, to: 4 }));
";

#[test]
fn renamed_fields_recover_key_colon_local_form() {
    assert_faithful_input("renamed", DEV_RENAMED, ORIG_RENAMED);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_RENAMED);
    assert!(
        stats.object_params_restructured >= 1,
        "renamed fields must restructure; got {}",
        stats.object_params_restructured
    );
    assert!(
        recovered.contains("function delta({ from: start, to: finish })"),
        "a field whose local name differs from its key must keep the `key: local` form:\n{recovered}"
    );
    assert_recovered_equivalent("renamed", DEV_RENAMED, &recovered);
}

const ORIG_COMPUTED_KEY: &str = r#"
function pluck(_ref) {
  var v = _ref["value"];
  return v + 1;
}
print(pluck({ value: 41 }));
"#;

const DEV_COMPUTED_KEY: &str = r"
function pluck({ value: v }) {
  return v + 1;
}
print(pluck({ value: 41 }));
";

#[test]
fn computed_string_key_extraction_recovers() {
    assert_faithful_input("computed", DEV_COMPUTED_KEY, ORIG_COMPUTED_KEY);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_COMPUTED_KEY);
    assert!(
        stats.object_params_restructured >= 1,
        "a `_ref[\"value\"]` extraction must restructure; got {}",
        stats.object_params_restructured
    );
    assert!(
        recovered.contains("{ value: v }") || recovered.contains("{ value }"),
        "the string-literal key must become a destructured field:\n{recovered}"
    );
    assert_recovered_equivalent("computed", DEV_COMPUTED_KEY, &recovered);
}

const SAFETY_WHOLE_OBJECT_USED: &str = r"
function handler(_ref) {
  var id = _ref.id;
  return JSON.stringify(_ref) + ':' + id;
}
print(handler({ id: 7, name: 'x' }));
";

#[test]
fn whole_object_reference_leaves_param_intact() {
    let want: String = eval_capture(SAFETY_WHOLE_OBJECT_USED).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_WHOLE_OBJECT_USED);
    assert_eq!(
        stats.object_params_restructured, 0,
        "the body uses the whole `_ref`, which a destructured `{{ id }}` would not bind; the param must be left as-is"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "behavior preserved when the object is used whole"
    );
}

const SAFETY_ORDINARY_PARAM: &str = r"
function f(opts) {
  var x = opts.x;
  return x * 2;
}
print(f({ x: 6 }));
";

#[test]
fn a_developer_named_param_is_not_restructured() {
    let want: String = eval_capture(SAFETY_ORDINARY_PARAM).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_ORDINARY_PARAM);
    assert_eq!(
        stats.object_params_restructured, 0,
        "an ordinary developer parameter name (not a synthetic `_ref`) must not be assumed to be a destructure scaffold"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const DEFAULTED_LOWERED: &str = r#"
function describe(_ref = { prefix: "fallback", value: 3 }) {
  var prefix = _ref.prefix, value = _ref.value;
  return prefix + ":" + value;
}
print(describe());
print(describe(undefined));
print(describe({ prefix: "given", value: 7 }));
"#;

const DEFAULTED_DEVELOPER: &str = r#"
function describe({ prefix, value } = { prefix: "fallback", value: 3 }) {
  return prefix + ":" + value;
}
print(describe());
print(describe(undefined));
print(describe({ prefix: "given", value: 7 }));
"#;

#[test]
fn defaulted_object_parameter_recovers_without_changing_default_or_explicit_arguments() {
    assert_faithful_input("defaulted object", DEFAULTED_DEVELOPER, DEFAULTED_LOWERED);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(DEFAULTED_LOWERED);
    let (second_recovery, second_stats): (String, AstUnminifyStats) =
        unminify_ast(DEFAULTED_LOWERED);
    assert_eq!(second_recovery, recovered);
    assert_eq!(second_stats.object_params_restructured, 1);
    assert_eq!(
        stats.object_params_restructured, 1,
        "the synthetic assignment-pattern parameter must recover exactly once:\n{recovered}"
    );
    assert!(
        recovered
            .contains("function describe({ prefix, value } = { prefix: \"fallback\", value: 3 })"),
        "the destructured parameter must retain the exact default expression:\n{recovered}"
    );
    assert_recovered_equivalent("defaulted object", DEFAULTED_DEVELOPER, &recovered);
}

const DEFAULTED_WHOLE_OBJECT_USED: &str = r#"
function describe(_ref = { prefix: "fallback", value: 3 }) {
  var prefix = _ref.prefix, value = _ref.value;
  print(JSON.stringify(_ref));
  return prefix + ":" + value;
}
print(describe());
"#;

#[test]
fn defaulted_object_parameter_read_as_a_whole_is_left_intact() {
    let expected: String =
        eval_capture(DEFAULTED_WHOLE_OBJECT_USED).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(DEFAULTED_WHOLE_OBJECT_USED);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("_ref = { prefix: \"fallback\", value: 3 }"));
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
}

const DEFAULT_CAPTURE: &str = r"
var value = { value: 11 };
function read(_ref = value) {
  var value = _ref.value;
  return value;
}
print(read());
print(read(undefined));
print(read({ value: 17 }));
";

#[test]
fn default_initializer_outer_capture_is_left_intact_for_omitted_and_undefined_arguments() {
    let expected: String = eval_capture(DEFAULT_CAPTURE).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(DEFAULT_CAPTURE);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("function read(_ref = value)"));
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
}

const DEFAULT_WRITE_CAPTURE: &str = r"
var value;
function read(_ref = (value = { value: 11 })) {
  var value = _ref.value;
  return value;
}
print(read());
print(read(undefined));
";

#[test]
fn default_initializer_outer_write_abstains_for_omitted_and_undefined_arguments() {
    let expected: String =
        eval_capture_node(DEFAULT_WRITE_CAPTURE).expect("lowered input must evaluate in Node");
    assert_eq!(expected, "11\u{1}11");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(DEFAULT_WRITE_CAPTURE);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("function read(_ref = (value = { value: 11 }))"));
    assert_eq!(
        eval_capture_node(&recovered).expect("refused source must evaluate in Node"),
        expected
    );
}

const DUPLICATE_PARAMETER: &str = r"
function read(_ref = { value: 5 }, value) {
  var value = _ref.value;
  return value;
}
print(read(undefined, 99));
print(read({ value: 17 }, 99));
";

#[test]
fn extracted_local_colliding_with_another_parameter_is_left_intact() {
    let expected: String =
        eval_capture_node(DUPLICATE_PARAMETER).expect("lowered input must evaluate in Node");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(DUPLICATE_PARAMETER);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("function read(_ref = { value: 5 }, value)"));
    assert_eq!(
        eval_capture_node(&recovered).expect("refused source must evaluate in Node"),
        expected
    );
}

const GETTER_ORDER: &str = r#"
var trace = [];
var input = { get value() { trace.push("getter"); return 7; } };
function read(_ref) {
  trace.push("before");
  var value = _ref.value;
  return value;
}
print(read(input));
print(trace.join(","));
"#;

#[test]
fn extraction_after_an_executable_statement_is_left_intact() {
    let expected: String = eval_capture(GETTER_ORDER).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(GETTER_ORDER);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("trace.push(\"before\")"));
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
}

const LATER_DEFAULT_ORDER: &str = r#"
var t = [];
var o = { get value() { t.push("getter"); return 7; } };
function f(_ref, x = (t.push("default"), 0)) {
  var value = _ref.value;
  return value;
}
f(o);
print(t.join(","));
"#;

#[test]
fn later_default_parameter_keeps_default_before_extracted_getter() {
    let expected: String =
        eval_capture_node(LATER_DEFAULT_ORDER).expect("lowered input must evaluate in Node");
    assert_eq!(expected, "default,getter");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(LATER_DEFAULT_ORDER);
    let actual: String =
        eval_capture_node(&recovered).expect("recovered source must evaluate in Node");
    assert_eq!(actual, expected, "recovered source:\n{recovered}");
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("function f(_ref, x = (t.push(\"default\"), 0))"));
}

const COMMENTED_DEFAULT: &str = r"
function read(_ref /* keep-default */ = { value: 5 }) {
  var value = _ref.value;
  return value;
}
print(read());
";

#[test]
fn comment_inside_assignment_parameter_causes_byte_preserving_refusal() {
    let expected: String = eval_capture(COMMENTED_DEFAULT).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(COMMENTED_DEFAULT);
    assert_eq!(stats.object_params_restructured, 0);
    assert!(recovered.contains("/* keep-default */"));
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
}
