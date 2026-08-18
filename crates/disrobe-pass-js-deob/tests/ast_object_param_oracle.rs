#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstPipeline, AstRuleId, AstUnminifyStats, unminify_ast};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

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
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput =
        run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE).ok()??;
    (output.exit_code == Some(0)).then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn assert_node_equivalent(input: &str, recovered: &str) {
    let expected: String = eval_capture_node(input).expect("input must evaluate in Node");
    let actual: String = eval_capture_node(recovered)
        .unwrap_or_else(|| panic!("recovered source must evaluate in Node:\n{recovered}"));
    assert_eq!(actual, expected, "recovered source:\n{recovered}");
}

fn unminify_object_param(input: &str) -> (String, AstUnminifyStats) {
    AstPipeline::default()
        .with_rule(AstRuleId::AliasInline, false)
        .with_rule(AstRuleId::DefaultParam, false)
        .with_rule(AstRuleId::VarToBlock, false)
        .run(input)
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

const RAW_DEFAULTED_OBJECT: &str = r#"
var trace = [];
var fallback = function() {
  trace.push("default");
  return { get value() { trace.push("default-getter"); return 11; } };
};
function read() {
  var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : fallback();
  var value = _ref.value;
  return value;
}
print(read());
print(trace.join(","));
trace.length = 0;
print(read(undefined));
print(trace.join(","));
trace.length = 0;
print(read({ get value() { trace.push("explicit-getter"); return 17; } }));
print(trace.join(","));
"#;

#[test]
fn raw_babel_defaulted_object_scaffold_recovers_end_to_end() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(RAW_DEFAULTED_OBJECT);
    assert_eq!(stats.object_params_restructured, 1, "source:\n{recovered}");
    assert_eq!(stats.default_params_recovered, 0, "source:\n{recovered}");
    assert!(
        recovered.contains("function read({ value } = fallback())"),
        "source:\n{recovered}"
    );
    assert!(!recovered.contains("arguments"), "source:\n{recovered}");
    assert!(!recovered.contains("_ref"), "source:\n{recovered}");
    assert_node_equivalent(RAW_DEFAULTED_OBJECT, &recovered);

    let (second, second_stats): (String, AstUnminifyStats) = unminify_ast(RAW_DEFAULTED_OBJECT);
    assert_eq!(second, recovered);
    assert_eq!(second_stats.object_params_restructured, 1);
}

const RAW_DEFAULTED_AFTER_PLAIN_PARAMETER: &str = r#"
var outer = { value: 5 };
var writes = 0;
function read(prefix) {
  var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : (writes++, outer);
  var value = _ref.value;
  return prefix + value;
}
print(read("a"));
print(read("b", undefined));
print(read("c", { value: 9 }));
print(writes);
"#;

#[test]
fn raw_scaffold_preserves_safe_outer_read_and_write_captures() {
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(RAW_DEFAULTED_AFTER_PLAIN_PARAMETER);
    assert_eq!(stats.object_params_restructured, 1, "source:\n{recovered}");
    assert!(
        recovered.contains("function read(prefix, { value } = (writes++, outer))"),
        "source:\n{recovered}"
    );
    assert_node_equivalent(RAW_DEFAULTED_AFTER_PLAIN_PARAMETER, &recovered);
}

#[test]
fn raw_scaffold_preserves_an_existing_trailing_parameter_comma() {
    let source: &str = r#"
function read(prefix,) {
  var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : { value: 5 };
  var value = _ref.value;
  return prefix + value;
}
print(read("a"));
print(read("b", { value: 9 }));
"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.object_params_restructured, 1, "source:\n{recovered}");
    assert!(
        recovered.contains("function read(prefix, { value } = { value: 5 })"),
        "source:\n{recovered}"
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn raw_scaffold_refuses_duplicate_plain_parameters_before_adding_a_default() {
    let source: &str = r#"
function read(prefix, prefix) {
  var _ref = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : { value: 5 };
  var value = _ref.value;
  return prefix + value;
}
print(read("a", "b"));
print(read("a", "b", { value: 9 }));
"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert_eq!(recovered, source);
    assert_node_equivalent(source, &recovered);
}

#[test]
fn raw_scaffold_refuses_semantic_near_misses_byte_for_byte() {
    let sources: [&str; 16] = [
        "function f() { side(); var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return arguments.length + x; }",
        "function f() { var _ref = arguments.length >= 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 1 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] != undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[1] : {}; var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; side(); var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return _ref; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; _ref = {}; return x; }",
        "function f(value) { var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {}; var value = _ref.value; return value; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var value = _ref.value; var value; return value; }",
        "function f(x = side()) { var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {}; var value = _ref.value; return value; }",
        "function f(undefined) { var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {}; var value = _ref.value; return value; }",
        "function f() { var _ref /* keep */ = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "var arguments = [{ x: 1 }]; function f() { var arguments; var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; }",
        "var f = () => { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return x; };",
    ];
    for source in sources {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
        assert_eq!(
            stats.object_params_restructured, 0,
            "input:\n{source}\noutput:\n{recovered}"
        );
        assert_eq!(recovered, source);
    }
}

#[test]
fn raw_scaffold_refuses_defaults_whose_binding_resolution_would_change() {
    let sources: [&str; 3] = [
        "var value = { value: 5 }; function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : value; var value = _ref.value; return value; }",
        "var value; function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : (value = { value: 5 }); var value = _ref.value; return value; }",
        "var fallback = function() { return { value: 5 }; }; function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : fallback(); var value = _ref.value; function fallback() { return { value: 7 }; } return value; }",
    ];
    for source in sources {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
        assert_eq!(
            stats.object_params_restructured, 0,
            "input:\n{source}\noutput:\n{recovered}"
        );
        assert_eq!(recovered, source);
    }
}

#[test]
fn raw_scaffold_refuses_eval_and_arrow_capture_hazards() {
    let sources: [&str; 3] = [
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : eval('({x: 1})'); var x = _ref.x; return x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return (() => arguments.length)() + x; }",
        "function f() { var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {}; var x = _ref.x; return (() => _ref.x)(); }",
    ];
    for source in sources {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
        assert_eq!(
            stats.object_params_restructured, 0,
            "input:\n{source}\noutput:\n{recovered}"
        );
        assert_eq!(recovered, source);
    }
}

const NESTED_OBJECT_LOWERED: &str = r#"
var trace = [];
var input = {
  get user() {
    trace.push("user");
    return {
      get name() { trace.push("name"); return "Ada"; },
      get score() { trace.push("score"); return 41; }
    };
  }
};
function read(_ref) {
  let _ref$user = _ref.user,
    name = _ref$user.name,
    score = _ref$user.score;
  return name + ":" + score;
}
print(read(input));
print(trace.join(","));
"#;

const NESTED_OBJECT_DEVELOPER: &str = r#"
var trace = [];
var input = {
  get user() {
    trace.push("user");
    return {
      get name() { trace.push("name"); return "Ada"; },
      get score() { trace.push("score"); return 41; }
    };
  }
};
function read({ user: { name, score } }) {
  return name + ":" + score;
}
print(read(input));
print(trace.join(","));
"#;

#[test]
fn babel_nested_object_parameter_recovers_with_getter_order() {
    assert_faithful_input(
        "nested object",
        NESTED_OBJECT_DEVELOPER,
        NESTED_OBJECT_LOWERED,
    );
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_object_param(NESTED_OBJECT_LOWERED);
    assert_eq!(stats.object_params_restructured, 1, "source:\n{recovered}");
    assert!(
        recovered.contains("function read({ user: { name, score } })"),
        "the nested synthetic temporary must become a nested binding pattern:\n{recovered}"
    );
    assert!(
        !recovered.contains("_ref"),
        "both synthetic bindings must be removed:\n{recovered}"
    );
    assert_recovered_equivalent("nested object", NESTED_OBJECT_DEVELOPER, &recovered);
    assert_node_equivalent(NESTED_OBJECT_LOWERED, &recovered);

    let (second, second_stats): (String, AstUnminifyStats) =
        unminify_object_param(NESTED_OBJECT_LOWERED);
    assert_eq!(second, recovered);
    assert_eq!(second_stats.object_params_restructured, 1);
}

#[test]
fn nested_temporary_used_after_extraction_is_left_intact() {
    let source: &str = r#"
function read(_ref) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return name + ":" + Object.keys(_ref$user).length;
}
print(read({ user: { name: "Ada", score: 41 } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn nested_field_captured_by_parameter_default_is_left_intact() {
    let source: &str = r#"
var name = { user: { name: "outer" } };
function read(_ref = name) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return name;
}
print(read());
print(read({ user: { name: "given" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn immutable_nested_extraction_is_left_intact() {
    let source: &str = r#"
function read(_ref) {
  const _ref$user = _ref.user,
    name = _ref$user.name;
  try {
    name = "changed";
    return name;
  } catch (error) {
    return error.constructor.name + ":" + name;
  }
}
print(read({ user: { name: "Ada" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "TypeError:Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(
        recovered.contains("const _ref$user"),
        "source:\n{recovered}"
    );
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn earlier_parameter_default_that_reads_a_nested_field_name_is_left_intact() {
    let source: &str = r#"
var name = "outer";
function read(prefix = name, _ref) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return prefix + ":" + name;
}
print(read(undefined, { user: { name: "Ada" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "outer:Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn nested_temporary_observed_by_direct_eval_is_left_intact() {
    let source: &str = r#"
function read(_ref) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return eval("_ref$user.name") + ":" + name;
}
print(read({ user: { name: "Ada" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "Ada:Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn generator_nested_extraction_is_left_intact() {
    let source: &str = r#"
var trace = [];
var input = {
  get user() {
    trace.push("user");
    return { get name() { trace.push("name"); return "Ada"; } };
  }
};
function* read(_ref) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  yield name;
}
var iterator = read(input);
print(trace.join(","));
print(iterator.next().value);
print(trace.join(","));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "\u{1}Ada\u{1}user,name");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn strict_directive_nested_extraction_is_left_intact() {
    let source: &str = r#"
function read(_ref) {
  "use strict";
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return name;
}
print(read({ user: { name: "Ada" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

const TYPESCRIPT_5_9_3_ARRAY_PARAM_ES5: &str = r#""use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sumPair = sumPair;
function sumPair(_a) {
    var left = _a[0], right = _a[1];
    return left + right;
}
print(sumPair([17, 25]));
"#;

#[test]
fn typescript_5_9_3_direct_index_array_parameter_recovers() {
    let expected: String = eval_capture_node(TYPESCRIPT_5_9_3_ARRAY_PARAM_ES5)
        .expect("the pinned TypeScript 5.9.3 ES5 output must execute in Node");
    assert_eq!(expected, "42");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(TYPESCRIPT_5_9_3_ARRAY_PARAM_ES5);
    assert_eq!(
        stats.object_params_restructured, 1,
        "the pinned TypeScript direct-index scaffold must recover exactly once:\n{recovered}"
    );
    assert!(
        recovered.contains("function sumPair([left, right])"),
        "consecutive direct indices must become the array binding parameter:\n{recovered}"
    );
    assert!(
        !recovered.contains("_a["),
        "the recovered body must not retain the synthetic direct-index accesses:\n{recovered}"
    );
    assert_node_equivalent(TYPESCRIPT_5_9_3_ARRAY_PARAM_ES5, &recovered);
}

#[test]
fn direct_index_array_parameter_recovery_is_byte_deterministic() {
    let source: &str = "function pair(_a) { var first = _a[0], renamed = _a[1]; return first + renamed; } print(pair([19, 23]));";
    let (first, first_stats): (String, AstUnminifyStats) = unminify_object_param(source);
    let (second, second_stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(first, second);
    assert_eq!(first_stats.object_params_restructured, 1);
    assert_eq!(
        first_stats.object_params_restructured,
        second_stats.object_params_restructured
    );
    assert!(
        first.contains("function pair([first, renamed])"),
        "source:\n{first}"
    );
    assert_node_equivalent(source, &first);
}

#[test]
fn direct_index_array_parameter_refuses_preceding_types_and_optional_parameters() {
    let cases: [&str; 2] = [
        "function f(prefix: number, _a) { var first = _a[0], second = _a[1]; return prefix + first + second; }",
        "function f(prefix?: number, _a) { var first = _a[0], second = _a[1]; return (prefix ?? 0) + first + second; }",
    ];
    for source in cases {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
        assert_eq!(
            stats.object_params_restructured, 0,
            "a preceding non-plain parameter must block recovery:\n{recovered}"
        );
        assert!(
            recovered.contains("_a[0]") && recovered.contains("_a[1]"),
            "a refused direct-index scaffold must remain intact:\n{recovered}"
        );
    }
}

#[test]
fn direct_index_array_parameter_near_misses_abstain() {
    let cases: [&str; 8] = [
        "function f(_a) { var first = _a[0], third = _a[2]; return first + third; } print(f([1, 2, 3]));",
        "function f(_a) { var second = _a[1], first = _a[0]; return first + second; } print(f([1, 2]));",
        "function f(_a = [1, 2]) { var first = _a[0], second = _a[1]; return first + second; } print(f());",
        "function f(_a) { var first = _a[0], second = _a[1]; return first + second + _a.length; } print(f([1, 2]));",
        "function f(_a) { let first = _a[0], second = _a[1]; return first + second; } print(f([1, 2]));",
        "function f(_a) { \"use strict\"; var first = _a[0], second = _a[1]; return first + second; } print(f([1, 2]));",
        "function f(_a) { var first = _a[0], second = _a[1]; return eval('first + second'); } print(f([1, 2]));",
        "function f(_b) { var first = _b[0], second = _b[1]; return first + second; } print(f([1, 2]));",
    ];
    for source in cases {
        let expected: String = eval_capture_node(source).expect("near-miss input must execute");
        let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
        assert_eq!(
            stats.object_params_restructured, 0,
            "an unproven direct-index parameter must abstain:\n{recovered}"
        );
        assert!(
            recovered.contains("function f(_"),
            "an unproven synthetic parameter must remain bound:\n{recovered}"
        );
        assert_eq!(
            eval_capture_node(&recovered).expect("refused output must execute"),
            expected
        );
    }
}

#[test]
fn parameter_eval_nested_extraction_is_left_intact() {
    let source: &str = r#"
var name = { user: { name: "Ada" } };
function read(_ref = eval("name")) {
  let _ref$user = _ref.user,
    name = _ref$user.name;
  return name;
}
print(read());
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}

#[test]
fn hoisted_function_colliding_with_nested_var_field_is_left_intact() {
    let source: &str = r#"
function read(_ref) {
  var _ref$user = _ref.user,
    name = _ref$user.name;
  function name() {}
  return typeof name + ":" + name;
}
print(read({ user: { name: "Ada" } }));
"#;
    let expected: String = eval_capture(source).expect("lowered input must evaluate");
    assert_eq!(expected, "string:Ada");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_object_param(source);
    assert_eq!(stats.object_params_restructured, 0, "source:\n{recovered}");
    assert!(recovered.contains("_ref$user"), "source:\n{recovered}");
    assert_eq!(
        eval_capture(&recovered).expect("refused source must evaluate"),
        expected
    );
    assert_node_equivalent(source, &recovered);
}
