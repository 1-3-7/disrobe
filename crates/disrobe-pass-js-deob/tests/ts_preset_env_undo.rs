#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::uninlined_format_args
)]

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::scratch::ScratchFile;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{PresetEnvUndoResult, undo_preset_env};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;
const BABEL_ASYNC_IMPORT: &str =
    "import babelAsync from '@babel/runtime/helpers/asyncToGenerator';";
const BABEL_ASYNC_RUNTIME: &str = r"function babelAsync(fn) {
  return function () {
    var self = this, args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);
      function step(key, arg) {
        try { var info = gen[key](arg); var value = info.value; } catch (e) { reject(e); return; }
        if (info.done) { resolve(value); } else { Promise.resolve(value).then(function (v) { step('next', v); }, function (e) { step('throw', e); }); }
      }
      step('next');
    });
  };
}";

fn with_babel_async_import(source: &str) -> String {
    format!("{BABEL_ASYNC_IMPORT}\n{source}")
}

fn executable_source(source: &str) -> String {
    source.replace(BABEL_ASYNC_IMPORT, BABEL_ASYNC_RUNTIME)
}

fn node_parse(source: &str) -> Result<(), String> {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_preset_env_async", "mjs").expect("scratch file");
    file.write_all(source.as_bytes()).expect("write source");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let args: [&OsStr; 2] = [OsStr::new("--check"), path.as_os_str()];
    let captured: CapturedOutput = run_captured(
        PathBuf::from("node").as_path(),
        &args,
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .expect("node is required for the preset-env syntax reference")
    .expect("node --check must finish within the timeout");
    if captured.exit_code == Some(0i32) {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&captured.stderr).into_owned())
}

fn node_capture(source: &str) -> String {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_preset_env_runtime", "mjs").expect("scratch file");
    file.write_all(source.as_bytes()).expect("write source");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let args: [&OsStr; 1] = [path.as_os_str()];
    let captured: CapturedOutput = run_captured(
        PathBuf::from("node").as_path(),
        &args,
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .expect("node is required for the preset-env runtime reference")
    .expect("node runtime reference must finish within the timeout");
    assert_eq!(
        captured.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    String::from_utf8(captured.stdout)
        .expect("node runtime output is utf-8")
        .trim()
        .to_owned()
}

fn assert_node_runtime_preserved(source: &str, expected: &str) {
    assert_eq!(node_capture(source), expected);
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert!(result.helpers_removed.is_empty());
    assert_eq!(result.spreads_restored, 0);
    assert_eq!(result.classes_restored, 0);
    assert_eq!(result.rewritten, source);
    assert_eq!(node_capture(&result.rewritten), expected);
}

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
    runtime.set_loop_iteration_limit(2_000_000);
    runtime.set_recursion_limit(1_500);
    runtime.set_stack_size_limit(50_000);
    let executable: String = executable_source(program);
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{executable}"
    );
    let _: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    context.run_jobs();
    let value: boa_engine::JsValue = context
        .eval(Source::from_bytes("__out.join('\\u0001');"))
        .ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

#[test]
fn preserves_unverified_spread_helper_calls() {
    let src: &str = "var combined = [].concat(_toConsumableArray(list), [42]);";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert_eq!(r.spreads_restored, 0);
    assert_eq!(r.rewritten, src);
}

#[test]
fn preserves_unverified_class_call_checks() {
    let src: &str = "function Cat() { _classCallCheck(this, Cat); this.name = 'mu'; }";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert_eq!(r.classes_restored, 0);
    assert_eq!(r.rewritten, src);
}

#[test]
fn helper_path_text_does_not_quarantine_preset_env_recovery() {
    let source: &str = r#"const marker = "@babel/runtime/helpers/asyncToGenerator";
const value = { field: 7 };
var optional = (value === null || value === void 0) ? void 0 : value.field;
var fallback = value !== null && value !== void 0 ? value : 42;"#;
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 1, "{result:?}");
    assert!(result.rewritten.contains("value?.field"));
    assert!(result.rewritten.contains("value ?? 42"));
}

#[test]
fn unused_babel_helper_import_does_not_quarantine_preset_env_recovery() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const value = { field: 7 };
var optional = (value === null || value === void 0) ? void 0 : value.field;
var fallback = value !== null && value !== void 0 ? value : 42;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 1, "{result:?}");
    assert!(result.rewritten.contains("value?.field"));
    assert!(result.rewritten.contains("value ?? 42"));
}

#[test]
fn escaped_babel_helper_import_quarantines_wrapper_rewrites() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGener\u0061tor';
function _classCallCheck(current, constructor) {
  return _classCallCheckAsync.apply(this, arguments);
}
function _classCallCheckAsync() {
  _classCallCheckAsync = babelAsync(function* (current, constructor) {
    return yield Promise.resolve(constructor.name);
  });
  return _classCallCheckAsync.apply(this, arguments);
}
function Example() { _classCallCheck(this, Example); }";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source);
    assert_eq!(result.classes_restored, 0);
    assert_eq!(result.async_restored, 0);
}

#[test]
fn shadowed_require_with_babel_helper_path_quarantines_preset_env_recovery() {
    let source: &str = r"function require(path) { return path; }
const helperPath = require('@babel/runtime/helpers/asyncToGenerator');
const value = { field: 7 };
var optional = (value === null || value === void 0) ? void 0 : value.field;
var fallback = value !== null && value !== void 0 ? value : 42;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 0, "{result:?}");
    assert_eq!(result.rewritten, source);
}

#[test]
fn suffixed_babel_helper_import_preserves_scoped_wrapper_helpers() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator.js';
function run() { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* () { return yield Promise.resolve(1); });
  return _run.apply(this, arguments);
}
function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) throw new TypeError('invalid');
}
function Example() { _classCallCheck(this, Example); }";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source, "{result:?}");
    assert!(result.helpers_removed.is_empty(), "{result:?}");
    assert_eq!(result.classes_restored, 0, "{result:?}");
    assert_eq!(result.async_restored, 0, "{result:?}");
}

#[test]
fn scoped_babel_wrapper_allows_disjoint_preset_env_expressions() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* () { return yield Promise.resolve(1); });
  return _run.apply(this, arguments);
}
const value = { field: 7 };
var optional = (value === null || value === void 0) ? void 0 : value.field;
var fallback = value !== null && value !== void 0 ? value : 42;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 1, "{result:?}");
    assert!(result.rewritten.contains("babelAsync(function*"));
    assert!(result.rewritten.contains("value?.field"));
    assert!(result.rewritten.contains("value ?? 42"));
}

#[test]
fn scoped_babel_wrapper_rejects_mixed_optional_outcomes_atomically() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const value = { field: 7 };
function run() { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* () {
    var inside = (value === null || value === void 0) ? void 0 : value.field;
    return inside;
  });
  return _run.apply(this, arguments);
}
var outside = (value === null || value === void 0) ? void 0 : value.field;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0, "{result:?}");
    assert_eq!(result.rewritten, source);
}

#[test]
fn scoped_babel_wrapper_rejects_mixed_nullish_outcomes_atomically() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const value = { field: 7 };
function run() { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* () {
    var inside = value !== null && value !== void 0 ? value : 42;
    return inside;
  });
  return _run.apply(this, arguments);
}
var outside = value !== null && value !== void 0 ? value : 42;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.nullish_coalesce_restored, 0, "{result:?}");
    assert_eq!(result.rewritten, source);
}

#[test]
fn scoped_babel_wrapper_recomputes_spans_before_nullish_recovery() {
    let source: &str = r"import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const veryLongDisjointValueIdentifierForStaleSpanControl = { field: 7 };
var optional = (veryLongDisjointValueIdentifierForStaleSpanControl === null || veryLongDisjointValueIdentifierForStaleSpanControl === void 0) ? void 0 : veryLongDisjointValueIdentifierForStaleSpanControl.field;
const helper = babelAsync(function* () { const x = 7; var inside = x !== null && x !== void 0 ? x : 42; return inside; });";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 0, "{result:?}");
    assert!(
        result
            .rewritten
            .contains("veryLongDisjointValueIdentifierForStaleSpanControl?.field")
    );
    assert!(
        result
            .rewritten
            .contains("var inside = x !== null && x !== void 0 ? x : 42"),
        "the protected nullish candidate must remain lowered:\n{}",
        result.rewritten
    );
}

#[test]
fn exact_babel_helper_specifier_call_quarantines_preset_env_expressions() {
    let source: &str = r"const babelAsync = require('@babel/runtime/helpers/asyncToGenerator');
const value = { field: 7 };
var optional = (value === null || value === void 0) ? void 0 : value.field;
var fallback = value !== null && value !== void 0 ? value : 42;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
}

#[test]
fn preset_env_public_restored_helper_like_name_remains_runnable() {
    let lowered: String = with_babel_async_import(
        r"function _typeof(n) {
  return _typeofAsync.apply(this, arguments);
}
function _typeofAsync() {
  _typeofAsync = babelAsync(function* (n) {
    return yield Promise.resolve(n + 2);
  });
  return _typeofAsync.apply(this, arguments);
}
_typeof(40).then(function(v) { print(v); });",
    );
    assert_eq!(
        eval_capture(&lowered).expect("lowered helper-name fixture evaluates"),
        "42"
    );
    let result: PresetEnvUndoResult = undo_preset_env(&lowered);
    assert_eq!(result.async_restored, 0);
    assert!(!result.helpers_removed.contains_key("_typeof"));
    assert!(result.rewritten.contains("function _typeof"));
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the restored helper-like public name:\n{stderr}\n{}",
            result.rewritten
        )
    });
    assert_eq!(
        eval_capture(&result.rewritten).unwrap_or_else(|| panic!(
            "restored helper-like name must evaluate:\n{}",
            result.rewritten
        )),
        "42"
    );
}

#[test]
fn preset_env_public_preserves_restored_spread_helper_calls() {
    let lowered: String = with_babel_async_import(
        r"function _toConsumableArray(value) {
  return _toConsumableArrayAsync.apply(this, arguments);
}
function _toConsumableArrayAsync() {
  _toConsumableArrayAsync = babelAsync(function* (value) {
    return yield Promise.resolve(value + 1);
  });
  return _toConsumableArrayAsync.apply(this, arguments);
}
var input = 1;
Promise.all([_toConsumableArray(input)]).then(function(v) { print(v[0]); });",
    );
    assert_eq!(
        eval_capture(&lowered).expect("restored spread-helper fixture evaluates"),
        "2"
    );
    let result: PresetEnvUndoResult = undo_preset_env(&lowered);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.spreads_restored, 0);
    assert!(!result.helpers_removed.contains_key("_toConsumableArray"));
    assert!(result.rewritten.contains("_toConsumableArray(input)"));
    assert_eq!(
        eval_capture(&result.rewritten).unwrap_or_else(|| panic!(
            "restored spread-helper call must evaluate:\n{}",
            result.rewritten
        )),
        "2"
    );
}

#[test]
fn preset_env_public_preserves_restored_class_helper_calls() {
    let lowered: String = with_babel_async_import(
        r"function _classCallCheck(current, constructor) {
  return _classCallCheckAsync.apply(this, arguments);
}
function _classCallCheckAsync() {
  _classCallCheckAsync = babelAsync(function* (current, constructor) {
    yield Promise.resolve(current);
    print(constructor.name);
  });
  return _classCallCheckAsync.apply(this, arguments);
}
function Example() {}
function invoke() { _classCallCheck(this, Example); }
invoke();",
    );
    assert_eq!(
        eval_capture(&lowered).expect("restored class-helper fixture evaluates"),
        "Example"
    );
    let result: PresetEnvUndoResult = undo_preset_env(&lowered);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.classes_restored, 0);
    assert!(!result.helpers_removed.contains_key("_classCallCheck"));
    assert!(result.rewritten.contains("_classCallCheck(this, Example)"));
    assert_eq!(
        eval_capture(&result.rewritten).unwrap_or_else(|| panic!(
            "restored class-helper call must evaluate:\n{}",
            result.rewritten
        )),
        "Example"
    );
}

#[test]
fn preset_env_public_preserves_wrapper_pair_comments() {
    let source: String = with_babel_async_import(
        r"function run() {
  return _run.apply(this, arguments);
}
/*! retained-wrapper-license */
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(42);
  });
  return _run.apply(this, arguments);
}
run().then(function(v) { print(v); });",
    );
    assert_eq!(
        eval_capture(&source).expect("commented wrapper fixture evaluates"),
        "42"
    );
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert!(result.rewritten.contains("/*! retained-wrapper-license */"));
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the comment-preserving output:\n{stderr}\n{}",
            result.rewritten
        )
    });
    assert_eq!(
        eval_capture(&result.rewritten).unwrap_or_else(|| panic!(
            "comment-preserving output must evaluate:\n{}",
            result.rewritten
        )),
        "42"
    );
}

#[test]
fn preset_env_public_rolls_back_invalid_followup_rewrites() {
    let lowered: String = with_babel_async_import(
        r"const _toConsumableArray = function(values) { return values.slice(); };
function countValues(values) {
  return _countValues.apply(this, arguments);
}
function _countValues() {
  _countValues = babelAsync(function* (values) {
    var copied = _toConsumableArray(values);
    return yield Promise.resolve(copied.length);
  });
  return _countValues.apply(this, arguments);
}
countValues([1, 2]).then(function(v) { print(v); });",
    );
    assert_eq!(
        eval_capture(&lowered).expect("followup-rewrite fixture evaluates"),
        "2"
    );
    let result: PresetEnvUndoResult = undo_preset_env(&lowered);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.spreads_restored, 0);
    assert!(result.rewritten.contains("_toConsumableArray(values)"));
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the transactional preset-env output:\n{stderr}\n{}",
            result.rewritten
        )
    });
    assert_eq!(
        eval_capture(&result.rewritten)
            .unwrap_or_else(|| panic!("transactional output must evaluate:\n{}", result.rewritten)),
        "2"
    );
}

#[test]
fn preset_env_public_rolls_back_invalid_spread_without_async() {
    let source: &str = "var copied = _toConsumableArray(values);";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source);
    assert_eq!(result.spreads_restored, 0);
    assert_eq!(result.async_restored, 0);
}

#[test]
fn direct_async_helper_assignment_is_preserved() {
    let source: String =
        with_babel_async_import("var fetch = babelAsync(function* () { yield 1; });");
    let r: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(r.async_restored, 0);
    assert_eq!(r.rewritten, source);
    assert!(!r.helpers_removed.contains_key("_asyncToGenerator"));
    node_parse(&r.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the preserved direct helper assignment:\n{stderr}\n{}",
            r.rewritten
        )
    });
}

#[test]
fn direct_async_helper_assignment_keeps_runtime_behavior_under_boa() {
    let original: &str = r"
async function fetch(n) {
  return await Promise.resolve(n + 2);
}
fetch(40).then(function(v) { print(v); });
";
    let lowered: String = with_babel_async_import(
        r"var fetch = babelAsync(function* (n) {
  return yield Promise.resolve(n + 2);
});
fetch(40).then(function(v) { print(v); });
",
    );
    let expected: String = eval_capture(original).expect("original async fixture evaluates");
    assert_eq!(expected, "42");
    assert_eq!(
        eval_capture(&lowered).expect("lowered async fixture evaluates"),
        expected
    );
    let result: PresetEnvUndoResult = undo_preset_env(&lowered);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, lowered);
    assert_eq!(
        eval_capture(&result.rewritten).unwrap_or_else(|| panic!(
            "preserved direct helper assignment must evaluate:\n{}",
            result.rewritten
        )),
        expected
    );
}

#[test]
fn direct_generator_default_parameter_is_preserved() {
    let source: String = with_babel_async_import(
        r"function create() { return 41; }
var fetch = babelAsync(function* (value = create()) {
  return yield Promise.resolve(value + 1);
});
fetch().then(function(v) { print(v); });",
    );
    let expected: String =
        eval_capture(&source).expect("lowered default-parameter fixture evaluates");
    assert_eq!(expected, "42");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the preserved default-parameter helper assignment:\n{stderr}\n{}",
            result.rewritten
        )
    });
    assert_eq!(
        eval_capture(&result.rewritten).expect("preserved default-parameter fixture evaluates"),
        expected
    );
}

#[test]
fn direct_generator_yield_argument_precedence_is_preserved() {
    let source: String = with_babel_async_import(
        r"var fetch = babelAsync(function* () {
  return yield Promise.resolve(1) + 2;
});",
    );
    let runtime_source: String = format!("{source}\nfetch().then(function(v) {{ print(v); }});");
    let expected: String =
        eval_capture(&runtime_source).expect("precedence fixture evaluates before restoration");
    assert!(!expected.is_empty());
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
    let recovered_runtime: String = format!(
        "{}\nfetch().then(function(v) {{ print(v); }});",
        result.rewritten
    );
    assert_eq!(
        eval_capture(&recovered_runtime).expect("precedence fixture evaluates after restoration"),
        expected
    );
}

#[test]
fn delegated_yield_and_its_live_helper_are_preserved() {
    let source: String = with_babel_async_import(
        r"var delegated = babelAsync(function* () { yield* [1, 2]; });
delegated().then(function(v) { print(v); });",
    );
    let expected: String = eval_capture(&source).expect("delegated-yield fixture evaluates");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert!(!result.helpers_removed.contains_key("_asyncToGenerator"));
    assert_eq!(result.rewritten, source);
    assert_eq!(
        eval_capture(&result.rewritten).expect("preserved delegated-yield fixture evaluates"),
        expected
    );
}

#[test]
fn direct_assignments_with_supported_and_delegated_yields_are_preserved() {
    let source: String = with_babel_async_import(
        r"var supported = babelAsync(function* () { return yield Promise.resolve(1); });
var delegated = babelAsync(function* () { return yield* [2]; });
supported().then(function(v) { print(v); });
delegated().then(function(v) { print(v); });",
    );
    let expected: String = eval_capture(&source).expect("mixed async fixture evaluates");
    assert!(!expected.is_empty());
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert!(!result.helpers_removed.contains_key("_asyncToGenerator"));
    assert_eq!(result.rewritten, source);
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the preserved direct helper assignments:\n{stderr}\n{}",
            result.rewritten
        )
    });
    assert_eq!(
        eval_capture(&result.rewritten).expect("preserved direct helper assignments evaluate"),
        expected
    );
}

#[test]
fn wrapper_with_extra_side_effects_is_preserved() {
    let source: String = with_babel_async_import(
        r"function run() { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* () { yield 1; });
  record();
  return _run.apply(this, arguments);
}",
    );
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn non_generator_async_helper_argument_is_preserved() {
    let source: String =
        with_babel_async_import("var fetch = babelAsync(function () { return 1; });");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn named_generator_self_binding_is_preserved() {
    let source: String =
        with_babel_async_import("var fetch = babelAsync(function* named() { return named; });");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn unknown_and_shadowed_helper_bindings_are_preserved() {
    let unknown: &str = r"function _asyncToGenerator(fn) { return fn; }
var fetch = _asyncToGenerator(function* () { yield 1; });";
    let unknown_result: PresetEnvUndoResult = undo_preset_env(unknown);
    assert_eq!(unknown_result.async_restored, 0);
    assert_eq!(unknown_result.rewritten, unknown);
    assert!(unknown_result.helpers_removed.is_empty());

    let shadowed: &str = r"function outer(babelAsync) {
  var fetch = babelAsync(function* () { yield 1; });
  return fetch;
}";
    let shadowed_result: PresetEnvUndoResult = undo_preset_env(shadowed);
    assert_eq!(shadowed_result.async_restored, 0);
    assert_eq!(shadowed_result.rewritten, shadowed);

    let mutated: String = with_babel_async_import(
        "babelAsync = custom; var fetch = babelAsync(function* () { yield 1; });",
    );
    let mutated_result: PresetEnvUndoResult = undo_preset_env(&mutated);
    assert_eq!(mutated_result.async_restored, 0);
    assert_eq!(mutated_result.rewritten, mutated);
}

#[test]
fn named_babel_helper_import_is_preserved() {
    let source: &str = r"import { default as babelAsync } from '@babel/runtime/helpers/asyncToGenerator';
var fetch = babelAsync(function* () { yield 1; });";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn namespace_babel_helper_import_is_preserved() {
    let source: &str = r"import * as babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var fetch = babelAsync(function* () { yield 1; });";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn direct_generator_body_directive_is_preserved() {
    let source: String =
        with_babel_async_import("var fetch = babelAsync(function* () { 'use strict'; yield 1; });");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn unsafe_wrapper_signatures_and_directives_are_preserved() {
    let cases: [&str; 7] = [
        r"function run(value = record()) { return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* (value) { yield value; }); return _run.apply(this, arguments); }",
        r"function run(...values) { return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* (...values) { yield values; }); return _run.apply(this, arguments); }",
        r"function run(a, b) { return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* (a) { yield a; }); return _run.apply(this, arguments); }",
        r"function run() { 'use strict'; return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* () { yield 1; }); return _run.apply(this, arguments); }",
        r"function run() { return _run.apply(this, arguments); }
function _run() { 'use strict'; _run = babelAsync(function* () { yield 1; }); return _run.apply(this, arguments); }",
        r"function run(value) { return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* (value = record()) { yield value; }); return _run.apply(this, arguments); }",
        r"function run() { return _run.apply(this, arguments); }
function _run() { _run = babelAsync(function* () { yield 1; }); return _run.apply(this, arguments); }
print(_run);",
    ];
    for candidate in cases {
        let source: String = with_babel_async_import(candidate);
        let result: PresetEnvUndoResult = undo_preset_env(&source);
        assert_eq!(result.async_restored, 0);
        assert_eq!(result.rewritten, source);
    }
}

#[test]
fn wrapper_shadow_of_helper_with_external_reference_is_preserved() {
    let source: String = with_babel_async_import(
        r"function run(_run) { return _run.apply(this, arguments); }
function _run() {
  _run = babelAsync(function* (_run) { return yield Promise.resolve(_run); });
  return _run.apply(this, arguments);
}
print(_run);",
    );
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn esm_helper_alias_and_nested_expression_yields_are_preserved() {
    let source: &str = r"import babelAsync2 from '@babel/runtime/helpers/esm/asyncToGenerator';
var fetch = babelAsync2(function* () {
  var result = { answer: yield Promise.resolve(42) };
    return result.answer;
});";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
    node_parse(&result.rewritten).unwrap_or_else(|stderr: String| {
        panic!(
            "Node rejected the preserved nested-expression helper assignment:\n{stderr}\n{}",
            result.rewritten
        )
    });
}

#[test]
fn invalid_async_candidate_rolls_back_with_zero_count() {
    let source: String =
        with_babel_async_import("var fetch = babelAsync(function* () { yield; });");
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn nested_yields_are_preserved() {
    let source: String = with_babel_async_import(
        "var fetch = babelAsync(function* () { return yield yield Promise.resolve(1); });",
    );
    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn restores_strict_identifier_optional_chain() {
    let src: &str =
        "const obj = {}; var v = (obj === null || obj === void 0) ? void 0 : obj.field;";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert_eq!(r.optional_chains_restored, 1, "{:?}", r);
    assert_eq!(r.nullish_coalesce_restored, 0);
    assert!(r.rewritten.contains("obj?.field"));
}

#[test]
fn restores_strict_identifier_nullish_coalescing() {
    let src: &str = "const val = 7; var x = (val !== null && val !== void 0 ? val : fallback);";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert_eq!(r.optional_chains_restored, 0);
    assert_eq!(r.nullish_coalesce_restored, 1);
    assert!(r.rewritten.contains("val ?? fallback"));
}

#[test]
fn preserves_global_accessor_repeated_reads() {
    let source: &str = r#"var optional_reads = 0;
Object.defineProperty(globalThis, "optionalValue", { get: function () { optional_reads += 1; return optional_reads === 1 ? { field: 7 } : void 0; } });
var nullish_reads = 0;
Object.defineProperty(globalThis, "nullishValue", { get: function () { nullish_reads += 1; return nullish_reads === 1 ? 7 : void 0; } });
var optional = (optionalValue === null || optionalValue === void 0) ? void 0 : optionalValue.field;
var nullish = nullishValue !== null && nullishValue !== void 0 ? nullishValue : 42;
print(String(optional) + ":" + optional_reads + ":" + nullish + ":" + nullish_reads);"#;
    let lowered_output: String = eval_capture(source).expect("lowered accessor fixture evaluates");
    assert_eq!(lowered_output, "undefined:2:42:2");

    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 0, "{result:?}");
    assert_eq!(result.rewritten, source);
    assert_eq!(
        eval_capture(&result.rewritten).expect("preserved accessor fixture evaluates"),
        lowered_output
    );
}

#[test]
fn preserves_root_var_global_accessor_repeated_reads() {
    let source: &str = "var rootValue; var result = (rootValue === null || rootValue === void 0) ? void 0 : rootValue.field; console.log(String(result) + ':' + reads);";
    let setup: &str = "var reads = 0; Object.defineProperty(globalThis, 'rootValue', { configurable: true, get: function () { reads += 1; return reads === 1 ? { field: 7 } : void 0; } });";
    let lowered_runtime: String = format!(
        "import vm from 'node:vm'; const context = vm.createContext({{ console }}); vm.runInContext({setup:?}, context); vm.runInContext({source:?}, context);"
    );
    let lowered_output: String = node_capture(&lowered_runtime);
    assert_eq!(lowered_output, "undefined:2");

    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0, "{result:?}");
    assert_eq!(result.rewritten, source);
    let restored_runtime: String = format!(
        "import vm from 'node:vm'; const context = vm.createContext({{ console }}); vm.runInContext({setup:?}, context); vm.runInContext({:?}, context);",
        result.rewritten
    );
    assert_eq!(node_capture(&restored_runtime), lowered_output);
}

#[test]
fn restores_root_const_repeated_reads() {
    let source: &str = "const optionalValue = { field: 7 }; const nullishValue = 7; var optional = (optionalValue === null || optionalValue === void 0) ? void 0 : optionalValue.field; var nullish = nullishValue !== null && nullishValue !== void 0 ? nullishValue : 42; print(optional + ':' + nullish);";
    let lowered_output: String = eval_capture(source).expect("lowered local fixture evaluates");
    assert_eq!(lowered_output, "7:7");

    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 1, "{result:?}");
    assert_eq!(
        eval_capture(&result.rewritten).expect("restored local fixture evaluates"),
        lowered_output
    );
}

#[test]
fn restores_mutated_function_local_repeated_reads() {
    let source: &str = "function read() { let value = { field: 7 }; value = { field: 9 }; var optional = (value === null || value === void 0) ? void 0 : value.field; var nullish = value !== null && value !== void 0 ? value : { field: 42 }; print(optional + ':' + nullish.field); } read();";
    let lowered_output: String =
        eval_capture(source).expect("lowered mutable-local fixture evaluates");
    assert_eq!(lowered_output, "9:9");

    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert_eq!(result.nullish_coalesce_restored, 1, "{result:?}");
    assert_eq!(
        eval_capture(&result.rewritten).expect("restored mutable-local fixture evaluates"),
        lowered_output
    );
}

#[test]
fn preserves_loose_optional_and_nullish_comparisons() {
    let source: &str = "var a = (obj == null || obj == void 0) ? void 0 : obj.field; var b = val != null && val != void 0 ? val : fallback;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn preserves_optional_and_nullish_text_in_literals_and_comments() {
    let source: &str = r#"var a = "(obj === null || obj === void 0) ? void 0 : obj.field";
/* val !== null && val !== void 0 ? val : fallback */
var b = "val !== null && val !== void 0 ? val : fallback";
var c = (kept === null || /* retained-optional */ kept === void 0) ? void 0 : kept.field;
var d = kept !== null && /* retained-nullish */ kept !== void 0 ? kept : fallback;"#;
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn preserves_strict_static_member_candidates() {
    let source: &str = "var a = (box.value === null || box.value === void 0) ? void 0 : box.value.field; var b = box.value !== null && box.value !== void 0 ? box.value : fallback;";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn preserves_undefined_identifier_checks() {
    let source: &str = "function read(undefined) { var a = (obj === null || obj === undefined) ? undefined : obj.field; var b = (obj === null || obj === void 0) ? undefined : obj.field; return val !== null && val !== undefined ? val : fallback; }";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn preserves_unverified_helper_function_definitions() {
    let src: &str = "function _classCallCheck(a, b) { if (!(a instanceof b)) throw 1; } var z = 0;";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(r.helpers_removed.is_empty());
    assert_eq!(r.rewritten, src);
}

#[test]
fn helper_shaped_string_and_template_text_are_preserved() {
    let source: &str = r#"var literal = "function _toConsumableArray(value) { return value; }";
var template = `template _toConsumableArray(items) and _classCallCheck(this, Example);`;
var callText = "_toConsumableArray(items)";
function _toConsumableArray(value) { return value; }
function Example() { _classCallCheck(this, Example); return literal + template + callText; }
var combined = [].concat(_toConsumableArray(items), [42]);"#;
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert!(result.helpers_removed.is_empty());
    assert_eq!(result.classes_restored, 0);
    assert_eq!(result.spreads_restored, 0);
    assert_eq!(result.rewritten, source);
}

#[test]
fn comment_separated_async_helper_guard_preserves_source() {
    let source: &str = "async /* retained */ function _classCallCheck(instance, constructor) { return instance; }\nfunction Example() { _classCallCheck(this, Example); return 7; }";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source);
    assert!(result.helpers_removed.is_empty());
    assert_eq!(result.classes_restored, 0);
}

#[test]
fn whitespace_separated_async_helper_guard_preserves_source() {
    let source: &str = "async\tfunction _classCallCheck(instance, constructor) { return instance; }\nfunction Example() { _classCallCheck(this, Example); return 7; }";
    let result: PresetEnvUndoResult = undo_preset_env(source);
    assert_eq!(result.rewritten, source);
    assert!(result.helpers_removed.is_empty());
    assert_eq!(result.classes_restored, 0);
}

#[test]
fn user_defined_typeof_helper_preserves_runtime() {
    let source: &str =
        "function _typeof(value) { return 'custom:' + value; }\nconsole.log(_typeof(1));";
    assert_node_runtime_preserved(source, "custom:1");
}

#[test]
fn user_defined_class_check_side_effect_preserves_runtime() {
    let source: &str = "const _classCallCheck = function () { console.log('called'); };\nfunction Example() { _classCallCheck(this, Example); }\nnew Example();";
    assert_node_runtime_preserved(source, "called");
}

#[test]
fn user_defined_consumable_array_concat_preserves_runtime() {
    let source: &str = "const _toConsumableArray = function (value) { return value; };\nconst values = [1, 2];\nvalues[Symbol.isConcatSpreadable] = false;\nconst result = [].concat(_toConsumableArray(values));\nconsole.log(String(result.length) + ':' + String(result[0] === values));";
    assert_node_runtime_preserved(source, "1:true");
}

#[test]
fn user_defined_consumable_array_nested_array_preserves_runtime() {
    let source: &str = "const _toConsumableArray = function (value) { return value; };\nconst values = [[1], [2]];\nconsole.log(JSON.stringify([].concat(_toConsumableArray(values))));";
    assert_node_runtime_preserved(source, "[[1],[2]]");
}

#[test]
fn class_call_check_without_new_preserves_runtime() {
    let source: &str = "function _classCallCheck(instance, constructor) { if (!(instance instanceof constructor)) throw new TypeError('called without new'); }\nfunction Example() { _classCallCheck(this, Example); return 7; }\ntry { Example(); console.log('returned'); } catch (error) { console.log(error.message); }";
    assert_node_runtime_preserved(source, "called without new");
}

#[test]
fn comment_bearing_helper_preserves_runtime() {
    let source: &str = "function _typeof(value) { /* retained */ return 'comment:' + value; }\nconsole.log(_typeof(1));";
    assert_node_runtime_preserved(source, "comment:1");
}
