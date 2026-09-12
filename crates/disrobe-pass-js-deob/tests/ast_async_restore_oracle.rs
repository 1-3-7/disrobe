#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsStr;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::scratch::ScratchFile;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{
    AstPipeline, AstRuleId, AstUnminifyStats, PresetEnvUndoResult, undo_preset_env, unminify_ast,
};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;
const BABEL_RUNTIME_VERSION: &str = "7.24.5";
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

fn executable_source(source: &str) -> String {
    source.replace(BABEL_ASYNC_IMPORT, BABEL_ASYNC_RUNTIME)
}

fn babel_async_helper() -> PathBuf {
    let root: PathBuf = std::env::var_os("DISROBE_BABEL_RUNTIME_ROOT")
        .map(PathBuf::from)
        .expect("DISROBE_BABEL_RUNTIME_ROOT must point at the pinned Babel runtime root");
    let package: PathBuf = root.join("@babel").join("runtime").join("package.json");
    let package_text: String = std::fs::read_to_string(&package)
        .unwrap_or_else(|error| panic!("read {}: {error}", package.display()));
    let package_value: serde_json::Value = serde_json::from_str(&package_text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", package.display()));
    assert_eq!(
        package_value
            .get("version")
            .and_then(serde_json::Value::as_str),
        Some(BABEL_RUNTIME_VERSION),
        "DISROBE_BABEL_RUNTIME_ROOT must contain @babel/runtime {BABEL_RUNTIME_VERSION}"
    );
    let helper: PathBuf = root
        .join("@babel")
        .join("runtime")
        .join("helpers")
        .join("asyncToGenerator.js");
    assert!(
        helper.is_file(),
        "DISROBE_BABEL_RUNTIME_ROOT does not contain @babel/runtime/helpers/asyncToGenerator.js: {}",
        helper.display()
    );
    helper
}

fn node_capture_babel_runtime(source: &str) -> String {
    let helper: PathBuf = babel_async_helper();
    let helper_src: String = serde_json::to_string(&helper.to_string_lossy())
        .expect("Babel helper path is JSON encodable");
    let executable: String = source.replace(
        BABEL_ASYNC_IMPORT,
        &format!("const babelAsync = require({helper_src});"),
    );
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_babel_async_identity", "cjs").expect("scratch file");
    file.write_all(executable.as_bytes())
        .expect("write Node reference source");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let args: [&OsStr; 1] = [path.as_os_str()];
    let captured: CapturedOutput = run_captured(
        PathBuf::from("node").as_path(),
        &args,
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .expect("node is required for the Babel async identity reference")
    .expect("Babel async identity reference must finish within the timeout");
    assert_eq!(
        captured.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    String::from_utf8(captured.stdout)
        .expect("Node runtime output is utf-8")
        .trim()
        .to_owned()
}

fn node_capture(source: &str) -> String {
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{source}\nprocess.stdout.write(__out.join('\\u0001'));"
    );
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_js_semantic_oracle", "cjs").expect("scratch file");
    file.write_all(harness.as_bytes())
        .expect("write Node reference source");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let args: [&OsStr; 1] = [path.as_os_str()];
    let captured: CapturedOutput = run_captured(
        PathBuf::from("node").as_path(),
        &args,
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .expect("node is required for the JavaScript semantic reference")
    .expect("JavaScript semantic reference must finish within the timeout");
    assert_eq!(
        captured.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    String::from_utf8(captured.stdout)
        .expect("Node runtime output is utf-8")
        .trim()
        .to_owned()
}

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
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

fn assert_direct_helper_assignment_preserved(label: &str, source: &str) -> String {
    let want: String =
        eval_capture(source).unwrap_or_else(|| panic!("{label}: source must evaluate"));
    assert!(!want.is_empty(), "{label}: source output must be non-empty");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.async_functions_restored, 0,
        "{label}: direct helper assignment must not be restored"
    );
    assert!(
        recovered.contains("babelAsync(function*"),
        "{label}: direct helper call must remain:\n{recovered}"
    );
    let have: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("{label}: recovered source must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, have,
        "{label}: recovered source changed behavior\n--want--\n{want}\n--got--\n{have}\n--src--\n{recovered}"
    );
    recovered
}

const INPUT_WRAPPER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function load(n) {
  return _load.apply(this, arguments);
}
function _load() {
  _load = babelAsync(function* (n) {
    var a = yield Promise.resolve(n);
    var b = yield Promise.resolve(a + 1);
    return a + b;
  });
  return _load.apply(this, arguments);
}
load(10).then(function(v){ print(v); });
";

#[test]
fn babel_async_to_generator_wrapper_pair_is_preserved() {
    let want: String = eval_capture(INPUT_WRAPPER).expect("Babel async wrapper fixture evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_WRAPPER);
    assert_eq!(
        stats.async_functions_restored, 0,
        "default recovery must not replace the Babel wrapper pair"
    );
    assert!(
        recovered.contains("babelAsync(function*") && recovered.contains("function _load"),
        "the Babel wrapper pair must remain:\n{recovered}"
    );
    assert!(
        !recovered.contains("async function load(n)"),
        "native async output must not be emitted:\n{recovered}"
    );
    assert_eq!(
        eval_capture(&recovered).expect("preserved Babel wrapper fixture evaluates"),
        want
    );
}

#[test]
fn optional_member_call_preserves_missing_method_error() {
    let source: &str = r"const object = {};
function run() {
  var result = (object === null || object === void 0) ? void 0 : object.method();
  print(String(result));
}
try { run(); } catch (error) { print(error.name); }";
    let expected: String = node_capture(source);
    assert_eq!(expected, "TypeError");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{stats:?}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

#[test]
fn generic_expression_recovery_rejects_global_getter_reads() {
    let source: &str = r"var optionalReads = 0;
Object.defineProperty(globalThis, 'optionalValue', { get: function () { optionalReads += 1; return optionalReads === 1 ? { field: 7 } : void 0; } });
var nullishReads = 0;
Object.defineProperty(globalThis, 'nullishValue', { get: function () { nullishReads += 1; return nullishReads === 1 ? 7 : void 0; } });
var optional = (optionalValue === null || optionalValue === void 0) ? void 0 : optionalValue.field;
var nullish = nullishValue !== null && nullishValue !== void 0 ? nullishValue : 42;
print(String(optional) + ':' + optionalReads + ':' + nullish + ':' + nullishReads);";
    let expected: String = node_capture(source);
    assert_eq!(expected, "undefined:2:42:2");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{stats:?}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 0, "{stats:?}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

#[test]
fn generic_expression_recovery_rejects_property_getter_reads() {
    let source: &str = r"const box = {};
var optionalReads = 0;
Object.defineProperty(box, 'optionalValue', { get: function () { optionalReads += 1; return optionalReads === 1 ? { field: 7 } : void 0; } });
var nullishReads = 0;
Object.defineProperty(box, 'nullishValue', { get: function () { nullishReads += 1; return nullishReads === 1 ? 7 : void 0; } });
var optional = (box.optionalValue === null || box.optionalValue === void 0) ? void 0 : box.optionalValue.field;
var nullish = box.nullishValue !== null && box.nullishValue !== void 0 ? box.nullishValue : 42;
print(String(optional) + ':' + optionalReads + ':' + nullish + ':' + nullishReads);";
    let expected: String = node_capture(source);
    assert_eq!(expected, "undefined:2:42:2");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{stats:?}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 0, "{stats:?}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

#[test]
fn generic_expression_recovery_rejects_root_var_bindings() {
    let source: &str = r"var rootValue = { field: 7 };
var optional = (rootValue === null || rootValue === void 0) ? void 0 : rootValue.field;
var fallback = rootValue !== null && rootValue !== void 0 ? rootValue : { field: 42 };
print(String(optional) + ':' + String(fallback.field));";
    let expected: String = node_capture(source);
    assert_eq!(expected, "7:7");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{recovered}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 0, "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

#[test]
fn generic_expression_recovery_rebuilds_local_computed_reads() {
    let source: &str = r"function read(value) {
  var keyReads = 0;
  function key() { keyReads += 1; return 'field'; }
  var optional = (value === null || value === void 0) ? void 0 : value[key()];
  var fallback = value !== null && value !== void 0 ? value : { field: 42 };
  print(String(optional) + ':' + String(fallback.field) + ':' + String(keyReads));
}
read({ field: 7 });
read(null);";
    let expected: String = node_capture(source);
    assert_eq!(expected, "7:7:1\u{1}undefined:42:0");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 1, "{recovered}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 1, "{recovered}");
    assert!(recovered.contains("value?.[key()]"), "{recovered}");
    assert!(recovered.contains("value ?? { field: 42 }"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

#[test]
fn generic_expression_recovery_preserves_shadowed_undefined_guards() {
    let source: &str = r"function read(undefined) {
  const value = null;
  var optional = (value === null || value === undefined) ? undefined : value.field;
  var fallback = value !== null && value !== undefined ? value : undefined;
  print(String(optional) + ':' + String(fallback));
}
read(0);";
    let expected: String = node_capture(source);
    assert_eq!(expected, "0:0");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{recovered}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 0, "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const WRAPPER_PROMISE_IDENTITY: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const NativePromise = Promise;
class TaggedPromise extends NativePromise {}
globalThis.Promise = TaggedPromise;
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(42);
  });
  return _run.apply(this, arguments);
}
console.log(String(run() instanceof TaggedPromise));
";

const UNSAFE_NATIVE_ASYNC_PROMISE_IDENTITY: &str = r"
const NativePromise = Promise;
class TaggedPromise extends NativePromise {}
globalThis.Promise = TaggedPromise;
async function run() {
  return await (Promise.resolve(42));
}
console.log(String(run() instanceof TaggedPromise));
";

#[test]
fn babel_promise_identity_oracle_rejects_the_unsafe_native_async_mutation() {
    assert_eq!(
        node_capture_babel_runtime(UNSAFE_NATIVE_ASYNC_PROMISE_IDENTITY),
        "false"
    );
}

#[test]
fn wrapper_recovery_preserves_babel_promise_constructor_identity() {
    assert_eq!(node_capture_babel_runtime(WRAPPER_PROMISE_IDENTITY), "true");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(WRAPPER_PROMISE_IDENTITY);
    assert_eq!(
        stats.async_functions_restored, 0,
        "default recovery must not replace Babel's dynamic Promise construction"
    );
    assert!(
        recovered.contains("babelAsync(function*"),
        "the helper-backed wrapper must remain in output:\n{recovered}"
    );
    assert_eq!(node_capture_babel_runtime(&recovered), "true");
}

#[test]
fn preset_env_undo_preserves_babel_promise_constructor_identity() {
    assert_eq!(node_capture_babel_runtime(WRAPPER_PROMISE_IDENTITY), "true");
    let result: PresetEnvUndoResult = undo_preset_env(WRAPPER_PROMISE_IDENTITY);
    assert_eq!(result.rewritten, WRAPPER_PROMISE_IDENTITY);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.spreads_restored, 0);
    assert_eq!(result.classes_restored, 0);
    assert_eq!(node_capture_babel_runtime(&result.rewritten), "true");
}

const WRAPPER_HELPER_NAME_COLLISIONS: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function _toConsumableArray(values) {
  return _toConsumableArrayAsync.apply(this, arguments);
}
function _toConsumableArrayAsync() {
  _toConsumableArrayAsync = babelAsync(function* (values) {
    return yield Promise.resolve(values.length);
  });
  return _toConsumableArrayAsync.apply(this, arguments);
}
function _classCallCheck(instance, Ctor) {
  return _classCallCheckAsync.apply(this, arguments);
}
function _classCallCheckAsync() {
  _classCallCheckAsync = babelAsync(function* (instance, Ctor) {
    return yield Promise.resolve(Ctor.name);
  });
  return _classCallCheckAsync.apply(this, arguments);
}
function _createClass(Ctor, props) { return Ctor; }
function Example() {
  _classCallCheck(this, Example);
  this.value = 1;
}
_createClass(Example, []);
var size = _toConsumableArray([1, 2]);
";

const WRAPPER_WITH_DISJOINT_MEMBER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function load(value) {
  return _load.apply(this, arguments);
}
function _load() {
  _load = babelAsync(function* (value) {
    return yield Promise.resolve(value);
  });
  return _load.apply(this, arguments);
}
var record = { field: 7 };
print(record['field']);
load(1).then(function (value) { print(value); });
";

#[test]
fn default_pipeline_preserves_babel_wrapper_helper_name_collisions() {
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(WRAPPER_HELPER_NAME_COLLISIONS);
    assert_eq!(stats.async_functions_restored, 0);
    assert_eq!(stats.array_spreads_rebuilt, 0);
    assert_eq!(stats.classes_reconstructed, 0);
    assert!(
        recovered.contains("function _toConsumableArray")
            && recovered.contains("function _toConsumableArrayAsync")
            && recovered.contains("function _classCallCheck")
            && recovered.contains("function _classCallCheckAsync"),
        "Babel wrapper declarations must remain:\n{recovered}"
    );
    assert!(
        recovered.contains("_toConsumableArray([1, 2])"),
        "spread reconstruction must not consume the wrapper call:\n{recovered}"
    );
    assert!(
        recovered.contains("function Example()")
            && recovered.contains("_classCallCheck(this, Example)"),
        "class reconstruction must not consume the wrapper call:\n{recovered}"
    );
}

#[test]
fn wrapper_protection_allows_disjoint_member_normalization() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(WRAPPER_WITH_DISJOINT_MEMBER);
    assert_eq!(stats.async_functions_restored, 0);
    assert!(recovered.contains("babelAsync(function*"));
    assert!(
        recovered.contains("record.field"),
        "a member edit outside the wrapper spans must remain eligible:\n{recovered}"
    );
}

#[test]
fn exact_babel_helper_specifier_call_quarantines_the_whole_ast_pipeline() {
    let source: &str = "const babelAsync = require('@babel/runtime/helpers/asyncToGenerator');\nvar untouched = 1;";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(recovered, source);
    assert_eq!(stats.vars_promoted_to_const, 0);
}

#[test]
fn helper_specifier_argument_quarantines_without_a_require_callee() {
    let source: &str =
        "const babelAsync = load('@babel/runtime/helpers/asyncToGenerator');\nvar untouched = 1;";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(recovered, source);
    assert_eq!(stats.vars_promoted_to_const, 0);
}

const FORWARDED_COMMONJS_BABEL_WRAPPER: &str = r"
(function (require) {
  const babelAsync = (require)('@babel/runtime/helpers/asyncToGenerator');
  function run() { return _run.apply(this, arguments); }
  function _run() {
    _run = babelAsync(function* () { return yield Promise.resolve(42); });
    return _run.apply(this, arguments);
  }
  var untouched = { value: 1 };
  print(String(run() instanceof Promise) + ':' + untouched['value']);
})(function (specifier) {
  if (specifier !== '@babel/runtime/helpers/asyncToGenerator') {
    throw new Error('unexpected helper');
  }
  return module.require(__BABEL_HELPER_PATH__);
});
";

fn forwarded_commonjs_babel_wrapper_source() -> String {
    let helper: PathBuf = babel_async_helper();
    let helper_src: String = serde_json::to_string(&helper.to_string_lossy())
        .expect("Babel helper path is JSON encodable");
    FORWARDED_COMMONJS_BABEL_WRAPPER.replace("__BABEL_HELPER_PATH__", &helper_src)
}

#[test]
fn forwarded_babel_helper_specifier_quarantines_the_whole_ast_pipeline() {
    let source: String = forwarded_commonjs_babel_wrapper_source();
    let expected: String = node_capture(&source);
    assert_eq!(expected, "true:1");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&source);
    assert_eq!(recovered, source);
    assert_eq!(stats.vars_promoted_to_const, 0);
    assert_eq!(stats.bracket_accesses_dotted, 0);
    assert_eq!(node_capture(&recovered), expected);

    let result: PresetEnvUndoResult = undo_preset_env(&source);
    assert_eq!(result.rewritten, source);
    assert!(result.helpers_removed.is_empty());
    assert_eq!(result.spreads_restored, 0);
    assert_eq!(result.classes_restored, 0);
    assert_eq!(result.async_restored, 0);
    assert_eq!(result.optional_chains_restored, 0);
    assert_eq!(result.nullish_coalesce_restored, 0);
    assert_eq!(node_capture(&result.rewritten), expected);
}

const FORWARDED_COMMONJS_BABEL_NEAR_MISS: &str = r"
(function (require) {
  const helper = (require)('@babel/runtime/helpers/asyncToGenerator-extra');
})(function () { return function () {}; });

const record = { value: 1 };
var selected = record === null || record === void 0 ? void 0 : record.value;
process.stdout.write(String(selected));
";

#[test]
fn forwarded_commonjs_babel_near_miss_allows_safe_recovery() {
    let expected: String = node_capture(FORWARDED_COMMONJS_BABEL_NEAR_MISS);
    assert_eq!(expected, "1");

    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(FORWARDED_COMMONJS_BABEL_NEAR_MISS);
    assert_eq!(stats.optional_chains_rebuilt, 1, "{recovered}");
    assert!(recovered.contains("record?.value"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");

    let result: PresetEnvUndoResult = undo_preset_env(FORWARDED_COMMONJS_BABEL_NEAR_MISS);
    assert_eq!(result.optional_chains_restored, 1, "{result:?}");
    assert!(result.rewritten.contains("record?.value"), "{result:?}");
    assert_eq!(result.async_restored, 0, "{result:?}");
    assert_eq!(result.spreads_restored, 0, "{result:?}");
    assert_eq!(result.classes_restored, 0, "{result:?}");
    assert_eq!(node_capture(&result.rewritten), expected, "{result:?}");
}

const WRAPPER_DIRECT_EVAL: &str = r#"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(42);
  });
  return _run.apply(this, arguments);
}
print(eval("typeof _run"));
"#;

#[test]
fn wrapper_helper_observed_by_direct_eval_is_preserved() {
    assert_eq!(
        eval_capture(WRAPPER_DIRECT_EVAL).expect("direct-eval wrapper fixture evaluates"),
        "function"
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(WRAPPER_DIRECT_EVAL);
    assert_eq!(
        stats.async_functions_restored, 0,
        "a wrapper helper visible to direct eval must not be removed"
    );
    assert_eq!(
        eval_capture(&recovered).expect("preserved direct-eval wrapper evaluates"),
        "function"
    );
}

fn assert_wrapper_pair_preserved(label: &str, source: &str) {
    let want: String =
        eval_capture(source).unwrap_or_else(|| panic!("{label}: wrapper fixture must evaluate"));
    assert!(
        !want.is_empty(),
        "{label}: wrapper output must be non-empty"
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.async_functions_restored, 0,
        "{label}: observed public wrapper must not be restored"
    );
    assert!(
        recovered.contains("babelAsync(function*"),
        "{label}: Babel wrapper must remain:\n{recovered}"
    );
    let have: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("{label}: preserved wrapper must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, have,
        "{label}: recovered wrapper changed behavior\n--want--\n{want}\n--got--\n{have}\n--src--\n{recovered}"
    );
}

const WRAPPER_PUBLIC_PROTOTYPE: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(1);
  });
  return _run.apply(this, arguments);
}
print(typeof run.prototype);
";

const WRAPPER_PUBLIC_CONSTRUCTION: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(1);
  });
  return _run.apply(this, arguments);
}
try { new run(); print('constructible'); } catch (error) { print('not constructible'); }
";

const WRAPPER_PUBLIC_DIRECT_EVAL: &str = r#"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(1);
  });
  return _run.apply(this, arguments);
}
function inspect() {
  let _run = "shadowed";
  return eval("typeof run.prototype");
}
print(inspect());
"#;

#[test]
fn observed_wrapper_public_bindings_are_preserved() {
    let cases: [(&str, &str); 3] = [
        ("prototype", WRAPPER_PUBLIC_PROTOTYPE),
        ("construction", WRAPPER_PUBLIC_CONSTRUCTION),
        ("direct eval", WRAPPER_PUBLIC_DIRECT_EVAL),
    ];
    for (label, source) in cases {
        assert_wrapper_pair_preserved(label, source);
    }
}

const WRAPPER_WITH_INDIRECT_EVAL_REFERENCE: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const savedEval = eval;
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(42);
  });
  return _run.apply(this, arguments);
}
run().then(function(v){ print(v); });
";

#[test]
fn indirect_eval_reference_keeps_the_wrapper_pair() {
    assert_wrapper_pair_preserved(
        "async/indirect-eval-reference",
        WRAPPER_WITH_INDIRECT_EVAL_REFERENCE,
    );
}

const WRAPPER_WITH_SHADOWED_DIRECT_EVAL: &str = r#"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function run() {
  return _run.apply(this, arguments);
}
function _run() {
  _run = babelAsync(function* () {
    return yield Promise.resolve(42);
  });
  return _run.apply(this, arguments);
}
function inspect() {
  let run = "local-public";
  let _run = "local";
  return eval("_run");
}
print(inspect());
run().then(function(v){ print(v); });
"#;

#[test]
fn direct_eval_shadowed_from_helper_keeps_the_wrapper_pair() {
    assert_wrapper_pair_preserved(
        "async/shadowed-direct-eval",
        WRAPPER_WITH_SHADOWED_DIRECT_EVAL,
    );
}

const DIRECT_BARE_CALL: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function tag() {
  var marker = 'bare';
  return marker;
}
var run = babelAsync(function* (x) { return yield Promise.resolve(x); });
run(1).then(function (value) { print(tag() + ':' + value); });
";

const DIRECT_CONSTRUCTOR_AND_PROTOTYPE: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var run = babelAsync(function* () { return yield Promise.resolve(1); });
print('prototype:' + typeof run.prototype);
try { new run(); print('constructible'); } catch (error) { print('not constructible'); }
";

const DIRECT_ALIAS: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var run = babelAsync(function* () { return yield Promise.resolve(1); });
var alias = run;
alias().then(function (value) { print('alias:' + value); });
";

const DIRECT_REASSIGNMENT: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var run = babelAsync(function* () { return yield Promise.resolve(1); });
var other = function () { print('reassigned'); };
run = other;
run();
";

const DIRECT_EVAL: &str = r#"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var run = babelAsync(function* () { return yield Promise.resolve(1); });
print('eval:' + eval("typeof run.prototype"));
"#;

#[test]
fn direct_async_helper_assignments_are_preserved() {
    let recovered: String =
        assert_direct_helper_assignment_preserved("bare call", DIRECT_BARE_CALL);
    assert!(
        recovered.contains("var marker = 'bare'"),
        "an atomic outcome touching the protected binding must be rejected:\n{recovered}"
    );
    let cases: [(&str, &str); 4] = [
        (
            "constructor and prototype",
            DIRECT_CONSTRUCTOR_AND_PROTOTYPE,
        ),
        ("alias", DIRECT_ALIAS),
        ("reassignment", DIRECT_REASSIGNMENT),
        ("eval", DIRECT_EVAL),
    ];
    for (label, source) in cases {
        let _: String = assert_direct_helper_assignment_preserved(label, source);
    }
}

const DIRECT_BINDING_WITH_UNRELATED_MEMBER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
var run = babelAsync(function* (x) { return yield Promise.resolve(x); });
var record = { value: 1 };
print(record['value']);
run(1).then(function () {});
";

#[test]
fn direct_helper_binding_allows_disjoint_member_normalization() {
    let recovered: String = assert_direct_helper_assignment_preserved(
        "disjoint member normalization",
        DIRECT_BINDING_WITH_UNRELATED_MEMBER,
    );
    assert!(
        recovered.contains("record.value"),
        "a disjoint member edit must remain eligible:\n{recovered}"
    );
}

#[test]
fn async_restore_selector_remains_a_compatibility_no_op() {
    let default_debug: String = format!("{:?}", AstPipeline::default());
    let enabled_pipeline: AstPipeline =
        AstPipeline::default().with_rule(AstRuleId::AsyncRestore, true);
    let enabled_debug: String = format!("{enabled_pipeline:?}");
    let enabled: (String, AstUnminifyStats) = enabled_pipeline.run(NEG_INLINE_CUSTOM_HELPER);
    let disabled: (String, AstUnminifyStats) = AstPipeline::default()
        .with_rule(AstRuleId::AsyncRestore, false)
        .run(NEG_INLINE_CUSTOM_HELPER);
    assert!(!default_debug.contains("AsyncRestore"));
    assert!(!enabled_debug.contains("AsyncRestore"));
    assert_eq!(enabled.0, disabled.0);
    assert!(enabled.0.contains("_asyncToGenerator(function*"));
    assert_eq!(enabled.1.async_functions_restored, 0);
    assert_eq!(disabled.1.async_functions_restored, 0);
}

const INPUT_BRANCHED: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function classify(n) {
  return _classify.apply(this, arguments);
}
function _classify() {
  _classify = babelAsync(function* (n) {
    if (n > 0) {
      var p = yield Promise.resolve('pos');
      return p;
    }
    var z = yield Promise.resolve('nonpos');
    return z;
  });
  return _classify.apply(this, arguments);
}
classify(3).then(function(v){ print(v); });
classify(-1).then(function(v){ print(v); });
";

#[test]
fn branched_async_with_multiple_yields_is_preserved() {
    let want: String =
        eval_capture(INPUT_BRANCHED).expect("branched Babel wrapper fixture evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_BRANCHED);
    assert_eq!(stats.async_functions_restored, 0);
    assert!(
        recovered.contains("babelAsync(function*") && recovered.contains("function _classify"),
        "the branched Babel wrapper pair must remain:\n{recovered}"
    );
    assert_eq!(
        eval_capture(&recovered).expect("preserved branched wrapper fixture evaluates"),
        want
    );
}

const NEG_PLAIN_GENERATOR: &str = r"
function* counter() {
  yield 1;
  yield 2;
}
var it = counter();
print(it.next().value);
print(it.next().value);
";

const NEG_INLINE_CUSTOM_HELPER: &str = r"
function _asyncToGenerator(fn) { return fn; }
var run = _asyncToGenerator(function* () { yield 1; });
print(run().next().value);
";

#[test]
fn inline_custom_helper_binding_is_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_INLINE_CUSTOM_HELPER);
    assert_eq!(stats.async_functions_restored, 0);
    assert!(recovered.contains("function _asyncToGenerator"));
    assert!(recovered.contains("_asyncToGenerator(function*"));
}

#[test]
fn negative_plain_generator_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_PLAIN_GENERATOR);
    assert_eq!(
        stats.async_functions_restored, 0,
        "a real user generator with no _asyncToGenerator wrapper must not be touched"
    );
    assert!(
        !recovered.contains("async function"),
        "must not fabricate async from a plain generator:\n{recovered}"
    );
}

const NEG_DELEGATE_YIELD: &str = r"
function inner_src() {
  return _inner.apply(this, arguments);
}
function _inner() {
  _inner = _asyncToGenerator(function* () {
    yield* [1, 2, 3];
  });
  return _inner.apply(this, arguments);
}
print(typeof inner_src);
";

#[test]
fn negative_delegate_yield_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_DELEGATE_YIELD);
    assert_eq!(
        stats.async_functions_restored, 0,
        "a generator containing yield* (delegate) cannot be faithfully converted to await; must be left alone"
    );
    assert!(
        recovered.contains("yield*"),
        "delegate yield must survive untouched:\n{recovered}"
    );
}
