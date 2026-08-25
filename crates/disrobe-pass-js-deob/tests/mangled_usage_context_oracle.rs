#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{TerserRestoreReport, restore_terser_mangled};

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

fn node_capture(program: &str) -> String {
    let harness: String = format!(
        "var __out=[];var print=function(v){{__out.push(String(v));}};{program};process.stdout.write(__out.join('\\u0001'));"
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the name-inference semantic reference")
        .expect("name-inference semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute source\nstderr: {}\nsource:\n{program}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn assert_behavior_preserved(label: &str, original: &str, recovered: &str) {
    assert!(
        reparses(recovered),
        "{label}: recovered must re-parse:\n{recovered}"
    );
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate:\n{recovered}"));
    assert_eq!(want, got, "{label}: behavior diverged\n{recovered}");
}

const DOM_TARGET: &str = r#"
function bind(a) {
  a.addEventListener("click", function () {});
  a.removeEventListener("scroll", function () {});
  return typeof a.addEventListener;
}
print(bind({ addEventListener: function () {}, removeEventListener: function () {} }));
"#;

#[test]
fn a_param_that_calls_addeventlistener_is_named_from_usage() {
    let r: TerserRestoreReport = restore_terser_mangled(DOM_TARGET);
    assert!(
        r.rewritten.contains("target.addEventListener"),
        "the DOM-target usage context must rename `a`->`target`, not a corpus default:\n{}",
        r.rewritten
    );
    assert!(
        !r.rewritten.contains("(a)") && !r.rewritten.contains(" a.addEventListener"),
        "the minified `a` binding must be gone:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("dom-target", DOM_TARGET, &r.rewritten);
}

const PROMISE_LIKE: &str = r"
function chain(p) {
  return p.then(function (v) { return v; }).catch(function () { return 0; });
}
var fake = { then: function (cb) { cb(1); return { catch: function () { return 7; } }; } };
print(chain(fake));
";

#[test]
fn a_param_that_calls_then_is_named_promise() {
    let r: TerserRestoreReport = restore_terser_mangled(PROMISE_LIKE);
    assert!(
        r.rewritten.contains("promise.then") || r.rewritten.contains("promise\n"),
        "the `.then`/`.catch` usage must rename `p`->`promise`:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("promise", PROMISE_LIKE, &r.rewritten);
}

const ARRAY_LIKE: &str = r"
function fill(l) {
  l.push(1);
  l.push(2);
  return l.length;
}
print(fill([]));
";

#[test]
fn a_param_that_calls_push_is_named_list() {
    let r: TerserRestoreReport = restore_terser_mangled(ARRAY_LIKE);
    assert!(
        r.rewritten.contains("list.push"),
        "the `.push`/`.length` usage must rename `l`->`list`:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("array", ARRAY_LIKE, &r.rewritten);
}

const ASSIGNED_FROM_NEW: &str = r#"
function make() {
  var s = new Map();
  s.set("x", 1);
  return s.get("x");
}
print(make());
"#;

#[test]
fn a_local_assigned_from_new_map_keeps_behavior_and_renames() {
    let r: TerserRestoreReport = restore_terser_mangled(ASSIGNED_FROM_NEW);
    assert!(
        r.identifiers_renamed >= 1,
        "the short local `s` must be picked up:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("assigned-new", ASSIGNED_FROM_NEW, &r.rewritten);
}

const NO_USAGE_SIGNAL: &str = r"
function calc(a, b) {
  var c = a + b;
  return c * 2;
}
print(calc(3, 4));
";

#[test]
fn pure_arithmetic_locals_still_recover_and_preserve_behavior() {
    let r: TerserRestoreReport = restore_terser_mangled(NO_USAGE_SIGNAL);
    assert!(r.identifiers_renamed >= 1, "{}", r.rewritten);
    assert_behavior_preserved("arith", NO_USAGE_SIGNAL, &r.rewritten);
}

const OBJECT_KEYS_CONCAT: &str = r#"
function f() {
  var a = Object.keys({ left: 1 }).concat(Object.keys({ right: 2 }));
  print(a.join(","));
}
f();
"#;

#[test]
fn object_keys_concat_names_the_result_and_preserves_boa_and_node_behavior() {
    let report: TerserRestoreReport = restore_terser_mangled(OBJECT_KEYS_CONCAT);
    assert!(
        report.rewritten.contains("var keys = Object.keys"),
        "the Object.keys result must retain its collection provenance:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("object-keys-concat", OBJECT_KEYS_CONCAT, &report.rewritten);
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(OBJECT_KEYS_CONCAT),
        "Object.keys result inference must preserve Node output"
    );
}
