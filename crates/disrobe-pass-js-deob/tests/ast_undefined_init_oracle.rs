#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

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

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String = eval_capture(original).expect("orig evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ORIG_UNDEF: &str = r"
let a = undefined;
let b = undefined;
print(a);
print(b);
print(typeof a);
print(b === undefined);
";

#[test]
fn redundant_undefined_init_is_dropped_without_behavior_change() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_UNDEF);
    assert!(
        stats.undefined_inits_dropped >= 2,
        "both `= undefined` initializers must drop; got {}",
        stats.undefined_inits_dropped
    );
    assert!(
        !recovered.contains("a = undefined") && !recovered.contains("b = undefined"),
        "no redundant undefined declarator initializer may survive:\n{recovered}"
    );
    assert_recovered_equivalent("undef", ORIG_UNDEF, &recovered);
}

const ORIG_VOID_INIT: &str = r"
let x = void 0;
print(x);
print(typeof x);
";

#[test]
fn void_zero_init_normalizes_then_drops() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_VOID_INIT);
    assert!(
        stats.undefined_inits_dropped >= 1,
        "`let x = void 0` should normalize to `= undefined` then drop; got {}",
        stats.undefined_inits_dropped
    );
    assert!(
        !recovered.contains("void 0") && !recovered.contains("= undefined"),
        "neither void 0 nor undefined init may survive:\n{recovered}"
    );
    assert_recovered_equivalent("void_init", ORIG_VOID_INIT, &recovered);
}

const SAFETY_SHADOWED_UNDEFINED: &str = r"
function f(undefined) {
  let x = undefined;
  return x;
}
process.stdout.write(String(f(42)));
";

#[test]
fn shadowed_undefined_binding_blocks_the_drop() {
    let want: String = node_capture(SAFETY_SHADOWED_UNDEFINED);
    assert_eq!(want, "42");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHADOWED_UNDEFINED);
    assert_eq!(
        stats.undefined_inits_dropped, 0,
        "when `undefined` is a local parameter, `let x = undefined` reads that binding (42), not the global; dropping the init would change f(42) from 42 to undefined"
    );
    let got: String = node_capture(&recovered);
    assert_eq!(want, got, "behavior preserved when undefined is shadowed");
}

const SAFETY_PRIOR_VAR_ASSIGNMENT: &str = r"
var retained = 7;
var retained = undefined;
process.stdout.write(String(retained));
";

#[test]
fn prior_var_assignment_retains_undefined_initializer() {
    let expected: String = node_capture(SAFETY_PRIOR_VAR_ASSIGNMENT);
    assert_eq!(expected, "undefined");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_PRIOR_VAR_ASSIGNMENT);
    assert_eq!(stats.undefined_inits_dropped, 0, "{recovered}");
    assert!(
        recovered.contains("var retained = undefined"),
        "{recovered}"
    );
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_DIRECT_EVAL_UNDEFINED_INIT: &str = r"
function read() {
  (eval)('var undefined = 7');
  let value = undefined;
  return value;
}
process.stdout.write(String(read()));
";

#[test]
fn direct_eval_binding_blocks_the_drop() {
    let expected: String = node_capture(SAFETY_DIRECT_EVAL_UNDEFINED_INIT);
    assert_eq!(expected, "7");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_DIRECT_EVAL_UNDEFINED_INIT);
    assert_eq!(stats.undefined_inits_dropped, 0, "{recovered}");
    assert!(recovered.contains("value = undefined"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_WITH_UNDEFINED_INIT: &str = r"
with ({ undefined: 7 }) {
  let value = undefined;
  process.stdout.write(String(value));
}
";

#[test]
fn with_binding_blocks_the_drop() {
    let expected: String = node_capture(SAFETY_WITH_UNDEFINED_INIT);
    assert_eq!(expected, "7");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_WITH_UNDEFINED_INIT);
    assert_eq!(stats.undefined_inits_dropped, 0, "{recovered}");
    assert!(recovered.contains("value = undefined"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

const SAFETY_COMMENTED_LET_UNDEFINED_INIT: &str = r"
let before /* retain-before */ = undefined;
let after = /* retain-after */ undefined;
process.stdout.write(String(before) + ':' + String(after));
";

#[test]
fn comment_bearing_let_initializers_are_preserved() {
    let expected: String = node_capture(SAFETY_COMMENTED_LET_UNDEFINED_INIT);
    assert_eq!(expected, "undefined:undefined");
    let (recovered, stats): (String, AstUnminifyStats) =
        unminify_ast(SAFETY_COMMENTED_LET_UNDEFINED_INIT);
    assert_eq!(stats.undefined_inits_dropped, 0, "{recovered}");
    assert!(recovered.contains("/* retain-before */"), "{recovered}");
    assert!(recovered.contains("/* retain-after */"), "{recovered}");
    assert_eq!(node_capture(&recovered), expected, "{recovered}");
}

fn node_capture(source: &str) -> String {
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the undefined initializer semantic reference")
        .expect("undefined initializer semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

const SAFETY_REAL_INIT: &str = r"
var a = 1;
let b = computeValue();
const c = undefined;
function computeValue() { return 7; }
print(a);
print(b);
print(c);
";

#[test]
fn real_inits_and_const_are_left_intact() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_REAL_INIT);
    assert_eq!(
        stats.undefined_inits_dropped, 0,
        "a value initializer, a call initializer, and a const must all keep their init"
    );
    assert!(
        recovered.contains("const c = undefined"),
        "const requires an initializer and must keep it:\n{recovered}"
    );
    assert_recovered_equivalent("real_init", SAFETY_REAL_INIT, &recovered);
}
