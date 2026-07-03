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

const ORIG_VOID0: &str = r"
function greet(name) {
  if (name === void 0) { name = 'world'; }
  return 'hi ' + name;
}
print(greet());
print(greet('there'));
";

#[test]
fn void0_guard_becomes_default_parameter() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_VOID0);
    assert!(
        stats.default_params_recovered >= 1,
        "the `name === void 0` guard must become a default; got {}",
        stats.default_params_recovered
    );
    assert!(
        recovered.contains("name = 'world'")
            && recovered.contains("function greet(name = 'world')"),
        "the parameter must carry the default and the guard must be gone:\n{recovered}"
    );
    assert!(
        !recovered.contains("=== void 0") && !recovered.contains("=== undefined"),
        "the void/undefined guard must be removed:\n{recovered}"
    );
    assert_recovered_equivalent("void0", ORIG_VOID0, &recovered);
}

const ORIG_MULTI: &str = r"
function rect(w, h) {
  if (w === undefined) { w = 1; }
  if (h === undefined) { h = 2; }
  return w * h;
}
print(rect());
print(rect(5));
print(rect(5, 3));
";

#[test]
fn multiple_guards_become_multiple_defaults() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_MULTI);
    assert!(
        stats.default_params_recovered >= 2,
        "both guards must convert; got {}",
        stats.default_params_recovered
    );
    assert!(
        recovered.contains("function rect(w = 1, h = 2)"),
        "both defaults must appear on the signature:\n{recovered}"
    );
    assert_recovered_equivalent("multi", ORIG_MULTI, &recovered);
}

const SAFETY_LATER_PARAM: &str = r"
function f(a, b) {
  if (a === void 0) { a = b; }
  return a;
}
print(f(undefined, 7));
print(f(3, 7));
";

#[test]
fn default_referencing_a_later_param_is_left_intact() {
    let want: String = eval_capture(SAFETY_LATER_PARAM).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_LATER_PARAM);
    assert_eq!(
        stats.default_params_recovered, 0,
        "`a = b` reads a later param; hoisting it into `a = b` default would read b before it is the same b, and changes f(undefined, 7) semantics"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "behavior preserved when the default reads a later param"
    );
}

const SAFETY_NON_PARAM: &str = r"
function f(a) {
  var local;
  if (local === void 0) { local = 9; }
  return a + local;
}
print(f(1));
";

#[test]
fn guard_on_a_local_variable_is_not_a_default() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_NON_PARAM);
    assert_eq!(
        stats.default_params_recovered, 0,
        "the guard checks a local var, not a parameter, so it is not a recoverable default"
    );
    assert_recovered_equivalent("non_param", SAFETY_NON_PARAM, &recovered);
}

const ORIG_OBJECT_DEFAULT: &str = r"
function configure(options) {
  var opts = options === void 0 ? {} : options;
  opts.count = (opts.count || 0) + 1;
  return opts.count;
}
print(configure());
print(configure({ count: 5 }));
print(configure({}));
";

#[test]
fn object_default_ternary_becomes_default_parameter() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_OBJECT_DEFAULT);
    assert!(
        stats.default_params_recovered >= 1,
        "the object-default ternary must become a default; got {}",
        stats.default_params_recovered
    );
    assert!(
        recovered.contains("function configure(options = {})"),
        "the empty-object default must land on the signature:\n{recovered}"
    );
    assert!(
        !recovered.contains("=== void 0") && !recovered.contains("? {}"),
        "the ternary scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("object_default", ORIG_OBJECT_DEFAULT, &recovered);
}

const ORIG_ARGS_POSITIONAL: &str = r"
function power(base) {
  var exp = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 2;
  return Math.pow(base, exp);
}
print(power(3));
print(power(3, 3));
print(power(2, 10));
";

#[test]
fn arguments_positional_default_becomes_parameter() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_ARGS_POSITIONAL);
    assert!(
        stats.default_params_recovered >= 1,
        "the arguments-positional default must become a parameter; got {}",
        stats.default_params_recovered
    );
    assert!(
        recovered.contains("function power(base, exp = 2)"),
        "the synthesized parameter with its default must appear:\n{recovered}"
    );
    assert!(
        !recovered.contains("arguments.length") && !recovered.contains("arguments[1]"),
        "the arguments scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("args_positional", ORIG_ARGS_POSITIONAL, &recovered);
}
