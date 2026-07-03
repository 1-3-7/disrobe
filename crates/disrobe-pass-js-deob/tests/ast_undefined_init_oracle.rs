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

const ORIG_UNDEF: &str = r"
var a = undefined;
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
var x = void 0;
print(x);
print(typeof x);
";

#[test]
fn void_zero_init_normalizes_then_drops() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_VOID_INIT);
    assert!(
        stats.undefined_inits_dropped >= 1,
        "`var x = void 0` should normalize to `= undefined` then drop; got {}",
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
  var x = undefined;
  return x;
}
print(f(42));
";

#[test]
fn shadowed_undefined_binding_blocks_the_drop() {
    let want: String = eval_capture(SAFETY_SHADOWED_UNDEFINED).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHADOWED_UNDEFINED);
    assert_eq!(
        stats.undefined_inits_dropped, 0,
        "when `undefined` is a local parameter, `var x = undefined` reads that binding (42), not the global; dropping the init would change f(42) from 42 to undefined"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved when undefined is shadowed");
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
