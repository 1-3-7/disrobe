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

const ORIG_BABEL: &str = r"
function sum() {
  for (var _len = arguments.length, nums = new Array(_len), _i = 0; _i < _len; _i++) {
    nums[_i] = arguments[_i];
  }
  return nums.reduce(function (a, b) { return a + b; }, 0);
}
print(sum());
print(sum(1, 2, 3));
print(sum(10, 20, 30, 40));
";

#[test]
fn babel_arguments_copy_loop_becomes_rest_param() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_BABEL);
    assert!(
        stats.arguments_copy_loops_to_rest >= 1,
        "the arguments copy loop must become a rest param; got {}",
        stats.arguments_copy_loops_to_rest
    );
    assert!(
        recovered.contains("function sum(...nums)"),
        "the rest parameter must appear on the signature:\n{recovered}"
    );
    assert!(
        !recovered.contains("arguments.length") && !recovered.contains("new Array(_len)"),
        "the copy loop scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("babel", ORIG_BABEL, &recovered);
}

const ORIG_CTOR: &str = r"
function joinAll() {
  for (var _len = arguments.length, parts = Array(_len), _i = 0; _i < _len; _i++) parts[_i] = arguments[_i];
  return parts.join('-');
}
print(joinAll());
print(joinAll('a', 'b'));
print(joinAll('x', 'y', 'z'));
";

#[test]
fn array_ctor_call_copy_loop_also_recovers() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_CTOR);
    assert!(
        stats.arguments_copy_loops_to_rest >= 1,
        "the Array(_len) form must also recover; got {}",
        stats.arguments_copy_loops_to_rest
    );
    assert!(
        recovered.contains("function joinAll(...parts)"),
        "rest param must appear:\n{recovered}"
    );
    assert_recovered_equivalent("ctor", ORIG_CTOR, &recovered);
}

const SAFETY_FIXED_PARAM: &str = r"
function tagged(tag) {
  for (var _len = arguments.length, rest = new Array(_len), _i = 0; _i < _len; _i++) rest[_i] = arguments[_i];
  return tag + ':' + rest.length;
}
print(tagged('a'));
print(tagged('a', 1, 2));
";

#[test]
fn fixed_param_with_unshifted_loop_is_left_intact() {
    let want: String = eval_capture(SAFETY_FIXED_PARAM).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_FIXED_PARAM);
    assert_eq!(
        stats.arguments_copy_loops_to_rest, 0,
        "a leading param paired with an unshifted (_i = 0) copy loop does not encode a rest param; the shift must equal the param count"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved when not transformed");
}

const ORIG_ONE_LEADING: &str = r"
function tagged(tag) {
  for (var _len = arguments.length, rest = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
    rest[_key - 1] = arguments[_key];
  }
  return tag + ':' + rest.join(',');
}
print(tagged('a'));
print(tagged('a', 1, 2));
print(tagged('z', 9, 8, 7));
";

#[test]
fn one_leading_param_shifts_into_rest() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_ONE_LEADING);
    assert!(
        stats.arguments_copy_loops_to_rest >= 1,
        "a single leading param must shift into a rest param; got {}",
        stats.arguments_copy_loops_to_rest
    );
    assert!(
        recovered.contains("function tagged(tag, ...rest)"),
        "the rest param must append after the leading param:\n{recovered}"
    );
    assert!(
        !recovered.contains("arguments.length"),
        "the copy loop scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("one-leading", ORIG_ONE_LEADING, &recovered);
}

const ORIG_TWO_LEADING: &str = r"
function pair(a, b) {
  for (var _len = arguments.length, rest = Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) rest[_key - 2] = arguments[_key];
  return a + '|' + b + '|' + rest.join(',');
}
print(pair(1, 2));
print(pair(1, 2, 3, 4));
";

#[test]
fn two_leading_params_shift_into_rest() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_TWO_LEADING);
    assert!(
        stats.arguments_copy_loops_to_rest >= 1,
        "two leading params must shift into a rest param; got {}",
        stats.arguments_copy_loops_to_rest
    );
    assert!(
        recovered.contains("function pair(a, b, ...rest)"),
        "the rest param must append after both leading params:\n{recovered}"
    );
    assert_recovered_equivalent("two-leading", ORIG_TWO_LEADING, &recovered);
}

const SAFETY_SHIFT_MISMATCH: &str = r"
function f(a) {
  for (var _len = arguments.length, rest = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) rest[_key - 2] = arguments[_key];
  return a + ':' + rest.length;
}
print(f('a', 1, 2));
";

#[test]
fn shift_not_matching_param_count_is_left_intact() {
    let want: String = eval_capture(SAFETY_SHIFT_MISMATCH).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHIFT_MISMATCH);
    assert_eq!(
        stats.arguments_copy_loops_to_rest, 0,
        "a shift of 2 with a single leading param is not a faithful rest param; leave it"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved when not transformed");
}

const SAFETY_RESIDUAL_ARGUMENTS: &str = r"
function f() {
  for (var _len = arguments.length, a = new Array(_len), _i = 0; _i < _len; _i++) a[_i] = arguments[_i];
  var direct = arguments.length;
  return a.length + ':' + direct;
}
print(f(1, 2, 3));
";

#[test]
fn residual_direct_arguments_use_blocks_the_rewrite() {
    let want: String = eval_capture(SAFETY_RESIDUAL_ARGUMENTS).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_RESIDUAL_ARGUMENTS);
    assert_eq!(
        stats.arguments_copy_loops_to_rest, 0,
        "a second, direct `arguments` use outside the copy loop means a bare `...args` is not a faithful replacement; leave it"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const BABEL7_VERBATIM: &str = r#"
function power(base) {
  var exp = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 2;
  return Math.pow(base, exp);
}
function greet() {
  var name = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "world";
  return "hi " + name;
}
function sum() {
  for (var _len = arguments.length, nums = new Array(_len), _key = 0; _key < _len; _key++) {
    nums[_key] = arguments[_key];
  }
  return nums.reduce(function (a, b) {
    return a + b;
  }, 0);
}
function tagged(tag) {
  for (var _len2 = arguments.length, rest = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
    rest[_key2 - 1] = arguments[_key2];
  }
  return tag + ":" + rest.join(",");
}
function pair(a, b) {
  for (var _len3 = arguments.length, rest = new Array(_len3 > 2 ? _len3 - 2 : 0), _key3 = 2; _key3 < _len3; _key3++) {
    rest[_key3 - 2] = arguments[_key3];
  }
  return a + "|" + b + "|" + rest.join(",");
}
print(power(3));
print(power(2, 10));
print(greet());
print(greet("there"));
print(sum(1, 2, 3));
print(tagged("a", 1, 2));
print(pair(1, 2, 3, 4));
"#;

#[test]
fn real_babel7_es5_output_recovers_every_default_and_rest_param() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BABEL7_VERBATIM);
    assert_eq!(
        stats.default_params_recovered, 2,
        "both arguments-positional defaults (power, greet) must recover; got {}",
        stats.default_params_recovered
    );
    assert_eq!(
        stats.arguments_copy_loops_to_rest, 3,
        "all three copy loops (sum=0, tagged=1, pair=2 shift) must recover even with babel's _len2/_key2/_len3/_key3 suffixed names; got {}",
        stats.arguments_copy_loops_to_rest
    );
    assert!(
        recovered.contains("function power(base, exp = 2)")
            && recovered.contains("function greet(name = \"world\")")
            && recovered.contains("function sum(...nums)")
            && recovered.contains("function tagged(tag, ...rest)")
            && recovered.contains("function pair(a, b, ...rest)"),
        "every signature must carry its recovered default/rest:\n{recovered}"
    );
    assert!(
        !recovered.contains("arguments.length") && !recovered.contains("arguments["),
        "no arguments scaffolding may remain:\n{recovered}"
    );
    assert_recovered_equivalent("babel7-verbatim", BABEL7_VERBATIM, &recovered);
}
