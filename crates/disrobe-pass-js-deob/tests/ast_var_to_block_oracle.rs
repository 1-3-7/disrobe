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

fn assert_recovered_equivalent(label: &str, input: &str, recovered: &str) {
    let want: String = eval_capture(input)
        .unwrap_or_else(|| panic!("{label}: input must evaluate; src=\n{input}"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const INPUT_CONST: &str = r"
var a = 1;
var b = a + 2;
print(a);
print(b);
";

#[test]
fn pure_initialized_vars_promote_to_const_and_stay_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_CONST);
    assert_eq!(
        stats.vars_promoted_to_const, 2,
        "both pure vars must become const:\n{recovered}"
    );
    assert_eq!(stats.vars_promoted_to_let, 0);
    assert!(
        !recovered.contains("var "),
        "no var keyword should survive:\n{recovered}"
    );
    assert_recovered_equivalent("var/const", INPUT_CONST, &recovered);
}

const INPUT_LET: &str = r"
var total = 0;
var i = 0;
while (i < 4) {
  total = total + i;
  i = i + 1;
}
print(total);
";

#[test]
fn reassigned_vars_promote_to_let_and_stay_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_LET);
    assert!(
        stats.vars_promoted_to_let >= 2,
        "reassigned vars must become let:\n{recovered}"
    );
    assert!(
        recovered.contains("let total") && recovered.contains("let i"),
        "both reassigned vars must be let:\n{recovered}"
    );
    assert_recovered_equivalent("var/let", INPUT_LET, &recovered);
}

const INPUT_FOR_HEAD: &str = r"
var sum = 0;
for (var j = 0; j < 3; j++) {
  sum = sum + j;
}
print(sum);
";

#[test]
fn for_loop_var_head_is_preserved() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_FOR_HEAD);
    assert!(
        recovered.contains("for (var j = 0")
            || recovered.contains("for(var j=0")
            || recovered.contains("for (var j=0"),
        "for-head var must be left as var:\n{recovered}"
    );
    assert_eq!(
        stats.vars_promoted_to_const, 0,
        "no const promotion for the loop counter:\n{recovered}"
    );
    assert_recovered_equivalent("var/for-head", INPUT_FOR_HEAD, &recovered);
}

const INPUT_HOISTED: &str = r"
if (1) {
  var leaked = 7;
}
print(leaked);
";

#[test]
fn block_hoisted_var_is_not_promoted() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_HOISTED);
    assert_eq!(
        stats.vars_promoted_to_const + stats.vars_promoted_to_let,
        0,
        "a var hoisted out of a block must not be promoted (would break TDZ/scope):\n{recovered}"
    );
    assert_recovered_equivalent("var/hoisted", INPUT_HOISTED, &recovered);
}
