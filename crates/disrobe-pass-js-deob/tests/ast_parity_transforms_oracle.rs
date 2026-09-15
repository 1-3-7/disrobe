#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstRuleId, AstUnminifyStats, unminify_ast};

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

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-written input not behaviorally identical to original BEFORE transform"
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

const ORIG_INDIRECT: &str = r"
function greet(n) { return 'hi ' + n; }
function run() { return greet('a'); }
print(run());
";

const INPUT_INDIRECT: &str = r"
function greet(n) { return 'hi ' + n; }
function run() { return (0, greet)('a'); }
print(run());
";

#[test]
fn indirect_call_unwraps_zero_sequence() {
    assert_faithful_input("indirect", ORIG_INDIRECT, INPUT_INDIRECT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_INDIRECT);
    assert!(
        stats.indirect_calls_simplified >= 1,
        "the (0, greet)() call must simplify; got {}",
        stats.indirect_calls_simplified
    );
    assert!(
        recovered.contains("greet('a')") && !recovered.contains("(0, greet)"),
        "indirect call must collapse:\n{recovered}"
    );
    assert_recovered_equivalent("indirect", ORIG_INDIRECT, &recovered);
}

const ORIG_APPLY: &str = r"
function sum() { var t = 0; for (var i = 0; i < arguments.length; i++) { t += arguments[i]; } return t; }
var nums = [1, 2, 3, 4];
print(sum.apply(undefined, nums));
";

const INPUT_APPLY: &str = r"
function sum() { var t = 0; for (var i = 0; i < arguments.length; i++) { t += arguments[i]; } return t; }
var nums = [1, 2, 3, 4];
print(sum.apply(void 0, nums));
";

#[test]
fn argument_spread_preserves_apply_call() {
    assert_faithful_input("apply", ORIG_APPLY, INPUT_APPLY);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_APPLY);
    assert_eq!(stats.apply_calls_spread, 0, "{recovered}");
    assert!(
        recovered.contains("sum.apply("),
        "apply call must remain unchanged without intrinsic identity proof:\n{recovered}"
    );
    assert_recovered_equivalent("apply", ORIG_APPLY, &recovered);
}

#[test]
fn disabled_argument_spread_and_template_literal_selectors_are_noops() {
    let default_debug: String = format!("{:?}", AstPipeline::default());
    assert!(!default_debug.contains("ArgumentSpread"), "{default_debug}");
    assert!(
        !default_debug.contains("TemplateLiteral"),
        "{default_debug}"
    );

    let input: String = format!("{INPUT_APPLY}\n{INPUT_TEMPLATE}");
    let disabled_pipeline: AstPipeline = AstPipeline::default()
        .with_rule(AstRuleId::ArgumentSpread, false)
        .with_rule(AstRuleId::TemplateLiteral, false);
    let enabled_pipeline: AstPipeline = AstPipeline::default()
        .with_rule(AstRuleId::ArgumentSpread, true)
        .with_rule(AstRuleId::TemplateLiteral, true);
    let enabled_debug: String = format!("{enabled_pipeline:?}");

    assert!(enabled_debug.contains("ArgumentSpread"), "{enabled_debug}");
    assert!(enabled_debug.contains("TemplateLiteral"), "{enabled_debug}");

    let (disabled_output, disabled_stats): (String, AstUnminifyStats) = disabled_pipeline
        .try_run(&input)
        .expect("disabled selector pipeline runs");
    let (enabled_output, enabled_stats): (String, AstUnminifyStats) = enabled_pipeline
        .try_run(&input)
        .expect("enabled selector pipeline runs");

    assert_eq!(enabled_output, disabled_output);
    assert_eq!(enabled_stats.apply_calls_spread, 0usize);
    assert_eq!(enabled_stats.template_literals_rebuilt, 0usize);
    assert_eq!(disabled_stats.apply_calls_spread, 0usize);
    assert_eq!(disabled_stats.template_literals_rebuilt, 0usize);
}

const ORIG_BRACKET: &str = r"
var o = { alpha: 1, beta: 2 };
print(o.alpha + o.beta);
";

const INPUT_BRACKET: &str = r#"
var o = { alpha: 1, beta: 2 };
print(o["alpha"] + o["beta"]);
"#;

#[test]
fn bracket_to_dot_rewrites_string_keys() {
    assert_faithful_input("bracket", ORIG_BRACKET, INPUT_BRACKET);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_BRACKET);
    assert!(
        stats.bracket_accesses_dotted >= 2,
        "both o[\"alpha\"] and o[\"beta\"] must dot; got {}",
        stats.bracket_accesses_dotted
    );
    assert!(
        recovered.contains("o.alpha") && recovered.contains("o.beta"),
        "bracket access must become dotted:\n{recovered}"
    );
    assert_recovered_equivalent("bracket", ORIG_BRACKET, &recovered);
}

const NEG_BRACKET_NUMERIC: &str = r#"
var a = [10, 20, 30];
print(a["0"] + a[1]);
var weird = {};
weird["has-dash"] = 5;
print(weird["has-dash"]);
"#;

#[test]
fn bracket_to_dot_leaves_numeric_and_dashed_keys() {
    let want: String = eval_capture(NEG_BRACKET_NUMERIC).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_BRACKET_NUMERIC);
    assert_eq!(
        stats.bracket_accesses_dotted, 0,
        "numeric and dashed keys must NOT be converted to dot access"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_BRACKET_IN_CONTAINERS: &str = r#"
var o = { alpha: 1, beta: 2, gamma: 3 };
function run() {
  var sum = 0;
  try {
    sum += o["alpha"];
  } finally {
    sum += o["beta"];
  }
  for (const k of [0]) {
    sum += o["gamma"] + k;
  }
  return sum;
}
print(run());
"#;

#[test]
fn bracket_to_dot_reaches_try_and_for_of_bodies() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_BRACKET_IN_CONTAINERS);
    assert!(
        stats.bracket_accesses_dotted >= 3,
        "bracket access inside try/finally and for-of bodies must dot; got {}",
        stats.bracket_accesses_dotted
    );
    assert!(
        recovered.contains("o.alpha")
            && recovered.contains("o.beta")
            && recovered.contains("o.gamma"),
        "all three nested accesses must become dotted:\n{recovered}"
    );
    assert_recovered_equivalent("bracket-containers", ORIG_BRACKET_IN_CONTAINERS, &recovered);
}

const ORIG_TEMPLATE: &str = r"
function build(name, count) { return 'user ' + name + ' has ' + count + ' items'; }
print(build('ann', 3));
print(build('bob', 0));
";

const INPUT_TEMPLATE: &str = ORIG_TEMPLATE;

#[test]
fn template_literal_leaves_string_concat_intact() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_TEMPLATE);
    assert_eq!(stats.template_literals_rebuilt, 0, "{recovered}");
    assert_eq!(recovered, INPUT_TEMPLATE, "{recovered}");
    assert_recovered_equivalent("template", ORIG_TEMPLATE, &recovered);
}

const NEG_TEMPLATE_NUMERIC: &str = r"
function add(a, b) { return a + b; }
print(add(2, 3));
print(add(10, 20));
";

#[test]
fn template_literal_leaves_numeric_addition() {
    let want: String = eval_capture(NEG_TEMPLATE_NUMERIC).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_TEMPLATE_NUMERIC);
    assert_eq!(
        stats.template_literals_rebuilt, 0,
        "numeric addition with no string root must NOT become a template literal"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_OPTIONAL: &str = r"
function pick(o) { if (o && o.value) { return o.value; } return 'none'; }
function get(o) { return o === null || o === void 0 ? void 0 : o.value; }
print(get({ value: 7 }));
print(get(null));
print(get(undefined));
";

const INPUT_OPTIONAL: &str = ORIG_OPTIONAL;

#[test]
fn optional_chaining_rebuilds_null_guard() {
    assert_faithful_input("optional", ORIG_OPTIONAL, INPUT_OPTIONAL);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_OPTIONAL);
    assert!(
        stats.optional_chains_rebuilt >= 1,
        "the strict null/void guard must become o?.value; got {}",
        stats.optional_chains_rebuilt
    );
    assert!(
        recovered.contains("o?.value"),
        "optional chain must be emitted:\n{recovered}"
    );
    assert_recovered_equivalent("optional", ORIG_OPTIONAL, &recovered);
}

const ORIG_NULLISH: &str = r"
function def(x) { return x === null || x === void 0 ? 'fallback' : x; }
print(def('value'));
print(def(null));
print(def(undefined));
print(def(0));
print(def(''));
";

const INPUT_NULLISH: &str = ORIG_NULLISH;

#[test]
fn nullish_coalescing_rebuilds_null_default() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_NULLISH);
    assert!(
        stats.nullish_coalesces_rebuilt >= 1,
        "the strict null/void guard must become x ?? 'fallback'; got {}",
        stats.nullish_coalesces_rebuilt
    );
    assert!(
        recovered.contains("x ?? 'fallback'") || recovered.contains("x ?? \"fallback\""),
        "nullish coalescing must be emitted:\n{recovered}"
    );
    assert_recovered_equivalent("nullish", ORIG_NULLISH, &recovered);
}

const LOOSE_NULLISH_GUARDS: &str = r"
function read(value) {
  var optional = value == null ? void 0 : value.field;
  var fallback = value != null ? value : 42;
  return String(optional) + ':' + String(fallback);
}
print(read({ field: 7 }));
print(read(null));
";

#[test]
fn loose_nullish_guards_are_preserved() {
    let want: String = eval_capture(LOOSE_NULLISH_GUARDS).expect("loose input evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(LOOSE_NULLISH_GUARDS);
    assert_eq!(stats.optional_chains_rebuilt, 0, "{recovered}");
    assert_eq!(stats.nullish_coalesces_rebuilt, 0, "{recovered}");
    let got: String = eval_capture(&recovered).expect("recovered loose input evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const ORIG_NULLISH_STRICT: &str = r"
function def(x) { return x === null || x === void 0 ? 42 : x; }
print(def(5));
print(def(null));
print(def(undefined));
print(def(0));
";

#[test]
fn nullish_coalescing_strict_or_form() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_NULLISH_STRICT);
    assert!(
        stats.nullish_coalesces_rebuilt >= 1,
        "strict null/undefined OR-check must coalesce; got {}",
        stats.nullish_coalesces_rebuilt
    );
    assert!(
        recovered.contains("x ?? 42"),
        "must emit x ?? 42:\n{recovered}"
    );
    assert_recovered_equivalent("nullish-strict", ORIG_NULLISH_STRICT, &recovered);
}

const NEG_TERNARY_NOT_NULLISH: &str = r"
function clamp(x) { return x > 0 ? x : 0; }
print(clamp(5));
print(clamp(-3));
";

#[test]
fn ternary_unrelated_to_null_is_untouched() {
    let want: String = eval_capture(NEG_TERNARY_NOT_NULLISH).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_TERNARY_NOT_NULLISH);
    assert_eq!(
        stats.nullish_coalesces_rebuilt, 0,
        "a non-null-check ternary must NOT coalesce"
    );
    assert_eq!(
        stats.optional_chains_rebuilt, 0,
        "a non-null-check ternary must NOT become optional chaining"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
