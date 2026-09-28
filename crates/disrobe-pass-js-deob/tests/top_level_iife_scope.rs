#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_LIMIT);
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

const CONCATENATED_SCRIPTS: &str = r"
var first = [];
var second = [];
(function () {
  function helper() { return 'first'; }
  var state = 1;
  first.push(function () { return helper() + state; });
})();
(function () {
  function helper() { return 'second'; }
  var state = 2;
  second.push(function () { return helper() + state; });
})();
print(first[0]());
print(second[0]());
print(typeof helper);
print(typeof state);
";

#[test]
fn concatenated_iife_scripts_keep_their_own_bindings() {
    let want: String = eval_capture(CONCATENATED_SCRIPTS).expect("input evaluates");
    assert_eq!(
        want,
        ["first1", "second2", "undefined", "undefined"].join("\u{1}")
    );
    let (recovered, _): (String, AstUnminifyStats) = unminify_ast(CONCATENATED_SCRIPTS);
    let got: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "each IIFE's declarations must stay in its own scope\n--src--\n{recovered}"
    );
}

const USES_ARGUMENTS_AND_RETURN: &str = r"
function outer() {
  (function () {
    print(arguments.length);
  })();
}
outer(1, 2, 3);
var v = (function () { return 7; })();
print(v);
";

#[test]
fn iifes_reading_their_own_frame_evaluate_unchanged() {
    let want: String = eval_capture(USES_ARGUMENTS_AND_RETURN).expect("input evaluates");
    let (recovered, _): (String, AstUnminifyStats) = unminify_ast(USES_ARGUMENTS_AND_RETURN);
    let got: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("recovered must evaluate; src=\n{recovered}"));
    assert_eq!(want, got, "--src--\n{recovered}");
}
