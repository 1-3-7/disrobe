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

const THENABLE_SHIM: &str = r"
function makeRejected(reason) {
  return {
    then: function (onOk, onErr) {
      if (typeof onErr === 'function') { onErr(reason); }
      return this;
    },
    catch: function (onErr) {
      return this.then(null, onErr);
    }
  };
}
";

const ORIG_THEN_NULL: &str = r"
makeRejected('boom').then(null, function (e) { print('handled:' + e); });
";

#[test]
fn then_null_handler_converts_and_runs_the_same_handler() {
    let original: String = format!("{THENABLE_SHIM}{ORIG_THEN_NULL}");
    let (recovered_body, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_THEN_NULL);
    assert!(
        stats.then_to_catch >= 1,
        "`.then(null, fn)` must convert to `.catch(fn)`; got {}",
        stats.then_to_catch
    );
    assert!(
        recovered_body.contains(".catch(") && !recovered_body.contains(".then("),
        "the recovered body must use .catch and drop .then:\n{recovered_body}"
    );
    let recovered: String = format!("{THENABLE_SHIM}{recovered_body}");
    assert_recovered_equivalent("then_null", &original, &recovered);
}

const ORIG_THEN_UNDEFINED: &str = r"
makeRejected('x').then(undefined, function (e) { print('caught:' + e); });
";

#[test]
fn then_undefined_handler_converts() {
    let original: String = format!("{THENABLE_SHIM}{ORIG_THEN_UNDEFINED}");
    let (recovered_body, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_THEN_UNDEFINED);
    assert!(
        stats.then_to_catch >= 1,
        "`.then(undefined, fn)` must convert; got {}",
        stats.then_to_catch
    );
    let recovered: String = format!("{THENABLE_SHIM}{recovered_body}");
    assert_recovered_equivalent("then_undefined", &original, &recovered);
}

const SAFETY_TWO_HANDLERS: &str = r"
var thenable = {
  then: function (onOk, onErr) { if (onOk) onOk('ok'); return this; }
};
thenable.then(function (v) { print('ok:' + v); }, function (e) { print('err:' + e); });
";

#[test]
fn then_with_two_real_handlers_is_left_intact() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_TWO_HANDLERS);
    assert_eq!(
        stats.then_to_catch, 0,
        "`.then(onOk, onErr)` with a real success handler is NOT a .catch and must be left alone"
    );
    assert!(
        recovered.contains(".then("),
        "the two-handler then must survive:\n{recovered}"
    );
    assert_recovered_equivalent("two_handlers", SAFETY_TWO_HANDLERS, &recovered);
}
