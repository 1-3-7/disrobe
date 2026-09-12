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

const INPUT_GENERATOR_MODERN: &str = r"
function simple() {
  var x, y;
  return _regenerator().w(function (_context) {
    while (1) switch (_context.n) {
      case 0:
        _context.n = 1;
        return 1;
      case 1:
        x = _context.v;
        _context.n = 2;
        return x + 1;
      case 2:
        y = _context.v;
        return _context.a(2, x + y);
    }
  }, _marked);
}
var it = simple();
print(it.next().value);
print(it.next(10).value);
print(it.next(20).value);
";

#[test]
fn modern_regenerator_machine_is_preserved() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_GENERATOR_MODERN);
    assert_eq!(stats.regenerator_functions_restored, 0, "{recovered}");
    assert!(
        recovered.contains("_regenerator().w"),
        "the helper-shaped state machine must remain:\n{recovered}"
    );
    assert!(
        !recovered.contains("function* simple"),
        "a generator must not be inferred from helper-shaped syntax:\n{recovered}"
    );
}

const INPUT_GENERATOR_CLASSIC: &str = r#"
function simple() {
  var x, y;
  return regeneratorRuntime.wrap(function simple$(_context) {
    while (1) switch (_context.prev = _context.next) {
      case 0:
        _context.next = 2;
        return 1;
      case 2:
        x = _context.sent;
        _context.next = 5;
        return x + 1;
      case 5:
        y = _context.sent;
        return _context.abrupt("return", x + y);
      case 7:
      case "end":
        return _context.stop();
    }
  }, _marked);
}
var it = simple();
print(it.next().value);
print(it.next(10).value);
print(it.next(20).value);
"#;

#[test]
fn classic_regenerator_machine_is_preserved() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_GENERATOR_CLASSIC);
    assert_eq!(stats.regenerator_functions_restored, 0, "{recovered}");
    assert!(
        recovered.contains("regeneratorRuntime.wrap"),
        "the helper-shaped state machine must remain:\n{recovered}"
    );
    assert!(
        !recovered.contains("function* simple"),
        "a generator must not be inferred from helper-shaped syntax:\n{recovered}"
    );
}

const INPUT_ASYNC_MODERN: &str = r"
function load(_x) {
  return _load.apply(this, arguments);
}
function _load() {
  _load = _asyncToGenerator(_regenerator().m(function _callee(n) {
    var a, b;
    return _regenerator().w(function (_context2) {
      while (1) switch (_context2.n) {
        case 0:
          _context2.n = 1;
          return Promise.resolve(n);
        case 1:
          a = _context2.v;
          _context2.n = 2;
          return Promise.resolve(a + 1);
        case 2:
          b = _context2.v;
          return _context2.a(2, a + b);
      }
    }, _callee);
  }));
  return _load.apply(this, arguments);
}
load(10).then(function (v) { print(v); });
";

#[test]
fn modern_regenerator_async_pair_is_preserved() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_ASYNC_MODERN);
    assert_eq!(stats.async_functions_restored, 0);
    assert_eq!(stats.regenerator_functions_restored, 0);
    assert!(
        recovered.contains("_asyncToGenerator") && recovered.contains("_context2"),
        "the async wrapper and state machine must remain:\n{recovered}"
    );
    assert!(
        !recovered.contains("async function load"),
        "native async output must not be emitted:\n{recovered}"
    );
}

const NEG_BRANCHING: &str = r"
function tricky() {
  var x;
  return _regenerator().w(function (_context) {
    while (1) switch (_context.n) {
      case 0:
        if (x) {
          _context.n = 2;
          break;
        }
        _context.n = 3;
        break;
      case 2:
        return _context.a(2, 1);
      case 3:
        return _context.a(2, 2);
    }
  }, _marked);
}
print(typeof tricky);
";

#[test]
fn negative_branching_state_machine_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_BRANCHING);
    assert_eq!(
        stats.regenerator_functions_restored, 0,
        "a state machine with conditional jumps cannot be linearly reconstructed; must be left alone"
    );
    assert!(
        recovered.contains("_context"),
        "the unhandled state machine must survive untouched:\n{recovered}"
    );
}

const COUNTERFEIT_GIFTWRAP: &str = r#"
function giftwrap(callback) {
  return 17;
}
function victim() {
  return giftwrap(function (ctx) {
    while (1) switch (ctx.next) {
      case 0:
        return ctx.abrupt("return", 99);
    }
  });
}
print(victim());
"#;

#[test]
fn default_regenerator_rule_preserves_counterfeit_wrap_behavior() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(COUNTERFEIT_GIFTWRAP);
    assert_eq!(recovered, COUNTERFEIT_GIFTWRAP);
    assert_eq!(stats.regenerator_functions_restored, 0);
    assert_eq!(
        eval_capture(COUNTERFEIT_GIFTWRAP).expect("counterfeit input evaluates"),
        "17"
    );
    assert_eq!(
        eval_capture(&recovered).expect("counterfeit output evaluates"),
        "17"
    );
}

#[test]
fn regenerator_selector_is_disabled_and_opt_in_is_a_compatibility_noop() {
    let default_pipeline: AstPipeline = AstPipeline::default();
    let default_debug: String = format!("{default_pipeline:?}");
    assert!(
        !default_debug.contains("RegeneratorRestore"),
        "{default_debug}"
    );

    let enabled_pipeline: AstPipeline =
        AstPipeline::default().with_rule(AstRuleId::RegeneratorRestore, true);
    let enabled_debug: String = format!("{enabled_pipeline:?}");
    assert!(
        enabled_debug.contains("RegeneratorRestore"),
        "{enabled_debug}"
    );

    let (default_output, default_stats): (String, AstUnminifyStats) = default_pipeline
        .try_run(COUNTERFEIT_GIFTWRAP)
        .expect("default selector pipeline runs");
    let (enabled_output, enabled_stats): (String, AstUnminifyStats) = enabled_pipeline
        .try_run(COUNTERFEIT_GIFTWRAP)
        .expect("enabled selector pipeline runs");

    assert_eq!(default_output, COUNTERFEIT_GIFTWRAP);
    assert_eq!(enabled_output, default_output);
    assert_eq!(default_stats.regenerator_functions_restored, 0usize);
    assert_eq!(enabled_stats.regenerator_functions_restored, 0usize);
}
