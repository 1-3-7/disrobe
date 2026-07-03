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
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ORIG_GENERATOR: &str = r"
function* simple() {
  var x = yield 1;
  var y = yield x + 1;
  return x + y;
}
var it = simple();
print(it.next().value);
print(it.next(10).value);
print(it.next(20).value);
";

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
fn modern_regenerator_generator_restored_and_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_GENERATOR_MODERN);
    assert!(
        stats.regenerator_functions_restored >= 1,
        "the state-machine generator must be restored; got {}",
        stats.regenerator_functions_restored
    );
    assert!(
        recovered.contains("function* simple"),
        "must emit a real generator:\n{recovered}"
    );
    assert!(
        recovered.contains("x = yield 1")
            && recovered.contains("y = yield x + 1")
            && recovered.contains("return x + y"),
        "yields and abrupt return must be reconstructed:\n{recovered}"
    );
    assert!(
        !recovered.contains("_context") && !recovered.contains("_regenerator"),
        "the state machine and runtime indirection must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("modern-generator", ORIG_GENERATOR, &recovered);
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
fn classic_regenerator_generator_restored_and_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_GENERATOR_CLASSIC);
    assert!(
        stats.regenerator_functions_restored >= 1,
        "the classic .prev/.next/.abrupt machine must be restored; got {}",
        stats.regenerator_functions_restored
    );
    assert!(
        recovered.contains("function* simple"),
        "must emit a real generator:\n{recovered}"
    );
    assert!(
        recovered.contains("x = yield 1") && recovered.contains("return x + y"),
        "yields and abrupt return must be reconstructed:\n{recovered}"
    );
    assert_recovered_equivalent("classic-generator", ORIG_GENERATOR, &recovered);
}

const ORIG_ASYNC: &str = r"
async function load(n) {
  var a = await Promise.resolve(n);
  var b = await Promise.resolve(a + 1);
  return a + b;
}
load(10).then(function (v) { print(v); });
";

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
fn modern_regenerator_async_pair_restored_and_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_ASYNC_MODERN);
    assert!(
        stats.async_functions_restored >= 1,
        "the async wrapper pair must be restored; got {}",
        stats.async_functions_restored
    );
    assert!(
        recovered.contains("async function load"),
        "must emit a real async function:\n{recovered}"
    );
    assert!(
        recovered.contains("a = await Promise.resolve(n)") && recovered.contains("return a + b"),
        "yields must become await and abrupt return a real return:\n{recovered}"
    );
    assert!(
        !recovered.contains("_asyncToGenerator") && !recovered.contains("_context2"),
        "the generator helper and state machine must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("modern-async", ORIG_ASYNC, &recovered);
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
