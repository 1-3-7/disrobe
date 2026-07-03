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

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: down-compiled input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-written input is not behaviorally identical to the original BEFORE transform"
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

const ORIG_WRAPPER: &str = r"
async function load(n) {
  var a = await Promise.resolve(n);
  var b = await Promise.resolve(a + 1);
  return a + b;
}
load(10).then(function(v){ print(v); });
";

const INPUT_WRAPPER: &str = r"
function _asyncToGenerator(fn) {
  return function () {
    var self = this, args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);
      function step(key, arg) {
        try { var info = gen[key](arg); var value = info.value; } catch (e) { reject(e); return; }
        if (info.done) { resolve(value); } else { Promise.resolve(value).then(function (v) { step('next', v); }, function (e) { step('throw', e); }); }
      }
      step('next');
    });
  };
}
function load(n) {
  return _load.apply(this, arguments);
}
function _load() {
  _load = _asyncToGenerator(function* (n) {
    var a = yield Promise.resolve(n);
    var b = yield Promise.resolve(a + 1);
    return a + b;
  });
  return _load.apply(this, arguments);
}
load(10).then(function(v){ print(v); });
";

#[test]
fn babel_async_to_generator_wrapper_pair_reeval_equivalent() {
    assert_faithful_input("async/wrapper", ORIG_WRAPPER, INPUT_WRAPPER);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_WRAPPER);
    assert_eq!(
        stats.async_functions_restored, 1,
        "exactly one async function must be restored from the wrapper pair"
    );
    assert!(
        recovered.contains("async function load(n)"),
        "must emit `async function load(n)`:\n{recovered}"
    );
    assert!(
        recovered.contains("await Promise.resolve(n)"),
        "yield must be rewritten to await:\n{recovered}"
    );
    assert!(
        !recovered.contains("_asyncToGenerator(function*") && !recovered.contains("function _load"),
        "the generator helper and underscore wrapper must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("async/wrapper", ORIG_WRAPPER, &recovered);
}

const ORIG_DIRECT: &str = r"
var run = async function (x) {
  var y = await Promise.resolve(x * 2);
  return y + 1;
};
run(5).then(function(v){ print(v); });
";

const INPUT_DIRECT: &str = r"
function _asyncToGenerator(fn) {
  return function () {
    var self = this, args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);
      function step(key, arg) {
        try { var info = gen[key](arg); var value = info.value; } catch (e) { reject(e); return; }
        if (info.done) { resolve(value); } else { Promise.resolve(value).then(function (v) { step('next', v); }, function (e) { step('throw', e); }); }
      }
      step('next');
    });
  };
}
var run = _asyncToGenerator(function* (x) {
  var y = yield Promise.resolve(x * 2);
  return y + 1;
});
run(5).then(function(v){ print(v); });
";

#[test]
fn direct_async_to_generator_assignment_reeval_equivalent() {
    assert_faithful_input("async/direct", ORIG_DIRECT, INPUT_DIRECT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_DIRECT);
    assert_eq!(
        stats.async_functions_restored, 1,
        "the direct _asyncToGenerator assignment must be restored"
    );
    assert!(
        recovered.contains("run = async function"),
        "must emit `run = async function`:\n{recovered}"
    );
    assert!(
        recovered.contains("await Promise.resolve(x * 2)"),
        "yield must become await:\n{recovered}"
    );
    assert!(
        !recovered.contains("_asyncToGenerator(function*"),
        "generator indirection must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("async/direct", ORIG_DIRECT, &recovered);
}

const ORIG_BRANCHED: &str = r"
async function classify(n) {
  if (n > 0) {
    var p = await Promise.resolve('pos');
    return p;
  }
  var z = await Promise.resolve('nonpos');
  return z;
}
classify(3).then(function(v){ print(v); });
classify(-1).then(function(v){ print(v); });
";

const INPUT_BRANCHED: &str = r"
function _asyncToGenerator(fn) {
  return function () {
    var self = this, args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);
      function step(key, arg) {
        try { var info = gen[key](arg); var value = info.value; } catch (e) { reject(e); return; }
        if (info.done) { resolve(value); } else { Promise.resolve(value).then(function (v) { step('next', v); }, function (e) { step('throw', e); }); }
      }
      step('next');
    });
  };
}
function classify(n) {
  return _classify.apply(this, arguments);
}
function _classify() {
  _classify = _asyncToGenerator(function* (n) {
    if (n > 0) {
      var p = yield Promise.resolve('pos');
      return p;
    }
    var z = yield Promise.resolve('nonpos');
    return z;
  });
  return _classify.apply(this, arguments);
}
classify(3).then(function(v){ print(v); });
classify(-1).then(function(v){ print(v); });
";

#[test]
fn branched_async_with_multiple_yields_reeval_equivalent() {
    assert_faithful_input("async/branched", ORIG_BRANCHED, INPUT_BRANCHED);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_BRANCHED);
    assert_eq!(stats.async_functions_restored, 1);
    assert!(recovered.contains("async function classify(n)"));
    assert!(
        recovered.matches("await Promise.resolve").count() == 2,
        "both yields must become await:\n{recovered}"
    );
    assert_recovered_equivalent("async/branched", ORIG_BRANCHED, &recovered);
}

const NEG_PLAIN_GENERATOR: &str = r"
function* counter() {
  yield 1;
  yield 2;
}
var it = counter();
print(it.next().value);
print(it.next().value);
";

#[test]
fn negative_plain_generator_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_PLAIN_GENERATOR);
    assert_eq!(
        stats.async_functions_restored, 0,
        "a real user generator with no _asyncToGenerator wrapper must not be touched"
    );
    assert!(
        !recovered.contains("async function"),
        "must not fabricate async from a plain generator:\n{recovered}"
    );
}

const NEG_DELEGATE_YIELD: &str = r"
function inner_src() {
  return _inner.apply(this, arguments);
}
function _inner() {
  _inner = _asyncToGenerator(function* () {
    yield* [1, 2, 3];
  });
  return _inner.apply(this, arguments);
}
print(typeof inner_src);
";

#[test]
fn negative_delegate_yield_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_DELEGATE_YIELD);
    assert_eq!(
        stats.async_functions_restored, 0,
        "a generator containing yield* (delegate) cannot be faithfully converted to await; must be left alone"
    );
    assert!(
        recovered.contains("yield*"),
        "delegate yield must survive untouched:\n{recovered}"
    );
}
