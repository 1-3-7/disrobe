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

const HELPER_RUNTIME: &str = r"
function _createForOfIteratorHelper(o, allowArrayLike) {
  var it = typeof Symbol !== 'undefined' && o[Symbol.iterator] || o['@@iterator'];
  if (!it) {
    if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || (allowArrayLike && o && typeof o.length === 'number')) {
      if (it) o = it;
      var i = 0;
      var F = function () {};
      return {
        s: F,
        n: function () {
          if (i >= o.length) return { done: true };
          return { done: false, value: o[i++] };
        },
        e: function (e) { throw e; },
        f: F
      };
    }
    throw new TypeError('not iterable');
  }
  var normalCompletion = true, didErr = false, err;
  return {
    s: function () { it = it.call(o); },
    n: function () {
      var step = it.next();
      normalCompletion = step.done;
      return step;
    },
    e: function (e) { didErr = true; err = e; },
    f: function () {
      try { if (!normalCompletion && it.return != null) it.return(); }
      finally { if (didErr) throw err; }
    }
  };
}
function _unsupportedIterableToArray(o, minLen) {
  if (!o) return;
  if (typeof o === 'string') return _arrayLikeToArray(o, minLen);
  var n = Object.prototype.toString.call(o).slice(8, -1);
  if (n === 'Object' && o.constructor) n = o.constructor.name;
  if (n === 'Map' || n === 'Set') return Array.from(o);
  if (n === 'Arguments' || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
}
function _arrayLikeToArray(arr, len) {
  if (len == null || len > arr.length) len = arr.length;
  for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i];
  return arr2;
}
";

const ORIG_COMBINED_DECL: &str = r"
var letters = ['a', 'b', 'c'];
var _iterator = _createForOfIteratorHelper(letters), _step;
try {
  for (_iterator.s(); !(_step = _iterator.n()).done;) {
    var letter = _step.value;
    print(letter.toUpperCase());
  }
} catch (err) {
  _iterator.e(err);
} finally {
  _iterator.f();
}
";

#[test]
fn babel_helper_combined_decl_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_COMBINED_DECL);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the _createForOfIteratorHelper loop must become for...of; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains(" of letters)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("_createForOfIteratorHelper")
            && !recovered.contains("_step.value")
            && !recovered.contains("_iterator.s()"),
        "the iterator-helper scaffolding must be gone:\n{recovered}"
    );
    let original: String = format!("{HELPER_RUNTIME}{ORIG_COMBINED_DECL}");
    let recovered_full: String = format!("{HELPER_RUNTIME}{recovered}");
    assert_recovered_equivalent("combined_decl", &original, &recovered_full);
}

const ORIG_SEPARATE_STEP_DECL: &str = r"
var nums = [10, 20, 30];
var total = 0;
var _iterator = _createForOfIteratorHelper(nums);
var _step;
try {
  for (_iterator.s(); !(_step = _iterator.n()).done;) {
    var n = _step.value;
    total += n;
  }
} catch (err) {
  _iterator.e(err);
} finally {
  _iterator.f();
}
print(total);
";

#[test]
fn babel_helper_separate_step_decl_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_SEPARATE_STEP_DECL);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "a separate `var _step;` decl form must also convert; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains(" of nums)"),
        "the for...of head must reference the iterable:\n{recovered}"
    );
    let original: String = format!("{HELPER_RUNTIME}{ORIG_SEPARATE_STEP_DECL}");
    let recovered_full: String = format!("{HELPER_RUNTIME}{recovered}");
    assert_recovered_equivalent("separate_step", &original, &recovered_full);
}

const ORIG_REASSIGNED_ELEMENT: &str = r"
var src = [1, 2, 3];
var doubled = [];
var _iterator = _createForOfIteratorHelper(src), _step;
try {
  for (_iterator.s(); !(_step = _iterator.n()).done;) {
    let v = _step.value;
    v = v * 2;
    doubled.push(v);
  }
} catch (err) {
  _iterator.e(err);
} finally {
  _iterator.f();
}
print(doubled.join(','));
";

#[test]
fn reassigned_element_uses_let() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_REASSIGNED_ELEMENT);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "must convert; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (let v of src)"),
        "a reassigned element must use let, not const:\n{recovered}"
    );
    let original: String = format!("{HELPER_RUNTIME}{ORIG_REASSIGNED_ELEMENT}");
    let recovered_full: String = format!("{HELPER_RUNTIME}{recovered}");
    assert_recovered_equivalent("reassigned", &original, &recovered_full);
}

const SAFETY_STEP_USED_AFTER: &str = r"
var xs = ['x', 'y'];
var _iterator = _createForOfIteratorHelper(xs), _step;
try {
  for (_iterator.s(); !(_step = _iterator.n()).done;) {
    var item = _step.value;
    print(item);
  }
} catch (err) {
  _iterator.e(err);
} finally {
  _iterator.f();
}
print(typeof _step);
";

#[test]
fn step_referenced_after_the_loop_blocks_conversion() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_STEP_USED_AFTER);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "the `_step` binding escapes the loop (read afterwards); collapsing it would drop a live binding"
    );
}

const SAFETY_PLAIN_TRY: &str = r"
var _iterator = compute();
try {
  doWork();
} catch (err) {
  handle(err);
} finally {
  cleanup();
}
";

#[test]
fn an_ordinary_try_finally_is_not_an_iterator_helper() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_PLAIN_TRY);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "a try/finally with no iterator-helper protocol must be left untouched"
    );
}

#[test]
#[should_panic(expected = "separate_step_decl_mutant: recovered diverged")]
fn a_recovery_that_drops_an_element_turns_the_grade_red() {
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(ORIG_SEPARATE_STEP_DECL);
    let mutant: String = recovered.replacen("total += n", "total += n - 1", 1);
    assert_ne!(
        mutant, recovered,
        "the mutation must apply to the recovered loop body"
    );
    let original: String = format!("{HELPER_RUNTIME}{ORIG_SEPARATE_STEP_DECL}");
    let mutant_full: String = format!("{HELPER_RUNTIME}{mutant}");
    assert_recovered_equivalent("separate_step_decl_mutant", &original, &mutant_full);
}
