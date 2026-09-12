#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

const VALUES_HELPER: &str = r#"
var __values = function(o) {
  var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
  if (m) return m.call(o);
  if (o && typeof o.length === "number") return {
    next: function () {
      if (o && i >= o.length) o = void 0;
      return { value: o && o[i++], done: !o };
    }
  };
  throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
"#;

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
        "{label}: desugared input not behaviorally identical to original BEFORE transform"
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

const ORIG_ARRAY: &str = r"
function collect(items) {
  var out = [];
  for (var x of items) {
    out.push(String(x).toUpperCase());
  }
  return out.join(',');
}
print(collect(['a', 'b', 'c']));
print(collect([]));
";

fn array_input() -> String {
    format!(
        "{VALUES_HELPER}{}",
        r"
function collect(items) {
  var e_1, _a;
  var out = [];
  try {
    for (var items_1 = __values(items), items_1_1 = items_1.next(); !items_1_1.done; items_1_1 = items_1.next()) {
      var x = items_1_1.value;
      out.push(String(x).toUpperCase());
    }
  }
  catch (e_1_1) { e_1 = { error: e_1_1 }; }
  finally {
    try {
      if (items_1_1 && !items_1_1.done && (_a = items_1.return)) _a.call(items_1);
    }
    finally { if (e_1) throw e_1.error; }
  }
  return out.join(',');
}
print(collect(['a', 'b', 'c']));
print(collect([]));
"
    )
}

fn array_original() -> String {
    format!("{VALUES_HELPER}{ORIG_ARRAY}")
}

#[test]
fn ts_values_for_of_array_recovers() {
    let input: String = array_input();
    assert_faithful_input("values-array", &array_original(), &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the __values protocol loop must become for...of; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var x of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("__values(") && !recovered.contains(".done"),
        "the iterator-protocol scaffolding must be gone:\n{recovered}"
    );
    assert!(
        !recovered.contains("e_1") && !recovered.contains("items_1"),
        "the error/iterator scaffold vars must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("values-array", &array_original(), &recovered);
}

const ORIG_SET: &str = r"
function dump(s) {
  var out = [];
  for (var v of s) {
    out.push(v);
  }
  return out.join('|');
}
var set = new Set(['p', 'q', 'r']);
print(dump(set));
";

fn set_input() -> String {
    format!(
        "{VALUES_HELPER}{}",
        r"
function dump(s) {
  var e_1, _a;
  var out = [];
  try {
    for (var s_1 = __values(s), s_1_1 = s_1.next(); !s_1_1.done; s_1_1 = s_1.next()) {
      var v = s_1_1.value;
      out.push(v);
    }
  }
  catch (e_1_1) { e_1 = { error: e_1_1 }; }
  finally {
    try {
      if (s_1_1 && !s_1_1.done && (_a = s_1.return)) _a.call(s_1);
    }
    finally { if (e_1) throw e_1.error; }
  }
  return out.join('|');
}
var set = new Set(['p', 'q', 'r']);
print(dump(set));
"
    )
}

fn set_original() -> String {
    format!("{VALUES_HELPER}{ORIG_SET}")
}

#[test]
fn ts_values_for_of_set_recovers() {
    let input: String = set_input();
    assert_faithful_input("values-set", &set_original(), &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the __values loop over a Set must become for...of; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var v of s)"),
        "must recover the iterable `s`:\n{recovered}"
    );
    assert_recovered_equivalent("values-set", &set_original(), &recovered);
}

const ORIG_EARLY_BREAK: &str = r"
function firstTwo(items) {
  var out = [];
  for (var x of items) {
    if (out.length === 2) { break; }
    out.push(x);
  }
  return out.join(',');
}
print(firstTwo(['a', 'b', 'c', 'd']));
";

fn early_break_input() -> String {
    format!(
        "{VALUES_HELPER}{}",
        r"
function firstTwo(items) {
  var e_1, _a;
  var out = [];
  try {
    for (var items_1 = __values(items), items_1_1 = items_1.next(); !items_1_1.done; items_1_1 = items_1.next()) {
      var x = items_1_1.value;
      if (out.length === 2) { break; }
      out.push(x);
    }
  }
  catch (e_1_1) { e_1 = { error: e_1_1 }; }
  finally {
    try {
      if (items_1_1 && !items_1_1.done && (_a = items_1.return)) _a.call(items_1);
    }
    finally { if (e_1) throw e_1.error; }
  }
  return out.join(',');
}
print(firstTwo(['a', 'b', 'c', 'd']));
"
    )
}

fn early_break_original() -> String {
    format!("{VALUES_HELPER}{ORIG_EARLY_BREAK}")
}

#[test]
fn ts_values_for_of_early_break_recovers() {
    let input: String = early_break_input();
    assert_faithful_input("values-break", &early_break_original(), &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the loop with an early break must still become for...of; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var x of items)"),
        "must recover the for...of:\n{recovered}"
    );
    assert_recovered_equivalent("values-break", &early_break_original(), &recovered);
}

const ORIG_THROW_CLEANUP: &str = r"
function consume(items) {
  var log = [];
  var it = {};
  it[Symbol.iterator] = function () {
    var i = 0;
    return {
      next: function () {
        if (i < items.length) { return { value: items[i++], done: false }; }
        return { value: undefined, done: true };
      },
      return: function () { log.push('cleanup'); return { done: true }; }
    };
  };
  var err = 'none';
  try {
    for (var x of it) {
      if (x === 'boom') { throw new Error('halt'); }
      log.push(x);
    }
  } catch (e) {
    err = e.message;
  }
  return log.join(',') + '/' + err;
}
print(consume(['a', 'boom', 'c']));
";

fn throw_cleanup_input() -> String {
    format!(
        "{VALUES_HELPER}{}",
        r"
function consume(items) {
  var e_1, _a;
  var log = [];
  var it = {};
  it[Symbol.iterator] = function () {
    var i = 0;
    return {
      next: function () {
        if (i < items.length) { return { value: items[i++], done: false }; }
        return { value: undefined, done: true };
      },
      return: function () { log.push('cleanup'); return { done: true }; }
    };
  };
  var err = 'none';
  try {
    try {
      for (var it_1 = __values(it), it_1_1 = it_1.next(); !it_1_1.done; it_1_1 = it_1.next()) {
        var x = it_1_1.value;
        if (x === 'boom') { throw new Error('halt'); }
        log.push(x);
      }
    }
    catch (e_1_1) { e_1 = { error: e_1_1 }; }
    finally {
      try {
        if (it_1_1 && !it_1_1.done && (_a = it_1.return)) _a.call(it_1);
      }
      finally { if (e_1) throw e_1.error; }
    }
  } catch (e) {
    err = e.message;
  }
  return log.join(',') + '/' + err;
}
print(consume(['a', 'boom', 'c']));
"
    )
}

fn throw_cleanup_original() -> String {
    format!("{VALUES_HELPER}{ORIG_THROW_CLEANUP}")
}

#[test]
fn ts_values_for_of_throw_runs_iterator_cleanup() {
    let input: String = throw_cleanup_input();
    assert_faithful_input("values-throw", &throw_cleanup_original(), &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the protocol loop must recover even when the body throws; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var x of it)"),
        "must recover the for...of head:\n{recovered}"
    );
    assert_recovered_equivalent("values-throw", &throw_cleanup_original(), &recovered);
}

const SAFETY_PLAIN_TRY_FOR: &str = r"
function risky(n) {
  var total = 0;
  try {
    for (var i = 0, j = 10; i < j; i++) {
      total += i;
    }
  } catch (e) {
    total = -1;
  } finally {
    total += 100;
  }
  return total;
}
print(risky(5));
";

#[test]
fn ordinary_try_wrapped_counting_loop_is_not_a_for_of() {
    let want: String = eval_capture(SAFETY_PLAIN_TRY_FOR).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_PLAIN_TRY_FOR);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "a plain counting loop in try/catch/finally is not an iterator-protocol loop"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
