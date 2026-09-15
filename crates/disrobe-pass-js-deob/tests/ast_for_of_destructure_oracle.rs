#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

const BABEL_HELPERS: &str = r#"
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
function _createForOfIteratorHelper(r, e) { var t = "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (!t) { if (Array.isArray(r) || (t = _unsupportedIterableToArray(r)) || e && r && "number" == typeof r.length) { t && (r = t); var _n = 0, F = function F() {}; return { s: F, n: function n() { return _n >= r.length ? { done: !0 } : { done: !1, value: r[_n++] }; }, e: function e(r) { throw r; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var o, a = !0, u = !1; return { s: function s() { t = t.call(r); }, n: function n() { var r = t.next(); return a = r.done, r; }, e: function e(r) { u = !0, o = r; }, f: function f() { try { a || null == t.return || t.return(); } finally { if (u) throw o; } } }; }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
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
        eval_capture(input).unwrap_or_else(|| panic!("{label}: babel input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: babel-desugared input not behaviorally identical to original BEFORE transform"
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

const ORIG_ENTRIES: &str = r#"
function dump(m) {
  var out = [];
  for (var [k, v] of m) {
    out.push(k + "=" + v);
  }
  return out.join(",");
}
print(dump(new Map([["a", 1], ["b", 2]])));
print(dump([[1, 2], [3, 4]]));
"#;

const BABEL_ENTRIES: &str = r#"
function dump(m) {
  var out = [];
  var _iterator = _createForOfIteratorHelper(m),
    _step;
  try {
    for (_iterator.s(); !(_step = _iterator.n()).done;) {
      var _step$value = _slicedToArray(_step.value, 2),
        k = _step$value[0],
        v = _step$value[1];
      out.push(k + "=" + v);
    }
  } catch (err) {
    _iterator.e(err);
  } finally {
    _iterator.f();
  }
  return out.join(",");
}
print(dump(new Map([["a", 1], ["b", 2]])));
print(dump([[1, 2], [3, 4]]));
"#;

fn entries_original() -> String {
    format!("{BABEL_HELPERS}{ORIG_ENTRIES}")
}

fn entries_input() -> String {
    format!("{BABEL_HELPERS}{BABEL_ENTRIES}")
}

#[test]
fn babel_createforof_array_destructure_recovers() {
    let input: String = entries_input();
    assert_faithful_input("entries", &entries_original(), &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "the _createForOfIteratorHelper loop must become for...of; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var [k, v] of m)"),
        "the for...of head must restore the array-destructuring binding:\n{recovered}"
    );
    assert!(
        !recovered.contains("_slicedToArray(_step") && !recovered.contains("_step$value"),
        "the _slicedToArray destructuring scaffold must be gone from the loop body:\n{recovered}"
    );
    assert!(
        !recovered.contains("_createForOfIteratorHelper(m)")
            && !recovered.contains("_iterator.s()"),
        "the iterator-protocol call sites must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("entries", &entries_original(), &recovered);
}

const ORIG_THREE: &str = r#"
function triples(rows) {
  var out = [];
  for (var [a, b, c] of rows) {
    out.push(a * 100 + b * 10 + c);
  }
  return out.join("|");
}
print(triples([[1, 2, 3], [4, 5, 6]]));
"#;

const BABEL_THREE: &str = r#"
function triples(rows) {
  var out = [];
  var _iterator = _createForOfIteratorHelper(rows),
    _step;
  try {
    for (_iterator.s(); !(_step = _iterator.n()).done;) {
      var _step$value = _slicedToArray(_step.value, 3),
        a = _step$value[0],
        b = _step$value[1],
        c = _step$value[2];
      out.push(a * 100 + b * 10 + c);
    }
  } catch (err) {
    _iterator.e(err);
  } finally {
    _iterator.f();
  }
  return out.join("|");
}
print(triples([[1, 2, 3], [4, 5, 6]]));
"#;

#[test]
fn babel_createforof_three_element_destructure_recovers() {
    let original: String = format!("{BABEL_HELPERS}{ORIG_THREE}");
    let input: String = format!("{BABEL_HELPERS}{BABEL_THREE}");
    assert_faithful_input("triples", &original, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "three-element destructure loop must convert; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var [a, b, c] of rows)"),
        "must restore the 3-element destructure head:\n{recovered}"
    );
    assert_recovered_equivalent("triples", &original, &recovered);
}

const ORIG_PLAIN: &str = r#"
function names(items) {
  var out = [];
  for (var x of items) {
    out.push(x.toUpperCase());
  }
  return out.join(",");
}
print(names(["a", "b"]));
"#;

const BABEL_PLAIN: &str = r#"
function names(items) {
  var out = [];
  var _iterator = _createForOfIteratorHelper(items),
    _step;
  try {
    for (_iterator.s(); !(_step = _iterator.n()).done;) {
      var x = _step.value;
      out.push(x.toUpperCase());
    }
  } catch (err) {
    _iterator.e(err);
  } finally {
    _iterator.f();
  }
  return out.join(",");
}
print(names(["a", "b"]));
"#;

#[test]
fn babel_createforof_plain_binding_still_recovers() {
    let original: String = format!("{BABEL_HELPERS}{ORIG_PLAIN}");
    let input: String = format!("{BABEL_HELPERS}{BABEL_PLAIN}");
    assert_faithful_input("plain", &original, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.helper_loops_to_for_of >= 1,
        "plain helper loop must still convert; got {}",
        stats.helper_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var x of items)"),
        "plain single-binding head must be unaffected by the destructure path:\n{recovered}"
    );
    assert_recovered_equivalent("plain", &original, &recovered);
}

const BABEL_TEMP_LEAK: &str = r#"
function dump(m) {
  var out = [];
  var _iterator = _createForOfIteratorHelper(m),
    _step;
  try {
    for (_iterator.s(); !(_step = _iterator.n()).done;) {
      var _step$value = _slicedToArray(_step.value, 2),
        k = _step$value[0],
        v = _step$value[1];
      out.push(k + "=" + v + "/" + _step$value.length);
    }
  } catch (err) {
    _iterator.e(err);
  } finally {
    _iterator.f();
  }
  return out.join(",");
}
print(dump(new Map([["a", 1]])));
"#;

#[test]
fn temp_ref_used_in_body_blocks_destructure_conversion() {
    let input: String = format!("{BABEL_HELPERS}{BABEL_TEMP_LEAK}");
    let want: String = eval_capture(&input).expect("input evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert_eq!(
        stats.helper_loops_to_for_of, 0,
        "the loop body still reads the _slicedToArray temp, so collapsing it to a destructure would drop a live binding"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved when conversion is blocked");
}
