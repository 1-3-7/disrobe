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
        eval_capture(input).unwrap_or_else(|| panic!("{label}: input must evaluate"));
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

const HELPERS: &str = r"
function _arrayWithoutHoles(arr) { if (Array.isArray(arr)) { var r = []; for (var i = 0; i < arr.length; i++) { r[i] = arr[i]; } return r; } }
function _iterableToArray(iter) { var r = []; var it = iter[Symbol.iterator](); var step; while (!(step = it.next()).done) { r.push(step.value); } return r; }
function _toConsumableArray(arr) { return _arrayWithoutHoles(arr) || _iterableToArray(arr) || []; }
function _spread(arr) { return _toConsumableArray(arr); }
function _slicedToArray(arr, n) { var r = []; for (var i = 0; i < n; i++) { r[i] = arr[i]; } return r; }
function _extends() { var t = arguments[0]; for (var i = 1; i < arguments.length; i++) { var s = arguments[i]; for (var k in s) { if (Object.prototype.hasOwnProperty.call(s, k)) { t[k] = s[k]; } } } return t; }
function _defineProperty(o, k, v) { o[k] = v; return o; }
function ownKeys(o) { var keys = Object.keys(o); return keys; }
function _objectSpread(t) { for (var i = 1; i < arguments.length; i++) { var s = arguments[i] != null ? arguments[i] : {}; ownKeys(s).forEach(function(k) { _defineProperty(t, k, s[k]); }); } return t; }
function _objectSpread2(t) { return _objectSpread.apply(this, arguments); }
";

const ORIG_ARRAY_SPREAD: &str = r"
var head = [1, 2];
var tail = [3, 4];
var all = [...head, ...tail];
var copy = [...head];
print(all.join(','));
print(copy.join(','));
";

const INPUT_ARRAY_SPREAD: &str = r"
var head = [1, 2];
var tail = [3, 4];
var all = [].concat(_toConsumableArray(head), _toConsumableArray(tail));
var copy = _toConsumableArray(head);
print(all.join(','));
print(copy.join(','));
";

#[test]
fn array_spread_rebuild_reeval_equivalent() {
    let orig: String = format!("{HELPERS}{ORIG_ARRAY_SPREAD}");
    let input: String = format!("{HELPERS}{INPUT_ARRAY_SPREAD}");
    assert_faithful_input("array_spread", &orig, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.array_spreads_rebuilt >= 3,
        "two _toConsumableArray helper calls plus the .concat shape must rebuild; got {}",
        stats.array_spreads_rebuilt
    );
    assert!(
        recovered.contains("[...head, ...tail]"),
        "concat of spreads must become an array spread:\n{recovered}"
    );
    assert!(
        recovered.contains("[...head]"),
        "the lone _toConsumableArray must become [...head]:\n{recovered}"
    );
    assert!(
        !recovered.contains("_toConsumableArray(head)"),
        "the helper indirection must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("array_spread", &orig, &recovered);
}

const ORIG_OBJECT_SPREAD: &str = r"
var base = { a: 1, b: 2 };
var more = { c: 3 };
var merged = { ...base, ...more, d: 4 };
print(merged.a);
print(merged.b);
print(merged.c);
print(merged.d);
";

const INPUT_OBJECT_SPREAD: &str = r"
var base = { a: 1, b: 2 };
var more = { c: 3 };
var merged = _objectSpread(_objectSpread(_objectSpread({}, base), more), {}, { d: 4 });
print(merged.a);
print(merged.b);
print(merged.c);
print(merged.d);
";

#[test]
fn object_spread_rebuild_reeval_equivalent() {
    let orig: String = format!("{HELPERS}{ORIG_OBJECT_SPREAD}");
    let input: String = format!("{HELPERS}{INPUT_OBJECT_SPREAD}");
    assert_faithful_input("object_spread", &orig, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.object_spreads_rebuilt >= 1,
        "the _objectSpread helper chain must rebuild; got {}",
        stats.object_spreads_rebuilt
    );
    assert!(
        recovered.contains("..."),
        "must emit object spread syntax:\n{recovered}"
    );
    assert!(
        !recovered.contains("_objectSpread({}")
            && !recovered.contains("_objectSpread(_objectSpread"),
        "the helper call sites must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("object_spread", &orig, &recovered);
}

const ORIG_EXTENDS: &str = r"
var defaults = { theme: 'dark', size: 10 };
var overrides = { size: 20 };
var cfg = { ...defaults, ...overrides };
print(cfg.theme);
print(cfg.size);
";

const INPUT_EXTENDS: &str = r"
var defaults = { theme: 'dark', size: 10 };
var overrides = { size: 20 };
var cfg = _extends({}, defaults, overrides);
print(cfg.theme);
print(cfg.size);
";

#[test]
fn extends_rebuild_reeval_equivalent() {
    let orig: String = format!("{HELPERS}{ORIG_EXTENDS}");
    let input: String = format!("{HELPERS}{INPUT_EXTENDS}");
    assert_faithful_input("extends", &orig, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.object_spreads_rebuilt >= 1,
        "the _extends helper must rebuild into spread; got {}",
        stats.object_spreads_rebuilt
    );
    assert!(
        recovered.contains("...defaults") && recovered.contains("...overrides"),
        "must spread both source objects:\n{recovered}"
    );
    assert!(
        !recovered.contains("_extends({}"),
        "the helper call site must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("extends", &orig, &recovered);
}

const ORIG_OBJECT_ASSIGN: &str = r"
var src = { x: 1, y: 2 };
var clone = { ...src };
print(clone.x);
print(clone.y);
";

const INPUT_OBJECT_ASSIGN: &str = r"
var src = { x: 1, y: 2 };
var clone = Object.assign({}, src);
print(clone.x);
print(clone.y);
";

#[test]
fn object_assign_empty_first_arg_reeval_equivalent() {
    assert_faithful_input("object_assign", ORIG_OBJECT_ASSIGN, INPUT_OBJECT_ASSIGN);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_OBJECT_ASSIGN);
    assert!(
        stats.object_spreads_rebuilt >= 1,
        "Object.assign with an empty first arg must rebuild into spread; got {}",
        stats.object_spreads_rebuilt
    );
    assert!(
        recovered.contains("...src"),
        "must spread src:\n{recovered}"
    );
    assert!(
        !recovered.contains("Object.assign"),
        "the Object.assign indirection must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("object_assign", ORIG_OBJECT_ASSIGN, &recovered);
}

const ORIG_SLICED: &str = r"
var pair = [10, 20];
var a = pair[0], b = pair[1];
print(a);
print(b);
";

const INPUT_SLICED: &str = r"
var pair = [10, 20];
var _ref = _slicedToArray(pair, 2), a = _ref[0], b = _ref[1];
print(a);
print(b);
";

#[test]
fn sliced_to_array_destructure_reeval_equivalent() {
    let orig: String = format!("{HELPERS}{ORIG_SLICED}");
    let input: String = format!("{HELPERS}{INPUT_SLICED}");
    assert_faithful_input("sliced", &orig, &input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&input);
    assert!(
        stats.array_destructures_rebuilt >= 1,
        "the _slicedToArray triple must rebuild into a destructure; got {}",
        stats.array_destructures_rebuilt
    );
    assert!(
        recovered.contains("[a, b] = pair"),
        "must rebuild array destructuring binding:\n{recovered}"
    );
    assert!(
        !recovered.contains("_slicedToArray(pair"),
        "the helper call site must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("sliced", &orig, &recovered);
}

const NEG_OBJECT_ASSIGN_TARGET: &str = r"
var target = { existing: 1 };
var src = { added: 2 };
var out = Object.assign(target, src);
print(out.existing);
print(out.added);
print(target.added);
";

#[test]
fn negative_object_assign_into_existing_target_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_OBJECT_ASSIGN_TARGET);
    assert_eq!(
        stats.object_spreads_rebuilt, 0,
        "Object.assign that mutates a real first arg must NOT become spread (it mutates target)"
    );
    assert!(
        recovered.contains("Object.assign(target, src)"),
        "the mutating Object.assign must be left untouched:\n{recovered}"
    );
}

const NEG_CONCAT_NONEMPTY_BASE: &str = r"
var base = [0];
var more = [1, 2];
var out = base.concat(more);
print(out.join(','));
";

#[test]
fn negative_concat_with_nonempty_base_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_CONCAT_NONEMPTY_BASE);
    assert_eq!(
        stats.array_spreads_rebuilt, 0,
        "concat on a non-empty base array is not a spread rebuild; left conservative"
    );
    assert!(
        recovered.contains("base.concat(more)"),
        "the real concat must be preserved:\n{recovered}"
    );
}
