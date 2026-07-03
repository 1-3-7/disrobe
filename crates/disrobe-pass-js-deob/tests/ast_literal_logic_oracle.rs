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

const ORIG_INFINITY: &str = r"
function caps(x) {
  if (x > Infinity) { return 'over'; }
  if (x < -Infinity) { return 'under'; }
  return 'normal';
}
print(caps(5));
print(1 / 0);
print(-1 / 0);
";

const INPUT_INFINITY: &str = r"
function caps(x) {
  if (x > 1 / 0) { return 'over'; }
  if (x < -1 / 0) { return 'under'; }
  return 'normal';
}
print(caps(5));
print(1 / 0);
print(-1 / 0);
";

#[test]
fn un_infinity_fold_reeval_equivalent() {
    assert_faithful_input("infinity", ORIG_INFINITY, INPUT_INFINITY);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_INFINITY);
    assert!(
        stats.infinity_folds >= 3,
        "1/0 and -1/0 occurrences must be folded; got {}",
        stats.infinity_folds
    );
    assert!(
        recovered.contains("Infinity") && recovered.contains("-Infinity"),
        "must emit Infinity and -Infinity literals:\n{recovered}"
    );
    assert!(
        !recovered.contains("1 / 0"),
        "the 1/0 division shape must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("infinity", ORIG_INFINITY, &recovered);
}

const ORIG_TYPEOF: &str = r"
var x;
function probe(v) { return typeof v === 'undefined' ? 'no' : 'yes'; }
print(probe(x));
print(probe(7));
";

const INPUT_TYPEOF: &str = r"
var x;
function probe(v) { return 'undefined' == typeof v ? 'no' : 'yes'; }
print(probe(x));
print(probe(7));
";

#[test]
fn typeof_undefined_normalize_reeval_equivalent() {
    assert_faithful_input("typeof", ORIG_TYPEOF, INPUT_TYPEOF);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_TYPEOF);
    assert!(
        stats.typeof_undefined_normalized >= 1,
        "the yoda typeof comparison must be normalized; got {}",
        stats.typeof_undefined_normalized
    );
    assert!(
        recovered.contains("typeof v === \"undefined\""),
        "must canonicalize to `typeof v === \"undefined\"`:\n{recovered}"
    );
    assert_recovered_equivalent("typeof", ORIG_TYPEOF, &recovered);
}

const ORIG_YODA: &str = r"
function classify(n) {
  if (n === 5) { return 'five'; }
  if (n !== 0) { return 'nonzero'; }
  return 'zero';
}
print(classify(5));
print(classify(3));
print(classify(0));
";

const INPUT_YODA: &str = r"
function classify(n) {
  if (5 === n) { return 'five'; }
  if (0 !== n) { return 'nonzero'; }
  return 'zero';
}
print(classify(5));
print(classify(3));
print(classify(0));
";

#[test]
fn un_yoda_equality_flip_reeval_equivalent() {
    assert_faithful_input("yoda", ORIG_YODA, INPUT_YODA);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_YODA);
    assert!(
        stats.yoda_flips >= 2,
        "both yoda equality comparisons must flip; got {}",
        stats.yoda_flips
    );
    assert!(
        recovered.contains("n === 5") && recovered.contains("n !== 0"),
        "literal must move to the right of the comparison:\n{recovered}"
    );
    assert_recovered_equivalent("yoda", ORIG_YODA, &recovered);
}

const ORIG_JSON: &str = r"
var cfg = { name: 'app', version: 2, tags: ['a', 'b'] };
print(cfg.name);
print(cfg.version);
print(cfg.tags[1]);
";

const INPUT_JSON: &str = r#"
var cfg = JSON.parse("{\"name\":\"app\",\"version\":2,\"tags\":[\"a\",\"b\"]}");
print(cfg.name);
print(cfg.version);
print(cfg.tags[1]);
"#;

#[test]
fn json_parse_fold_reeval_equivalent() {
    assert_faithful_input("json", ORIG_JSON, INPUT_JSON);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_JSON);
    assert!(
        stats.json_parse_folds >= 1,
        "JSON.parse of a literal string must fold; got {}",
        stats.json_parse_folds
    );
    assert!(
        !recovered.contains("JSON.parse"),
        "the JSON.parse indirection must be gone:\n{recovered}"
    );
    assert!(
        recovered.contains("\"name\"") && recovered.contains("\"tags\""),
        "must emit the object literal:\n{recovered}"
    );
    assert_recovered_equivalent("json", ORIG_JSON, &recovered);
}

const ORIG_MERGE: &str = r"
var o = { a: 1, b: 2, c: 3 };
print(o.a + o.b + o.c);
";

const INPUT_MERGE: &str = r"
var o = {};
o.a = 1;
o.b = 2;
o.c = 3;
print(o.a + o.b + o.c);
";

#[test]
fn merge_object_assignments_reeval_equivalent() {
    assert_faithful_input("merge", ORIG_MERGE, INPUT_MERGE);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_MERGE);
    assert!(
        stats.object_assignment_merges >= 1,
        "the consecutive property assignments must merge; got {}",
        stats.object_assignment_merges
    );
    assert!(
        recovered.contains("a: 1") && recovered.contains("c: 3"),
        "must emit a merged object literal:\n{recovered}"
    );
    assert!(
        !recovered.contains("o.a = 1"),
        "the separate assignment statements must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("merge", ORIG_MERGE, &recovered);
}

const NEG_MERGE_READ_BETWEEN: &str = r"
function tap(v) { return v; }
var o = {};
o.a = 1;
tap(o);
o.b = 2;
print(o.a + o.b);
";

#[test]
fn negative_merge_does_not_span_a_read() {
    let want: String = eval_capture(NEG_MERGE_READ_BETWEEN).expect("evaluates");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(NEG_MERGE_READ_BETWEEN);
    assert!(
        recovered.contains("o.b = 2"),
        "the property after tap(o) must NOT be pulled into a literal across the read:\n{recovered}"
    );
    assert!(
        recovered.contains("tap(o)"),
        "the intervening read must be preserved in place:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "merging must not reorder the observable read; behavior preserved"
    );
}

const NEG_MERGE_SELF_READ: &str = r"
var o = {};
o.a = 1;
o.b = o.a + 1;
print(o.a + o.b);
";

#[test]
fn negative_merge_does_not_pull_a_self_referencing_value() {
    let want: String = eval_capture(NEG_MERGE_SELF_READ).expect("evaluates");
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(NEG_MERGE_SELF_READ);
    assert!(
        recovered.contains("o.b = o.a + 1"),
        "o.b reads o.a so it must NOT be folded into the literal (o.a is not yet a property there):\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior must be preserved");
}

const NEG_YODA_RELATIONAL: &str = r"
function f(n) { return 5 < n ? 'big' : 'small'; }
print(f(7));
print(f(2));
";

#[test]
fn negative_relational_yoda_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_YODA_RELATIONAL);
    assert_eq!(
        stats.yoda_flips, 0,
        "relational `<` is not flipped without swapping the operator; left conservative"
    );
    assert!(
        recovered.contains("5 < n"),
        "relational comparison must be left untouched:\n{recovered}"
    );
}
