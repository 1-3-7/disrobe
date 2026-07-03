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

const BABEL7_FORM_A: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (var _i2 = 0; _i2 < items.length; _i2++) {
  var item = items[_i2];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn babel7_direct_index_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BABEL7_FORM_A);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the direct index loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains(" of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("items[_i2]") && !recovered.contains("_i2 <"),
        "the index scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("babel7_form_a", BABEL7_FORM_A, &recovered);
}

const BABEL7_FORM_A_BLOCK_SCOPED: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (let _i = 0; _i < items.length; _i++) {
  const item = items[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

#[test]
fn babel7_block_scoped_index_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BABEL7_FORM_A_BLOCK_SCOPED);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "must convert; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (const item of items)"),
        "a non-reassigned const element must stay const:\n{recovered}"
    );
    assert_recovered_equivalent(
        "babel7_form_a_block",
        BABEL7_FORM_A_BLOCK_SCOPED,
        &recovered,
    );
}

const LENGTH_CACHE_FORM_B: &str = r"
var arr = [1, 2, 3, 4];
var total = 0;
for (var _i = 0, _len = arr.length; _i < _len; _i++) {
  var n = arr[_i];
  total += n;
}
print(total);
";

#[test]
fn length_cache_loop_recovers_to_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(LENGTH_CACHE_FORM_B);
    assert!(
        stats.index_loops_to_for_of >= 1,
        "the length-cache loop must become for...of; got {}",
        stats.index_loops_to_for_of
    );
    assert!(
        recovered.contains("for (var n of arr)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert!(
        !recovered.contains("_len") && !recovered.contains("arr[_i]"),
        "the index and length-cache scaffolding must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("form_b", LENGTH_CACHE_FORM_B, &recovered);
}

const SAFETY_INDEX_USED: &str = r"
var xs = ['x', 'y'];
for (var _i = 0; _i < xs.length; _i++) {
  var v = xs[_i];
  print(_i + ':' + v);
}
";

#[test]
fn direct_loop_using_the_index_is_left_intact() {
    let want: String = eval_capture(SAFETY_INDEX_USED).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_INDEX_USED);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "the body reads the loop index, which for...of does not provide; leave it as-is"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
