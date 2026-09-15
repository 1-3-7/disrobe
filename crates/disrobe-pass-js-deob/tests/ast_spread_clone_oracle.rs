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

const INPUT: &str = r"
var tt = { a: 1, b: 2 };
var k = 'c';
var v = 3;
var l = {...tt};
l[k] = v;
print(JSON.stringify(l));
";

#[test]
fn spread_clone_merges_and_stays_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT);
    assert!(
        stats.spread_clones_merged >= 1,
        "the clone-then-index pattern must merge; got {}",
        stats.spread_clones_merged
    );
    assert!(
        recovered.contains("{...tt, [k]: v}"),
        "must produce an object-spread with a computed key:\n{recovered}"
    );
    assert!(
        !recovered.contains("l[k] = v"),
        "the trailing index assignment must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("spread-clone", INPUT, &recovered);
}

const NEG_SIDE_EFFECT: &str = r"
var calls = [];
function side() { calls.push('side'); return 9; }
var tt = { a: 1 };
var l = {...tt};
l['x'] = side();
print(JSON.stringify(l));
print(calls.length);
";

#[test]
fn spread_clone_keeps_side_effecting_value_equivalent() {
    let want: String = eval_capture(NEG_SIDE_EFFECT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_SIDE_EFFECT);
    assert_eq!(
        stats.spread_clones_merged, 0,
        "a side-effecting value must not be merged (order/identity safety)"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved:\n{recovered}");
}
