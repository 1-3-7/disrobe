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

const INPUT: &str = r#"
print([10, 20, 30].length);
print("hello".length);
print([].length);
var arr = [1, 2];
print(arr.length);
"#;

#[test]
fn literal_length_folds_and_stays_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT);
    assert!(
        stats.literal_lengths_folded >= 3,
        "array/string literal .length must fold; got {}",
        stats.literal_lengths_folded
    );
    assert!(
        !recovered.contains("[10, 20, 30].length") && !recovered.contains("\"hello\".length"),
        "literal .length must be replaced with the constant:\n{recovered}"
    );
    assert!(
        recovered.contains("arr.length"),
        "a runtime array variable .length must be left untouched:\n{recovered}"
    );
    assert_recovered_equivalent("literal-length", INPUT, &recovered);
}
