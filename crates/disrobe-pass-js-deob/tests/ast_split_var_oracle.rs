#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
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

const ORIG: &str = r"
var a = 1;
var b = 2;
var c = a + b;
print(a);
print(b);
print(c);
";

const INPUT: &str = r"
var a = 1, b = 2, c = a + b;
print(a);
print(b);
print(c);
";

#[test]
fn grouped_var_declaration_splits_reeval_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT);
    assert!(
        stats.var_declarations_split >= 1,
        "the grouped var must split; got {}",
        stats.var_declarations_split
    );
    assert!(
        stats.var_declarators_emitted >= 3,
        "three declarators must be emitted; got {}",
        stats.var_declarators_emitted
    );
    assert!(
        recovered.contains("a = 1;")
            && recovered.contains("b = 2;")
            && recovered.contains("c = a + b;"),
        "each declarator must become its own statement:\n{recovered}"
    );
    assert!(
        !recovered.contains("var a = 1, b = 2"),
        "the grouped comma form must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("split", ORIG, &recovered);
}

const INPUT_LET: &str = r"
let p = 10, q = 20;
print(p + q);
";

#[test]
fn grouped_let_splits() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_LET);
    assert!(
        stats.var_declarations_split >= 1,
        "the grouped let must split"
    );
    assert!(
        recovered.contains("let p = 10;") && recovered.contains("let q = 20;"),
        "let declarators must split:\n{recovered}"
    );
    assert_recovered_equivalent("let", INPUT_LET, &recovered);
}

const NEG_FOR_INIT: &str = r"
var sum = 0;
for (var i = 0, n = 3; i < n; i++) { sum += i; }
print(sum);
";

#[test]
fn negative_for_init_grouped_decl_unchanged() {
    let want: String = eval_capture(NEG_FOR_INIT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_FOR_INIT);
    assert_eq!(
        stats.var_declarations_split, 0,
        "the for-init grouped declaration must NOT be split (illegal as separate statements there)"
    );
    assert!(
        recovered.contains("var i = 0, n = 3"),
        "the for-init comma must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_SINGLE: &str = r"
var only = 5;
print(only);
";

#[test]
fn negative_single_declarator_unchanged() {
    let (_, stats): (String, AstUnminifyStats) = unminify_ast(NEG_SINGLE);
    assert_eq!(
        stats.var_declarations_split, 0,
        "a single-declarator var must NOT be touched"
    );
}
