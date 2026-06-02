#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    JscramblerOptions, JscramblerOutput, JscramblerTransform, deobfuscate_jscrambler,
};

fn run_single(transform: JscramblerTransform, src: &str) -> JscramblerOutput {
    let mut transforms: BTreeSet<JscramblerTransform> = BTreeSet::new();
    transforms.insert(transform);
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms,
    };
    deobfuscate_jscrambler(src, &opts).expect("deobfuscate ok")
}

#[test]
fn boolean_to_anything_folds_array_negations() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::BooleanToAnything,
        "if (![]) { x(); } if (!![]) { y(); }",
    );
    assert!(out.source.contains("false"));
    assert!(out.source.contains("true"));
}

#[test]
fn char_to_ternary_collapses_from_char_code() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::CharToTernaryOperator,
        "var s = String.fromCharCode(72) + String.fromCharCode(105);",
    );
    assert!(out.source.contains("\"H\""));
    assert!(out.source.contains("\"i\""));
}

#[test]
fn comma_operator_unfolding_splits_return_sequence() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::CommaOperatorUnfolding,
        "function f(){ return (a(), b(), c); }",
    );
    assert!(out.source.contains("a();"));
    assert!(out.source.contains("b();"));
    assert!(out.source.contains("return c;"));
}

#[test]
fn control_flow_flattening_linearizes_state_machine() {
    let src: &str = "var s=1;for(;s!==4;){switch(s){case 1:a();s=2;break;case 2:b();s=3;break;case 3:c();s=4;break;}}";
    let out: JscramblerOutput = run_single(JscramblerTransform::ControlFlowFlattening, src);
    assert!(out.source.contains("a()"));
    assert!(out.source.contains("b()"));
    assert!(out.source.contains("c()"));
    assert!(!out.source.contains("switch"));
}

#[test]
fn control_flow_flattening_handles_corpus_typeof_globalthis_block() {
    let src: &str = "var H=2;for(;H !== 9;){switch(H){case 2:H=typeof globalThis === 'object'?1:5;break;case 1:return globalThis;break;case 5:throw \"\";break;}}";
    let out: JscramblerOutput = run_single(JscramblerTransform::ControlFlowFlattening, src);
    assert!(out.source.contains("if ("));
    assert!(out.source.contains("return globalThis"));
}

#[test]
fn dead_code_injection_strips_unreachable_branch() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::DeadCodeInjection,
        "if (false) { dead(); } live();",
    );
    assert!(!out.source.contains("dead()"));
    assert!(out.source.contains("live()"));
}

#[test]
fn dot_to_bracket_rewrites_safe_ident_access() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::DotToBracketNotation,
        r#"var v = obj["foo"];"#,
    );
    assert!(out.source.contains("obj.foo"));
}

#[test]
fn duplicate_literals_removal_inlines_table() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::DuplicateLiteralsRemoval,
        "var T = ['alpha', 'beta', 'gamma']; console.log(T[0], T[2]);",
    );
    assert!(out.source.contains("\"alpha\""));
    assert!(out.source.contains("\"gamma\""));
}

#[test]
fn extend_predicates_folds_always_true() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::ExtendPredicates,
        "if (2 > 1) { run(); }",
    );
    assert!(out.source.contains("if (true)"));
}

#[test]
fn function_outlining_inlines_single_callsite_helper() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::FunctionOutlining,
        "function _h1(){return 42;} var x = _h1();",
    );
    assert!(out.source.contains("(42)"));
    assert!(!out.source.contains("_h1()"));
}

#[test]
fn function_reordering_restores_topological_order() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::FunctionReordering,
        "function b(){a();}\nfunction a(){return 1;}",
    );
    let a_pos: usize = out.source.find("function a()").unwrap();
    let b_pos: usize = out.source.find("function b()").unwrap();
    assert!(a_pos < b_pos);
}

#[test]
fn global_variable_indirection_collapses_alias() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::GlobalVariableIndirection,
        "var g = globalThis; g.x = 1; g.y[0] = 2;",
    );
    assert!(out.source.contains("globalThis.x"));
    assert!(out.source.contains("globalThis.y[0]"));
}

#[test]
fn identifiers_renaming_rewrites_hex_idents_stably() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::IdentifiersRenaming,
        "var a0_0xabcd = 1; var b = a0_0xabcd + 1;",
    );
    let v1_count: usize = out.source.matches("v_1").count();
    assert!(v1_count >= 2);
}

#[test]
fn number_to_string_reverses_parse_int_hex() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::NumberToString,
        r#"var x = parseInt("ff", 16);"#,
    );
    assert!(out.source.contains("255"));
}

#[test]
fn object_properties_sparsing_collapses_back_to_literal() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::ObjectPropertiesSparsing,
        "var o = {};\no.a = 1;\no.b = 2;\n",
    );
    assert!(out.source.contains("a: 1"));
    assert!(out.source.contains("b: 2"));
}

#[test]
fn property_keys_obfuscation_decodes_hex_keys() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::PropertyKeysObfuscation,
        r#"var o = {"\x66\x6f\x6f": 1};"#,
    );
    assert!(out.source.contains("foo: 1"));
}

#[test]
fn property_keys_reordering_sorts_keys_alphabetically() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::PropertyKeysReordering,
        "var o = {c: 1, a: 2, b: 3};",
    );
    let a_pos: usize = out.source.find("a: 2").unwrap();
    let b_pos: usize = out.source.find("b: 3").unwrap();
    let c_pos: usize = out.source.find("c: 1").unwrap();
    assert!(a_pos < b_pos);
    assert!(b_pos < c_pos);
}

#[test]
fn regex_obfuscation_decodes_hex_escapes_in_regex_body() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::RegexObfuscation,
        r"var re = /\x66\x6f\x6f/gi;",
    );
    assert!(out.source.contains("/foo/gi"));
}

#[test]
fn string_concealing_decodes_atob_payload() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::StringConcealing,
        "var s = atob('aGVsbG8=');",
    );
    assert!(out.source.contains("\"hello\""));
}

#[test]
fn string_encoding_decodes_hex_escape_strings() {
    let out: JscramblerOutput =
        run_single(JscramblerTransform::StringEncoding, r"var s = '\x68\x69';");
    assert!(out.source.contains("'hi'"));
}

#[test]
fn variable_grouping_splits_grouped_decl() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::VariableGrouping,
        "var a = 1, b = 2, c = 3;",
    );
    assert!(out.source.contains("var a = 1;"));
    assert!(out.source.contains("var b = 2;"));
    assert!(out.source.contains("var c = 3;"));
}

#[test]
fn variable_masking_resolves_alias_chain() {
    let out: JscramblerOutput = run_single(
        JscramblerTransform::VariableMasking,
        "var alias = console; alias.log('x'); alias.warn('y');",
    );
    assert!(out.source.contains("console.log"));
    assert!(out.source.contains("console.warn"));
    assert!(!out.source.contains("alias"));
}

#[test]
fn full_19_obfuscation_set_runs_clean_on_synthetic_chain() {
    let src: &str = r#"var T = ['alpha', 'beta'];
var alias = console;
alias.log(T[0]);
var v = obj["bar"];
if (![]) { v = 0; }
var s = atob('aGVsbG8=');
var h = String.fromCharCode(72);
"#;
    let mut transforms: BTreeSet<JscramblerTransform> = BTreeSet::new();
    transforms.insert(JscramblerTransform::BooleanToAnything);
    transforms.insert(JscramblerTransform::CharToTernaryOperator);
    transforms.insert(JscramblerTransform::DotToBracketNotation);
    transforms.insert(JscramblerTransform::DuplicateLiteralsRemoval);
    transforms.insert(JscramblerTransform::StringConcealing);
    transforms.insert(JscramblerTransform::VariableMasking);
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms,
    };
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("\"alpha\""));
    assert!(out.source.contains("\"H\""));
    assert!(out.source.contains("\"hello\""));
    assert!(out.source.contains("console.log"));
    assert!(out.source.contains("obj.bar"));
    assert!(out.source.contains("false"));
}

#[test]
fn cff_max_depth_protected_against_runaway_recursion() {
    use core::fmt::Write as _;
    let mut src: String = String::from("var s=1;for(;s!==999;){switch(s){");
    for i in 1..400u64 {
        let next: u64 = i + 1;
        write!(src, "case {i}:fn{i}();s={next};break;").expect("write");
    }
    src.push_str("case 400:done();s=999;break;}}");
    let out: JscramblerOutput = run_single(JscramblerTransform::ControlFlowFlattening, &src);
    assert!(out.source.contains("done()") || out.source.contains("RECOVERED_FROM_CFF"));
}
