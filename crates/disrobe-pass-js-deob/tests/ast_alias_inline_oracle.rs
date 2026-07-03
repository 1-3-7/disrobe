#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstRuleId, AstUnminifyStats};

const LOOP_LIMIT: u64 = 2_000_000;

fn run_alias(source: &str) -> (String, AstUnminifyStats) {
    AstPipeline::default()
        .with_rule(AstRuleId::IifeUnwrap, false)
        .with_rule(AstRuleId::SplitVar, false)
        .with_rule(AstRuleId::DeadCode, false)
        .run(source)
}

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
var log = [];
function realName(v) { log.push(v); }
realName('a');
realName('b');
print(log.join(','));
";

const INPUT: &str = r"
var log = [];
function realName(v) { log.push(v); }
var p = realName;
p('a');
p('b');
print(log.join(','));
";

#[test]
fn identifier_alias_inlines_reeval_equivalent() {
    let (recovered, stats): (String, AstUnminifyStats) = run_alias(INPUT);
    assert!(
        stats.aliases_inlined >= 1,
        "the identifier alias must inline; got {}",
        stats.aliases_inlined
    );
    assert!(
        stats.alias_references_rewritten >= 2,
        "both call sites must rewrite; got {}",
        stats.alias_references_rewritten
    );
    assert!(
        recovered.contains("realName('a')") && recovered.contains("realName('b')"),
        "the alias must be replaced by the real name at call sites:\n{recovered}"
    );
    assert!(
        !recovered.contains("var p = realName"),
        "the alias binding must be removed:\n{recovered}"
    );
    assert_recovered_equivalent("alias", ORIG, &recovered);
}

const ORIG_MEMBER: &str = r"
var log = [];
log.push(String(1));
log.push(String(2));
print(log.join(','));
";

const INPUT_MEMBER: &str = r"
var log = [];
var s = String;
log.push(s(1));
log.push(s(2));
print(log.join(','));
";

#[test]
fn member_alias_inlines() {
    let (recovered, stats): (String, AstUnminifyStats) = run_alias(INPUT_MEMBER);
    assert!(
        stats.aliases_inlined >= 1,
        "the member-chain alias must inline"
    );
    assert!(
        recovered.contains("String(1)") && recovered.contains("String(2)"),
        "the aliased target must replace the alias:\n{recovered}"
    );
    assert_recovered_equivalent("member", ORIG_MEMBER, &recovered);
}

const NEG_REASSIGN: &str = r"
var log = [];
function f1(v) { log.push('1' + v); }
function f2(v) { log.push('2' + v); }
var p = f1;
p('a');
p = f2;
p('b');
print(log.join(','));
";

#[test]
fn negative_reassigned_alias_unchanged() {
    let want: String = eval_capture(NEG_REASSIGN).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = run_alias(NEG_REASSIGN);
    assert_eq!(
        stats.aliases_inlined, 0,
        "a reassigned alias must NOT be inlined (its target changes)"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_LITERAL: &str = r"
var n = 42;
print(n);
print(n + 1);
";

#[test]
fn negative_literal_initializer_not_treated_as_alias() {
    let (_, stats): (String, AstUnminifyStats) = run_alias(NEG_LITERAL);
    assert_eq!(
        stats.aliases_inlined, 0,
        "a numeric-literal binding is not a pure reference alias and must not be removed here"
    );
}

const NEG_CALL_INIT: &str = r"
var log = [];
function make() { log.push('made'); return function () { log.push('called'); }; }
var p = make();
p();
print(log.join(','));
";

#[test]
fn negative_call_initializer_unchanged() {
    let want: String = eval_capture(NEG_CALL_INIT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = run_alias(NEG_CALL_INIT);
    assert_eq!(
        stats.aliases_inlined, 0,
        "a call-expression initializer has side effects and must NOT be inlined"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
