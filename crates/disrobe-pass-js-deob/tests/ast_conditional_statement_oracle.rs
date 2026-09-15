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

const ORIG_TERNARY: &str = r"
var log = [];
function yes() { log.push('yes'); }
function no() { log.push('no'); }
function run(flag) { if (flag) { yes(); } else { no(); } }
run(true);
run(false);
print(log.join(','));
";

const INPUT_TERNARY: &str = r"
var log = [];
function yes() { log.push('yes'); }
function no() { log.push('no'); }
function run(flag) { flag ? yes() : no(); }
run(true);
run(false);
print(log.join(','));
";

#[test]
fn ternary_statement_to_if_reeval_equivalent() {
    assert_faithful_input("ternary", ORIG_TERNARY, INPUT_TERNARY);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_TERNARY);
    assert!(
        stats.ternary_statements_expanded >= 1,
        "the statement-position ternary must expand to if/else; got {}",
        stats.ternary_statements_expanded
    );
    assert!(
        recovered.contains("if (flag)") && recovered.contains("else"),
        "must produce an if/else:\n{recovered}"
    );
    assert!(
        !recovered.contains("flag ? yes() : no()"),
        "the ternary statement must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("ternary", ORIG_TERNARY, &recovered);
}

const ORIG_AND: &str = r"
var log = [];
function fire() { log.push('fire'); }
function maybe(flag) { if (flag) { fire(); } }
maybe(true);
maybe(false);
print(log.join(','));
";

const INPUT_AND: &str = r"
var log = [];
function fire() { log.push('fire'); }
function maybe(flag) { flag && fire(); }
maybe(true);
maybe(false);
print(log.join(','));
";

#[test]
fn and_short_circuit_to_if_reeval_equivalent() {
    assert_faithful_input("and", ORIG_AND, INPUT_AND);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_AND);
    assert!(
        stats.and_short_circuits_expanded >= 1,
        "the && short-circuit statement must expand; got {}",
        stats.and_short_circuits_expanded
    );
    assert!(
        recovered.contains("if (flag)") && recovered.contains("fire();"),
        "must guard the call with an if:\n{recovered}"
    );
    assert!(
        !recovered.contains("flag && fire()"),
        "the && short-circuit must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("and", ORIG_AND, &recovered);
}

const ORIG_OR: &str = r"
var log = [];
function fallback() { log.push('fb'); }
function ensure(ready) { if (!ready) { fallback(); } }
ensure(false);
ensure(true);
print(log.join(','));
";

const INPUT_OR: &str = r"
var log = [];
function fallback() { log.push('fb'); }
function ensure(ready) { ready || fallback(); }
ensure(false);
ensure(true);
print(log.join(','));
";

#[test]
fn or_short_circuit_to_if_reeval_equivalent() {
    assert_faithful_input("or", ORIG_OR, INPUT_OR);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_OR);
    assert!(
        stats.or_short_circuits_expanded >= 1,
        "the || short-circuit statement must expand; got {}",
        stats.or_short_circuits_expanded
    );
    assert!(
        recovered.contains("if (!(ready))") && recovered.contains("fallback();"),
        "must invert the condition and guard:\n{recovered}"
    );
    assert!(
        !recovered.contains("ready || fallback()"),
        "the || short-circuit must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("or", ORIG_OR, &recovered);
}

const NEG_VALUE_TERNARY: &str = r"
function pick(flag) { return flag ? 1 : 2; }
print(pick(true));
print(pick(false));
var assigned = true ? 'a' : 'b';
print(assigned);
";

#[test]
fn negative_value_position_ternary_unchanged() {
    let want: String = eval_capture(NEG_VALUE_TERNARY).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_VALUE_TERNARY);
    assert_eq!(
        stats.ternary_statements_expanded, 0,
        "ternaries in return/assignment value position must NOT be turned into statements"
    );
    assert!(
        recovered.contains("flag ? 1 : 2") && recovered.contains("true ? 'a' : 'b'"),
        "value-position ternaries must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_VALUE_AND: &str = r"
function coerce(a, b) { return a && b; }
print(coerce(1, 2));
print(coerce(0, 9));
";

#[test]
fn negative_value_position_logical_unchanged() {
    let want: String = eval_capture(NEG_VALUE_AND).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_VALUE_AND);
    assert_eq!(
        stats.and_short_circuits_expanded, 0,
        "a && in return value position must NOT be expanded into an if (the value matters)"
    );
    assert!(
        recovered.contains("a && b"),
        "value-position && must be preserved:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}
