#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstUnminifyStats, unminify_ast};

const AST_TRANSFORM_FLOOR: usize = 47;

fn distinct_enabled_transforms() -> usize {
    let rendered: String = format!("{:?}", AstPipeline::default());
    let start: usize = rendered
        .find("enabled: [")
        .map(|i: usize| i + "enabled: [".len())
        .expect("pipeline debug lists enabled rules");
    let end: usize = rendered[start..]
        .find(']')
        .map(|i: usize| start + i)
        .expect("enabled list is bracketed");
    let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for token in rendered[start..end].split(',') {
        let name: &str = token.trim();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names.len()
}

#[test]
fn ast_unminify_transform_count_holds_its_floor() {
    let count: usize = distinct_enabled_transforms();
    assert!(
        count >= AST_TRANSFORM_FLOOR,
        "the AST unminify pipeline regressed below its transform floor: {count} < {AST_TRANSFORM_FLOOR}"
    );
}

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
        "var __out = [];\nvar print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn assert_behavior_preserved(label: &str, original: &str, recovered: &str) {
    assert!(
        reparses(recovered),
        "{label}: recovered must re-parse:\n{recovered}"
    );
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate:\n{recovered}"));
    assert_eq!(want, got, "{label}: behavior diverged\n{recovered}");
}

const TERSER_FOR_BODY: &str = "function loop(n){for(var out=[],i=0;i<n;i++)out.push(i),out.push(2*i);return out.join(\",\")}print(loop(3));";

#[test]
fn terser_for_loop_comma_body_splits_and_preserves_behavior() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_FOR_BODY);
    assert_eq!(
        stats.loop_comma_bodies_split, 1,
        "the terser-packed for-body comma sequence must split into a block:\n{recovered}"
    );
    assert!(
        recovered.contains("out.push(i);") && recovered.contains("out.push(2*i);"),
        "each comma element must become its own statement:\n{recovered}"
    );
    assert!(
        !recovered.contains("out.push(i),out.push(2*i)")
            && !recovered.contains("out.push(i), out.push(2*i)"),
        "the comma-sequence body must be gone:\n{recovered}"
    );
    assert_behavior_preserved("terser-for-body", TERSER_FOR_BODY, &recovered);
}

const TERSER_WHILE_BODY: &str = "function run(){var i=0,s=0;while(i<5)s+=i,i++;print(s);}run();";

#[test]
fn terser_while_loop_comma_body_splits_and_preserves_behavior() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_WHILE_BODY);
    assert_eq!(
        stats.loop_comma_bodies_split, 1,
        "the while-body comma sequence must split:\n{recovered}"
    );
    assert_behavior_preserved("terser-while-body", TERSER_WHILE_BODY, &recovered);
}

const TERSER_IF_BODY: &str =
    "function pick(c){var a=0,b=0;if(c)a=1,b=2;else a=3,b=4;print(a+\":\"+b);}pick(1);pick(0);";

#[test]
fn terser_if_comma_bodies_split_and_preserve_behavior() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_IF_BODY);
    assert_eq!(
        stats.branch_comma_bodies_split, 2,
        "both if-consequent and else comma bodies must split:\n{recovered}"
    );
    assert_behavior_preserved("terser-if-body", TERSER_IF_BODY, &recovered);
}

const FOR_UPDATE_COMMA: &str = "function s(n){var t=0;for(var i=0;i<n;t+=i,i++);print(t);}s(4);";

#[test]
fn for_update_comma_is_never_split() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(FOR_UPDATE_COMMA);
    assert_eq!(
        stats.loop_comma_bodies_split, 0,
        "a comma in the for-update clause is not a loop body and must not be split:\n{recovered}"
    );
    assert_eq!(stats.branch_comma_bodies_split, 0);
    assert_behavior_preserved("for-update-comma", FOR_UPDATE_COMMA, &recovered);
}

const ALREADY_BLOCKED: &str = "function loop(n){var out=[];for(var i=0;i<n;i++){out.push(i);out.push(2*i);}print(out.join(\",\"));}loop(3);";

#[test]
fn blocked_loop_body_has_nothing_to_split() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(ALREADY_BLOCKED);
    assert_eq!(
        stats.loop_comma_bodies_split, 0,
        "a body already in a block is not a comma sequence"
    );
}
