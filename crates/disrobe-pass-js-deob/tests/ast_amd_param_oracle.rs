#![allow(clippy::expect_used, clippy::panic)]

use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstRuleId, AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const REAL_AMD_DEFINE: &str = include_str!("../corpus/bundlers/amd/define/bundle.js");

fn eval_capture(program: &str) -> String {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        r#"
var __out = [];
var print = function(value) {{ __out.push(String(value)); }};
var __modules = {{
    "./math-utils": {{ sum: function(left, right) {{ return left + right; }} }},
    "./text-format": function(value) {{ return "value=" + value; }},
    "jquery": {{ fn: true }},
    "lodash": {{}}
}};
var define = function(first, second, third) {{
    var dependencies = Array.isArray(first) ? first : second;
    var factory = typeof second === "function" ? second : third;
    return factory.apply(undefined, dependencies.map(function(id) {{ return __modules[id]; }}));
}};
{program}
__out.join("\u0001");
"#
    );
    context
        .eval(Source::from_bytes(harness.as_bytes()))
        .expect("the bounded AMD fixture must execute")
        .as_string()
        .expect("the bounded AMD fixture must return a string")
        .to_std_string_escaped()
}

fn assert_behavior_preserved(original: &str, recovered: &str) {
    assert_eq!(
        eval_capture(original),
        eval_capture(recovered),
        "AMD parameter recovery changed execution:\n{recovered}"
    );
}

#[test]
fn amd_dependencies_restore_factory_parameter_names() {
    let source: &str = r#"define("app/main", ["./math-utils", "./text-format"], function(a, b) {
    print(b(a.sum(2, 3)));
});"#;
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert!(
        recovered.contains("function(mathUtils, textFormat)"),
        "dependency basenames must name the matching factory parameters:\n{recovered}"
    );
    assert!(
        recovered.contains("textFormat(mathUtils.sum(2, 3))"),
        "resolved factory references must follow both renames:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}

#[test]
fn amd_parameter_renaming_uses_a_collision_safe_suffix() {
    let source: &str = r#"const mathUtils = 40;
define(["./math-utils"], function(a) {
    print(a.sum(mathUtils, 2));
});"#;
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert!(
        recovered.contains("function(mathUtils_1)"),
        "the dependency-derived name must not capture the outer binding:\n{recovered}"
    );
    assert!(
        recovered.contains("mathUtils_1.sum(mathUtils, 2)"),
        "the renamed parameter and outer binding must remain distinct:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}

#[test]
fn locally_bound_define_is_not_treated_as_an_amd_loader() {
    let source: &str = r#"function define(dependencies, factory) { print(dependencies[0]); return factory({ sum: function() { return 7; } }); }
define(["./math-utils"], function(a) { print(a.sum()); });"#;
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert!(
        recovered.contains("function(a)"),
        "a locally bound function named define must retain its parameter:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}

#[test]
fn amd_runtime_dependencies_stay_positional_and_object_keys_stay_stable() {
    let source: &str = r#"define(["require", "exports", "module", "./math-utils"], function(r, e, m, a) {
    var object = { a };
    print(object.a.sum(1, 2));
});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.amd_parameters_renamed, 1,
        "only the ordinary module dependency must rename:\n{recovered}"
    );
    assert!(
        recovered.contains("function(r, e, m, mathUtils)"),
        "AMD runtime injection parameters must retain their original bindings:\n{recovered}"
    );
    assert!(
        recovered.contains("{ a: mathUtils }"),
        "object shorthand must preserve its public property key:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}

#[test]
fn amd_parameter_recovery_is_byte_deterministic() {
    let source: &str = r#"define(["./math-utils", "./math-utils"], function(a, b) {
    print(a.sum(1, b.sum(2, 3)));
});"#;
    let (first, first_stats): (String, AstUnminifyStats) = unminify_ast(source);
    let (second, second_stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(first, second, "repeated recovery must be byte-identical");
    assert_eq!(
        first_stats.amd_parameters_renamed,
        second_stats.amd_parameters_renamed
    );
    assert!(
        first.contains("function(mathUtils, mathUtils_1)"),
        "duplicate dependencies require deterministic distinct bindings:\n{first}"
    );
    assert_behavior_preserved(source, &first);
}

#[test]
fn amd_arrow_factory_parameters_follow_dependency_names() {
    let source: &str = r#"define(["./math-utils", "./text-format"], (a, b) => {
    print(b(a.sum(3, 4)));
});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.amd_parameters_renamed, 2);
    assert!(
        recovered.contains("(mathUtils, textFormat) =>"),
        "arrow factories must use the same positional dependency mapping:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}

#[test]
fn amd_parameter_recovery_is_individually_toggleable() {
    let source: &str = r#"define(["./math-utils"], function(a) { print(a.sum(4, 5)); });"#;
    let pipeline: AstPipeline = AstPipeline::default().with_rule(AstRuleId::AmdParam, false);
    let (recovered, stats): (String, AstUnminifyStats) = pipeline.run(source);
    assert_eq!(recovered, source);
    assert_eq!(stats.amd_parameters_renamed, 0);
}

#[test]
fn a_dynamic_dependency_abstains_before_any_parameter_rename() {
    let source: &str = r#"define(["./math-utils", dependencyName], function(a, b) {
    print(a.sum(1, b));
});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.amd_parameters_renamed, 0);
    assert!(
        recovered.contains("function(a, b)"),
        "an unproven dependency list must remain transactionally unchanged:\n{recovered}"
    );
}

#[test]
fn tracked_amd_bundle_uses_its_dependency_names() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(REAL_AMD_DEFINE);
    assert_eq!(stats.amd_parameters_renamed, 2);
    assert!(
        recovered.contains("function (jquery, lodash)"),
        "the tracked AMD bundle must recover both dependency bindings:\n{recovered}"
    );
    assert!(
        recovered.contains("return jquery.fn ? \"ok\" : \"fail\";"),
        "the tracked factory reference must follow the positional rename:\n{recovered}"
    );
    assert_behavior_preserved(REAL_AMD_DEFINE, &recovered);
}

#[test]
fn direct_eval_in_a_factory_forces_byte_preserving_abstention() {
    let source: &str = r#"define(["./math-utils"], function(a) {
    print(eval("a.sum(1, 2)"));
});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.amd_parameters_renamed, 0);
    assert!(
        recovered.contains("function(a)"),
        "a string-resolved binding cannot be renamed safely:\n{recovered}"
    );
    assert_behavior_preserved(source, &recovered);
}
