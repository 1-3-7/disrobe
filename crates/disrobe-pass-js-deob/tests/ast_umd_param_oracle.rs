#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn harness(program: &str, amd_enabled: bool, tail: &str) -> String {
    let define_setup: &str = if amd_enabled {
        r#"var define = function(first, second, third) {
    var dependencies = Array.isArray(first) ? first : second;
    var factory = typeof second === "function" ? second : third;
    return factory.apply(undefined, dependencies.map(function(id) { return __modules[id]; }));
};
define.amd = {};"#
    } else {
        "var define;"
    };
    format!(
        r#"
var __out = [];
var print = function(value) {{ __out.push(String(value)); }};
var __modules = {{
    "./math-utils": {{ sum: function(left, right) {{ return left + right; }} }},
    "./text-format": function(value) {{ return "value=" + value; }}
}};
var __root = {{ mathUtils: __modules["./math-utils"], textFormat: __modules["./text-format"] }};
{define_setup}
{program}
{tail}
"#
    )
}

fn boa_output(program: &str, amd_enabled: bool) -> String {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let source: String = harness(program, amd_enabled, "__out.join('\\u0001');");
    context
        .eval(Source::from_bytes(source.as_bytes()))
        .expect("the bounded UMD fixture must execute in Boa")
        .as_string()
        .expect("the bounded UMD fixture must return a string in Boa")
        .to_std_string_escaped()
}

fn node_output(program: &str, amd_enabled: bool) -> String {
    let source: String = harness(
        program,
        amd_enabled,
        "process.stdout.write(__out.join('\\u0001'));",
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the UMD semantic reference")
        .expect("the UMD semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute the UMD fixture\nstderr: {}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Node UMD output must be utf-8")
}

fn assert_runtime_parity(original: &str, recovered: &str) {
    for amd_enabled in [true, false] {
        let expected: String = node_output(original, amd_enabled);
        assert_eq!(boa_output(original, amd_enabled), expected);
        assert_eq!(node_output(recovered, amd_enabled), expected);
        assert_eq!(boa_output(recovered, amd_enabled), expected);
    }
}

#[test]
fn guarded_umd_function_factory_recovers_amd_dependency_names() {
    let source: &str = r#"(function(root, factory) {
    if (typeof define === "function" && define.amd) {
        define(["./math-utils", "./text-format"], factory);
    } else {
        root.output = factory(root.mathUtils, root.textFormat);
    }
}(__root, function(a, b) {
    print(b(a.sum(2, 3)));
}));"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.amd_parameters_renamed, 2,
        "the guarded UMD factory must reuse the static AMD dependency mapping:\n{recovered}"
    );
    assert!(
        recovered.contains("function(mathUtils, textFormat)"),
        "the direct UMD factory argument must receive dependency-derived names:\n{recovered}"
    );
    assert!(
        recovered.contains("textFormat(mathUtils.sum(2, 3))"),
        "resolved UMD factory references must follow both renames:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn guarded_umd_arrow_factory_recovers_amd_dependency_names() {
    let source: &str = r#"(function(factory) {
    if (typeof define == "function" && define.amd) {
        define("app/main", ["./math-utils"], factory);
    } else {
        factory(__root.mathUtils);
    }
})(a => {
    print(a.sum(4, 5));
});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.amd_parameters_renamed, 1, "source:\n{recovered}");
    assert!(
        recovered.contains("mathUtils =>"),
        "the direct arrow argument must receive its AMD dependency name:\n{recovered}"
    );
    assert!(
        recovered.contains("mathUtils.sum(4, 5)"),
        "the arrow body reference must follow the rename:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn non_umd_and_ambiguous_wrappers_abstain() {
    let cases: [&str; 11] = [
        r"(function(factory) { factory(__root.mathUtils); })(function(a) { print(a.sum(1, 2)); });",
        r#"(function(factory) { if (typeof module === "object") { module.exports = factory(require("./math-utils")); } })(function(a) { return a.sum(1, 2); });"#,
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory, other) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { other(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); }, function(value) { return value; });"#,
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(dependencies, factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); define(["./text-format"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { observe(...[define(["./text-format"], factory)]); if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { if (ready) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(define, factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(loader, function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { factory = replacement; if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(prefix, factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(...values, function(a) { print(a.sum(1, 2)); });"#,
    ];
    for source in cases {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
        assert_eq!(
            stats.amd_parameters_renamed, 0,
            "an unproven UMD shape must abstain:\n{recovered}"
        );
        assert!(
            recovered.contains("function(a)"),
            "an unproven UMD shape must retain the factory parameter:\n{recovered}"
        );
    }
}

#[test]
fn unsafe_umd_factory_shapes_abstain() {
    let cases: [&str; 5] = [
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(eval("a.sum(1, 2)")); });"#,
        r#"(function(factory) { eval("factory"); if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { with (__root) { factory = factory; } if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a) { print(a.sum(1, 2)); });"#,
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function(a, ...rest) { print(a.sum(rest.length, 2)); });"#,
        r#"(function(factory) { if (typeof define === "function" && define.amd) { define(["./math-utils"], factory); } else { factory(__root.mathUtils); } })(function({ sum }) { print(sum(1, 2)); });"#,
    ];
    for source in cases {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
        assert_eq!(
            stats.amd_parameters_renamed, 0,
            "dynamic scope, rest, and binding patterns must abstain:\n{recovered}"
        );
    }
}
