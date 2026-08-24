#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::unminify_ast;

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn harness(program: &str, tail: &str) -> String {
    format!(
        r#"var __out=[];var print=function(value){{__out.push(String(value));}};var __modules={{2:{{sum:function(left,right){{return left+right;}}}}}};var __require=function(id){{return __modules[id==="./math-utils"?2:id];}};{program}{tail}"#,
    )
}

fn boa_output(program: &str) -> String {
    let mut context: Context = Context::default();
    let source: String = harness(program, "__out.join('\\u0001');");
    context
        .eval(Source::from_bytes(source.as_bytes()))
        .expect("the registry fixture must execute in Boa")
        .as_string()
        .expect("the registry fixture must return a string in Boa")
        .to_std_string_escaped()
}

fn node_output(program: &str) -> String {
    let source: String = harness(program, "process.stdout.write(__out.join('\\u0001'));");
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the registry semantic reference")
        .expect("the registry semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute the registry fixture"
    );
    String::from_utf8(output.stdout).expect("Node registry output must be utf-8")
}

fn assert_runtime_parity(original: &str, recovered: &str) {
    let expected: String = node_output(original);
    assert_eq!(boa_output(original), expected);
    assert_eq!(node_output(recovered), expected);
    assert_eq!(boa_output(recovered), expected);
}

#[test]
fn browserify_registry_factory_recovers_runtime_parameter_names() {
    let source: &str = r#"var bundle={1:[function(a,b,c){var d=a("./math-utils");print(d.sum(2,3));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#;
    let (recovered, _stats) = unminify_ast(source);
    assert!(
        recovered.contains("function(require,module,exports)"),
        "the bounded Browserify factory must expose its runtime parameter roles:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn browserify_registry_parameter_recovery_is_scope_safe_and_deterministic() {
    let source: &str = r#"const require=0;var bundle={1:[function(a,b,c){print(a("./math-utils").sum(require,2));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#;
    let (first, _stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(first, second, "registry recovery must be byte-identical");
    assert!(
        first.contains("function(require_1,module,exports)"),
        "the runtime lookup must not capture the outer binding:\n{first}"
    );
    assert!(
        first.contains("require_1(\"./math-utils\").sum(require,2)"),
        "resolved factory references must follow the collision-safe rename:\n{first}"
    );
    assert_runtime_parity(source, &first);
}

#[test]
fn browserify_registry_recovers_each_static_factory() {
    let source: &str = r#"var bundle={1:[function(a,b,c){print(a("./math-utils").sum(2,3));},{"./math-utils":2}],2:[function(d,e,f){print(d("./math-utils").sum(4,5));},{"./math-utils":2}]};bundle[1][0](__require,{},{});bundle[2][0](__require,{},{});"#;
    let (recovered, _stats) = unminify_ast(source);
    assert_eq!(
        recovered
            .matches("function(require,module,exports)")
            .count(),
        2,
        "each proven factory in one registry must recover independently:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn non_static_or_dynamic_registry_factories_abstain() {
    let sources: [&str; 2] = [
        r#"var bundle={1:[function(a,b,c){print(a("./math-utils").sum(2,3));},{"./math-utils":dependency}]};bundle[1][0](__require,{},{});"#,
        r#"var bundle={1:[function(a,b,c){print(eval("a('./math-utils').sum(2,3)"));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#,
    ];
    for source in sources {
        let (recovered, _stats) = unminify_ast(source);
        assert!(
            recovered.contains("function(a,b,c)"),
            "unproven registry factories must remain untouched:\n{recovered}"
        );
    }
}
