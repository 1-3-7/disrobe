#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_core::{Artifact, Rung, chain::Pass};
use disrobe_pass_js_deob::chain_detector::JS_OBF_PASS;
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const FIXTURE: &str = include_str!("fixtures/rollup_iife_param/fixture.min.js");
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn node_output(source: &str) -> Vec<u8> {
    let harness: String = format!(
        "globalThis.MathUtils={{sum:(left,right)=>left+right}};globalThis.TextFormat=value=>`value=${{value}}`;globalThis.DifferenceMath={{sum:(left,right)=>left-right}};{source};process.stdout.write(globalThis.__result);"
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("Node is required for the Rollup IIFE semantic reference")
        .expect("the Rollup IIFE semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "Node must execute the Rollup IIFE fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn compact(source: &str) -> String {
    source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect()
}

#[test]
fn registered_pass_recovers_rollup_iife_global_parameter_names() {
    assert_eq!(FIXTURE.len(), 224);
    let original_stdout: Vec<u8> = node_output(FIXTURE);
    let mutated: String = FIXTURE.replacen(
        "globalThis.MathUtils,globalThis.TextFormat",
        "globalThis.DifferenceMath,globalThis.TextFormat",
        1,
    );
    assert_ne!(node_output(&mutated), original_stdout);

    let input: Artifact = Artifact::new(Rung::Raw, FIXTURE.as_bytes().to_vec(), [0x24_u8; 32]);
    let recovered: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered js.deob pass must recover the real Rollup IIFE fixture");
    let recovered_source: String = String::from_utf8(recovered.envelope)
        .expect("the recovered JavaScript surface must remain UTF-8");
    let compact_recovered: String = compact(&recovered_source);
    assert!(
        compact_recovered.contains("function(MathUtils,TextFormat)"),
        "the global member arguments must name both IIFE parameters:\n{recovered_source}"
    );
    assert!(
        compact_recovered.contains("TextFormat(MathUtils.sum(20,22))"),
        "resolved IIFE references must follow both renames:\n{recovered_source}"
    );
    assert_eq!(node_output(&recovered_source), original_stdout);

    let repeated: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered pass must deterministically recover the same IIFE");
    assert_eq!(repeated.envelope, recovered_source.as_bytes());
}

#[test]
fn global_iife_recognizer_accepts_static_roots_and_rejects_ambiguous_shapes() {
    let positive: &str =
        r#"!((a,b)=>{globalThis.result=b(a.sum(1,2))})(self["MathUtils"],window.TextFormat);"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(positive);
    let compact_recovered: String = compact(&recovered);
    assert_eq!(stats.global_iife_parameters_renamed, 2);
    assert_eq!(stats.amd_parameters_renamed, 0);
    assert!(compact_recovered.contains("(MathUtils,TextFormat)=>"));
    assert!(compact_recovered.contains("TextFormat(MathUtils.sum(1,2))"));

    let excluded: [&str; 12] = [
        r"!function(a){use(a)}(globalThis[name]);",
        r"!function(a){use(a)}(globalThis?.MathUtils);",
        r"!function(a){use(a)}(loadMath());",
        r"!function(a){use(a)}(globalThis.MathUtils=replacement);",
        r"!function(a){a=replacement;use(a)}(globalThis.MathUtils);",
        r"!function(a,b){use(a,b)}(globalThis.MathUtils);",
        r"!function(a,b){use(a,b)}(globalThis.MathUtils,globalThis.MathUtils);",
        r"!function(a=zero){use(a)}(globalThis.MathUtils);",
        r"!function(...a){use(a)}(globalThis.MathUtils);",
        r"!function({a}){use(a)}(globalThis.MathUtils);",
        r"!function(a){eval('use(a)')}(globalThis.MathUtils);",
        r"!function(globalThis){!function(a){use(a)}(globalThis.MathUtils)}(root);",
    ];
    for source in excluded {
        let (output, stats): (String, AstUnminifyStats) = unminify_ast(source);
        assert_eq!(
            stats.global_iife_parameters_renamed, 0,
            "excluded IIFE shape must not infer a global parameter name: {source}\n{output}"
        );
    }
}
