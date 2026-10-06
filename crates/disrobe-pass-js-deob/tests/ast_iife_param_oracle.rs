#![allow(clippy::expect_used, clippy::panic)]

#[path = "common/mod.rs"]
mod common;

use disrobe_core::{Artifact, Rung, chain::Pass};
use disrobe_pass_js_deob::chain_detector::JS_OBF_PASS;
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("fixtures/rollup_iife_param/fixture.min.js");
const FIXTURE_SHA256: &str = "e9f7c5c0e6ca1dadfb87f0d4da77133da9f0457f41db0a74db39a6c92a409932";
const AUTHORED_REFERENCE: &str = "globalThis.__result = [\n    TextFormat(MathUtils.sum(20, 22)),\n    TextFormat(MathUtils.sum(1, 2)),\n    TextFormat(MathUtils.sum(3, 4)),\n    TextFormat(MathUtils.sum(5, 6)),\n    TextFormat(MathUtils.sum(7, 8)),\n    TextFormat(MathUtils.sum(9, 10)),\n    TextFormat(MathUtils.sum(11, 12)),\n    TextFormat(MathUtils.sum(13, 14)),\n].join(\"|\");\n";
const AUTHORED_REFERENCE_SHA256: &str =
    "024de721d78f02420a86bdbde39dcf7b4e69e4a7bd8cb9981b0734c50b27a9d9";
const REFERENCE_OUTPUT: &str =
    "value=42|value=3|value=7|value=11|value=15|value=19|value=23|value=27";
const DIFFERENCE_OUTPUT: &str =
    "value=-2|value=-1|value=-1|value=-1|value=-1|value=-1|value=-1|value=-1";

fn harness_output(source: &str) -> String {
    let harness: String = format!(
        "globalThis.MathUtils={{sum:(left,right)=>left+right}};globalThis.TextFormat=value=>`value=${{value}}`;globalThis.DifferenceMath={{sum:(left,right)=>left-right}};{source};console.log(globalThis.__result);"
    );
    common::eval_capture(&harness).expect("bounded Boa evaluation of the IIFE must finish")
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
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE.as_bytes())),
        FIXTURE_SHA256,
        "the Rollup and Terser bundle is not the one PROVENANCE.txt records, so its pinned \
         reference output no longer applies"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(AUTHORED_REFERENCE.as_bytes())),
        AUTHORED_REFERENCE_SHA256,
        "the authored IIFE reference changed, so its pinned stdout no longer applies"
    );
    let authored_output: String = harness_output(AUTHORED_REFERENCE);
    assert_eq!(
        authored_output, REFERENCE_OUTPUT,
        "the authored IIFE reference must produce the pinned independent stdout"
    );

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
    assert!(compact_recovered.contains("globalThis.MathUtils"));
    assert_eq!(harness_output(&recovered_source), authored_output);
    let mutated: String =
        recovered_source.replacen("globalThis.MathUtils", "globalThis.DifferenceMath", 1);
    assert_ne!(
        mutated, recovered_source,
        "the recovered IIFE must still receive globalThis.MathUtils as an argument"
    );
    assert_eq!(
        harness_output(&mutated),
        DIFFERENCE_OUTPUT,
        "the reference comparator must reject a wrong IIFE global binding"
    );

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
