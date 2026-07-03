#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, lift_module_to_wat,
};
use wasmparser::{FunctionBody, Parser, Payload};

const SIMD_CORPUS: &str = include_str!("fixtures/simd_full.wat");
const ATOMICS_CORPUS: &str = include_str!("fixtures/atomics_corpus.wat");
const REFTABLE_CORPUS: &str = include_str!("fixtures/reftable_corpus.wat");
const WIDE_CORPUS: &str = include_str!("fixtures/wide_corpus.wat");
const SHARED_CORPUS: &str = include_str!("fixtures/shared_everything_corpus.wat");

const PLACEHOLDERS: &[&str] = &[
    "todo!(\"DR-WASMDEOB",
    "untranslated op",
    "DR-WASMDEOB: untranslated",
    "__builtin_trap()",
];

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

fn callees(bytes: &[u8], sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::from_module(
        bytes,
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn assert_no_placeholders(label: &str, source: &str) {
    for needle in PLACEHOLDERS {
        assert!(
            !source.contains(needle),
            "{label}: lifted output still contains placeholder `{needle}`:\n{source}"
        );
    }
}

fn check_corpus(name: &str, wat: &str) {
    let bytes: Vec<u8> = wat::parse_str(wat).unwrap_or_else(|e| panic!("assemble {name}: {e}"));
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(&bytes, &sigs);
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);

    let mut function_count: usize = 0;
    for (i, body) in bodies.iter().enumerate() {
        let sig: &FunctionSig = &defined[i];
        for target in [LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C] {
            let lifted: LiftResult = lift_function_body(body, sig, &cs, target);
            assert_no_placeholders(
                &format!("{name}:{}:{target:?}", sig.name),
                &lifted.pseudo_source,
            );
            assert!(
                lifted.coverage.fully_recovered(),
                "{name}:{}:{target:?} reported untranslated ops: {:?}",
                sig.name,
                lifted.coverage.untranslated
            );
        }
        function_count += 1;
    }

    for (i, body) in defined_bodies(&bytes).iter().enumerate() {
        let sig: &FunctionSig = &defined[i];
        let wat_one: LiftResult = lift_function_body(body, sig, &cs, LiftTarget::Wat);
        assert!(
            wat_one.coverage.fully_recovered(),
            "{name}:{}:Wat reported untranslated ops: {:?}",
            sig.name,
            wat_one.coverage.untranslated
        );
    }

    let pairs: Vec<(FunctionBody<'_>, FunctionSig)> =
        bodies.into_iter().zip(defined.iter().cloned()).collect();
    let _: String = lift_module_to_wat(&pairs, 0);

    assert!(function_count > 0, "{name}: no functions checked");
}

#[test]
fn simd_corpus_lifts_without_placeholders() {
    check_corpus("simd", SIMD_CORPUS);
}

#[test]
fn atomics_corpus_lifts_without_placeholders() {
    check_corpus("atomics", ATOMICS_CORPUS);
}

#[test]
fn reftable_corpus_lifts_without_placeholders() {
    check_corpus("reftable", REFTABLE_CORPUS);
}

#[test]
fn wide_corpus_lifts_without_placeholders() {
    check_corpus("wide", WIDE_CORPUS);
}

#[test]
fn shared_everything_corpus_lifts_without_placeholders() {
    check_corpus("shared_everything", SHARED_CORPUS);
}
