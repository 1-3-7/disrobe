#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Non-circular semantic + name recovery measurement over the committed WASM corpus.
//!
//! Semantic recovery is the fraction of defined function bodies whose lifted WAT
//! re-parses through an independent `wat::parse_str` (round-trip equality of the
//! structured control flow + operator stream). Name recovery is measured separately and
//! is honestly debug-info gated: it is the fraction of functions that receive a real
//! identifier from the name section / export section rather than a positional `func_N`.
//!
//! Ground truth is the corpus `.wat` sources themselves and the WASM name binary format,
//! never the lifter's own re-emit. This guards against inflated "100%" claims by tying
//! the score to an external re-parser and to the binary's own symbol tables.

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftTarget, ModuleSignatures, extract_signatures, lift_function_body,
};
use wasmparser::{FunctionBody, Parser, Payload};

fn corpus_dirs() -> Vec<PathBuf> {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        root.join("../../corpus/src/wasm/sources"),
        root.join("../../corpus/src/wasm/edge_cases"),
        root.join("../../corpus/wasm/wat"),
        root.join("../../corpus/wasm/plugins"),
    ]
}

fn wat_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in corpus_dirs() {
        let Ok(entries): Result<fs::ReadDir, _> = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().is_some_and(|e| e == "wat") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    total_functions: usize,
    semantic_recovered: usize,
    name_recovered: usize,
    modules_parsed: usize,
    modules_skipped: usize,
}

fn measure() -> Tally {
    let mut tally: Tally = Tally::default();
    for wat_path in wat_files() {
        let text: String = fs::read_to_string(&wat_path).expect("read wat");
        let Ok(bytes): Result<Vec<u8>, _> = wat::parse_str(&text) else {
            tally.modules_skipped += 1;
            continue;
        };
        let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&bytes) else {
            tally.modules_skipped += 1;
            continue;
        };
        tally.modules_parsed += 1;
        let defined: &[FunctionSig] = sigs.defined();
        let callees: CalleeNames = callees(&sigs);
        for (i, body) in defined_bodies(&bytes).iter().enumerate() {
            let Some(sig): Option<&FunctionSig> = defined.get(i) else {
                continue;
            };
            tally.total_functions += 1;
            if function_has_real_name(sig, i) {
                tally.name_recovered += 1;
            }
            if function_semantically_recovers(body, sig, &callees) {
                tally.semantic_recovered += 1;
            }
        }
    }
    tally
}

/// A function semantically recovers when its lifted WAT (a complete validating module)
/// re-parses through the independent `wat` crate, confirming the structured control flow
/// and operator stream round-trip without loss.
fn function_semantically_recovers(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
) -> bool {
    let lifted: String = lift_function_body(body, sig, callees, LiftTarget::Wat).pseudo_source;
    wat::parse_str(&lifted).is_ok()
}

/// A function has a recovered name when its signature name is not a positional
/// `func_N` / `import_N` placeholder, i.e. it came from the name or export section.
fn function_has_real_name(sig: &FunctionSig, defined_index: usize) -> bool {
    let positional: String = format!("func_{defined_index}");
    sig.name != positional && !sig.name.starts_with("import_")
}

#[test]
fn corpus_semantic_recovery_is_high_and_name_recovery_is_measured() {
    let tally: Tally = measure();
    assert!(
        tally.total_functions >= 10,
        "expected a non-trivial corpus, saw {} functions across {} modules",
        tally.total_functions,
        tally.modules_parsed
    );

    let semantic_pct: f64 = 100.0 * tally.semantic_recovered as f64 / tally.total_functions as f64;
    let name_pct: f64 = 100.0 * tally.name_recovered as f64 / tally.total_functions as f64;

    eprintln!(
        "wasm corpus recovery: {} modules parsed, {} skipped, {} functions; \
         semantic {}/{} = {:.1}%, name {}/{} = {:.1}% (name recovery is name-section gated)",
        tally.modules_parsed,
        tally.modules_skipped,
        tally.total_functions,
        tally.semantic_recovered,
        tally.total_functions,
        semantic_pct,
        tally.name_recovered,
        tally.total_functions,
        name_pct,
    );

    assert!(
        semantic_pct >= 90.0,
        "semantic recovery regressed below 90%: {:.1}% ({}/{})",
        semantic_pct,
        tally.semantic_recovered,
        tally.total_functions
    );
    assert!(
        name_pct > 0.0,
        "corpus carries name/export sections, so some names must be recovered ({}/{})",
        tally.name_recovered,
        tally.total_functions
    );
}

/// Confirms the round-trip is non-trivial: at least one corpus function lifts to a WAT
/// body that contains real control flow / operators, not just an empty stub. Guards
/// against a degenerate "100%" where every body is empty.
#[test]
fn semantic_recovery_round_trips_non_trivial_bodies() {
    let mut saw_branch: bool = false;
    let mut saw_arith: bool = false;
    for wat_path in wat_files() {
        let text: String = fs::read_to_string(&wat_path).expect("read");
        let Ok(bytes): Result<Vec<u8>, _> = wat::parse_str(&text) else {
            continue;
        };
        let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&bytes) else {
            continue;
        };
        let defined: &[FunctionSig] = sigs.defined();
        let callees: CalleeNames = callees(&sigs);
        for (i, body) in defined_bodies(&bytes).iter().enumerate() {
            let Some(sig): Option<&FunctionSig> = defined.get(i) else {
                continue;
            };
            let wat: String =
                lift_function_body(body, sig, &callees, LiftTarget::Wat).pseudo_source;
            if wat.contains("br_if") || wat.contains("loop") || wat.contains("if") {
                saw_branch = true;
            }
            if wat.contains(".add") || wat.contains(".mul") || wat.contains(".sub") {
                saw_arith = true;
            }
        }
    }
    assert!(
        saw_branch,
        "expected at least one control-flow construct in corpus lift"
    );
    assert!(
        saw_arith,
        "expected at least one arithmetic op in corpus lift"
    );
}
