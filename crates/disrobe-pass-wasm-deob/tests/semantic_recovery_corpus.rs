#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body,
};
use wasmparser::{FunctionBody, Parser, Payload};

const CORPUS_MODULES: usize = 38;
const CORPUS_FUNCTIONS: usize = 133;
const CORPUS_FULLY_RECOVERED: usize = 133;

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

#[derive(Debug, Default, Clone)]
struct Tally {
    total_functions: usize,
    fully_recovered: usize,
    parses_only: usize,
    name_recovered: usize,
    modules_parsed: usize,
    modules_skipped: usize,
    untranslated_by_family: BTreeMap<String, usize>,
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
            let lifted: LiftResult = lift_function_body(body, sig, &callees, LiftTarget::Wat);
            let parses: bool = wat::parse_str(&lifted.pseudo_source).is_ok();
            let full: bool = lifted.coverage.fully_recovered();
            if parses {
                tally.parses_only += 1;
            }
            if full && parses {
                tally.fully_recovered += 1;
            }
            for mnemonic in &lifted.coverage.untranslated {
                *tally
                    .untranslated_by_family
                    .entry(family_of(mnemonic))
                    .or_default() += 1;
            }
        }
    }
    tally
}

fn family_of(mnemonic: &str) -> String {
    let lower: String = mnemonic.to_ascii_lowercase();
    if lower.contains("x16")
        || lower.contains("x8")
        || lower.contains("x4")
        || lower.contains("x2")
        || lower.starts_with("v128")
    {
        return "simd".to_owned();
    }
    if lower.contains("atomic") {
        return "atomics".to_owned();
    }
    if lower.starts_with("memory.") || lower.contains("data.") {
        return "bulk-memory".to_owned();
    }
    if lower.starts_with("table.") || lower.contains("elem.") {
        return "table".to_owned();
    }
    if lower.starts_with("ref.") {
        return "reference".to_owned();
    }
    if lower.starts_with("return_call") {
        return "tail-call".to_owned();
    }
    if lower.contains("try") || lower.contains("catch") || lower.contains("throw") {
        return "exceptions".to_owned();
    }
    if lower.contains("struct") || lower.contains("array") || lower.contains("ref.cast") {
        return "gc".to_owned();
    }
    mnemonic.to_owned()
}

fn function_has_real_name(sig: &FunctionSig, defined_index: usize) -> bool {
    let positional: String = format!("func_{defined_index}");
    sig.name != positional && !sig.name.starts_with("import_")
}

#[test]
fn corpus_recovery_requires_full_op_coverage_not_just_parseability() {
    let tally: Tally = measure();
    assert_eq!(
        tally.modules_parsed, CORPUS_MODULES,
        "the wat corpus is fixed at {CORPUS_MODULES} parseable modules; got {} parsed and {} \
         skipped, so the published denominator no longer describes what ran",
        tally.modules_parsed, tally.modules_skipped
    );
    assert_eq!(
        tally.total_functions, CORPUS_FUNCTIONS,
        "the wat corpus is fixed at {CORPUS_FUNCTIONS} defined functions; got {}, so the \
         published denominator no longer describes what ran",
        tally.total_functions
    );

    let semantic_pct: f64 = 100.0 * tally.fully_recovered as f64 / tally.total_functions as f64;
    let parse_pct: f64 = 100.0 * tally.parses_only as f64 / tally.total_functions as f64;
    let name_pct: f64 = 100.0 * tally.name_recovered as f64 / tally.total_functions as f64;

    eprintln!(
        "wasm corpus recovery (HONEST): {} modules parsed, {} skipped, {} functions",
        tally.modules_parsed, tally.modules_skipped, tally.total_functions
    );
    eprintln!(
        "  semantic (full op coverage + validates): {}/{} = {:.1}%",
        tally.fully_recovered, tally.total_functions, semantic_pct
    );
    eprintln!(
        "  parseability-only (old, inflated metric): {}/{} = {:.1}%",
        tally.parses_only, tally.total_functions, parse_pct
    );
    eprintln!(
        "  name recovery (name/export-section gated): {}/{} = {:.1}%",
        tally.name_recovered, tally.total_functions, name_pct
    );
    eprintln!("  untranslated ops by family:");
    for (family, count) in &tally.untranslated_by_family {
        eprintln!("    {family}: {count}");
    }

    assert!(
        tally.fully_recovered <= tally.parses_only,
        "full recovery can never exceed parseability"
    );
    assert!(
        name_pct > 0.0,
        "corpus carries name/export sections, so some names must be recovered ({}/{})",
        tally.name_recovered,
        tally.total_functions
    );
    let no_untranslated: bool = tally.untranslated_by_family.is_empty();
    assert!(
        no_untranslated || semantic_pct < parse_pct,
        "while any op family is untranslated, honest recovery MUST be strictly below \
         parseability ({semantic_pct:.1}% vs {parse_pct:.1}%); equality is allowed only when \
         nothing is stubbed"
    );
    assert!(
        tally.fully_recovered >= CORPUS_FULLY_RECOVERED,
        "full op-coverage recovery must not regress below {CORPUS_FULLY_RECOVERED}/{CORPUS_FUNCTIONS} \
         functions, the figure the docs publish; got {}/{}",
        tally.fully_recovered,
        tally.total_functions
    );
}

#[test]
fn recovered_bodies_are_non_trivial() {
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
            let lifted: LiftResult = lift_function_body(body, sig, &callees, LiftTarget::Wat);
            if !lifted.coverage.fully_recovered() {
                continue;
            }
            let wat: String = lifted.pseudo_source;
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
        "expected at least one fully-recovered control-flow construct"
    );
    assert!(
        saw_arith,
        "expected at least one fully-recovered arithmetic op"
    );
}

#[test]
fn simd_sqrt_function_is_fully_recovered() {
    let wat: &str = r"
        (module
          (func $sw (result v128)
            v128.const i32x4 0 0 0 0
            f32x4.sqrt))
    ";
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("sigs");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = callees(&sigs);
    let body: &FunctionBody<'_> = &defined_bodies(&bytes)[0];
    let lifted: LiftResult = lift_function_body(body, &defined[0], &callees, LiftTarget::Wat);
    assert!(
        wat::parse_str(&lifted.pseudo_source).is_ok(),
        "recovered wat must reassemble"
    );
    assert!(
        lifted.coverage.fully_recovered(),
        "f32x4.sqrt is lifted now; nothing should remain untranslated, got {:?}",
        lifted.coverage.untranslated
    );
}
