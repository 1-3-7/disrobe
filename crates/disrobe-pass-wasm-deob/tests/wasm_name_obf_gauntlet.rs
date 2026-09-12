#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{
    FunctionSig, ModuleSignatures, ModuleSummary, WasmDetection, analyze_module, detect,
    extract_signatures,
};
use wasmparser::ValType;

const CLEAN: &[u8] = include_bytes!("fixtures/wasm_name_obf_clean.wasm");
const STRIPPED: &[u8] = include_bytes!("fixtures/wasm_name_obf_stripped.wasm");

fn defined_names(sigs: &ModuleSignatures) -> Vec<String> {
    sigs.defined()
        .iter()
        .map(|s: &FunctionSig| s.name.clone())
        .collect()
}

#[test]
fn both_fixtures_are_real_parseable_wasm() {
    assert_eq!(&CLEAN[..4], b"\0asm", "clean is a real wasm module");
    assert_eq!(&STRIPPED[..4], b"\0asm", "stripped is a real wasm module");
    let clean: ModuleSummary = analyze_module(CLEAN).expect("clean parses");
    let stripped: ModuleSummary = analyze_module(STRIPPED).expect("stripped parses");
    assert_eq!(clean.func_count, 4, "clean has four defined functions");
    assert_eq!(
        stripped.func_count, 4,
        "stripped keeps four defined functions"
    );
}

#[test]
fn clean_original_carries_the_name_section() {
    let det: WasmDetection = detect(CLEAN).expect("detect clean");
    assert!(
        det.has_name_section,
        "clean original retains its name section"
    );
    let sigs: ModuleSignatures = extract_signatures(CLEAN).expect("clean sigs");
    assert_eq!(
        defined_names(&sigs),
        vec![
            "square".to_owned(),
            "add".to_owned(),
            "accumulate".to_owned(),
            "sum_of_squares".to_owned(),
        ],
        "clean name section maps every function to its source identifier"
    );
}

#[test]
fn name_obfuscation_discarded_the_name_section() {
    let det: WasmDetection = detect(STRIPPED).expect("detect stripped");
    assert!(
        !det.has_name_section,
        "name obfuscation removed the custom name section"
    );
    let summary: ModuleSummary = analyze_module(STRIPPED).expect("stripped parses");
    assert!(
        summary.names.function_names.is_empty(),
        "no function identifiers survive in the obfuscated module"
    );
}

#[test]
fn structure_is_fully_recovered_from_the_obfuscated_module() {
    let clean: ModuleSummary = analyze_module(CLEAN).expect("clean parses");
    let stripped: ModuleSummary = analyze_module(STRIPPED).expect("stripped parses");
    assert_eq!(
        stripped.func_count, clean.func_count,
        "function count recovered"
    );
    assert_eq!(
        stripped.global_count, clean.global_count,
        "global recovered"
    );
    assert_eq!(
        stripped.type_count, clean.type_count,
        "type table recovered"
    );
    assert_eq!(
        stripped.exports, clean.exports,
        "export table recovered intact"
    );
}

#[test]
fn signatures_survive_name_obfuscation_byte_for_byte() {
    let clean: ModuleSignatures = extract_signatures(CLEAN).expect("clean sigs");
    let stripped: ModuleSignatures = extract_signatures(STRIPPED).expect("stripped sigs");
    assert_eq!(clean.defined().len(), 4, "clean has four signatures");
    assert_eq!(stripped.defined().len(), 4, "stripped has four signatures");
    for (defined_index, (c, s)) in clean
        .defined()
        .iter()
        .zip(stripped.defined().iter())
        .enumerate()
    {
        assert_eq!(
            c.params, s.params,
            "params recovered for defined function {defined_index}"
        );
        assert_eq!(
            c.results, s.results,
            "results recovered for defined function {defined_index}"
        );
        assert_eq!(
            c.exported, s.exported,
            "export flag recovered for defined function {defined_index}"
        );
    }
    let acc: &FunctionSig = stripped.defined_sig(2).expect("accumulate sig");
    assert_eq!(acc.params, vec![ValType::I32], "i32 -> i32 type recovered");
    assert_eq!(acc.results, vec![ValType::I32]);
}

#[test]
fn exported_names_are_canonicalized_from_the_export_table() {
    let stripped: ModuleSignatures = extract_signatures(STRIPPED).expect("stripped sigs");
    let recovered: Vec<String> = defined_names(&stripped);
    assert_eq!(
        recovered,
        vec![
            "func_0".to_owned(),
            "func_1".to_owned(),
            "accumulate".to_owned(),
            "sum_of_squares".to_owned(),
        ],
        "exported functions recover their real names, internal functions canonicalize positionally"
    );
}

#[test]
fn internal_function_names_are_the_honest_residual() {
    let clean: ModuleSignatures = extract_signatures(CLEAN).expect("clean sigs");
    let stripped: ModuleSignatures = extract_signatures(STRIPPED).expect("stripped sigs");
    let clean_square: &FunctionSig = clean.defined_sig(0).expect("clean square");
    let stripped_square: &FunctionSig = stripped.defined_sig(0).expect("stripped square");
    assert_eq!(clean_square.name, "square", "clean keeps the source name");
    assert_eq!(
        stripped_square.name, "func_0",
        "no in-module map -> internal name is canonicalized, not restored"
    );
    assert!(
        !stripped_square.exported,
        "the residual functions are the non-exported internals"
    );
}

#[test]
fn recovery_ratio_matches_what_the_export_table_preserves() {
    let clean: ModuleSignatures = extract_signatures(CLEAN).expect("clean sigs");
    let stripped: ModuleSignatures = extract_signatures(STRIPPED).expect("stripped sigs");
    let total: usize = stripped.defined().len();
    let recovered: usize = clean
        .defined()
        .iter()
        .zip(stripped.defined().iter())
        .filter(|(c, s): &(&FunctionSig, &FunctionSig)| c.name == s.name)
        .count();
    assert_eq!(total, 4, "four functions in the module");
    assert_eq!(
        recovered, 2,
        "the two exported functions recover their source names exactly"
    );
}

#[test]
fn obfuscation_is_lossy_only_on_internal_names_not_on_behavior() {
    let clean: ModuleSignatures = extract_signatures(CLEAN).expect("clean sigs");
    let stripped: ModuleSignatures = extract_signatures(STRIPPED).expect("stripped sigs");
    let clean_shape: Vec<(Vec<ValType>, Vec<ValType>, bool)> = clean
        .defined()
        .iter()
        .map(|s: &FunctionSig| (s.params.clone(), s.results.clone(), s.exported))
        .collect();
    let stripped_shape: Vec<(Vec<ValType>, Vec<ValType>, bool)> = stripped
        .defined()
        .iter()
        .map(|s: &FunctionSig| (s.params.clone(), s.results.clone(), s.exported))
        .collect();
    assert_eq!(
        clean_shape, stripped_shape,
        "every observable function shape is recovered; only the discarded identifiers differ"
    );
}
