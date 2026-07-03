#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;

use disrobe_pass_go::{GoAnalysis, GoFunc, GoGenericInstantiation, analyze};

fn nm_text_symbols(raw: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in raw.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && matches!(cols[cols.len() - 2], "T" | "t") {
            out.insert(cols[cols.len() - 1].to_owned());
        }
    }
    out
}

fn recovered_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &analysis.symbols.funcs {
        out.insert(f.name.clone());
        if let Some(ls) = &f.linker_symbol {
            out.insert(ls.clone());
        }
    }
    out
}

#[test]
fn nonstripped_function_names_match_go_tool_nm() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let Some(nm_bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS_NM) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let truth: BTreeSet<String> = nm_text_symbols(&String::from_utf8_lossy(&nm_bytes));
    let recovered: BTreeSet<String> = recovered_names(&analysis);

    let hit: usize = truth.iter().filter(|n| recovered.contains(*n)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.99,
        "function-name recovery against `go tool nm` ground truth regressed below 99%: \
         {hit}/{total} = {ratio:.4}"
    );

    let unmatched: Vec<&String> = truth.iter().filter(|n| !recovered.contains(*n)).collect();
    assert!(
        unmatched
            .iter()
            .all(|n: &&String| n.as_str() == "runtime.text" || n.as_str() == "runtime.etext"),
        "the only acceptable unmatched nm text symbols are the zero-size section anchors \
         runtime.text/runtime.etext; got {unmatched:?}"
    );
}

#[test]
fn abi0_assembly_functions_carry_their_linker_symbol() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let abi0: Vec<&GoFunc> = analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.abi0)
        .collect();
    assert!(
        abi0.len() >= 50,
        "a real amd64 go binary has dozens of .abi0 assembly functions; the pclntab stores the \
         bare name, the linker symbol table the .abi0 variant. expected the cross-reference to \
         flag >= 50, got {}",
        abi0.len()
    );
    for f in &abi0 {
        let linker: &String = f
            .linker_symbol
            .as_ref()
            .expect("an abi0 func must carry its exact linker symbol");
        assert_eq!(
            linker,
            &format!("{}.abi0", f.name),
            "the abi0 linker symbol must be the canonical pclntab name plus the .abi0 selector"
        );
    }

    let morestack: &GoFunc = analysis
        .symbols
        .funcs
        .iter()
        .find(|f: &&GoFunc| f.name == "runtime.morestack")
        .expect("runtime.morestack must be recovered");
    assert!(
        morestack.abi0,
        "runtime.morestack is an assembly abi0 function"
    );
    assert_eq!(
        morestack.linker_symbol.as_deref(),
        Some("runtime.morestack.abi0")
    );
}

#[test]
fn stripped_build_recovers_canonical_pclntab_names() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS_STRIPPED)
    else {
        return;
    };
    let Some(nm_bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS_NM) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped bench");
    assert!(
        analysis.stripped.stripped,
        "the -s -w build must be classified as stripped"
    );
    let truth: BTreeSet<String> = nm_text_symbols(&String::from_utf8_lossy(&nm_bytes));
    let recovered: BTreeSet<String> = recovered_names(&analysis);
    let hit: usize = truth.iter().filter(|n| recovered.contains(*n)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.93,
        "even with the linker symbol table stripped, the pclntab funcname table is intact and \
         must yield the canonical names: {hit}/{total} = {ratio:.4}"
    );

    let no_linker: bool = analysis
        .symbols
        .funcs
        .iter()
        .all(|f: &GoFunc| f.linker_symbol.is_none() && !f.abi0);
    assert!(
        no_linker,
        "a -s -w build has no linker symbol table, so no abi0/linker_symbol enrichment is \
         possible; reporting any would be a fabricated recovery"
    );
}

#[test]
fn generic_instantiations_have_clean_bases_on_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let generics: &[GoGenericInstantiation] = &analysis.typemeta.generics;
    assert!(
        generics.len() >= 20,
        "the multi-package generic fixture exercises many instantiations, got {}",
        generics.len()
    );

    let bad: Vec<&GoGenericInstantiation> = generics
        .iter()
        .filter(|g: &&GoGenericInstantiation| {
            g.base.starts_with('*')
                || g.base.starts_with('[')
                || g.base.contains("func(")
                || g.base.starts_with("type:")
                || g.base.starts_with("go:")
                || g.base.starts_with('.')
        })
        .collect();
    assert!(
        bad.is_empty(),
        "generic bases must be the bare pkg.Name with no pointer/slice/array/func type-constructor \
         wrapper and no type:/go:/.eq linker-namespace prefix: {bad:?}"
    );

    assert!(
        generics
            .iter()
            .any(|g: &GoGenericInstantiation| g.base == "main.Box"),
        "expected the user generic main.Box instantiation"
    );
    assert!(
        generics
            .iter()
            .any(|g: &GoGenericInstantiation| g.base == "main.Registry"),
        "expected the user generic main.Registry instantiation"
    );
    assert!(
        generics
            .iter()
            .any(|g: &GoGenericInstantiation| g.base == "main.Tree"),
        "expected the user generic main.Tree instantiation"
    );

    for g in generics {
        assert!(
            g.full.starts_with(&g.base),
            "the reconstructed full instantiation must begin with its bare base: {g:?}"
        );
    }
}
