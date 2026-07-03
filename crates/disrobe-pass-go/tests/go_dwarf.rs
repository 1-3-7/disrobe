#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{DwarfFunction, GoAnalysis, analyze};

#[test]
fn dwarf_recovers_param_and_local_names() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GENERICS);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze generics");
    let dwarf = &analysis.dwarf;
    assert!(dwarf.present, "non-stripped binary must expose DWARF");
    assert!(dwarf.compressed, "go windows DWARF is zlib .zdebug_*");
    assert!(dwarf.compile_units > 0);

    let sum: &DwarfFunction = dwarf
        .functions
        .iter()
        .find(|f: &&DwarfFunction| f.name.starts_with("main.Sum["))
        .expect("main.Sum instantiation present in DWARF");
    assert!(
        sum.params.iter().any(|p: &String| p == "xs"),
        "Sum parameter name `xs` must survive in DWARF, got {:?}",
        sum.params
    );
    assert!(
        sum.locals.iter().any(|l: &String| l == "total"),
        "Sum local `total` must survive in DWARF, got {:?}",
        sum.locals
    );
    assert!(
        !sum.type_params.is_empty(),
        "generic Sum must carry type-parameter DIEs"
    );

    let main_fn: &DwarfFunction = dwarf
        .functions
        .iter()
        .find(|f: &&DwarfFunction| f.name == "main.main")
        .expect("main.main present");
    assert!(
        main_fn.locals.iter().any(|l: &String| l == "keys"),
        "main local `keys` must survive in DWARF, got {:?}",
        main_fn.locals
    );
}

#[test]
fn dwarf_absent_on_stripped_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    assert!(
        !analysis.dwarf.present,
        "stripped (-w) binary carries no DWARF"
    );
    assert!(analysis.dwarf.functions.is_empty());
}

#[test]
fn dwarf_adds_names_beyond_pclntab() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    let detailed: usize = analysis
        .dwarf
        .functions
        .iter()
        .filter(|f: &&DwarfFunction| {
            !f.params.is_empty() || !f.locals.is_empty() || !f.type_params.is_empty()
        })
        .count();
    assert!(
        detailed > 100,
        "expected hundreds of functions with DWARF-only local/param names, got {detailed}"
    );
}
