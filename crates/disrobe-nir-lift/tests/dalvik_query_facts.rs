#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_dex;
use disrobe_query::{
    CallSiteMatch, Capability, CapabilitySiteMatch, Function, FunctionMatch, Module, Query,
    QueryResult, XrefMatch, run,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");

fn lifted() -> Module {
    let nir: NirModule = lift_dex(HELLO_DEX).expect("lift dex to NIR");
    Module::from_nir(&nir)
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions, got {other:?}"),
    }
}

fn xrefs_to(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    match run(
        module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo, got {other:?}"),
    }
}

fn calls_to(module: &Module, target: &str) -> Vec<CallSiteMatch> {
    match run(
        module,
        &Query::CallsTo {
            target: target.to_owned(),
        },
    ) {
        QueryResult::CallsTo { matches, .. } => matches,
        other => panic!("expected CallsTo, got {other:?}"),
    }
}

fn capability_symbols(module: &Module, capability: Capability) -> Vec<String> {
    match run(module, &Query::CapabilitySites { capability }) {
        QueryResult::CapabilitySites { matches, .. } => matches
            .into_iter()
            .map(|m: CapabilitySiteMatch| m.symbol)
            .collect(),
        other => panic!("expected CapabilitySites, got {other:?}"),
    }
}

#[test]
fn dex_methods_are_recovered_as_qualified_functions() {
    let module: Module = lifted();
    let names: Vec<String> = function_names(&module);
    for expected in [
        "Greeter.greet",
        "Hello.main",
        "Hello.bumpCounter",
        "Hello.describe",
    ] {
        assert!(
            names.iter().any(|n: &String| n == expected),
            "method {expected} must be lifted: {names:?}"
        );
    }

    let bump: &Function = module
        .function_by_name("Hello.bumpCounter")
        .expect("bumpCounter");
    assert!(bump.is_export, "the virtual bumpCounter is callable/export");
    let main: &Function = module.function_by_name("Hello.main").expect("main");
    assert!(!main.is_export, "the direct main is not a virtual export");
}

#[test]
fn main_calls_the_intra_dex_methods() {
    let module: Module = lifted();

    let xrefs: Vec<XrefMatch> = xrefs_to(&module, "Hello.bumpCounter");
    assert_eq!(xrefs.len(), 1, "one call to bumpCounter: {xrefs:?}");
    assert_eq!(xrefs[0].from_function.as_deref(), Some("Hello.main"));
    assert!(
        xrefs[0].mnemonic.starts_with("invoke"),
        "the dalvik call site is an invoke: {:?}",
        xrefs[0]
    );

    let bump_calls: Vec<CallSiteMatch> = calls_to(&module, "Hello.bumpCounter");
    assert_eq!(bump_calls.len(), 1, "exactly main calls bumpCounter");
    assert_eq!(bump_calls[0].caller, "Hello.main");

    let describe_xrefs: Vec<XrefMatch> = xrefs_to(&module, "Hello.describe");
    assert!(
        describe_xrefs
            .iter()
            .any(|x: &XrefMatch| x.from_function.as_deref() == Some("Hello.main")),
        "main also calls describe: {describe_xrefs:?}"
    );
}

#[test]
fn external_runtime_calls_are_not_intra_dex_functions() {
    let module: Module = lifted();
    assert!(
        module
            .symbol_address("java.io.PrintStream.println")
            .is_some(),
        "the println call must register an external import symbol"
    );
    assert!(
        module
            .function_by_name("java.io.PrintStream.println")
            .is_none(),
        "println is not a function defined in this dex"
    );
    assert!(
        capability_symbols(&module, Capability::Network).is_empty(),
        "Hello.dex has no network capability sites"
    );
}

#[test]
fn lift_is_deterministic() {
    let first: Module = lifted();
    let second: Module = lifted();
    assert_eq!(function_names(&first), function_names(&second));
}
