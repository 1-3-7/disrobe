#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_pyc;
use disrobe_query::{
    CallSiteMatch, Capability, DecoderMatch, FunctionMatch, Module, Query, QueryResult, XrefMatch,
    run,
};

const AGENT_PYC: &[u8] = include_bytes!("../../../corpus/python/queryable/agent.cpython-314.pyc");

fn lifted() -> Module {
    let nir: NirModule = lift_pyc(AGENT_PYC).expect("lift recovered python ast to NIR");
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

fn decoders(module: &Module) -> Vec<DecoderMatch> {
    match run(module, &Query::StringDecoders) {
        QueryResult::StringDecoders { matches } => matches,
        other => panic!("expected StringDecoders, got {other:?}"),
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

fn capability_sites(module: &Module, capability: Capability) -> Vec<String> {
    match run(module, &Query::CapabilitySites { capability }) {
        QueryResult::CapabilitySites { matches, .. } => {
            matches.into_iter().map(|m| m.symbol).collect()
        }
        other => panic!("expected CapabilitySites, got {other:?}"),
    }
}

#[test]
fn recovered_defs_are_lifted_as_functions() {
    let module: Module = lifted();
    let names: Vec<String> = function_names(&module);
    for expected in ["<module>", "decrypt", "beacon", "main"] {
        assert!(
            names.iter().any(|n: &String| n == expected),
            "function {expected} must be lifted from the recovered ast: {names:?}"
        );
    }

    let main: &disrobe_query::Function = module.function_by_name("main").expect("main");
    assert!(main.is_export, "top-level main must be flagged exported");
    let decrypt: &disrobe_query::Function = module.function_by_name("decrypt").expect("decrypt");
    assert!(
        decrypt.is_export,
        "a public top-level def is an export site"
    );
}

#[test]
fn xor_loop_is_detected_as_a_byte_decoder() {
    let module: Module = lifted();
    let found: Vec<DecoderMatch> = decoders(&module);
    let decrypt: &DecoderMatch = found
        .iter()
        .find(|d: &&DecoderMatch| d.name == "decrypt")
        .expect("the for-loop xor over data[i] must surface decrypt as a decoder");
    assert!(
        decrypt.loop_back_edges >= 1,
        "the for-loop back-edge must be present: {decrypt:?}"
    );
    assert!(
        decrypt.byte_arith_ops >= 1,
        "data[i] ^ key over a subscript must count as byte-arith: {decrypt:?}"
    );
    assert!(
        decrypt.memory_ops >= 1,
        "the out[i] / data[i] subscripts must count as memory ops: {decrypt:?}"
    );
}

#[test]
fn main_calls_the_internal_decrypt() {
    let module: Module = lifted();

    let xrefs: Vec<XrefMatch> = xrefs_to(&module, "decrypt");
    let callers: Vec<&str> = xrefs
        .iter()
        .filter_map(|x: &XrefMatch| x.from_function.as_deref())
        .collect();
    assert!(
        callers.contains(&"main"),
        "main must reference the internal decrypt: callers={callers:?}"
    );
    assert!(
        xrefs.iter().all(|x: &XrefMatch| x.mnemonic == "call"),
        "intra-module calls to decrypt are call sites: {xrefs:?}"
    );

    let call_sites: Vec<CallSiteMatch> = calls_to(&module, "decrypt");
    assert_eq!(
        call_sites.len(),
        1,
        "exactly the one main call reaches decrypt: {call_sites:?}"
    );
    assert_eq!(call_sites[0].caller, "main");
}

#[test]
fn network_and_process_calls_are_capability_sites() {
    let module: Module = lifted();

    let network: Vec<String> = capability_sites(&module, Capability::Network);
    assert!(
        network.iter().any(|s: &String| s.contains("connect")),
        "sock.connect must surface a Network capability site: {network:?}"
    );

    let process: Vec<String> = capability_sites(&module, Capability::Process);
    assert!(
        process.iter().any(|s: &String| s.contains("system")),
        "os.system must surface a Process capability site: {process:?}"
    );
}

#[test]
fn lift_is_deterministic() {
    let first: Module = lifted();
    let second: Module = lifted();
    assert_eq!(function_names(&first), function_names(&second));
    assert_eq!(decoders(&first).len(), decoders(&second).len());
}
