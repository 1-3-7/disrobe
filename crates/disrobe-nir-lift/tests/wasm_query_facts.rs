#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_wasm_module;
use disrobe_query::{
    Capability, DecoderMatch, FunctionMatch, Module, Query, QueryResult, XrefMatch, run,
};

const COMPUTE_XOR_WAT: &str = include_str!("../../../corpus/wasm/plugins/compute_xor.wat");
const SOCK_OPEN_WAT: &str = include_str!("../../../corpus/wasm/plugins/deny_net_sock_open.wat");

const NETWORK_IMPORT_WAT: &str = r#"
    (module
      (import "env" "connect" (func $connect (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "dial") (param i32) (result i32)
        (drop (call $connect (i32.const 0) (i32.const 0)))
        (i32.const 0)))
"#;

fn lifted_module(wat: &str) -> Module {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat fixture");
    let nir: NirModule = lift_wasm_module(&bytes).expect("lift wasm module to NIR");
    Module::from_nir(&nir)
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions result, got {other:?}"),
    }
}

fn decoder_matches(module: &Module) -> Vec<DecoderMatch> {
    match run(module, &Query::StringDecoders) {
        QueryResult::StringDecoders { matches } => matches,
        other => panic!("expected StringDecoders result, got {other:?}"),
    }
}

fn xref_matches(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    match run(
        module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo result, got {other:?}"),
    }
}

fn capability_sites(module: &Module, capability: Capability) -> Vec<String> {
    match run(module, &Query::CapabilitySites { capability }) {
        QueryResult::CapabilitySites { matches, .. } => {
            matches.into_iter().map(|m| m.symbol).collect()
        }
        other => panic!("expected CapabilitySites result, got {other:?}"),
    }
}

#[test]
fn compute_xor_lifts_to_one_exported_function() {
    let module: Module = lifted_module(COMPUTE_XOR_WAT);
    let names: Vec<String> = function_names(&module);
    assert_eq!(names, vec!["run".to_owned()], "names={names:?}");
    let run_fn: &disrobe_query::Function = module.function_by_name("run").expect("run function");
    assert!(run_fn.is_export, "the run export must be flagged exported");
}

#[test]
fn compute_xor_loop_is_detected_as_a_byte_decoder() {
    let module: Module = lifted_module(COMPUTE_XOR_WAT);
    let decoders: Vec<DecoderMatch> = decoder_matches(&module);
    assert_eq!(decoders.len(), 1, "decoders={decoders:?}");
    let decoder: &DecoderMatch = &decoders[0];
    assert_eq!(decoder.name, "run");
    assert!(
        decoder.loop_back_edges >= 1,
        "the br $next loop must be a back-edge: {decoder:?}"
    );
    assert!(
        decoder.byte_arith_ops >= 1,
        "the i32.xor over a byte load must count as byte-arith: {decoder:?}"
    );
    assert!(
        decoder.memory_ops >= 1,
        "the load8/store8 must count as memory ops: {decoder:?}"
    );
}

#[test]
fn sock_open_import_call_is_an_xref() {
    let module: Module = lifted_module(SOCK_OPEN_WAT);
    let names: Vec<String> = function_names(&module);
    assert_eq!(names, vec!["run".to_owned()], "names={names:?}");

    let xrefs: Vec<XrefMatch> = xref_matches(&module, "sock_open");
    assert_eq!(xrefs.len(), 1, "exactly one call to sock_open: {xrefs:?}");
    let xref: &XrefMatch = &xrefs[0];
    assert_eq!(xref.to_symbol, "sock_open");
    assert_eq!(xref.from_function.as_deref(), Some("run"));
    assert_eq!(xref.mnemonic, "call");
}

#[test]
fn network_import_call_is_a_capability_site() {
    let module: Module = lifted_module(NETWORK_IMPORT_WAT);
    let sites: Vec<String> = capability_sites(&module, Capability::Network);
    assert_eq!(
        sites,
        vec!["connect".to_owned()],
        "the call $connect must surface a Network capability site: {sites:?}"
    );
}

#[test]
fn lifting_is_deterministic_across_runs() {
    let first: Module = lifted_module(COMPUTE_XOR_WAT);
    let second: Module = lifted_module(COMPUTE_XOR_WAT);
    assert_eq!(
        function_names(&first),
        function_names(&second),
        "two lifts of the same artifact must agree"
    );
    assert_eq!(
        decoder_matches(&first).len(),
        decoder_matches(&second).len()
    );
}
