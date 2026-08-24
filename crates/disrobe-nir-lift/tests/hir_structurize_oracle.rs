#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{HirFunction, HirModule, NirBlock, NirModule, basic_blocks, structurize_module};
use disrobe_nir_lift::lift_wasm_module;
use disrobe_query::{Capability, Module, Query, QueryResult, run};

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

fn mir_of(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat fixture");
    lift_wasm_module(&bytes).expect("lift wasm module to NIR")
}

fn names(result: &QueryResult) -> Vec<String> {
    match result {
        QueryResult::Functions { matches } => {
            let mut out: Vec<String> = matches.iter().map(|m| m.name.clone()).collect();
            out.sort();
            out
        }
        QueryResult::StringDecoders { matches } => {
            let mut out: Vec<String> = matches.iter().map(|m| m.name.clone()).collect();
            out.sort();
            out
        }
        QueryResult::XrefsTo { matches, .. } => {
            let mut out: Vec<String> = matches.iter().map(|m| m.to_symbol.clone()).collect();
            out.sort();
            out
        }
        QueryResult::CapabilitySites { matches, .. } => {
            let mut out: Vec<String> = matches.iter().map(|m| m.symbol.clone()).collect();
            out.sort();
            out
        }
        QueryResult::ComplexityOver { matches, .. } => {
            let mut out: Vec<String> = matches
                .iter()
                .map(|m| format!("{} c{}", m.name, m.complexity))
                .collect();
            out.sort();
            out
        }
        QueryResult::CallsTo { matches, .. } => {
            let mut out: Vec<String> = matches.iter().map(|m| m.target.clone()).collect();
            out.sort();
            out
        }
        QueryResult::ConcreteImplementors(_) | QueryResult::Unsupported { .. } => {
            panic!("unexpected query result")
        }
    }
}

fn oracle_queries() -> Vec<Query> {
    vec![
        Query::Functions,
        Query::StringDecoders,
        Query::XrefsTo {
            symbol: "sock_open".to_owned(),
        },
        Query::XrefsTo {
            symbol: "connect".to_owned(),
        },
        Query::CapabilitySites {
            capability: Capability::Network,
        },
        Query::CapabilitySites {
            capability: Capability::Crypto,
        },
        Query::CapabilitySites {
            capability: Capability::Filesystem,
        },
        Query::CapabilitySites {
            capability: Capability::Process,
        },
        Query::ComplexityOver { threshold: 0 },
    ]
}

fn assert_hir_preserves_mir_facts(wat: &str) {
    let mir: NirModule = mir_of(wat);
    let hir: HirModule = structurize_module(&mir);
    let lowered: NirModule = hir.to_nir_module();

    let mir_module: Module = Module::from_nir(&mir);
    let hir_module: Module = Module::from_nir(&lowered);

    for query in oracle_queries() {
        let mir_facts: QueryResult = run(&mir_module, &query);
        let hir_facts: QueryResult = run(&hir_module, &query);
        assert_eq!(
            names(&mir_facts),
            names(&hir_facts),
            "query {query:?} diverged between Mir and Hir for wat fixture"
        );
    }
}

#[test]
fn hir_preserves_compute_xor_mir_query_facts() {
    assert_hir_preserves_mir_facts(COMPUTE_XOR_WAT);
}

#[test]
fn hir_preserves_sock_open_mir_query_facts() {
    assert_hir_preserves_mir_facts(SOCK_OPEN_WAT);
}

#[test]
fn hir_preserves_network_import_mir_query_facts() {
    assert_hir_preserves_mir_facts(NETWORK_IMPORT_WAT);
}

#[test]
fn hir_accounts_for_every_mir_basic_block() {
    for wat in [COMPUTE_XOR_WAT, SOCK_OPEN_WAT, NETWORK_IMPORT_WAT] {
        let mir: NirModule = mir_of(wat);
        let hir: HirModule = structurize_module(&mir);
        assert_eq!(
            mir.functions.len(),
            hir.functions.len(),
            "every Mir function must have a Hir counterpart"
        );
        for (nir_fn, hir_fn) in mir.functions.iter().zip(hir.functions.iter()) {
            let mir_block_starts: BTreeSet<u64> = basic_blocks(nir_fn)
                .iter()
                .map(|b: &NirBlock| b.start)
                .collect();
            let hir_block_starts: BTreeSet<u64> = hir_fn.block_starts();
            assert_eq!(
                mir_block_starts, hir_block_starts,
                "Hir dropped or invented a basic block for {}",
                nir_fn.name
            );
        }
    }
}

#[test]
fn hir_accounts_for_every_mir_instruction_address() {
    for wat in [COMPUTE_XOR_WAT, SOCK_OPEN_WAT, NETWORK_IMPORT_WAT] {
        let mir: NirModule = mir_of(wat);
        let hir: HirModule = structurize_module(&mir);
        for (nir_fn, hir_fn) in mir.functions.iter().zip(hir.functions.iter()) {
            let mir_addrs: BTreeSet<u64> = nir_fn.instructions.iter().map(|i| i.address).collect();
            let hir_addrs: BTreeSet<u64> = hir_fn.instruction_addresses();
            assert_eq!(
                mir_addrs, hir_addrs,
                "Hir dropped or invented an instruction address for {}",
                nir_fn.name
            );
        }
    }
}

#[test]
fn compute_xor_decoder_loop_survives_to_hir() {
    let mir: NirModule = mir_of(COMPUTE_XOR_WAT);
    let hir: HirModule = structurize_module(&mir);

    let mir_module: Module = Module::from_nir(&mir);
    let QueryResult::StringDecoders {
        matches: mir_decoders,
    } = run(&mir_module, &Query::StringDecoders)
    else {
        panic!("wrong variant");
    };
    assert_eq!(
        mir_decoders
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        vec!["run"],
        "sanity: the Mir fixture must carry exactly one byte-xor decoder loop"
    );

    let hir_module: Module = Module::from_nir(&hir.to_nir_module());
    let QueryResult::StringDecoders {
        matches: hir_decoders,
    } = run(&hir_module, &Query::StringDecoders)
    else {
        panic!("wrong variant");
    };
    assert_eq!(
        hir_decoders
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        vec!["run"],
        "the decoder-loop fact that holds at Mir must still resolve after structurizing to Hir"
    );
}

#[test]
fn compute_xor_structurizes_with_a_loop() {
    let mir: NirModule = mir_of(COMPUTE_XOR_WAT);
    let hir: HirModule = structurize_module(&mir);
    let run_fn: &HirFunction = hir
        .functions
        .iter()
        .find(|f: &&HirFunction| f.name == "run")
        .expect("run function in hir");
    assert!(
        run_fn.structured,
        "the compute_xor loop is reducible and must fully structurize: {:?}",
        run_fn.body
    );
}

#[test]
fn structurize_is_deterministic() {
    let first: NirModule = mir_of(COMPUTE_XOR_WAT);
    let second: NirModule = mir_of(COMPUTE_XOR_WAT);
    assert_eq!(structurize_module(&first), structurize_module(&second));
}
