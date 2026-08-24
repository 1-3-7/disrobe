#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{
    HirFunction, HirModule, NirModule, SurfaceFunction, SurfaceModule, structurize_module,
    surfacify_module,
};
use disrobe_nir_lift::lift_wasm_module;
use disrobe_query::{Capability, Module, Query, QueryResult, run};

const COMPUTE_XOR_WAT: &str = include_str!("../../../corpus/wasm/plugins/compute_xor.wat");
const SOCK_OPEN_WAT: &str = include_str!("../../../corpus/wasm/plugins/deny_net_sock_open.wat");
const FD_WRITE_WAT: &str = include_str!("../../../corpus/wasm/plugins/deny_fs_fd_write.wat");
const NETWORK_IMPORT_WAT: &str = r#"
    (module
      (import "env" "connect" (func $connect (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "dial") (param i32) (result i32)
        (drop (call $connect (i32.const 0) (i32.const 0)))
        (i32.const 0)))
"#;

const FIXTURES: [&str; 4] = [
    COMPUTE_XOR_WAT,
    SOCK_OPEN_WAT,
    FD_WRITE_WAT,
    NETWORK_IMPORT_WAT,
];

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
            symbol: "fd_write".to_owned(),
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

#[test]
fn surface_preserves_hir_query_facts() {
    for wat in FIXTURES {
        let mir: NirModule = mir_of(wat);
        let hir: HirModule = structurize_module(&mir);
        let surface: SurfaceModule = surfacify_module(&hir);

        let hir_module: Module = Module::from_nir(&hir.to_nir_module());
        let surface_module: Module = Module::from_nir(&surface.to_nir_module());

        for query in oracle_queries() {
            let hir_facts: QueryResult = run(&hir_module, &query);
            let surface_facts: QueryResult = run(&surface_module, &query);
            assert_eq!(
                names(&hir_facts),
                names(&surface_facts),
                "query {query:?} diverged between Hir and Surface for a wat fixture"
            );
        }
    }
}

#[test]
fn surface_accounts_for_every_hir_basic_block() {
    for wat in FIXTURES {
        let mir: NirModule = mir_of(wat);
        let hir: HirModule = structurize_module(&mir);
        let surface: SurfaceModule = surfacify_module(&hir);
        assert_eq!(
            hir.functions.len(),
            surface.functions.len(),
            "every Hir function must have a Surface counterpart"
        );
        for (hir_fn, surface_fn) in hir.functions.iter().zip(surface.functions.iter()) {
            let hir_blocks: BTreeSet<u64> = hir_fn.block_starts();
            let surface_blocks: BTreeSet<u64> = surface_fn.block_starts();
            assert_eq!(
                hir_blocks, surface_blocks,
                "Surface dropped or invented a basic block for {}",
                hir_fn.name
            );
        }
    }
}

#[test]
fn surface_accounts_for_every_hir_instruction_address() {
    for wat in FIXTURES {
        let mir: NirModule = mir_of(wat);
        let hir: HirModule = structurize_module(&mir);
        let surface: SurfaceModule = surfacify_module(&hir);
        for (hir_fn, surface_fn) in hir.functions.iter().zip(surface.functions.iter()) {
            let hir_addrs: BTreeSet<u64> = hir_fn.instruction_addresses();
            let surface_addrs: BTreeSet<u64> = surface_fn.instruction_addresses();
            assert_eq!(
                hir_addrs, surface_addrs,
                "Surface dropped or invented an instruction address for {}",
                hir_fn.name
            );
        }
    }
}

#[test]
fn compute_xor_decoder_loop_survives_to_surface() {
    let mir: NirModule = mir_of(COMPUTE_XOR_WAT);
    let hir: HirModule = structurize_module(&mir);
    let surface: SurfaceModule = surfacify_module(&hir);

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
        "sanity: the Hir level must carry exactly one byte-xor decoder loop"
    );

    let surface_module: Module = Module::from_nir(&surface.to_nir_module());
    let QueryResult::StringDecoders {
        matches: surface_decoders,
    } = run(&surface_module, &Query::StringDecoders)
    else {
        panic!("wrong variant");
    };
    assert_eq!(
        surface_decoders
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        vec!["run"],
        "the decoder-loop fact that holds at Hir must still resolve after lifting to Surface"
    );
}

#[test]
fn compute_xor_run_lifts_to_a_structured_surface_function() {
    let mir: NirModule = mir_of(COMPUTE_XOR_WAT);
    let hir: HirModule = structurize_module(&mir);
    let surface: SurfaceModule = surfacify_module(&hir);
    let run_fn: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|f: &&SurfaceFunction| f.name() == "run")
        .expect("run function in surface");
    let run_hir: &HirFunction = hir
        .functions
        .iter()
        .find(|f: &&HirFunction| f.name == "run")
        .expect("run function in hir");
    assert_eq!(
        run_fn.structured, run_hir.structured,
        "a structured Hir function must lift to a structured Surface function"
    );
}

#[test]
fn surfacify_is_deterministic() {
    let first: NirModule = mir_of(COMPUTE_XOR_WAT);
    let second: NirModule = mir_of(COMPUTE_XOR_WAT);
    assert_eq!(
        surfacify_module(&structurize_module(&first)),
        surfacify_module(&structurize_module(&second))
    );
}
