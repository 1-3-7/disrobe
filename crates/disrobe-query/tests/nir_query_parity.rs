#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
};
use disrobe_ir::{Envelope, Rung};
use disrobe_nir::{NirModule, encode_nir};
use disrobe_query::{
    Capability, Module, Query, QueryResult, disasm_to_nir, module_from_bytes, run,
};

fn insn(
    offset: u64,
    bytes: Vec<u8>,
    mnemonic: &str,
    operands: &[&str],
    flow: InsnFlow,
    branch_target: Option<u64>,
) -> DisasmInstruction {
    DisasmInstruction {
        offset,
        bytes,
        mnemonic: mnemonic.to_owned(),
        operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
        flow,
        branch_target,
        ..DisasmInstruction::default()
    }
}

fn sym(address: u64, name: &str, kind: DisasmSymbolKind) -> DisasmSymbol {
    DisasmSymbol {
        address,
        name: name.to_owned(),
        kind,
    }
}

fn fixture_payload() -> DisasmPayload {
    let instructions: Vec<DisasmInstruction> = vec![
        insn(
            0x00,
            vec![0x8a, 0x07],
            "mov",
            &["al", "[rdi]"],
            InsnFlow::Sequential,
            None,
        ),
        insn(0x02, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(
            0x10,
            vec![0x53],
            "push",
            &["rbx"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x11,
            vec![0x31, 0xdb],
            "xor",
            &["ebx", "ebx"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x13,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x0"],
            InsnFlow::Call,
            Some(0x00),
        ),
        insn(
            0x18,
            vec![0x34, 0x5a],
            "xor",
            &["al", "0x5a"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x1a,
            vec![0x88, 0x04, 0x1f],
            "mov",
            &["[rdi+rbx]", "al"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x1d,
            vec![0x43],
            "inc",
            &["ebx"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x1e,
            vec![0x83, 0xfb, 0x10],
            "cmp",
            &["ebx", "0x10"],
            InsnFlow::Sequential,
            None,
        ),
        insn(
            0x21,
            vec![0x7c, 0xf3],
            "jl",
            &["0x16"],
            InsnFlow::ConditionalBranch,
            Some(0x16),
        ),
        insn(
            0x23,
            vec![0x5b],
            "pop",
            &["rbx"],
            InsnFlow::Sequential,
            None,
        ),
        insn(0x24, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(
            0x30,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x70"],
            InsnFlow::Call,
            Some(0x70),
        ),
        insn(0x35, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(
            0x40,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x74"],
            InsnFlow::Call,
            Some(0x74),
        ),
        insn(
            0x45,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x78"],
            InsnFlow::Call,
            Some(0x78),
        ),
        insn(0x4a, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(
            0x50,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x10"],
            InsnFlow::Call,
            Some(0x10),
        ),
        insn(
            0x55,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x30"],
            InsnFlow::Call,
            Some(0x30),
        ),
        insn(
            0x5a,
            vec![0xe8, 0, 0, 0, 0],
            "call",
            &["0x40"],
            InsnFlow::Call,
            Some(0x40),
        ),
        insn(
            0x5f,
            vec![0x31, 0xc0],
            "xor",
            &["eax", "eax"],
            InsnFlow::Sequential,
            None,
        ),
        insn(0x61, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(0x70, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(0x74, vec![0xc3], "ret", &[], InsnFlow::Return, None),
        insn(0x78, vec![0xc3], "ret", &[], InsnFlow::Return, None),
    ];
    let symbol_table: Vec<DisasmSymbol> = vec![
        sym(0x00, "read_byte", DisasmSymbolKind::Function),
        sym(0x10, "decode", DisasmSymbolKind::Function),
        sym(0x30, "crypto_init", DisasmSymbolKind::Function),
        sym(0x40, "net_send", DisasmSymbolKind::Function),
        sym(0x50, "main", DisasmSymbolKind::Export),
        sym(0x70, "CryptEncrypt", DisasmSymbolKind::Import),
        sym(0x74, "connect", DisasmSymbolKind::Import),
        sym(0x78, "send", DisasmSymbolKind::Import),
    ];
    DisasmPayload {
        source_hash: [0x5au8; 32],
        instructions,
        symbol_table,
    }
}

fn disasm_module(payload: &DisasmPayload) -> Module {
    let hot: Vec<u8> = encode_disasm(payload).expect("encode disasm");
    let env: Envelope = Envelope::new(Rung::Disasm, hot, Vec::new());
    module_from_bytes(&env.encode().expect("encode env")).expect("disasm module")
}

fn nir_module(payload: &DisasmPayload) -> Module {
    let nir: NirModule = disasm_to_nir(payload);
    let hot: Vec<u8> = encode_nir(&nir).expect("encode nir");
    let env: Envelope = Envelope::new(Rung::Mir, hot, Vec::new());
    module_from_bytes(&env.encode().expect("encode env")).expect("nir module")
}

fn all_queries() -> Vec<Query> {
    vec![
        Query::Functions,
        Query::CallsTo {
            target: "read_byte".to_owned(),
        },
        Query::CallsTo {
            target: "decode".to_owned(),
        },
        Query::CallsTo {
            target: "CryptEncrypt".to_owned(),
        },
        Query::XrefsTo {
            symbol: "read_byte".to_owned(),
        },
        Query::XrefsTo {
            symbol: "net_send".to_owned(),
        },
        Query::StringDecoders,
        Query::ComplexityOver { threshold: 1 },
        Query::ComplexityOver { threshold: 0 },
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
    ]
}

#[test]
fn nir_module_reproduces_disasm_query_results_exactly() {
    let payload: DisasmPayload = fixture_payload();
    let from_disasm: Module = disasm_module(&payload);
    let from_nir: Module = nir_module(&payload);

    for query in all_queries() {
        let disasm_result: QueryResult = run(&from_disasm, &query);
        let nir_result: QueryResult = run(&from_nir, &query);
        assert_eq!(
            disasm_result, nir_result,
            "query parity diverged for {query:?}"
        );
    }
}

#[test]
fn nir_path_finds_the_same_function_set() {
    let payload: DisasmPayload = fixture_payload();
    let module: Module = nir_module(&payload);
    let QueryResult::Functions { matches } = run(&module, &Query::Functions) else {
        panic!("wrong variant");
    };
    let mut names: Vec<String> = matches.iter().map(|m| m.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["crypto_init", "decode", "main", "net_send", "read_byte"],
        "imports are not local functions even through NIR"
    );
}

#[test]
fn nir_path_detects_the_loop_byte_xor_decoder() {
    let payload: DisasmPayload = fixture_payload();
    let module: Module = nir_module(&payload);
    let QueryResult::StringDecoders { matches } = run(&module, &Query::StringDecoders) else {
        panic!("wrong variant");
    };
    let names: Vec<&str> = matches.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["decode"], "only decode is loop+byte-xor shaped");
}

#[test]
fn nir_path_reports_network_capability_sites() {
    let payload: DisasmPayload = fixture_payload();
    let module: Module = nir_module(&payload);
    let QueryResult::CapabilitySites { matches, .. } = run(
        &module,
        &Query::CapabilitySites {
            capability: Capability::Network,
        },
    ) else {
        panic!("wrong variant");
    };
    let sites: Vec<(u64, &str)> = matches
        .iter()
        .map(|m| (m.offset, m.symbol.as_str()))
        .collect();
    assert_eq!(sites, vec![(0x40, "connect"), (0x45, "send")]);
}
