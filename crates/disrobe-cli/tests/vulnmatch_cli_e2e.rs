#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::unreadable_literal
)]

mod common;

use std::path::PathBuf;

use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
};
use disrobe_ir::{Envelope, Rung};

fn fixture_path() -> PathBuf {
    common::temp_path("vulnmatch", "dr")
}

fn write_fixture(path: &std::path::Path) {
    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0u8; 32],
        instructions: vec![
            DisasmInstruction {
                offset: 0x10,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "call".to_owned(),
                operands: vec!["gets".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x20),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x15,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: Vec::new(),
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0x10,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Export,
            },
            DisasmSymbol {
                address: 0x20,
                name: "gets".to_owned(),
                kind: DisasmSymbolKind::Import,
            },
        ],
    };
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode disassembly payload");
    let envelope: Envelope = Envelope::new(Rung::Disasm, hot, Vec::new());
    let bytes: Vec<u8> = envelope.encode().expect("encode envelope");
    common::write_bytes(path, &bytes);
}

#[test]
fn vulnmatch_reports_reachable_gets_deterministically() {
    let input: PathBuf = fixture_path();
    write_fixture(&input);
    let input_arg: String = input.display().to_string();
    let first: common::Run = common::run_disrobe(&["vulnmatch", &input_arg]);
    let second: common::Run = common::run_disrobe(&["vulnmatch", &input_arg]);

    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    assert!(
        first.stdout.contains("cwe-242-gets"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("tier: reachable"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("analysis: incomplete"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("path: query:0000000000000010:main"),
        "stdout: {}",
        first.stdout
    );

    let _: std::io::Result<()> = std::fs::remove_file(input);
}
