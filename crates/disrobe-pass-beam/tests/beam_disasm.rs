#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use disrobe_pass_beam::{BeamFile, Disassembly, Operand, disassemble};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, encode_compact_small,
};

fn build_disasm_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["m", "id", "answer"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 1));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(64u8);
    code.extend(encode_compact_small(3, 0));
    code.extend(encode_compact_small(3, 1));
    code.push(64u8);
    code.extend(encode_compact_small(1, 42));
    code.extend(encode_compact_small(3, 0));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 1u32, 2u32)])),
    ];
    build_beam(&chunks)
}

#[test]
fn disassembles_full_function() {
    let buf: Vec<u8> = build_disasm_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let code = beam.chunks.code.as_ref().expect("code");
    let dis: Disassembly = disassemble(code).expect("disasm");
    let mnemonics: Vec<&str> = dis.instructions.iter().map(|i| i.name).collect();
    assert_eq!(
        mnemonics,
        vec![
            "label",
            "func_info",
            "label",
            "move",
            "move",
            "return",
            "int_code_end"
        ]
    );
}

#[test]
fn move_carries_integer_literal() {
    let buf: Vec<u8> = build_disasm_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let dis: Disassembly = disassemble(beam.chunks.code.as_ref().unwrap()).expect("disasm");
    let move_int = dis
        .instructions
        .iter()
        .find(|i| i.name == "move" && matches!(i.operands.first(), Some(Operand::SignedInteger(_))))
        .expect("move int present");
    let Operand::SignedInteger(v) = move_int.operands[0] else {
        panic!("expected integer operand");
    };
    assert_eq!(v, 42);
}

#[test]
fn unknown_opcode_is_diagnosed() {
    let atoms: Vec<u8> = build_atu8(&["m"]);
    let code: Vec<u8> = vec![255u8];
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(0, 0, &code)),
    ];
    let buf: Vec<u8> = build_beam(&chunks);
    let beam: BeamFile = BeamFile::parse(&buf).unwrap();
    let err = disassemble(beam.chunks.code.as_ref().unwrap()).unwrap_err();
    assert!(err.to_string().contains("DR-BEAM-0012"));
}
