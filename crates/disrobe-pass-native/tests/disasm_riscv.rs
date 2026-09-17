#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn riscv32_addi_decodes() {
    let bytes: [u8; 4] = [0x13, 0x05, 0x00, 0x00];
    let out: Vec<DisasmInsn> = disassemble(Arch::RiscV32, 0, &bytes).expect("rv32");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "mv");
    assert_eq!(out[0].operands, "a0, zero");
}

#[test]
fn riscv64_addi_decodes() {
    let bytes: [u8; 4] = [0x13, 0x05, 0x00, 0x00];
    let out: Vec<DisasmInsn> = disassemble(Arch::RiscV64, 0, &bytes).expect("rv64");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "mv");
    assert_eq!(out[0].operands, "a0, zero");
}
