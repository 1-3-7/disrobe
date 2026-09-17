#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn x86_64_mov_immediate() {
    let bytes: [u8; 7] = [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00];
    let out: Vec<DisasmInsn> = disassemble(Arch::X86_64, 0, &bytes).expect("disasm");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "mov");
}
