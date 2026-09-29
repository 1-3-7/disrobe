#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn ppc32_addi_decodes() {
    let bytes: [u8; 4] = [0x38, 0x60, 0x00, 0x01];
    let out: Vec<DisasmInsn> = disassemble(Arch::PowerPc32, 0, &bytes).expect("ppc32");
    assert_eq!(out.len(), 1);
}
