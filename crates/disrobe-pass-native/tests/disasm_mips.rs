#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn mips_be_lui_decodes() {
    let bytes: [u8; 4] = [0x3C, 0x01, 0x00, 0x01];
    let out: Vec<DisasmInsn> = disassemble(Arch::MipsBe32, 0, &bytes).expect("mips-be");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "lui");
}
