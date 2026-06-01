#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn aarch64_ret_decodes() {
    let bytes: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6];
    let out: Vec<DisasmInsn> = disassemble(Arch::Aarch64, 0, &bytes).expect("aarch64");
    assert_eq!(out.len(), 1);
    assert!(out[0].mnemonic.starts_with("ret"));
}
