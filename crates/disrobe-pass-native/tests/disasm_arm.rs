#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn arm_a32_decodes_single_word() {
    let bytes: [u8; 4] = [0x00, 0xF0, 0x20, 0xE3];
    let out: Vec<DisasmInsn> = disassemble(Arch::Arm32, 0, &bytes).expect("a32");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "nop");
    assert!(out[0].operands.is_empty());
}

#[test]
fn arm_thumb_decodes_pair_of_halfwords() {
    let bytes: [u8; 4] = [0x00, 0x00, 0x00, 0xBF];
    let out: Vec<DisasmInsn> = disassemble(Arch::Thumb, 0, &bytes).expect("thumb");
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].mnemonic, "nop");
    assert_eq!(out[1].bytes, [0x00, 0xBF]);
}
