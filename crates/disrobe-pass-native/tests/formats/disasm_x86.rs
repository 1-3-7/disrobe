#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn x86_nop_ret_round_trip() {
    let bytes: [u8; 2] = [0x90, 0xC3];
    let out: Vec<DisasmInsn> = disassemble(Arch::X86, 0x1000, &bytes).expect("disasm");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].mnemonic, "nop");
    assert_eq!(out[1].mnemonic, "ret");
}
