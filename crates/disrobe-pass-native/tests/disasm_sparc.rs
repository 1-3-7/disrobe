#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn sparc_decodes_nop_word() {
    let bytes: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
    let out: Vec<DisasmInsn> = disassemble(Arch::Sparc, 0, &bytes).expect("sparc");
    assert!(!out.is_empty());
}
