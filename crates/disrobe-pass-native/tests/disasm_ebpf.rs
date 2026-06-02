#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

#[test]
fn ebpf_exit_decodes() {
    let bytes: [u8; 8] = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let out: Vec<DisasmInsn> = disassemble(Arch::Ebpf, 0, &bytes).expect("ebpf");
    assert!(!out.is_empty());
}
