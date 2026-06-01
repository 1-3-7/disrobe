#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, Error, disassemble};

#[test]
fn avr_returns_unsupported_arch_until_capstone_rust_bindings_expose_avr() {
    let bytes: [u8; 4] = [0x00; 4];
    let err: Error = disassemble(Arch::Avr, 0, &bytes).expect_err("avr disabled");
    assert!(matches!(err, Error::UnsupportedArch(_)));
}

#[test]
#[ignore = "FIXTURE PENDING: real AVR firmware once rust-capstone exposes the AVR builder"]
fn real_avr_firmware_disasm() {}
