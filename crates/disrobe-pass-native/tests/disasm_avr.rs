#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Arch, DisasmInsn, disassemble};
use object::{Object, ObjectSection};

const REAL_AVR_ELF: &[u8] = include_bytes!("../../../corpus/native/formats/avr_firmware.elf");

#[test]
fn avr_decodes_nop_words() {
    let bytes: [u8; 4] = [0x00; 4];
    let insns: Vec<DisasmInsn> = disassemble(Arch::Avr, 0, &bytes).expect("avr nop decode");
    assert_eq!(insns.len(), 2, "two 0x0000 words decode to two AVR nops");
    assert!(
        insns.iter().all(|i: &DisasmInsn| i.mnemonic == "nop"),
        "0x0000 is the AVR nop encoding; got {:?}",
        insns
            .iter()
            .map(|i| i.mnemonic.as_str())
            .collect::<Vec<&str>>()
    );
}

#[test]
fn real_avr_firmware_disasm() {
    let file: object::File<'_> = object::File::parse(REAL_AVR_ELF).expect("parse avr elf");
    assert_eq!(
        file.architecture(),
        object::Architecture::Avr,
        "the fixture must be a real AVR ELF (EM_AVR)"
    );
    let text: object::Section<'_, '_> = file
        .section_by_name(".text")
        .expect("avr firmware must carry a .text section");
    let code: &[u8] = text.data().expect(".text data");
    assert!(!code.is_empty(), "real .text must hold AVR machine code");

    let insns: Vec<DisasmInsn> =
        disassemble(Arch::Avr, 0, code).expect("disassemble real AVR .text");
    assert!(
        insns.len() >= 8,
        "the real firmware must decode to many AVR instructions; got {}",
        insns.len()
    );

    let mnemonics: Vec<&str> = insns
        .iter()
        .map(|i: &DisasmInsn| i.mnemonic.as_str())
        .collect();
    assert!(
        mnemonics.contains(&"jmp"),
        "the AVR interrupt vector table at .text start decodes to jmp instructions; got first 8: {:?}",
        &mnemonics[..mnemonics.len().min(8)]
    );

    let jmp_bytes: usize = insns
        .iter()
        .find(|i: &&DisasmInsn| i.mnemonic == "jmp")
        .map(|i: &DisasmInsn| i.bytes.len())
        .expect("a jmp instruction is present");
    assert_eq!(
        jmp_bytes, 4,
        "AVR jmp is a 32-bit (two-word) instruction; variable-length decode must consume 4 bytes"
    );

    let total: usize = insns.iter().map(|i: &DisasmInsn| i.bytes.len()).sum();
    assert!(
        total <= code.len(),
        "decoded instruction bytes must not exceed the section size"
    );
    assert!(
        REAL_AVR_ELF.len() < 256 * 1024,
        "fixture under 256KB budget"
    );
}
