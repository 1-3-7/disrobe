use std::collections::BTreeSet;

use iced_x86::code_asm::{CodeAssembler, qword_ptr, rax};

use super::*;

fn assemble(asm: &mut CodeAssembler, base: u64) -> Vec<u8> {
    asm.assemble(base).expect("assemble")
}

#[test]
fn jmp_to_import_thunk_is_a_tail_call() {
    const SECTION: u64 = 0x1000;
    const STUB: u64 = 0x2000;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.jmp(STUB).unwrap();
    let code: Vec<u8> = assemble(&mut asm, SECTION);

    let stubs: Vec<ImportStub> = vec![ImportStub {
        stub_address: STUB,
        slot_address: 0x3000,
        name: "printf".to_owned(),
    }];
    let starts: BTreeSet<u64> = BTreeSet::from([SECTION]);
    let tails: Vec<TailCall> = classify_tail_calls(64, SECTION, &code, &starts, &stubs);
    assert_eq!(tails.len(), 1, "the jmp to printf@plt is one tail call");
    assert_eq!(tails[0].kind, TailCallKind::ImportThunk);
    assert_eq!(tails[0].name.as_deref(), Some("printf"));
}

#[test]
fn jmp_to_another_function_start_is_a_tail_call() {
    const SECTION: u64 = 0x1000;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.nop().unwrap();
    asm.jmp(0x1400u64).unwrap();
    let code: Vec<u8> = assemble(&mut asm, SECTION);

    let starts: BTreeSet<u64> = BTreeSet::from([SECTION, 0x1400]);
    let tails: Vec<TailCall> = classify_tail_calls(64, SECTION, &code, &starts, &[]);
    assert_eq!(tails.len(), 1);
    assert_eq!(tails[0].kind, TailCallKind::FunctionStart);
    assert_eq!(tails[0].target, 0x1400);
}

#[test]
fn jmp_back_to_own_function_start_is_not_a_tail_call() {
    const SECTION: u64 = 0x1000;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.nop().unwrap();
    asm.jmp(SECTION).unwrap();
    let code: Vec<u8> = assemble(&mut asm, SECTION);

    let starts: BTreeSet<u64> = BTreeSet::from([SECTION, 0x2000]);
    let tails: Vec<TailCall> = classify_tail_calls(64, SECTION, &code, &starts, &[]);
    assert!(
        tails.is_empty(),
        "a loop edge back to the containing function's own entry is not a tail call: {tails:?}"
    );
}

#[test]
fn jmp_into_the_middle_of_a_function_is_not_a_tail_call() {
    const SECTION: u64 = 0x1000;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.jmp(0x1234u64).unwrap();
    let code: Vec<u8> = assemble(&mut asm, SECTION);

    let starts: BTreeSet<u64> = BTreeSet::from([SECTION, 0x1400]);
    let tails: Vec<TailCall> = classify_tail_calls(64, SECTION, &code, &starts, &[]);
    assert!(
        tails.is_empty(),
        "an intra-function jmp to a non-start address is an ordinary edge, not a tail call: {tails:?}"
    );
}

#[test]
fn indirect_register_jump_is_not_a_resolvable_plt_slot() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.jmp(qword_ptr(rax)).unwrap();
    let code: Vec<u8> = assemble(&mut asm, 0x1000);
    let mut decoder: iced_x86::Decoder<'_> =
        iced_x86::Decoder::with_ip(64, &code, 0x1000, iced_x86::DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    decoder.decode_out(&mut insn);
    assert!(
        super::indirect_jmp_slot(&insn).is_none(),
        "a register-indirect jmp has no statically resolvable slot"
    );
}
