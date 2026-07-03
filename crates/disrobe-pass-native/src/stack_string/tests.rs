use iced_x86::code_asm::{CodeAssembler, dword_ptr, rsp};

use super::*;

const BASE: u64 = 0x1000;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble stack-string function")
}

#[test]
fn reassembles_dword_immediate_stack_string() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(dword_ptr(rsp + 0x10), i32::from_le_bytes(*b"http"))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x14), i32::from_le_bytes(*b"://e"))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x18), i32::from_le_bytes(*b"vil."))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x1c), i32::from_le_bytes(*b"com\0"))
        .unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "http://evil.com"),
        "the four contiguous dword stores must reassemble to the full URL: {strings:?}"
    );
}

#[test]
fn reassembles_word_and_byte_immediate_tail() {
    use iced_x86::code_asm::{byte_ptr, word_ptr};
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(dword_ptr(rsp + 0x20), i32::from_le_bytes(*b"cmd."))
        .unwrap();
    asm.mov(word_ptr(rsp + 0x24), i32::from(i16::from_le_bytes(*b"ex")))
        .unwrap();
    asm.mov(byte_ptr(rsp + 0x26), 0x65i32).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "cmd.exe"),
        "mixed dword + word + byte contiguous stores must reassemble cmd.exe: {strings:?}"
    );
}

#[test]
fn discontiguous_groups_do_not_merge_across_a_gap() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(dword_ptr(rsp + 0x10), i32::from_le_bytes(*b"FIRS"))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x14), i32::from_le_bytes(*b"T_\0\0"))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x80), i32::from_le_bytes(*b"SECO"))
        .unwrap();
    asm.mov(dword_ptr(rsp + 0x84), i32::from_le_bytes(*b"ND_\0"))
        .unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "FIRST_"),
        "first contiguous group must reassemble independently: {strings:?}"
    );
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "SECOND_"),
        "second group at a distant displacement must not merge with the first: {strings:?}"
    );
    assert!(
        !strings
            .iter()
            .any(|s: &ReassembledStackString| s.value.contains("FIRST_SECOND")),
        "non-contiguous displacements must not be concatenated: {strings:?}"
    );
}

#[test]
fn plain_arithmetic_yields_no_stack_strings() {
    use iced_x86::code_asm::{eax, ebx};
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, 1i32).unwrap();
    asm.add(eax, ebx).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings.is_empty(),
        "code with no immediate stack stores must not invent strings: {strings:?}"
    );
}

#[test]
fn reassembles_push_imm32_chain_built_downward_x86() {
    let mut asm: CodeAssembler = CodeAssembler::new(32).expect("assembler");
    asm.push(i32::from_le_bytes(*b"com\0")).unwrap();
    asm.push(i32::from_le_bytes(*b"vil.")).unwrap();
    asm.push(i32::from_le_bytes(*b"://e")).unwrap();
    asm.push(i32::from_le_bytes(*b"http")).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(32, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "http://evil.com"),
        "a 32-bit downward push-imm32 chain must reassemble low-to-high into the URL: {strings:?}"
    );
}

#[test]
fn push_imm32_in_x64_occupies_eight_byte_slots() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.push(i32::from_le_bytes(*b"://e")).unwrap();
    asm.push(i32::from_le_bytes(*b"http")).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "http"),
        "a 64-bit push imm32 occupies a sign-extended 8-byte slot, so adjacent imm32 pushes are \
         not byte-contiguous; only the leading run surfaces: {strings:?}"
    );
    assert!(
        !strings
            .iter()
            .any(|s: &ReassembledStackString| s.value.contains("http://e")),
        "the 4-byte gap between 8-byte slots must not be silently fused: {strings:?}"
    );
}

fn sse_literal_program(literal: &[u8; 16]) -> (Vec<u8>, u64) {
    use iced_x86::code_asm::{qword_ptr, rsp, xmm0};
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut data: iced_x86::code_asm::CodeLabel = asm.create_label();
    asm.movups(xmm0, qword_ptr(data)).unwrap();
    asm.movups(qword_ptr(rsp + 0x20), xmm0).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut data).unwrap();
    asm.db(literal).unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let data_va: u64 = BASE + (bytes.len() - literal.len()) as u64;
    (bytes, data_va)
}

#[test]
fn reassembles_sse_block_store_from_rip_literal() {
    let literal: &[u8; 16] = b"sse-literal-15\0\0";
    let (bytes, data_va): (Vec<u8>, u64) = sse_literal_program(literal);

    let rodata: Vec<ReadOnlyWindow<'_>> = vec![ReadOnlyWindow {
        address: data_va,
        bytes: literal,
    }];
    let strings: Vec<ReassembledStackString> =
        reassemble_stack_strings_with_rodata(64, BASE, &bytes, &rodata);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "sse-literal-15"),
        "an xmm block store fed from a rip-relative literal must recover the literal text: {strings:?}"
    );
}

#[test]
fn sse_block_store_without_rodata_recovers_nothing() {
    let literal: &[u8; 16] = b"sse-literal-15\0\0";
    let (bytes, _data_va): (Vec<u8>, u64) = sse_literal_program(literal);
    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings.is_empty(),
        "without the literal bytes the block store must not invent a string: {strings:?}"
    );
}

#[test]
fn xor_decodes_obfuscated_dword_stores() {
    use iced_x86::code_asm::{byte_ptr, dword_ptr, rsp};
    const KEY: u8 = 0x5a;
    let plain: &[u8; 8] = b"P@sSw0rd";
    let mut enc: [u8; 8] = *plain;
    for b in &mut enc {
        *b ^= KEY;
    }
    let lo: i32 = i32::from_le_bytes([enc[0], enc[1], enc[2], enc[3]]);
    let hi: i32 = i32::from_le_bytes([enc[4], enc[5], enc[6], enc[7]]);

    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(dword_ptr(rsp + 0x10), lo).unwrap();
    asm.mov(dword_ptr(rsp + 0x14), hi).unwrap();
    for i in 0..8i64 {
        asm.xor(byte_ptr(rsp + (0x10 + i)), i32::from(KEY)).unwrap();
    }
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, BASE, &bytes);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == "P@sSw0rd"),
        "store-then-xor-decode must recover the plaintext: {strings:?}"
    );
}
