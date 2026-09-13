use std::collections::BTreeSet;

use iced_x86::code_asm::{CodeAssembler, qword_ptr, rax};

use super::*;

fn assemble(asm: &mut CodeAssembler, base: u64) -> Vec<u8> {
    asm.assemble(base).expect("assemble")
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn macho_stub_fixture() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0; 368];
    put_u32(&mut bytes, 0, 0xfeed_facf);
    put_u32(&mut bytes, 16, 3);
    put_u32(&mut bytes, 20, 256);

    put_u32(&mut bytes, 32, 0x19);
    put_u32(&mut bytes, 36, 152);
    put_u32(&mut bytes, 96, 1);
    put_u64(&mut bytes, 136, 0x1000);
    put_u64(&mut bytes, 144, 24);
    put_u32(&mut bytes, 152, 288);
    put_u32(&mut bytes, 168, 0x8);
    put_u32(&mut bytes, 172, 0);
    put_u32(&mut bytes, 176, 12);

    put_u32(&mut bytes, 184, 0x2);
    put_u32(&mut bytes, 188, 24);
    put_u32(&mut bytes, 192, 312);
    put_u32(&mut bytes, 196, 2);
    put_u32(&mut bytes, 200, 344);
    put_u32(&mut bytes, 204, 15);

    put_u32(&mut bytes, 208, 0xb);
    put_u32(&mut bytes, 212, 80);
    put_u32(&mut bytes, 264, 360);
    put_u32(&mut bytes, 268, 2);

    put_u32(&mut bytes, 312, 1);
    bytes[316] = 1;
    put_u32(&mut bytes, 328, 9);
    bytes[332] = 1;
    bytes[344..359].copy_from_slice(b"\0_system\0_fgets\0");
    put_u32(&mut bytes, 360, 0);
    put_u32(&mut bytes, 364, 1);
    bytes
}

fn macho_stub_alias_fixture(stub_count: usize) -> Vec<u8> {
    let stub_bytes: usize = stub_count.checked_mul(12).expect("bounded fixture");
    let symbol_offset: usize = 288 + stub_bytes;
    let string_offset: usize = symbol_offset + 16;
    let indirect_offset: usize = string_offset + 9;
    let indirect_bytes: usize = stub_count.checked_mul(4).expect("bounded fixture");
    let mut bytes: Vec<u8> = vec![0; indirect_offset + indirect_bytes];
    put_u32(&mut bytes, 0, 0xfeed_facf);
    put_u32(&mut bytes, 16, 3);
    put_u32(&mut bytes, 20, 256);
    put_u32(&mut bytes, 32, 0x19);
    put_u32(&mut bytes, 36, 152);
    put_u32(&mut bytes, 96, 1);
    put_u64(&mut bytes, 136, 0x1000);
    put_u64(
        &mut bytes,
        144,
        u64::try_from(stub_bytes).expect("bounded fixture"),
    );
    put_u32(&mut bytes, 152, 288);
    put_u32(&mut bytes, 168, 0x8);
    put_u32(&mut bytes, 176, 12);
    put_u32(&mut bytes, 184, 0x2);
    put_u32(&mut bytes, 188, 24);
    put_u32(
        &mut bytes,
        192,
        u32::try_from(symbol_offset).expect("bounded fixture"),
    );
    put_u32(&mut bytes, 196, 1);
    put_u32(
        &mut bytes,
        200,
        u32::try_from(string_offset).expect("bounded fixture"),
    );
    put_u32(&mut bytes, 204, 9);
    put_u32(&mut bytes, 208, 0xb);
    put_u32(&mut bytes, 212, 80);
    put_u32(
        &mut bytes,
        264,
        u32::try_from(indirect_offset).expect("bounded fixture"),
    );
    put_u32(
        &mut bytes,
        268,
        u32::try_from(stub_count).expect("bounded fixture"),
    );
    put_u32(&mut bytes, symbol_offset, 1);
    bytes[symbol_offset + 4] = 1;
    bytes[string_offset..string_offset + 9].copy_from_slice(b"\0_system\0");
    bytes
}

fn macho_duplicate_dysymtab_fixture() -> Vec<u8> {
    let mut bytes: Vec<u8> = macho_stub_fixture();
    let dysymtab: Vec<u8> = bytes[208..288].to_vec();
    bytes.splice(288..288, dysymtab);
    put_u32(&mut bytes, 16, 4);
    put_u32(&mut bytes, 20, 336);
    put_u32(&mut bytes, 152, 368);
    put_u32(&mut bytes, 192, 392);
    put_u32(&mut bytes, 200, 424);
    put_u32(&mut bytes, 264, 440);
    put_u32(&mut bytes, 344, 440);
    bytes
}

fn macho_distinct_name_fixture(count: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = macho_stub_fixture()[..288].to_vec();
    bytes.resize(288 + count * 12, 0);
    let symbol_offset: usize = bytes.len();
    bytes.resize(symbol_offset + count * 16, 0);
    let string_offset: usize = bytes.len();
    bytes.push(0);
    for index in 0..count {
        let offset: u32 = u32::try_from(bytes.len() - string_offset).expect("bounded names");
        put_u32(&mut bytes, symbol_offset + index * 16, offset);
        bytes[symbol_offset + index * 16 + 4] = 1;
        bytes.extend_from_slice(format!("_s{index:04}\0").as_bytes());
    }
    bytes.resize(bytes.len() + MAX_MACHO_SYMBOL_NAME_BYTES, b'x');
    let indirect_offset: usize = bytes.len();
    for index in 0..count {
        bytes.extend_from_slice(&u32::try_from(index).expect("bounded symbols").to_le_bytes());
    }
    put_u64(
        &mut bytes,
        144,
        u64::try_from(count * 12).expect("bounded stubs"),
    );
    for (field, value) in [
        (192, symbol_offset),
        (196, count),
        (200, string_offset),
        (204, indirect_offset - string_offset),
        (264, indirect_offset),
        (268, count),
    ] {
        put_u32(
            &mut bytes,
            field,
            u32::try_from(value).expect("bounded fixture"),
        );
    }
    bytes
}

#[test]
fn macho_short_distinct_names_charge_only_consumed_bytes() {
    let imports: Vec<ImportStub> = resolve_macho_stub_imports(&macho_distinct_name_fixture(5000));
    assert_eq!(imports.len(), 5000);
    assert_eq!(imports[0].name, "s0000");
    assert_eq!(imports[4999].name, "s4999");
}

#[test]
fn macho_unterminated_and_invalid_utf8_names_are_not_imports() {
    let mut unterminated: Vec<u8> = macho_stub_fixture();
    unterminated[344..359].fill(b'x');
    assert!(resolve_macho_stub_imports(&unterminated).is_empty());
    let mut invalid: Vec<u8> = macho_stub_fixture();
    invalid[346] = 0xff;
    invalid[354] = 0xff;
    assert!(resolve_macho_stub_imports(&invalid).is_empty());
}

fn macho_duplicate_symtab_fixture() -> Vec<u8> {
    let mut bytes: Vec<u8> = macho_stub_fixture();
    let symtab: Vec<u8> = bytes[184..208].to_vec();
    bytes.splice(288..288, symtab);
    put_u32(&mut bytes, 16, 4);
    put_u32(&mut bytes, 20, 280);
    put_u32(&mut bytes, 152, 312);
    put_u32(&mut bytes, 192, 336);
    put_u32(&mut bytes, 200, 368);
    put_u32(&mut bytes, 264, 384);
    put_u32(&mut bytes, 296, 336);
    put_u32(&mut bytes, 304, 368);
    bytes
}

#[test]
fn macho_indirect_symbols_name_variable_sized_stubs() {
    let imports: Vec<ImportStub> = resolve_macho_stub_imports(&macho_stub_fixture());
    assert_eq!(
        imports,
        vec![
            ImportStub {
                stub_address: 0x1000,
                slot_address: 0x1000,
                name: "system".to_owned(),
            },
            ImportStub {
                stub_address: 0x100c,
                slot_address: 0x100c,
                name: "fgets".to_owned(),
            },
        ]
    );
}

#[test]
fn macho_stub_table_outside_the_file_is_rejected() {
    let mut bytes: Vec<u8> = macho_stub_fixture();
    put_u32(&mut bytes, 264, u32::MAX);
    assert!(resolve_macho_stub_imports(&bytes).is_empty());
}

#[test]
fn macho_stub_alias_amplification_is_rejected() {
    let bytes: Vec<u8> = macho_stub_alias_fixture(MAX_MACHO_IMPORT_STUBS + 1);
    assert!(resolve_macho_stub_imports(&bytes).is_empty());
}

#[test]
fn macho_stub_alias_fixture_binds_valid_names_below_the_cap() {
    let imports: Vec<ImportStub> = resolve_macho_stub_imports(&macho_stub_alias_fixture(2));
    assert_eq!(imports.len(), 2);
    assert!(
        imports
            .iter()
            .all(|stub: &ImportStub| stub.name == "system")
    );
}

#[test]
fn macho_duplicate_indirect_symbol_tables_are_rejected() {
    assert!(resolve_macho_stub_imports(&macho_duplicate_dysymtab_fixture()).is_empty());
}

#[test]
fn macho_duplicate_symbol_tables_are_rejected() {
    assert!(resolve_macho_stub_imports(&macho_duplicate_symtab_fixture()).is_empty());
}

#[test]
fn plt_padding_is_not_part_of_a_stub_and_endbr_is_preserved() {
    let cases: [(&[u8], u64); 3] = [
        (&[0x0f, 0x1f, 0x40, 0x00][..], 0x1004),
        (&[0xf3, 0x0f, 0x1e, 0xfa][..], 0x1000),
        (&[0x90, 0xf3, 0x0f, 0x1e, 0xfa][..], 0x1001),
    ];
    for (prefix, expected) in cases {
        let mut code: Vec<u8> = prefix.to_vec();
        code.extend_from_slice(&[0xff, 0x25]);
        let next: u64 = 0x1000 + u64::try_from(code.len() + 4).expect("short fixture");
        let displacement: u32 = u32::try_from(0x2000 - next).expect("near GOT slot");
        code.extend_from_slice(&displacement.to_le_bytes());
        let names: BTreeMap<u64, String> = BTreeMap::from([(0x2000, "puts".to_owned())]);
        let mut imports: Vec<ImportStub> = Vec::new();
        decode_plt_section(64, 0x1000, &code, &names, &mut imports);
        assert_eq!(
            imports,
            vec![ImportStub {
                stub_address: expected,
                slot_address: 0x2000,
                name: "puts".to_owned(),
            }]
        );
    }
}

#[test]
fn elf32_absolute_plt_slot_starts_after_padding() {
    let code: [u8; 10] = [0x0f, 0x1f, 0x40, 0x00, 0xff, 0x25, 0x00, 0x20, 0x00, 0x00];
    let names: BTreeMap<u64, String> = BTreeMap::from([(0x2000, "puts".to_owned())]);
    let mut imports: Vec<ImportStub> = Vec::new();
    decode_plt_section(32, 0x1000, &code, &names, &mut imports);
    assert_eq!(
        imports,
        vec![ImportStub {
            stub_address: 0x1004,
            slot_address: 0x2000,
            name: "puts".to_owned(),
        }]
    );
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
