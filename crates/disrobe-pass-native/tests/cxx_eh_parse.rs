#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    EhEntry, ProgramFunction, PseudoAbi, RecoveredProgram, SehScopeEntry, UnrecoveredFunction,
    parse_itanium_lsda, parse_windows_seh_scope_table, recover_itanium_exception_regions,
    recover_program,
};

#[path = "support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;

#[test]
fn itanium_lsda_minimal_entry_round_trip() {
    let buf: Vec<u8> = vec![0xff, 0xff, 0x01, 0x05, 0x40, 0x40, 0xc0, 0x01, 0x00];
    let out: Vec<EhEntry> = parse_itanium_lsda(&buf).expect("lsda");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].start, 64);
    assert_eq!(out[0].end, 128);
    assert_eq!(out[0].landing_pad, 192);
}

#[test]
fn itanium_lsda_rejects_excessive_entries() {
    let entries: usize = 65_537;
    let table_length: usize = entries * 4;
    let mut buf: Vec<u8> = vec![0xff, 0xff, 0x01];
    let mut value: usize = table_length;
    loop {
        let mut byte: u8 = u8::try_from(value & 0x7f).expect("seven-bit group");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
    buf.resize(buf.len() + table_length, 0);
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn itanium_lsda_rejects_a_truncated_leb128_field() {
    let buf: [u8; 5] = [0xff, 0xff, 0x01, 0x01, 0x80];
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn itanium_lsda_rejects_an_out_of_range_type_index() {
    let buf: [u8; 14] = [
        0xff, 0x03, 0x0b, 0x01, 0x04, 0x00, 0x01, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn itanium_lsda_rejects_a_cyclic_action_chain() {
    let buf: [u8; 10] = [0xff, 0xff, 0x01, 0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x7f];
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn itanium_lsda_rejects_action_displacements_before_the_action_table() {
    let buf: [u8; 10] = [0xff, 0xff, 0x01, 0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x7e];
    let error: disrobe_pass_native::error::Error =
        parse_itanium_lsda(&buf).expect_err("backward action displacement");
    assert!(error.to_string().contains("before the action table"));
}

#[test]
fn itanium_lsda_rejects_action_records_crossing_the_type_table() {
    let buf: [u8; 11] = [
        0xff, 0x03, 0x07, 0x01, 0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00,
    ];
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn itanium_lsda_bounds_actions_across_all_call_sites() {
    let entries: usize = 32_769;
    let table_length: usize = entries * 4;
    let mut buf: Vec<u8> = vec![0xff, 0xff, 0x01];
    let mut value: usize = table_length;
    loop {
        let mut byte: u8 = u8::try_from(value & 0x7f).expect("seven-bit group");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
    for _ in 0..entries {
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x01]);
    }
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    let result: Result<Vec<EhEntry>, disrobe_pass_native::error::Error> = parse_itanium_lsda(&buf);
    assert!(matches!(
        result,
        Err(disrobe_pass_native::error::Error::Dwarf(_))
    ));
}

#[test]
fn windows_seh_scope_table_round_trip() {
    let mut buf: Vec<u8> = 1u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&200u32.to_le_bytes());
    buf.extend_from_slice(&300u32.to_le_bytes());
    buf.extend_from_slice(&400u32.to_le_bytes());
    let out: Vec<SehScopeEntry> = parse_windows_seh_scope_table(&buf).expect("seh");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].begin_address, 100);
}

#[test]
fn clang_o0_elf_surfaces_bounded_exception_ranges_on_the_native_caller() {
    let object: &[u8] = include_bytes!("fixtures/itanium_lsda_low_opt.elf");
    let (code, address): (Vec<u8>, u64) =
        object_symbol::function_code(object, "recover_try").expect("fixture function");
    let functions: Vec<ProgramFunction> = vec![ProgramFunction {
        name: "recover_try".to_owned(),
        address,
        code,
    }];

    let recovered: RecoveredProgram = recover_program(object, &functions, PseudoAbi::SysV);
    assert!(recovered.recovered.is_empty());
    let [function]: &[UnrecoveredFunction] = recovered.unrecovered.as_slice() else {
        panic!("one exception function must receive one typed outcome");
    };
    assert_eq!(function.name, "recover_try");
    assert_eq!(
        function.reason,
        "control-flow-partial: Itanium LSDA protects 0x15c4..0x15c9 with landing pad 0x15d9 and catch type index 1; try/catch emission is withheld until the landing-pad CFG is re-nested"
    );
}

#[test]
fn mixed_personality_elf_does_not_decode_a_non_gxx_lsda() {
    const GXX_PERSONALITY_RELOCATION_SYMBOL_BYTE: usize = 0x414;
    let mut object: Vec<u8> = include_bytes!("fixtures/itanium_lsda_low_opt.elf").to_vec();
    assert_eq!(object[GXX_PERSONALITY_RELOCATION_SYMBOL_BYTE], 7);
    object[GXX_PERSONALITY_RELOCATION_SYMBOL_BYTE] = 2;
    let regions: Vec<disrobe_pass_native::ItaniumEhFunction> =
        recover_itanium_exception_regions(&object).expect("mixed-personality fixture");
    assert!(regions.is_empty());
}
