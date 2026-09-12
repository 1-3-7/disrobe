#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};
use disrobe_pass_jvm::{
    DecompiledDex, DexCodeState, decompile_dex, disassemble, extract_native_methods,
    parse_classfile, parse_code_attribute, parse_code_items, parse_dex, parse_dex_header,
    parse_field_descriptor, parse_method_descriptor,
};

#[test]
fn classfile_rejects_truncated_after_magic() {
    let bytes: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE, 0x00];
    assert!(parse_classfile(bytes).is_err());
}

#[test]
fn classfile_rejects_oversized_constant_pool_count_without_oom() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&52u16.to_be_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_be_bytes());
    let res = parse_classfile(&bytes);
    assert!(
        res.is_err(),
        "huge cp_count with no data must error, not hang"
    );
}

#[test]
fn classfile_rejects_unknown_constant_tag() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&52u16.to_be_bytes());
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.push(0xFE);
    assert!(parse_classfile(&bytes).is_err());
}

#[test]
fn dex_rejects_oversized_string_ids_without_oom() {
    let mut bytes: Vec<u8> = vec![0u8; 0x70];
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    bytes[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes[56..60].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    bytes[60..64].copy_from_slice(&0x70_u32.to_le_bytes());
    let parsed: disrobe_pass_jvm::Result<disrobe_pass_jvm::DexFile> = parse_dex(&bytes);
    assert!(parsed.is_err());
}

#[test]
fn dex_header_rejects_bad_endian() {
    let mut bytes: Vec<u8> = vec![0u8; 0x70];
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    bytes[40..44].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    assert!(parse_dex_header(&bytes).is_err());
}

#[test]
fn code_attribute_rejects_inflated_code_length() {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0xFFFF_FFFF_u32.to_be_bytes());
    assert!(parse_code_attribute(&info).is_err());
}

#[test]
fn code_attribute_rejects_zero_and_oversized_code_arrays() {
    let zero_length: [u8; 12] = [0; 12];
    assert!(parse_code_attribute(&zero_length).is_err());

    let mut oversized: Vec<u8> = Vec::with_capacity(65_548);
    oversized.extend_from_slice(&0u16.to_be_bytes());
    oversized.extend_from_slice(&0u16.to_be_bytes());
    oversized.extend_from_slice(&65_536u32.to_be_bytes());
    oversized.resize(65_544, 0x00);
    oversized.extend_from_slice(&0u16.to_be_bytes());
    oversized.extend_from_slice(&0u16.to_be_bytes());
    assert!(parse_code_attribute(&oversized).is_err());
}

#[test]
fn disassemble_rejects_truncated_tableswitch_without_panic() {
    let code: &[u8] = &[0xAA, 0x00, 0x00];
    assert!(disassemble(code).is_err());
}

#[test]
fn disassemble_handles_every_single_byte_opcode_input() {
    for op in 0u16..=0xFFu16 {
        let code: [u8; 1] = [op as u8];
        let _ = disassemble(&code);
    }
}

#[test]
fn descriptor_rejects_excessive_array_nesting_without_stack_overflow() {
    let deep: String = "[".repeat(100_000) + "I";
    assert_eq!(parse_field_descriptor(&deep), None);
}

#[test]
fn descriptor_accepts_max_legal_array_dimensions() {
    let legal: String = "[".repeat(255) + "I";
    assert!(parse_field_descriptor(&legal).is_some());
    let illegal: String = "[".repeat(256) + "I";
    assert!(parse_field_descriptor(&illegal).is_none());
}

#[test]
fn method_descriptor_rejects_unterminated_object() {
    assert_eq!(parse_method_descriptor("(Ljava/lang/String)V"), None);
}

#[test]
fn method_descriptor_rejects_missing_close_paren() {
    assert_eq!(parse_method_descriptor("(III"), None);
}

#[test]
fn empty_inputs_do_not_panic() {
    assert!(parse_classfile(&[]).is_err());
    assert!(parse_dex_header(&[]).is_err());
    assert!(disassemble(&[]).is_ok());
    assert_eq!(parse_field_descriptor(""), None);
}

fn build_minimal_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/A;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "Lcom/disrobe/A;".to_owned(),
                proto: ProtoRef {
                    return_type: "I".to_owned(),
                    params: vec!["I".to_owned(), "Ljava/lang/String;".to_owned()],
                },
                name: "f".to_owned(),
            },
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 2,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x000F, 0x0012],
            relocations: Vec::new(),
        }],
    });
    builder.build()
}

fn build_two_class_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    for class in ["Lcom/disrobe/A;", "Lcom/disrobe/B;"] {
        builder.add_class(ClassDef {
            class: class.to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: class.to_owned(),
                    proto: ProtoRef {
                        return_type: "I".to_owned(),
                        params: Vec::new(),
                    },
                    name: "f".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x000F],
                relocations: Vec::new(),
            }],
        });
    }
    builder.build()
}

fn build_body_state_dex(access_flags: u32, insns: Vec<u16>) -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/Bodyless;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0401,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "Lcom/disrobe/Bodyless;".to_owned(),
                proto: ProtoRef {
                    return_type: "V".to_owned(),
                    params: Vec::new(),
                },
                name: "body".to_owned(),
            },
            access_flags,
            is_direct: false,
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            insns,
            relocations: Vec::new(),
        }],
    });
    builder.build()
}

fn build_single_method_dex(insns: Vec<u16>) -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/Instructions;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "Lcom/disrobe/Instructions;".to_owned(),
                proto: ProtoRef {
                    return_type: "V".to_owned(),
                    params: Vec::new(),
                },
                name: "body".to_owned(),
            },
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns,
            relocations: Vec::new(),
        }],
    });
    builder.build()
}

fn read_test_uleb(bytes: &[u8], mut cursor: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = bytes[cursor];
        cursor += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return (value, cursor);
        }
        shift += 7;
    }
}

fn first_code_offset(bytes: &[u8], class_defs_off: usize) -> usize {
    let class_data_start: usize = class_defs_off + 24;
    let class_data_bytes: [u8; 4] = bytes[class_data_start..class_data_start + 4]
        .try_into()
        .expect("class data offset");
    let mut cursor: usize = u32::from_le_bytes(class_data_bytes) as usize;
    for _ in 0..4 {
        let (_, next): (u32, usize) = read_test_uleb(bytes, cursor);
        cursor = next;
    }
    let (_, after_index): (u32, usize) = read_test_uleb(bytes, cursor);
    let (_, after_access): (u32, usize) = read_test_uleb(bytes, after_index);
    let (code_offset, _): (u32, usize) = read_test_uleb(bytes, after_access);
    code_offset as usize
}

#[test]
fn dex_oversized_proto_and_class_counts_terminate_fast() {
    let base: Vec<u8> = build_minimal_dex();
    let limit: Duration = Duration::from_secs(5);
    for &count_off in &[72_usize, 96] {
        let mut bytes: Vec<u8> = base.clone();
        bytes[count_off..count_off + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        let t0: Instant = Instant::now();
        let parsed: disrobe_pass_jvm::Result<disrobe_pass_jvm::DexFile> = parse_dex(&bytes);
        let elapsed: Duration = t0.elapsed();
        assert!(parsed.is_err());
        assert!(
            elapsed < limit,
            "corrupt count at offset {count_off} must not hang: took {elapsed:?}"
        );
    }
}

#[test]
fn dex_clean_decode_preserves_method_body() {
    let bytes: Vec<u8> = build_minimal_dex();
    let dex = parse_dex(&bytes).expect("valid dex");
    let codes: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
    let decoded: &[disrobe_pass_jvm::CodeItem] = codes.decoded();
    assert_eq!(decoded.len(), 1, "the single declared method survives");
    assert_eq!(decoded[0].insns.len(), 2, "method body is not truncated");
    assert_eq!(decoded[0].registers_size, 2);
}

#[test]
fn dex_invalid_method_metadata_is_rejected() {
    let base: Vec<u8> = build_minimal_dex();
    let method_ids_off: usize =
        u32::from_le_bytes(base[92..96].try_into().expect("method ids offset")) as usize;

    let mut bad_name: Vec<u8> = base.clone();
    bad_name[method_ids_off + 4..method_ids_off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_dex(&bad_name).is_err());

    let mut bad_proto: Vec<u8> = base;
    bad_proto[method_ids_off + 2..method_ids_off + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(parse_dex(&bad_proto).is_err());
}

#[test]
fn absent_and_refused_dex_bodies_are_distinct() {
    let abstract_bytes: Vec<u8> = build_body_state_dex(0x0401, Vec::new());
    let abstract_dex: disrobe_pass_jvm::DexFile = parse_dex(&abstract_bytes).expect("abstract dex");
    let abstract_report: disrobe_pass_jvm::CodeItemsReport =
        parse_code_items(&abstract_dex, &abstract_bytes);
    assert!(matches!(
        &abstract_report.methods()[0].state,
        DexCodeState::Absent
    ));
    let abstract_output: DecompiledDex = decompile_dex(&abstract_dex, &abstract_bytes);
    assert_eq!(abstract_output.fallback_methods, 0);
    assert!(
        abstract_output
            .source
            .contains("public abstract class Bodyless")
    );
    assert!(abstract_output.source.contains("abstract void body();"));

    let concrete_bytes: Vec<u8> = build_body_state_dex(0x0001, Vec::new());
    let concrete_dex: disrobe_pass_jvm::DexFile = parse_dex(&concrete_bytes).expect("concrete dex");
    let concrete_report: disrobe_pass_jvm::CodeItemsReport =
        parse_code_items(&concrete_dex, &concrete_bytes);
    assert!(matches!(
        &concrete_report.methods()[0].state,
        DexCodeState::Refused(_)
    ));
    let concrete_output: DecompiledDex = decompile_dex(&concrete_dex, &concrete_bytes);
    assert_eq!(concrete_output.fallback_methods, 1);
    assert!(
        concrete_output
            .source
            .contains("<decompile: malformed bytecode>")
    );
}

#[test]
fn decoded_empty_and_bodyless_with_code_dex_states_are_distinct() {
    let mut empty_bytes: Vec<u8> = build_minimal_dex();
    let empty_dex: disrobe_pass_jvm::DexFile =
        parse_dex(&empty_bytes).expect("valid dex container");
    let code_offset: usize =
        first_code_offset(&empty_bytes, empty_dex.header.class_defs_off as usize);
    empty_bytes[code_offset + 12..code_offset + 16].copy_from_slice(&0u32.to_le_bytes());
    let empty_report: disrobe_pass_jvm::CodeItemsReport =
        parse_code_items(&empty_dex, &empty_bytes);
    assert!(matches!(
        &empty_report.methods()[0].state,
        DexCodeState::Decoded(_)
    ));
    assert!(empty_report.decoded()[0].insns.is_empty());

    let bodyless_bytes: Vec<u8> = build_body_state_dex(0x0401, vec![0x000E]);
    let bodyless_dex: disrobe_pass_jvm::DexFile =
        parse_dex(&bodyless_bytes).expect("valid dex container");
    let bodyless_report: disrobe_pass_jvm::CodeItemsReport =
        parse_code_items(&bodyless_dex, &bodyless_bytes);
    assert!(matches!(
        &bodyless_report.methods()[0].state,
        DexCodeState::Refused(_)
    ));
    let decompiled: DecompiledDex = decompile_dex(&bodyless_dex, &bodyless_bytes);
    assert_eq!(decompiled.fully_lifted_methods, 0);
    assert_eq!(decompiled.fallback_methods, 1);
}

#[test]
fn malformed_dex_code_item_is_reported_as_fallback() {
    let mut bytes: Vec<u8> = build_minimal_dex();
    let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex");
    let code_offset: usize = first_code_offset(&bytes, dex.header.class_defs_off as usize);
    bytes[code_offset + 12..code_offset + 16].copy_from_slice(&u32::MAX.to_le_bytes());

    let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
    assert_eq!(decompiled.fully_lifted_methods, 0);
    assert_eq!(decompiled.fallback_methods, 1);
    assert!(
        decompiled
            .source
            .contains("<decompile: malformed bytecode>")
    );
    assert!(
        decompiled
            .source
            .contains("throw new UnsupportedOperationException(\"malformed bytecode\");")
    );
}

#[test]
fn truncated_dalvik_instruction_is_reported_as_fallback() {
    let mut bytes: Vec<u8> = build_minimal_dex();
    let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex");
    let code_offset: usize = first_code_offset(&bytes, dex.header.class_defs_off as usize);
    bytes[code_offset + 16..code_offset + 18].copy_from_slice(&0x0014_u16.to_le_bytes());

    let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
    assert!(matches!(
        &report.methods()[0].state,
        DexCodeState::Refused(_)
    ));
    let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
    assert_eq!(decompiled.fully_lifted_methods, 0);
    assert_eq!(decompiled.fallback_methods, 1);
    assert!(
        decompiled
            .source
            .contains("<decompile: malformed bytecode>")
    );
}

#[test]
fn truncated_dalvik_payloads_are_reported_as_fallback() {
    for payload_identifier in [0x0100_u16, 0x0200_u16, 0x0300_u16] {
        let mut bytes: Vec<u8> = build_minimal_dex();
        let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex");
        let code_offset: usize = first_code_offset(&bytes, dex.header.class_defs_off as usize);
        bytes[code_offset + 16..code_offset + 18]
            .copy_from_slice(&payload_identifier.to_le_bytes());

        let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
        assert!(matches!(
            &report.methods()[0].state,
            DexCodeState::Refused(_)
        ));
        let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }
}

#[test]
fn invalid_dalvik_payload_references_are_reported_as_fallback() {
    let cases: [Vec<u16>; 4] = [
        vec![0x002B, 0x7FFF, 0x7FFF],
        vec![0x002B, 0x0004, 0x0000, 0x0000, 0x0200, 0x0000],
        vec![0x0300, 0x0003, 0x0000, 0x0000],
        vec![0x0000, 0x0100, 0x0000, 0x0000, 0x0000],
    ];
    for insns in cases {
        let bytes: Vec<u8> = build_single_method_dex(insns);
        let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex container");
        let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
        assert!(matches!(
            &report.methods()[0].state,
            DexCodeState::Refused(_)
        ));
        let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
    }
}

#[test]
fn reserved_dalvik_opcode_is_reported_as_fallback() {
    let bytes: Vec<u8> = build_single_method_dex(vec![0x003E]);
    let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex container");
    let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
    assert!(matches!(
        &report.methods()[0].state,
        DexCodeState::Refused(_)
    ));
    let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
    assert_eq!(decompiled.fully_lifted_methods, 0);
    assert_eq!(decompiled.fallback_methods, 1);
}

#[test]
fn invalid_dalvik_control_flow_is_reported_as_fallback() {
    let cases: [Vec<u16>; 3] = [
        vec![0x0029, 0x0001, 0x000E],
        vec![
            0x002B, 0x0004, 0x0000, 0x000E, 0x0100, 0x0001, 0x0000, 0x0000, 0x0001, 0x0000,
        ],
        vec![
            0x002C, 0x0004, 0x0000, 0x000E, 0x0200, 0x0002, 0x0002, 0x0000, 0x0001, 0x0000, 0x0003,
            0x0000, 0x0003, 0x0000,
        ],
    ];
    for insns in cases {
        let bytes: Vec<u8> = build_single_method_dex(insns);
        let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex container");
        let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
        assert!(matches!(
            &report.methods()[0].state,
            DexCodeState::Refused(_)
        ));
        let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
    }
}

#[test]
fn invalid_dalvik_pool_references_are_reported_as_fallback() {
    let cases: [Vec<u16>; 8] = [
        vec![0x001A, 0xFFFF, 0x000E],
        vec![0x001C, 0xFFFF, 0x000E],
        vec![0x0052, 0xFFFF, 0x000E],
        vec![0x0071, 0xFFFF, 0x0000, 0x000E],
        vec![0x00FA, 0x0000, 0x0000, 0xFFFF, 0x000E],
        vec![0x00FC, 0xFFFF, 0x0000, 0x000E],
        vec![0x00FE, 0xFFFF, 0x000E],
        vec![0x00FF, 0xFFFF, 0x000E],
    ];
    for insns in cases {
        let bytes: Vec<u8> = build_single_method_dex(insns);
        let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex container");
        let report: disrobe_pass_jvm::CodeItemsReport = parse_code_items(&dex, &bytes);
        assert!(matches!(
            &report.methods()[0].state,
            DexCodeState::Refused(_)
        ));
        let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
    }
}

#[test]
fn malformed_dex_class_tail_is_reported_as_fallback() {
    let mut bytes: Vec<u8> = build_two_class_dex();
    let dex: disrobe_pass_jvm::DexFile = parse_dex(&bytes).expect("valid dex");
    assert_eq!(dex.header.class_defs_size, 2);
    let second_class_data_field: usize = dex.header.class_defs_off as usize + 32 + 24;
    let truncated_offset: u32 = u32::try_from(bytes.len() - 1).expect("DEX length fits u32");
    bytes[second_class_data_field..second_class_data_field + 4]
        .copy_from_slice(&truncated_offset.to_le_bytes());

    let decompiled: DecompiledDex = decompile_dex(&dex, &bytes);
    assert_eq!(decompiled.fully_lifted_methods, 1);
    assert_eq!(decompiled.method_count, 1);
    assert_eq!(decompiled.fallback_methods, 0);
    assert!(!decompiled.code_scan_complete);
    assert_eq!(decompiled.decode_error_count, 1);
    assert!(
        decompiled
            .source
            .contains("<decompile: malformed bytecode>")
    );
    assert!(extract_native_methods(&dex, &bytes).is_err());
}
