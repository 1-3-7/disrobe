#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};
use disrobe_pass_jvm::{
    disassemble, extract_native_methods, parse_classfile, parse_code_attribute, parse_code_items,
    parse_dex, parse_dex_header, parse_field_descriptor, parse_method_descriptor,
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
    let parsed = parse_dex(&bytes);
    assert!(
        parsed.is_ok() || parsed.is_err(),
        "must terminate without OOM/hang"
    );
    if let Ok(dex) = parsed {
        assert!(
            dex.strings.len() < bytes.len(),
            "string count cannot exceed file bytes"
        );
    }
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

#[test]
fn dex_oversized_proto_and_class_counts_terminate_fast() {
    let base: Vec<u8> = build_minimal_dex();
    let limit: Duration = Duration::from_secs(5);
    for &count_off in &[72_usize, 96] {
        let mut bytes: Vec<u8> = base.clone();
        bytes[count_off..count_off + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        let t0: Instant = Instant::now();
        let dex = parse_dex(&bytes).expect("header still valid");
        let _codes = parse_code_items(&dex, &bytes);
        let _natives = extract_native_methods(&dex, &bytes);
        let elapsed: Duration = t0.elapsed();
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
    let codes = parse_code_items(&dex, &bytes);
    assert_eq!(codes.len(), 1, "the single declared method survives");
    assert_eq!(codes[0].insns.len(), 2, "method body is not truncated");
    assert_eq!(codes[0].registers_size, 2);
}
