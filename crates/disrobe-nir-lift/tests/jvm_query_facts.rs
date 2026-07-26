#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::{LiftError, lift_classfile};
use disrobe_query::{
    CallSiteMatch, DecoderMatch, Function, FunctionMatch, Module, Query, QueryResult, XrefMatch,
    run,
};

const STRINGER_CLASS: &[u8] = include_bytes!("../../../corpus/jvm/stringer/StringerClassic.class");

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_utf8(bytes: &mut Vec<u8>, value: &str) {
    bytes.push(1);
    push_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
}

fn code_info(
    code: &[u8],
    exceptions: &[(u16, u16, u16, u16)],
    nested_attribute_names: &[u16],
) -> Vec<u8> {
    let mut info: Vec<u8> = Vec::new();
    push_u16(&mut info, 1);
    push_u16(&mut info, 1);
    push_u32(&mut info, code.len() as u32);
    info.extend_from_slice(code);
    push_u16(&mut info, exceptions.len() as u16);
    for (start, end, handler, catch_type) in exceptions {
        push_u16(&mut info, *start);
        push_u16(&mut info, *end);
        push_u16(&mut info, *handler);
        push_u16(&mut info, *catch_type);
    }
    push_u16(&mut info, nested_attribute_names.len() as u16);
    for name_index in nested_attribute_names {
        push_u16(&mut info, *name_index);
        push_u32(&mut info, 0);
    }
    info
}

fn lookup_switch_code(default: i32, keys: [i32; 2]) -> Vec<u8> {
    let mut code: Vec<u8> = vec![0xAB, 0x00, 0x00, 0x00];
    code.extend_from_slice(&default.to_be_bytes());
    code.extend_from_slice(&2i32.to_be_bytes());
    for key in keys {
        code.extend_from_slice(&key.to_be_bytes());
        code.extend_from_slice(&28i32.to_be_bytes());
    }
    code.push(0xB1);
    code
}

fn push_method(
    bytes: &mut Vec<u8>,
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    attributes: &[(u16, &[u8])],
) {
    push_u16(bytes, access_flags);
    push_u16(bytes, name_index);
    push_u16(bytes, descriptor_index);
    push_u16(bytes, attributes.len() as u16);
    for (attribute_name, info) in attributes {
        push_u16(bytes, *attribute_name);
        push_u32(bytes, info.len() as u32);
        bytes.extend_from_slice(info);
    }
}

fn decode_state_class(
    include_malformed: bool,
    absent_access_flags: u16,
    empty_access_flags: u16,
) -> Vec<u8> {
    decode_state_class_with_empty_attributes(
        include_malformed,
        absent_access_flags,
        empty_access_flags,
        &[9],
    )
}

fn decode_state_class_with_empty_attributes(
    include_malformed: bool,
    absent_access_flags: u16,
    empty_access_flags: u16,
    empty_attribute_names: &[u16],
) -> Vec<u8> {
    let empty_code: Vec<u8> = code_info(&[0xB1], &[], &[]);
    decode_state_class_with_code_attributes(
        include_malformed,
        absent_access_flags,
        empty_access_flags,
        empty_code.as_slice(),
        empty_attribute_names,
        6,
        8,
    )
}

fn decode_state_class_with_code_attributes(
    include_malformed: bool,
    absent_access_flags: u16,
    empty_access_flags: u16,
    code_attribute: &[u8],
    empty_attribute_names: &[u16],
    empty_name_index: u16,
    empty_descriptor_index: u16,
) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    push_u32(&mut bytes, 0xCAFE_BABE);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 52);
    push_u16(&mut bytes, 10);
    push_utf8(&mut bytes, "DecodeStates");
    bytes.push(7);
    push_u16(&mut bytes, 1);
    push_utf8(&mut bytes, "java/lang/Object");
    bytes.push(7);
    push_u16(&mut bytes, 3);
    push_utf8(&mut bytes, "absent");
    push_utf8(&mut bytes, "empty");
    push_utf8(&mut bytes, "malformed");
    push_utf8(&mut bytes, "()V");
    push_utf8(&mut bytes, "Code");
    push_u16(&mut bytes, 0x0021);
    push_u16(&mut bytes, 2);
    push_u16(&mut bytes, 4);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, if include_malformed { 3 } else { 2 });
    push_method(&mut bytes, absent_access_flags, 5, 8, &[]);
    let empty_attributes: Vec<(u16, &[u8])> = empty_attribute_names
        .iter()
        .map(|name_index: &u16| (*name_index, code_attribute))
        .collect();
    push_method(
        &mut bytes,
        empty_access_flags,
        empty_name_index,
        empty_descriptor_index,
        &empty_attributes,
    );
    if include_malformed {
        let malformed_code: [u8; 7] = [0; 7];
        push_method(&mut bytes, 0x0009, 7, 8, &[(9, &malformed_code)]);
    }
    push_u16(&mut bytes, 0);
    bytes
}

fn lifted() -> Module {
    let nir: NirModule = lift_classfile(STRINGER_CLASS).expect("lift classfile to NIR");
    Module::from_nir(&nir)
}

#[test]
fn classfile_code_states_remain_distinct() {
    let decoded_bytes: Vec<u8> = decode_state_class(false, 0x0401, 0x0009);
    let decoded: NirModule = lift_classfile(&decoded_bytes).expect("lift decoded no-op method");
    assert_eq!(decoded.functions.len(), 1);
    assert_eq!(decoded.functions[0].instructions.len(), 1);

    let malformed_bytes: Vec<u8> = decode_state_class(true, 0x0401, 0x0009);
    let malformed: disrobe_nir_lift::Result<NirModule> = lift_classfile(&malformed_bytes);
    assert!(
        matches!(
            malformed,
            Err(LiftError::Source(message))
                if message.contains("malformed") && message.contains("Code")
        ),
        "malformed Code must not be omitted from a recovered module"
    );
}

#[test]
fn concrete_method_without_code_refuses_the_lift() {
    let bytes: Vec<u8> = decode_state_class(false, 0x0001, 0x0009);

    let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("absent") && message.contains("Code")
        ),
        "a concrete method without Code must not disappear from a recovered module"
    );
}

#[test]
fn code_on_abstract_method_refuses_the_lift() {
    let bytes: Vec<u8> = decode_state_class(false, 0x0401, 0x0401);
    let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("bodyless") && message.contains("Code")
        ),
        "Code on an abstract method must not become a recovered function"
    );
}

#[test]
fn duplicate_code_attributes_refuse_the_lift() {
    let bytes: Vec<u8> = decode_state_class_with_empty_attributes(false, 0x0401, 0x0009, &[9, 9]);
    let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("empty") && message.contains("duplicate Code")
        ),
        "duplicate Code attributes must not become a recovered function"
    );
}

#[test]
fn invalid_attribute_name_after_code_refuses_the_lift() {
    let bytes: Vec<u8> =
        decode_state_class_with_empty_attributes(false, 0x0401, 0x0009, &[9, u16::MAX]);
    let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("empty") && message.contains("attribute name")
        ),
        "a later invalid attribute name must not be hidden by a decoded Code attribute"
    );
}

#[test]
fn invalid_code_semantics_refuse_the_lift() {
    let cases: [Vec<u8>; 8] = [
        code_info(&[0x10, 0x01, 0xB1], &[(1, 2, 2, 0)], &[]),
        code_info(&[0xB1], &[(0, 1, 0, 1)], &[]),
        code_info(&[0xB1], &[], &[u16::MAX]),
        code_info(&[0xCA], &[], &[]),
        code_info(&[0xC4, 0xB1, 0x00, 0x00], &[], &[]),
        code_info(&[0xA7, 0x00, 0x01, 0xB1], &[], &[]),
        code_info(&lookup_switch_code(28, [2, 1]), &[], &[]),
        code_info(&lookup_switch_code(1, [1, 2]), &[], &[]),
    ];
    for code_attribute in cases {
        let bytes: Vec<u8> = decode_state_class_with_code_attributes(
            false,
            0x0401,
            0x0009,
            &code_attribute,
            &[9],
            6,
            8,
        );
        let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
        assert!(
            matches!(lifted, Err(LiftError::Source(_))),
            "invalid Code semantics must not become a recovered function"
        );
    }
}

#[test]
fn invalid_method_metadata_refuses_the_lift() {
    for (name_index, descriptor_index) in [(u16::MAX, 8), (6, 5)] {
        let empty_code: Vec<u8> = code_info(&[0xB1], &[], &[]);
        let bytes: Vec<u8> = decode_state_class_with_code_attributes(
            false,
            0x0401,
            0x0009,
            empty_code.as_slice(),
            &[9],
            name_index,
            descriptor_index,
        );
        let lifted: disrobe_nir_lift::Result<NirModule> = lift_classfile(&bytes);
        assert!(
            matches!(lifted, Err(LiftError::Source(_))),
            "invalid method metadata must not become a recovered function"
        );
    }
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions, got {other:?}"),
    }
}

fn decoders(module: &Module) -> Vec<DecoderMatch> {
    match run(module, &Query::StringDecoders) {
        QueryResult::StringDecoders { matches } => matches,
        other => panic!("expected StringDecoders, got {other:?}"),
    }
}

fn xrefs_to(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    match run(
        module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo, got {other:?}"),
    }
}

fn calls_to(module: &Module, target: &str) -> Vec<CallSiteMatch> {
    match run(
        module,
        &Query::CallsTo {
            target: target.to_owned(),
        },
    ) {
        QueryResult::CallsTo { matches, .. } => matches,
        other => panic!("expected CallsTo, got {other:?}"),
    }
}

#[test]
fn classfile_methods_are_recovered_as_functions() {
    let module: Module = lifted();
    let names: Vec<String> = function_names(&module);
    for expected in [
        "buildKey",
        "decrypt",
        "dbUrl",
        "authHeader",
        "vaultUrl",
        "role",
        "keyPath",
        "main",
    ] {
        assert!(
            names.iter().any(|n: &String| n == expected),
            "method {expected} must be lifted: {names:?}"
        );
    }

    let dburl: &Function = module.function_by_name("dbUrl").expect("dbUrl");
    assert!(dburl.is_export, "public dbUrl must be flagged exported");
    let decrypt: &Function = module.function_by_name("decrypt").expect("decrypt");
    assert!(
        !decrypt.is_export,
        "private decrypt must not be flagged exported"
    );
}

#[test]
fn decrypt_loop_is_detected_as_a_byte_decoder() {
    let module: Module = lifted();
    let found: Vec<DecoderMatch> = decoders(&module);
    let decrypt: &DecoderMatch = found
        .iter()
        .find(|d: &&DecoderMatch| d.name == "decrypt")
        .expect("decrypt must be a decoder");
    assert!(
        decrypt.loop_back_edges >= 1,
        "the for-loop goto is a back-edge: {decrypt:?}"
    );
    assert!(
        decrypt.byte_arith_ops >= 1,
        "the ixor over a loaded char must count as byte-arith: {decrypt:?}"
    );
    assert!(
        decrypt.memory_ops >= 1,
        "the caload/castore must count as memory ops: {decrypt:?}"
    );
}

#[test]
fn accessor_methods_call_the_internal_decrypt() {
    let module: Module = lifted();

    let xrefs: Vec<XrefMatch> = xrefs_to(&module, "decrypt");
    let callers: Vec<&str> = xrefs
        .iter()
        .filter_map(|x: &XrefMatch| x.from_function.as_deref())
        .collect();
    for accessor in ["dbUrl", "authHeader", "vaultUrl", "role", "keyPath"] {
        assert!(
            callers.contains(&accessor),
            "{accessor} must reference decrypt: callers={callers:?}"
        );
    }
    assert!(
        xrefs
            .iter()
            .all(|x: &XrefMatch| x.mnemonic == "invokestatic"),
        "intra-class calls to decrypt are invokestatic: {xrefs:?}"
    );

    let call_sites: Vec<CallSiteMatch> = calls_to(&module, "decrypt");
    assert_eq!(
        call_sites.len(),
        5,
        "exactly the five accessors call decrypt: {call_sites:?}"
    );
}

#[test]
fn lift_is_deterministic() {
    let first: Module = lifted();
    let second: Module = lifted();
    assert_eq!(function_names(&first), function_names(&second));
    assert_eq!(decoders(&first).len(), decoders(&second).len());
}
