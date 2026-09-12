#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::PerlOpTree;
use disrobe_pass_scriptlang::lang::perl::PerlSub;
use disrobe_pass_scriptlang::lang::perl_bytecode::{ByteOrder, is_bytecode, read_bytecode};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const MAGIC_NATIVE: u32 = 0x4342_4c50;

const OP_NEWSVX: u8 = 9u8;
const OP_NEWOPX: u8 = 12u8;
const OP_NEWPV: u8 = 14u8;
const OP_PV_CUR: u8 = 15u8;
const OP_SV_FLAGS: u8 = 20u8;
const OP_RET: u8 = 0u8;

fn put_u32(out: &mut Vec<u8>, v: u32, order: ByteOrder) {
    match order {
        ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
        ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16, order: ByteOrder) {
    match order {
        ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
        ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
    }
}

fn put_asciiz(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

fn put_pv(out: &mut Vec<u8>, s: &str, order: ByteOrder) {
    put_u32(out, s.len() as u32, order);
    out.extend_from_slice(s.as_bytes());
}

fn put_padoffset(out: &mut Vec<u8>, v: u64, order: ByteOrder) {
    match order {
        ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
        ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
    }
}

fn hello_bytecode(order: ByteOrder) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"#!/usr/bin/perl\nuse ByteLoader 0.06;\n");
    put_u32(&mut out, MAGIC_NATIVE, order);
    put_asciiz(&mut out, "x86_64-linux-gnu");
    put_asciiz(&mut out, "0.06");
    put_u32(&mut out, 8, order);
    put_u32(&mut out, 8, order);

    for pv in [
        "main::greet",
        "main::add",
        "Hello, ",
        "disrobe",
        "$name",
        "$a",
        "$b",
    ] {
        out.push(OP_NEWSVX);
        put_u32(&mut out, 0x0c, order);
        out.push(OP_NEWPV);
        put_pv(&mut out, pv, order);
        out.push(OP_PV_CUR);
        put_padoffset(&mut out, pv.len() as u64, order);
        out.push(OP_SV_FLAGS);
        put_u32(&mut out, 0x4005, order);
    }
    out.push(OP_NEWOPX);
    put_u16(&mut out, 178, order);
    out.push(OP_RET);
    out
}

#[test]
fn bytecode_magic_detected_both_byte_orders() {
    assert!(is_bytecode(&hello_bytecode(ByteOrder::Little)));
    assert!(is_bytecode(&hello_bytecode(ByteOrder::Big)));
}

#[test]
fn bytecode_classifies_and_analyzes_as_perl() {
    let bc: Vec<u8> = hello_bytecode(ByteOrder::Little);
    assert_eq!(classify(&bc), Some(ScriptLang::Perl));
    let art: ScriptArtifact = analyze(&bc).expect("analyze bytecode");
    match art {
        ScriptArtifact::Perl(tree) => assert!(tree.op_count > 0),
        other => panic!("expected Perl artifact from bytecode, got {other:?}"),
    }
}

#[test]
fn bytecode_reads_synthetic_pv_strings() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let bc: Vec<u8> = hello_bytecode(order);
        let tree: PerlOpTree = read_bytecode(&bc).expect("parse");
        let main: &PerlSub = &tree.subs[0];
        for expected in [
            "main::greet",
            "main::add",
            "Hello, ",
            "disrobe",
            "$name",
            "$a",
            "$b",
        ] {
            assert!(
                main.constants.iter().any(|c: &String| c == expected),
                "PV '{expected}' from hello.pl op-tree must round-trip for {order:?}: {:?}",
                main.constants
            );
        }
    }
}

#[test]
fn bytecode_header_archname_becomes_source_hint() {
    let tree: PerlOpTree = read_bytecode(&hello_bytecode(ByteOrder::Big)).expect("parse");
    assert_eq!(tree.source_hint.as_deref(), Some("x86_64-linux-gnu"));
}
