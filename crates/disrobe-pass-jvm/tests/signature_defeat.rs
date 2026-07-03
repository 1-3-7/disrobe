#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_jvm::{ClassFile, DexFile, parse_classfile, parse_dex, parse_dex_header};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push(rel);
    std::fs::read(&p).ok()
}

const DEX_REL: &str = "jvm/dex/Hello.dex";
const CLASS_REL: &str = "jvm/callerkeyed/CallerKeyed.class";

#[test]
fn zeroed_magic_dex_still_parses_to_identical_body() {
    let Some(dex): Option<Vec<u8>> = corpus(DEX_REL) else {
        eprintln!("FIXTURE PENDING: {DEX_REL}");
        return;
    };
    let baseline: DexFile = parse_dex(&dex).expect("intact dex must parse");

    let mut zeroed: Vec<u8> = dex;
    zeroed[0..8].copy_from_slice(&[0u8; 8]);
    assert_ne!(&zeroed[0..4], b"dex\n");

    let header = parse_dex_header(&zeroed)
        .expect("zeroed-magic dex must still parse its header structurally");
    assert_eq!(header.header_size, 0x70);

    let recovered: DexFile =
        parse_dex(&zeroed).expect("zeroed-magic dex must still parse end to end");
    assert_eq!(
        recovered.strings, baseline.strings,
        "string pool from scrambled-magic dex must match the intact parse"
    );
    assert_eq!(
        recovered.type_names, baseline.type_names,
        "type names from scrambled-magic dex must match the intact parse"
    );
}

#[test]
fn flipped_magic_dex_still_parses() {
    let Some(dex): Option<Vec<u8>> = corpus(DEX_REL) else {
        return;
    };
    let baseline: DexFile = parse_dex(&dex).expect("intact dex must parse");
    let mut flipped: Vec<u8> = dex;
    for b in &mut flipped[0..8] {
        *b ^= 0xFF;
    }
    let recovered: DexFile = parse_dex(&flipped).expect("flipped-magic dex must still parse");
    assert_eq!(recovered.strings, baseline.strings);
}

#[test]
fn scrambled_magic_classfile_still_parses_to_identical_pool() {
    let Some(class): Option<Vec<u8>> = corpus(CLASS_REL) else {
        eprintln!("FIXTURE PENDING: {CLASS_REL}");
        return;
    };
    let baseline: ClassFile = parse_classfile(&class).expect("intact class must parse");

    let mut scrambled: Vec<u8> = class;
    for b in &mut scrambled[0..4] {
        *b ^= 0xFF;
    }
    assert_ne!(
        u32::from_be_bytes([scrambled[0], scrambled[1], scrambled[2], scrambled[3]]),
        0xCAFE_BABE
    );

    let recovered: ClassFile = parse_classfile(&scrambled)
        .expect("scrambled-magic class must still parse via constant-pool walk");
    assert_eq!(
        recovered.constant_pool.len(),
        baseline.constant_pool.len(),
        "constant pool from scrambled-magic class must match the intact parse"
    );
    assert_eq!(
        recovered.methods.len(),
        baseline.methods.len(),
        "method table from scrambled-magic class must match the intact parse"
    );
}

#[test]
fn garbage_with_class_magic_still_rejected() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes[6..8].copy_from_slice(&52u16.to_be_bytes());
    bytes[8..10].copy_from_slice(&3u16.to_be_bytes());
    bytes[10] = 0xFE;
    assert!(
        parse_classfile(&bytes).is_err(),
        "a real-magic but structurally broken constant pool must still be rejected"
    );
}
