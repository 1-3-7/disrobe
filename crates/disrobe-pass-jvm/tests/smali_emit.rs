#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{DEX_ENDIAN_TAG, DexFile, SmaliEmission, emit_smali, parse_dex};

fn synth_minimal_dex() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 0x70];
    bytes[0] = b'd';
    bytes[1] = b'e';
    bytes[2] = b'x';
    bytes[3] = b'\n';
    bytes[4] = b'0';
    bytes[5] = b'3';
    bytes[6] = b'5';
    bytes[7] = 0;
    bytes[40..44].copy_from_slice(&DEX_ENDIAN_TAG.to_le_bytes());
    bytes
}

#[test]
fn emits_empty_smali_for_minimal_dex() {
    let bytes: Vec<u8> = synth_minimal_dex();
    let dex: DexFile = parse_dex(&bytes).expect("parse");
    let smali: SmaliEmission = emit_smali(&dex).expect("emit");
    assert_eq!(smali.class_count, 0);
    assert!(smali.text.is_empty());
}
