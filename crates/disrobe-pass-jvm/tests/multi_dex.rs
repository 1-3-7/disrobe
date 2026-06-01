#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{DEX_ENDIAN_TAG, MultiDex, parse_multi_dex};

fn synth_dex(version: [u8; 3]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 0x70];
    bytes[0] = b'd';
    bytes[1] = b'e';
    bytes[2] = b'x';
    bytes[3] = b'\n';
    bytes[4] = version[0];
    bytes[5] = version[1];
    bytes[6] = version[2];
    bytes[7] = 0;
    bytes[40..44].copy_from_slice(&DEX_ENDIAN_TAG.to_le_bytes());
    bytes
}

#[test]
fn walks_classes_classes2_classes3() {
    let d1: Vec<u8> = synth_dex(*b"035");
    let d2: Vec<u8> = synth_dex(*b"038");
    let d3: Vec<u8> = synth_dex(*b"041");
    let named: Vec<(&str, &[u8])> = vec![
        ("classes.dex", d1.as_slice()),
        ("classes2.dex", d2.as_slice()),
        ("classes3.dex", d3.as_slice()),
    ];
    let mx: MultiDex = parse_multi_dex(&named).expect("multi-dex parse");
    assert_eq!(mx.files.len(), 3);
}
