#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{DEX_ENDIAN_TAG, DexHeader, DexVersion, parse_dex_header};

fn synth_dex_header(version: [u8; 3]) -> Vec<u8> {
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
fn parses_every_supported_dex_version() {
    for v in [b"035", b"037", b"038", b"039", b"040", b"041"] {
        let bytes: Vec<u8> = synth_dex_header(*v);
        let h: DexHeader = parse_dex_header(&bytes).expect("parse");
        assert!(matches!(
            h.version,
            DexVersion::V035
                | DexVersion::V037
                | DexVersion::V038
                | DexVersion::V039
                | DexVersion::V040
                | DexVersion::V041
        ));
    }
}

#[test]
fn rejects_unknown_dex_version() {
    let bytes: Vec<u8> = synth_dex_header(*b"999");
    let err: disrobe_pass_jvm::Error = parse_dex_header(&bytes).expect_err("unsupported");
    assert!(matches!(
        err,
        disrobe_pass_jvm::Error::UnsupportedDexVersion(_)
    ));
}
