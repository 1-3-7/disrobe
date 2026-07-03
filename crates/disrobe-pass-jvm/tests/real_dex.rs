#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{DEX_ENDIAN_TAG, DexHeader, DexVersion, parse_dex_header};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

#[test]
fn parses_real_hello_dex_from_d8() {
    assert_eq!(&HELLO_DEX[..4], b"dex\n");
    assert_eq!(&HELLO_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(HELLO_DEX).expect("parse hello.dex");
    assert!(matches!(h.version, DexVersion::V035));
    let endian: u32 =
        u32::from_le_bytes([HELLO_DEX[40], HELLO_DEX[41], HELLO_DEX[42], HELLO_DEX[43]]);
    assert_eq!(endian, DEX_ENDIAN_TAG);
}

#[test]
fn parses_real_edgecases_dex_from_d8() {
    assert_eq!(&EDGECASES_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(EDGECASES_DEX).expect("parse edgecases.dex");
    assert!(matches!(h.version, DexVersion::V035));
    assert!(
        EDGECASES_DEX.len() > 10_000,
        "expected non-trivial dex size"
    );
}

#[test]
fn parses_real_kotlin_dex_v039_for_min_api_33() {
    assert_eq!(&EDGECASES_KT_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_KT_DEX[4..7], b"039");
    let h: DexHeader = parse_dex_header(EDGECASES_KT_DEX).expect("parse kotlin dex");
    assert!(matches!(h.version, DexVersion::V039));
    assert!(
        EDGECASES_KT_DEX.len() > 50_000,
        "expected substantial kotlin dex"
    );
}
