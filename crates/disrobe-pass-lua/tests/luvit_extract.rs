#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::luvit::{self, LuvitBundle, LuvitFormat};

#[test]
fn detect_lit_zip() {
    let mut bytes: Vec<u8> = vec![b'L', b'I', b'T', 0x01];
    bytes.extend_from_slice(&[0u8; 32]);
    let kind: Option<LuvitFormat> = luvit::detect(&bytes);
    assert_eq!(kind, Some(LuvitFormat::LitZip));
}

#[test]
fn detect_luvi_trailer() {
    let mut bytes: Vec<u8> = vec![0xAA; 32];
    bytes.extend_from_slice(b"LIT!");
    let kind: Option<LuvitFormat> = luvit::detect(&bytes);
    assert_eq!(kind, Some(LuvitFormat::LuviAppended));
}

#[test]
fn extract_lit_zip_returns_format() {
    let mut bytes: Vec<u8> = vec![b'L', b'I', b'T', 0x01];
    bytes.extend_from_slice(&[0u8; 32]);
    let bundle: LuvitBundle = luvit::extract(&bytes).expect("extract");
    assert_eq!(bundle.format, LuvitFormat::LitZip);
}

#[test]
fn extract_rejects_unknown_payload() {
    let bytes: &[u8] = &[0u8; 16];
    let err: disrobe_pass_lua::Error = luvit::extract(bytes).unwrap_err();
    assert!(matches!(err, disrobe_pass_lua::Error::LuvitMalformed(_)));
}
