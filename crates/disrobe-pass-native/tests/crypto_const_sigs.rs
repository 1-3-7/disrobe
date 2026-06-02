#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::path::PathBuf;

use disrobe_pass_native::{
    CryptoConstConfidence, CryptoConstHit, CryptoPrimitive, detect_crypto_constants,
};
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&path).ok()
}

#[test]
fn chacha20_sigma_detected_in_constructed_buffer() {
    let sigma: &[u8] = b"expand 32-byte k";
    let lead: usize = 4096;
    let mut buf: Vec<u8> = vec![0u8; lead];
    buf.extend_from_slice(sigma);
    buf.extend_from_slice(&[0u8; 64]);
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(&buf);
    let sigma_hit: &CryptoConstHit = hits
        .iter()
        .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::Chacha20Sigma)
        .expect("chacha20 sigma detected in constructed buffer");
    assert_eq!(sigma_hit.offset, lead as u64);
    assert_eq!(sigma_hit.confidence, CryptoConstConfidence::High);
}

#[test]
fn pyarmor_runtime_embeds_aes_ttables() {
    let Some(bytes): Option<Vec<u8>> = corpus(
        "../../corpus/python/pyarmor/v8/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so",
    ) else {
        eprintln!("skip: pyarmor_runtime.so corpus fixture absent");
        return;
    };
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(&bytes);
    let enc: &CryptoConstHit = hits
        .iter()
        .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::AesTtableEnc)
        .expect("aes ttable enc detected");
    assert_eq!(enc.offset, 556_320);
    assert_eq!(enc.confidence, CryptoConstConfidence::High);
    let dec: &CryptoConstHit = hits
        .iter()
        .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::AesTtableDec)
        .expect("aes ttable dec detected");
    assert_eq!(dec.offset, 564_512);
    assert_eq!(dec.confidence, CryptoConstConfidence::High);
}

#[test]
fn rustdesk_libflutter_embeds_chacha20_sigma() {
    let Some(bytes): Option<Vec<u8>> = corpus("../../corpus/mobile/flutter/rustdesk/libflutter.so")
    else {
        eprintln!("skip: libflutter.so corpus fixture absent");
        return;
    };
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(&bytes);
    let sigma: &CryptoConstHit = hits
        .iter()
        .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::Chacha20Sigma)
        .expect("chacha20 sigma detected");
    assert_eq!(sigma.offset, 1_747_328);
    assert_eq!(sigma.confidence, CryptoConstConfidence::High);
}

#[test]
fn random_buffer_has_no_false_hits() {
    let mut rng: StdRng = StdRng::seed_from_u64(0x0DDC_0FFE_EBAD_F00D);
    let mut buf: Vec<u8> = vec![0u8; 65_536];
    rng.fill_bytes(&mut buf);
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(&buf);
    assert!(
        hits.is_empty(),
        "unexpected hits in random buffer: {hits:?}"
    );
}
