#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{
    CHAIN_SIGNATURES, ChainDetection, Confidence, Packer, detect_packer_chain,
};

fn buf_with_markers(markers: &[&[u8]]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 4096];
    let mut cursor: usize = 128;
    for marker in markers {
        buf[cursor..cursor + marker.len()].copy_from_slice(marker);
        cursor += marker.len() + 64;
    }
    buf
}

#[test]
fn upx_aspack_chain_detected_via_independent_section_markers() {
    let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack"]);
    let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
    let chain: &ChainDetection = chains
        .iter()
        .find(|c: &&ChainDetection| c.layers == vec![Packer::Upx, Packer::AsPack])
        .expect("UPX+ASPack chain witnessed by the real UPX! and .aspack section markers");
    assert_eq!(chain.confidence, Confidence::High);
    assert_eq!(chain.witnesses.len(), 2);
    for w in &chain.witnesses {
        assert!(
            w.matched_offset.is_some(),
            "each layer witness must carry the concrete offset of its real marker",
        );
    }
}

#[test]
fn petite_vmprotect_chain_detected() {
    let buf: Vec<u8> = buf_with_markers(&[b".petite", b".vmp1"]);
    let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
    assert!(
        chains
            .iter()
            .any(|c: &ChainDetection| c.layers == vec![Packer::Petite, Packer::VmProtect]),
    );
}

#[test]
fn triple_layer_chain_outranks_two_layer_subsets() {
    let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack", b".vmp0"]);
    let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
    assert_eq!(
        chains
            .first()
            .expect("a chain must be detected")
            .layers
            .len(),
        3,
        "the 3-layer UPX+ASPack+VMProtect chain must rank first",
    );
}

#[test]
fn yodas_family_escalation_chain_detected() {
    let buf: Vec<u8> = buf_with_markers(&[b"yC2.0", b"yP1.0"]);
    let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
    assert!(
        chains.iter().any(
            |c: &ChainDetection| c.layers == vec![Packer::YodasCrypter, Packer::YodasProtector]
        ),
        "Yoda's Crypter -> Yoda's Protector same-family escalation chain must be detected",
    );
}

#[test]
fn single_marker_never_fabricates_a_chain() {
    let buf: Vec<u8> = buf_with_markers(&[b"UPX!"]);
    assert!(
        detect_packer_chain(&buf).is_empty(),
        "a lone packer marker is not a chain; detection must stay non-circular",
    );
}

#[test]
fn clean_binary_yields_no_chain() {
    let buf: Vec<u8> = vec![0u8; 8192];
    assert!(detect_packer_chain(&buf).is_empty());
}

#[test]
fn curated_ledger_count_is_in_band() {
    assert!(
        (20..=30).contains(&CHAIN_SIGNATURES.len()),
        "the chain ledger must carry 20-30 fingerprints, got {}",
        CHAIN_SIGNATURES.len(),
    );
}
