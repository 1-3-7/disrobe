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
    let section_names: Vec<&[u8]> = markers.iter().copied().filter(|m| m.len() <= 8).collect();
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let header_end: usize = sec_table + section_names.len().max(1) * 40;
    let mut buf: Vec<u8> = vec![0u8; header_end + 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x80 + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(section_names.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    for (i, name) in section_names.iter().enumerate() {
        let entry: usize = sec_table + i * 40;
        buf[entry..entry + name.len()].copy_from_slice(name);
    }
    for marker in markers {
        let cursor: usize = buf.len();
        buf.extend_from_slice(marker);
        buf.resize(cursor + marker.len() + 16, 0);
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
