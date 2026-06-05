#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_binfmt::containers::innosetup::{InnosetupExternalHint, innosetup_external_hint};
use disrobe_binfmt::containers::installshield::{
    InstallshieldExternalHint, installshield_external_hint,
};
use disrobe_binfmt::containers::nsis::{NsisHeader, detect_nsis};

const NSIS_FIRSTHEADER_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

#[test]
fn nsis_signature_detected_in_pe_tail_synthetic() {
    let mut bytes: Vec<u8> = vec![0u8; 4096];
    let off: usize = 2048;
    let flags: u32 = 0;
    bytes[off - 4..off].copy_from_slice(&flags.to_le_bytes());
    bytes[off..off + 16].copy_from_slice(&NSIS_FIRSTHEADER_MAGIC);
    bytes[off + 16..off + 20].copy_from_slice(&4096u32.to_le_bytes());
    bytes[off + 20..off + 24].copy_from_slice(&65_536u32.to_le_bytes());
    let header: NsisHeader = detect_nsis(&bytes).expect("nsis");
    assert_eq!(header.offset, 2048);
    assert_eq!(header.header_size, 4096);
    assert_eq!(header.archive_size, 65_536);
}

#[test]
fn innosetup_external_hint_points_to_innoextract() {
    let hint: InnosetupExternalHint = innosetup_external_hint();
    assert_eq!(hint.tool_binary, "innoextract");
    assert!(hint.install_hint.to_lowercase().contains("install"));
}

#[test]
fn installshield_external_hint_present() {
    let hint: InstallshieldExternalHint = installshield_external_hint();
    assert_eq!(hint.tool_binary, "i6comp");
    assert!(!hint.install_hint.is_empty());
}
