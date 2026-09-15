#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Packer, UnpackerStatus, detect_packers};

fn pe_with_sections(names: &[&[u8]]) -> Vec<u8> {
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let section_names: Vec<&[u8]> = names.iter().copied().filter(|n| n.len() <= 8).collect();
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
    for pattern in names {
        let cursor: usize = buf.len();
        buf.extend_from_slice(pattern);
        buf.resize(cursor + pattern.len() + 16, 0);
    }
    buf
}

fn detect_with_pattern(pattern: &[u8], expected: Packer) -> bool {
    let buf: Vec<u8> = pe_with_sections(&[pattern]);
    detect_packers(&buf).iter().any(|h| h.packer == expected)
}

#[test]
fn aspack_unpack_signature_detected() {
    assert!(detect_with_pattern(b".aspack", Packer::AsPack));
}

#[test]
fn asprotect_signature_detected() {
    assert!(detect_with_pattern(b".asprotect", Packer::AsProtect));
}

#[test]
fn petite_signature_detected() {
    assert!(detect_with_pattern(b".petite", Packer::Petite));
}

#[test]
fn mpress_signature_detected() {
    assert!(detect_with_pattern(b".MPRESS1", Packer::Mpress));
}

#[test]
fn fsg_signature_detected() {
    assert!(detect_with_pattern(b"FSG!", Packer::Fsg));
}

#[test]
fn morphine_signature_detected() {
    assert!(detect_with_pattern(b"morphine", Packer::Morphine));
}

#[test]
fn pecompact_signature_detected() {
    assert!(detect_with_pattern(b"PEC2", Packer::PeCompact));
}

#[test]
fn yodas_signature_detected() {
    assert!(detect_with_pattern(b"yC2.0", Packer::YodasCrypter));
    assert!(detect_with_pattern(b"yP1.0", Packer::YodasProtector));
}

#[test]
fn npack_neolite_signature_detected() {
    assert!(detect_with_pattern(b".nPack", Packer::NPack));
    assert!(detect_with_pattern(b"neolite", Packer::NeoLite));
}

#[test]
fn mew_signature_detected() {
    assert!(detect_with_pattern(b"MEW", Packer::Mew));
}

#[test]
fn polycryptor_signature_detected() {
    assert!(detect_with_pattern(b"PolyCryptor", Packer::PolyCryptor));
}

#[test]
fn pelock_signature_detected_and_grey_zone() {
    assert!(detect_with_pattern(b"PELock", Packer::PeLock));
    assert!(Packer::PeLock.is_grey_zone());
}

#[test]
fn vmprotect_signature_detected_and_carve_only() {
    assert!(detect_with_pattern(b".vmp0", Packer::VmProtect));
    assert_eq!(
        Packer::VmProtect.unpacker_status(),
        UnpackerStatus::GreyZoneDetectAndCarve
    );
}

#[test]
fn themida_signature_detected_and_carve_only() {
    assert!(detect_with_pattern(b".themida", Packer::Themida));
    assert_eq!(
        Packer::Themida.unpacker_status(),
        UnpackerStatus::GreyZoneDetectAndCarve
    );
}

#[test]
fn enigma_signature_detected_and_detect_only() {
    assert!(detect_with_pattern(b".enigma", Packer::EnigmaProtector));
    assert_eq!(
        Packer::EnigmaProtector.unpacker_status(),
        UnpackerStatus::GreyZoneDetectOnly
    );
}

#[test]
fn armadillo_signature_detected_and_detect_only() {
    assert!(detect_with_pattern(b"ARMADILLO", Packer::Armadillo));
    assert_eq!(
        Packer::Armadillo.unpacker_status(),
        UnpackerStatus::GreyZoneDetectOnly
    );
}

#[test]
fn obsidium_signature_detected_and_detect_only() {
    assert!(detect_with_pattern(b"Obsidium", Packer::Obsidium));
    assert_eq!(
        Packer::Obsidium.unpacker_status(),
        UnpackerStatus::GreyZoneDetectOnly
    );
}

#[test]
fn winlicense_signature_detected_and_detect_only() {
    let buf: Vec<u8> = pe_with_sections(&[b".winlice"]);
    let hits = detect_packers(&buf);
    assert!(
        hits.iter()
            .any(|h| matches!(h.packer, Packer::WinLicense | Packer::Themida))
    );
}

#[test]
fn warzone_dotnetpatcher_netcryptor_signatures_detected() {
    assert!(detect_with_pattern(b"WarzoneRAT", Packer::WarzoneCrypter));
    assert!(detect_with_pattern(b"DNPatcher", Packer::DotNetPatcher));
    assert!(detect_with_pattern(b"NETCryptor", Packer::NetCryptor));
}

#[test]
fn aspack_ep_stub_detected() {
    let stub: &[u8] = &[
        0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
    ];
    assert!(detect_with_pattern(stub, Packer::AsPack));
}

#[test]
fn winlicense_literal_disambiguates_from_shared_section() {
    assert!(detect_with_pattern(b"WinLicense", Packer::WinLicense));
    assert_eq!(
        Packer::WinLicense.unpacker_status(),
        UnpackerStatus::GreyZoneDetectOnly
    );
}

#[test]
fn enigma_overlay_literal_detected_detect_only() {
    assert!(detect_with_pattern(
        b"Enigma protector",
        Packer::EnigmaProtector
    ));
    assert_eq!(
        Packer::EnigmaProtector.unpacker_status(),
        UnpackerStatus::GreyZoneDetectOnly
    );
}

#[test]
fn bare_delta_prologue_yields_no_winlicense_or_enigma() {
    let bare: &[u8] = &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED];
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[16..16 + bare.len()].copy_from_slice(bare);
    let hits = detect_packers(&buf);
    assert!(
        !hits
            .iter()
            .any(|h| matches!(h.packer, Packer::EnigmaProtector | Packer::WinLicense))
    );
}

#[test]
fn protect_chain_combined_signatures() {
    let buf: Vec<u8> = pe_with_sections(&[b"UPX!", b".petite", b".themida"]);
    let hits = detect_packers(&buf);
    assert!(hits.len() >= 3);
}
