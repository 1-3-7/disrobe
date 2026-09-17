#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Packer, UnpackerStatus, detect_packers};

fn pe_with_marker(pattern: &[u8]) -> Vec<u8> {
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let n_sections: usize = usize::from(pattern.len() <= 8);
    let mut buf: Vec<u8> = vec![0u8; sec_table + n_sections.max(1) * 40 + 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x80 + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(n_sections as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    if n_sections == 1 {
        buf[sec_table..sec_table + pattern.len()].copy_from_slice(pattern);
    }
    let cursor: usize = buf.len();
    buf.extend_from_slice(pattern);
    buf.resize(cursor + pattern.len() + 16, 0);
    buf
}

#[test]
fn signature_matrix_covers_known_packers() {
    let probes: &[(&[u8], Packer)] = &[
        (b".aspack", Packer::AsPack),
        (b".asprotect", Packer::AsProtect),
        (b".petite", Packer::Petite),
        (b".MPRESS1", Packer::Mpress),
        (b"FSG!", Packer::Fsg),
        (b"morphine", Packer::Morphine),
        (b"PEC2", Packer::PeCompact),
        (b"yC2.0", Packer::YodasCrypter),
        (b"yP1.0", Packer::YodasProtector),
        (b".nPack", Packer::NPack),
        (b"neolite", Packer::NeoLite),
        (b"MEW", Packer::Mew),
        (b"PolyCryptor", Packer::PolyCryptor),
        (b"PELock", Packer::PeLock),
        (b".vmp0", Packer::VmProtect),
        (b".themida", Packer::Themida),
        (b".enigma", Packer::EnigmaProtector),
        (b"ARMADILLO", Packer::Armadillo),
        (b"Obsidium", Packer::Obsidium),
        (b"WarzoneRAT", Packer::WarzoneCrypter),
        (b"DNPatcher", Packer::DotNetPatcher),
        (b"NETCryptor", Packer::NetCryptor),
        (
            &[
                0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
            ],
            Packer::AsPack,
        ),
        (b"Enigma protector", Packer::EnigmaProtector),
        (b"WinLicense", Packer::WinLicense),
    ];
    for (pattern, expected) in probes {
        let buf: Vec<u8> = pe_with_marker(pattern);
        let hits = detect_packers(&buf);
        assert!(
            hits.iter().any(|h| h.packer == *expected),
            "missing detection for {expected:?} via pattern {pattern:?}"
        );
    }
}

#[test]
fn grey_zone_packers_remain_carve_only() {
    assert_eq!(
        Packer::VmProtect.unpacker_status(),
        UnpackerStatus::GreyZoneDetectAndCarve
    );
    assert_eq!(
        Packer::Themida.unpacker_status(),
        UnpackerStatus::GreyZoneDetectAndCarve
    );
    for p in [
        Packer::EnigmaProtector,
        Packer::Armadillo,
        Packer::Obsidium,
        Packer::WinLicense,
        Packer::PeProtector,
        Packer::PeLock,
    ] {
        assert_eq!(p.unpacker_status(), UnpackerStatus::GreyZoneDetectOnly);
    }
}
