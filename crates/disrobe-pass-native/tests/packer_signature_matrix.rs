#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Packer, UnpackerStatus, detect_packers};

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
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[100..100 + pattern.len()].copy_from_slice(pattern);
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
