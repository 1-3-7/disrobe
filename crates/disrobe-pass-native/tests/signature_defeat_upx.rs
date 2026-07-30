#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use disrobe_pass_native::packers::{
    self, Packer, PeImage, UpxUnpackOutput, parse_pe_image, unpack_upx,
};
use packer_fixture::{PackerFixture, load_fixture};

fn corpus(name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: "UPX",
        family: "upx",
        name,
    })
}

const UPX_PE: &str = "hello.packed.nrv2b.exe";

fn rename_upx_sections(bytes: &mut [u8]) {
    let Ok(pe): Result<PeImage, _> = parse_pe_image(bytes) else {
        return;
    };
    let dos_e_lfanew: usize = 0x3C;
    let e_lfanew: usize = u32::from_le_bytes([
        bytes[dos_e_lfanew],
        bytes[dos_e_lfanew + 1],
        bytes[dos_e_lfanew + 2],
        bytes[dos_e_lfanew + 3],
    ]) as usize;
    let coff: usize = e_lfanew + 4;
    let opt_size: usize = u16::from_le_bytes([bytes[coff + 16], bytes[coff + 17]]) as usize;
    let sec_table: usize = coff + 20 + opt_size;
    for i in 0..pe.sections.len() {
        let entry: usize = sec_table + i * 40;
        if &bytes[entry..entry + 3] == b"UPX" {
            bytes[entry] = b'Z';
            bytes[entry + 1] = b'Z';
            bytes[entry + 2] = b'Z';
        }
    }
}

fn corrupt_upx_marker(bytes: &mut [u8]) {
    if let Some(pos) = bytes.windows(4).position(|w: &[u8]| w == b"UPX!") {
        for b in &mut bytes[pos..pos + 4] {
            *b ^= 0xFF;
        }
    }
}

#[test]
fn scrambled_marker_and_renamed_sections_upx_still_unpacks_byte_identically() {
    let Some(intact): Option<Vec<u8>> = corpus(UPX_PE) else {
        eprintln!("FIXTURE PENDING: {UPX_PE}");
        return;
    };

    let baseline: UpxUnpackOutput = unpack_upx(&intact).expect("intact UPX must unpack");
    assert!(
        baseline.adler_verified,
        "baseline unpack must verify its adler checksum"
    );
    let baseline_hits: Vec<packers::Detection> = packers::detect(&intact);
    assert!(
        baseline_hits.iter().any(|h| h.packer == Packer::Upx),
        "intact UPX must be detected via the marker/section signatures"
    );

    let mut scrambled: Vec<u8> = intact;
    rename_upx_sections(&mut scrambled);
    corrupt_upx_marker(&mut scrambled);

    assert!(
        !scrambled.windows(4).any(|w: &[u8]| w == b"UPX!"),
        "the UPX! marker must be gone after scrambling"
    );
    if let Ok(pe) = parse_pe_image(&scrambled) {
        assert!(
            !pe.sections
                .iter()
                .any(|s| s.name_trimmed().starts_with(b"UPX")),
            "no UPX-prefixed section names may remain after renaming"
        );
    }

    let hits: Vec<packers::Detection> = packers::detect(&scrambled);
    assert!(
        hits.iter().any(|h| h.packer == Packer::Upx),
        "renamed-section + corrupted-marker UPX must still be detected structurally"
    );

    let recovered: UpxUnpackOutput =
        unpack_upx(&scrambled).expect("scrambled-marker UPX must still unpack via PackHeader scan");
    assert_eq!(
        recovered.recovered_image, baseline.recovered_image,
        "scrambled-marker unpack must be byte-identical to the intact unpack"
    );
    assert!(
        recovered.adler_verified,
        "recovered image from scrambled input must still verify its adler"
    );
}

#[test]
fn upx_unpack_tolerates_flipped_mz() {
    let Some(intact): Option<Vec<u8>> = corpus(UPX_PE) else {
        return;
    };
    let baseline: UpxUnpackOutput = unpack_upx(&intact).expect("intact UPX must unpack");

    let mut flipped: Vec<u8> = intact;
    flipped[0] ^= 0xFF;
    flipped[1] ^= 0xFF;
    assert_ne!(&flipped[..2], b"MZ");

    let recovered: UpxUnpackOutput =
        unpack_upx(&flipped).expect("flipped-MZ UPX must still unpack");
    assert_eq!(recovered.recovered_image, baseline.recovered_image);
}
