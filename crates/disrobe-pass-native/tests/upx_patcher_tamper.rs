#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_native::packers::{
    self, Packer, PeImage, UpxUnpackOutput, parse_pe_image, unpack_upx,
};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push(rel);
    std::fs::read(&p).ok()
}

const UPX_PE: &str = "native/packers/upx/hello.packed.nrv2b.exe";
const UPX_LZMA: &str = "native/packers/upx/hello.packed.lzma.exe";

fn pe_section_table_offset(bytes: &[u8]) -> usize {
    let e_lfanew: usize =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let coff: usize = e_lfanew + 4;
    let opt_size: usize = u16::from_le_bytes([bytes[coff + 16], bytes[coff + 17]]) as usize;
    coff + 20 + opt_size
}

fn rename_upx_sections(bytes: &mut [u8]) {
    let Ok(pe): Result<PeImage, _> = parse_pe_image(bytes) else {
        return;
    };
    let sec_table: usize = pe_section_table_offset(bytes);
    for i in 0..pe.sections.len() {
        let entry: usize = sec_table + i * 40;
        if &bytes[entry..entry + 3] == b"UPX" {
            bytes[entry..entry + 8].copy_from_slice(b"\x00data00\x00");
        }
    }
}

fn upx_patcher_tamper(bytes: &mut [u8]) {
    let pos: usize = bytes
        .windows(4)
        .position(|w: &[u8]| w == b"UPX!")
        .expect("fixture must carry the UPX! PackHeader magic");
    bytes[pos] = 0x00;
    bytes[pos + 1] = 0x00;
    bytes[pos + 2] = 0x00;
    bytes[pos + 3] = 0x00;
    bytes[pos + 4] = 0xFF;
    bytes[pos + 5] = 0x00;
    rename_upx_sections(bytes);
}

fn assert_tamper_is_thorough(bytes: &[u8]) {
    assert!(
        !bytes.windows(4).any(|w: &[u8]| w == b"UPX!"),
        "UPX-Patcher tamper must leave no UPX! magic"
    );
    if let Ok(pe) = parse_pe_image(bytes) {
        assert!(
            !pe.sections
                .iter()
                .any(|s| s.name_trimmed().starts_with(b"UPX")),
            "UPX-Patcher tamper must leave no UPX-prefixed section name"
        );
    }
}

fn run_tamper_oracle(rel: &str) {
    let Some(intact): Option<Vec<u8>> = corpus(rel) else {
        eprintln!("FIXTURE PENDING: {rel}");
        return;
    };

    let baseline: UpxUnpackOutput =
        unpack_upx(&intact).unwrap_or_else(|e| panic!("intact UPX must unpack ({rel}): {e:?}"));
    assert!(
        baseline.adler_verified,
        "baseline unpack must verify its adler ({rel})"
    );

    let mut tampered: Vec<u8> = intact;
    upx_patcher_tamper(&mut tampered);
    assert_tamper_is_thorough(&tampered);

    let hits: Vec<packers::Detection> = packers::detect(&tampered);
    assert!(
        hits.iter().any(|h| h.packer == Packer::Upx),
        "UPX-Patcher-tampered binary (magic gone, version byte 0xFF, sections renamed) must still \
         be detected as UPX via the verified PackHeader scan ({rel})"
    );

    let recovered: UpxUnpackOutput = unpack_upx(&tampered).unwrap_or_else(|e| {
        panic!("UPX-Patcher-tampered binary must still unpack via verified structural locate ({rel}): {e:?}")
    });
    assert!(
        recovered.adler_verified,
        "recovered image from tampered input must still verify its adler ({rel})"
    );
    assert_eq!(
        recovered.recovered_image, baseline.recovered_image,
        "tampered-header unpack must be byte-identical to the intact unpack ({rel})"
    );
    assert_eq!(
        recovered.method, baseline.method,
        "method id survives the version/magic tamper ({rel})"
    );

    let matched: usize = recovered
        .recovered_image
        .iter()
        .zip(baseline.recovered_image.iter())
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let pct: f64 = 100.0 * matched as f64 / baseline.recovered_image.len() as f64;
    println!(
        "{rel}: tampered-vs-clean OEP-image recovery {matched}/{} = {pct:.2}%",
        baseline.recovered_image.len()
    );
    assert!(
        (pct - 100.0).abs() < f64::EPSILON,
        "tampered recovery must equal the clean unpack exactly, got {pct:.2}% ({rel})"
    );
}

#[test]
fn upx_patcher_tampered_nrv2b_recovers_to_clean_oep_image() {
    run_tamper_oracle(UPX_PE);
}

#[test]
fn upx_patcher_tampered_lzma_recovers_to_clean_oep_image() {
    run_tamper_oracle(UPX_LZMA);
}

#[test]
fn upx_patcher_tampered_large_nrv2e_rg_recovers_to_clean_oep_image() {
    run_tamper_oracle("native/packers/upx/rg.packed.upx.exe");
}

#[test]
fn version_byte_tamper_alone_no_longer_blocks_structural_locate() {
    let Some(intact): Option<Vec<u8>> = corpus(UPX_PE) else {
        return;
    };
    let baseline: UpxUnpackOutput = unpack_upx(&intact).expect("intact UPX must unpack");

    let mut tampered: Vec<u8> = intact;
    let pos: usize = tampered
        .windows(4)
        .position(|w: &[u8]| w == b"UPX!")
        .expect("UPX! present");
    for b in &mut tampered[pos..pos + 4] {
        *b ^= 0xFF;
    }
    tampered[pos + 4] = 0x00;

    let recovered: UpxUnpackOutput = unpack_upx(&tampered).expect(
        "a zeroed version byte (rejected by the version-gated plausibility scan) must still \
         resolve through the decompression-verified locate",
    );
    assert_eq!(recovered.recovered_image, baseline.recovered_image);
    assert!(recovered.adler_verified);
}
