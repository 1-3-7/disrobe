#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{
    DisFilterStreamSizes, Error, KkrunchyByteRecoveryReport, KkrunchyEmulatedUnpackOutput,
    KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo,
    KkrunchyHeaderReconstructionEmulator, KkrunchyUnpackOutput, KkrunchyVariant, Packer,
    PackerDetection, UnpackerStatus, compute_byte_recovery, detect_packers, dis_filter,
    dis_unfilter, parse_kkrunchy_header, unpack_kkrunchy, unpack_kkrunchy_emulated,
};

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("kkrunchy");
    p
}

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = corpus_dir();
    p.push(name);
    fs::read(&p).ok()
}

#[test]
fn kkrunchy_packer_status_is_implemented() {
    assert_eq!(Packer::Kkrunchy.label(), "kkrunchy");
    assert_eq!(
        Packer::Kkrunchy.unpacker_status(),
        UnpackerStatus::Implemented
    );
    assert!(!Packer::Kkrunchy.is_grey_zone());
}

#[test]
fn kkrunchy_signatures_detected_on_synthetic_buffer() {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[0..12].copy_from_slice(b"MZfarbrausch");
    buf[64..72].copy_from_slice(b"kkrunchy");
    let hits: Vec<PackerDetection> = detect_packers(&buf);
    assert!(
        hits.iter()
            .any(|h: &PackerDetection| h.packer == Packer::Kkrunchy),
        "MZfarbrausch + kkrunchy section name must classify",
    );
}

#[test]
fn dis_filter_round_trip_random_x86_sequences() {
    let cases: &[&[u8]] = &[
        &[0xC3],
        &[0x90, 0x90, 0x90, 0x90, 0xC3],
        &[0xCC; 16],
        &[0x55, 0x89, 0xE5, 0x5D, 0xC3],
        &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        &[0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3],
        &[0x83, 0xEC, 0x10, 0x83, 0xC4, 0x10, 0xC3],
        &[0x6A, 0x00, 0x6A, 0x01, 0xC3],
        &[0x8B, 0x44, 0x24, 0x04, 0xC3],
        &[0x33, 0xC0, 0xC3],
        &[0x40, 0x48, 0x41, 0x49, 0xC3],
        &[0xFF, 0x25, 0x00, 0x10, 0x40, 0x00],
    ];
    let origin: u32 = 0x0040_1000;
    for (i, code) in cases.iter().enumerate() {
        let (filtered, sizes): (Vec<u8>, DisFilterStreamSizes) =
            dis_filter(code, origin).expect("dis_filter");
        assert_eq!(
            sizes.total as usize,
            filtered.len(),
            "case {i}: total size must match buffer",
        );
        let restored: Vec<u8> = dis_unfilter(&filtered, code.len(), origin).expect("dis_unfilter");
        assert_eq!(restored, *code, "case {i}: round-trip must be identity");
    }
}

#[test]
fn dis_filter_property_zero_length_and_padding() {
    let origin: u32 = 0x0040_2000;
    let empty: Vec<u8> = Vec::new();
    let (filtered, _sizes): (Vec<u8>, DisFilterStreamSizes) =
        dis_filter(&empty, origin).expect("empty filter");
    let restored: Vec<u8> = dis_unfilter(&filtered, 0, origin).expect("empty unfilter");
    assert!(restored.is_empty(), "empty input -> empty output");

    let padding: Vec<u8> = vec![0xCC; 64];
    let (filtered, _sizes): (Vec<u8>, DisFilterStreamSizes) =
        dis_filter(&padding, origin).expect("padding filter");
    let restored: Vec<u8> =
        dis_unfilter(&filtered, padding.len(), origin).expect("padding unfilter");
    assert_eq!(restored, padding, "INT3 padding round-trip");
}

#[test]
fn detect_and_parse_real_kkrunchy_k7_fixture() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy.exe") else {
        eprintln!("skipping: kkrunchy k7 corpus fixture missing");
        return;
    };
    assert_eq!(packed.len(), 5632, "k7 fixture must be 5632 bytes");

    let hits: Vec<PackerDetection> = detect_packers(&packed);
    assert!(
        hits.iter()
            .any(|h: &PackerDetection| h.packer == Packer::Kkrunchy),
        "real k7 sample must classify as kkrunchy",
    );

    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(&packed).expect("k7 header parse");
    assert_eq!(
        header.variant,
        KkrunchyVariant::K7Variant023A2,
        "k7 stub fingerprint must classify as K7",
    );
    assert_eq!(header.number_of_sections, 1, "single packed section");
    assert!(
        header.section_raw_size > 0 && header.section_raw_offset > 0,
        "section must point at non-zero raw payload",
    );
    assert!(
        header.section_va >= 0x1000,
        "section VA must be inside loadable image",
    );
    assert!(
        header.size_of_image > header.section_vsize,
        "image at least covers section",
    );

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(&packed).expect("structural unpack");
    assert_eq!(out.header.variant, KkrunchyVariant::K7Variant023A2);
    assert!(!out.packed_payload.is_empty(), "payload bytes captured");
    assert!(!out.stub_bytes.is_empty(), "stub bytes captured");
    assert!(
        out.note.contains("dis_unfilter") || out.note.contains("DisFilter"),
        "note must document DisFilter inverse path",
    );
    assert!(
        out.note.contains("not implemented")
            || out.note.contains("backend")
            || out.note.contains("compression"),
        "note must honestly disclose the closed-source backend gap",
    );
}

#[test]
fn detect_and_parse_real_kkrunchy_classic_fixture() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy_classic.exe") else {
        eprintln!("skipping: kkrunchy classic corpus fixture missing");
        return;
    };
    assert_eq!(packed.len(), 4608, "classic fixture must be 4608 bytes");

    let hits: Vec<PackerDetection> = detect_packers(&packed);
    assert!(
        hits.iter()
            .any(|h: &PackerDetection| h.packer == Packer::Kkrunchy),
        "real classic sample must classify as kkrunchy",
    );

    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(&packed).expect("classic header parse");
    assert!(
        matches!(
            header.variant,
            KkrunchyVariant::Classic023A | KkrunchyVariant::UnknownVersion
        ),
        "classic stub must classify as Classic or Unknown (k7 explicitly excluded)",
    );
    assert_eq!(header.number_of_sections, 1, "single packed section");

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(&packed).expect("structural unpack");
    assert!(!out.packed_payload.is_empty());
}

#[test]
fn parse_rejects_random_data_with_signature_error() {
    let bytes: Vec<u8> = vec![0u8; 4096];
    let err = parse_kkrunchy_header(&bytes).unwrap_err();
    let msg: String = err.to_string();
    assert!(
        msg.contains("kkrunchy") || msg.contains("signature") || msg.contains("MZfarbrausch"),
        "error must mention kkrunchy or signature failure (got: {msg})",
    );
}

#[test]
fn parse_rejects_truncated_with_truncation_error() {
    let bytes: Vec<u8> = b"MZfarbrausch".to_vec();
    let err = parse_kkrunchy_header(&bytes).unwrap_err();
    let msg: String = err.to_string();
    assert!(
        msg.contains("shorter") || msg.contains("truncat") || msg.contains("needed"),
        "error must surface truncation (got: {msg})",
    );
}

#[test]
fn dis_unfilter_rejects_oversized_dest() {
    let header_only: Vec<u8> = vec![0u8; 19 * 4];
    let huge: usize = 256 * 1024 * 1024;
    let err = dis_unfilter(&header_only, huge, 0x1000).unwrap_err();
    let msg: String = err.to_string();
    assert!(
        msg.contains("exceeds") || msg.contains("safety"),
        "must surface the safety cap (got: {msg})",
    );
}

#[test]
fn unpack_emulated_without_provider_surfaces_pr_welcome_error() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy.exe") else {
        eprintln!("skipping: kkrunchy k7 corpus fixture missing");
        return;
    };
    let err: Error = unpack_kkrunchy_emulated(&packed, None).unwrap_err();
    match err {
        Error::EmulatorNotConfigured {
            packer,
            trait_name,
            pr_hint,
        } => {
            assert_eq!(packer, "kkrunchy");
            assert_eq!(trait_name, "KkrunchyEmulator");
            assert!(
                pr_hint.contains("unicorn")
                    || pr_hint.contains("icicle")
                    || pr_hint.contains("libmwemu"),
                "PR hint must name candidate emulators (got: {pr_hint})",
            );
        }
        other => panic!("expected EmulatorNotConfigured, got {other:?}"),
    }
}

#[derive(Debug)]
struct FakePassthroughEmulator;

impl KkrunchyEmulator for FakePassthroughEmulator {
    fn label(&self) -> &'static str {
        "fake-passthrough"
    }
    fn emulate_until_oep(
        &self,
        packed_bytes: &[u8],
        header: &KkrunchyHeaderInfo,
    ) -> Result<KkrunchyEmulationSnapshot, Error> {
        Ok(KkrunchyEmulationSnapshot {
            image_base: header.image_base,
            image_bytes: packed_bytes.to_vec(),
            original_entry_rva: header.entry_rva,
            recovered_imports: Vec::new(),
        })
    }
}

#[test]
fn unpack_emulated_with_fake_provider_returns_snapshot() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy.exe") else {
        eprintln!("skipping: kkrunchy k7 corpus fixture missing");
        return;
    };
    let provider: FakePassthroughEmulator = FakePassthroughEmulator;
    let out: KkrunchyEmulatedUnpackOutput =
        unpack_kkrunchy_emulated(&packed, Some(&provider)).expect("emulated unpack");
    assert_eq!(out.provider_label, "fake-passthrough");
    assert_eq!(out.reconstructed_image.len(), packed.len());
    assert_eq!(out.header.variant, KkrunchyVariant::K7Variant023A2);
    assert!(out.note.contains("fake-passthrough"));
}

#[test]
fn compute_byte_recovery_metric_is_correct() {
    let zero_match: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&[1, 2, 3, 4], &[5, 6, 7, 8]);
    assert_eq!(zero_match.matching_bytes, 0);
    assert_eq!(zero_match.recovery_pct_basis_points, 0);
    assert!((zero_match.pct() - 0.0).abs() < 1e-9);

    let full_match: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&[1, 2, 3, 4], &[1, 2, 3, 4]);
    assert_eq!(full_match.matching_bytes, 4);
    assert_eq!(full_match.recovery_pct_basis_points, 10_000);
    assert!((full_match.pct() - 100.0).abs() < 1e-9);

    let half_match: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&[1, 2, 3, 4], &[1, 2, 9, 9]);
    assert_eq!(half_match.matching_bytes, 2);
    assert_eq!(half_match.recovery_pct_basis_points, 5_000);

    let recovered_short: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&[1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3, 4]);
    assert_eq!(recovered_short.matching_bytes, 4);
    assert_eq!(recovered_short.recovery_pct_basis_points, 5_000);

    let empty: KkrunchyByteRecoveryReport = compute_byte_recovery(&[], &[]);
    assert_eq!(empty.matching_bytes, 0);
    assert_eq!(empty.recovery_pct_basis_points, 0);
}

#[test]
fn test_kkrunchy_hello_byte_recovery() {
    let Some(original): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skipping: hello.exe corpus fixture missing");
        return;
    };
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy.exe") else {
        eprintln!("skipping: kkrunchy k7 corpus fixture missing");
        return;
    };
    assert_eq!(original.len(), 1024, "hand-rolled hello.exe is 1024 bytes");

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(&packed).expect("structural unpack");
    let structural_report: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&original, &out.packed_payload);
    eprintln!(
        "kkrunchy structural-only byte recovery: {} / {} matching ({:.2}%) [recovered_len={}]",
        structural_report.matching_bytes,
        structural_report.original_len,
        structural_report.pct(),
        structural_report.recovered_len,
    );

    let emulator_attempt: Result<KkrunchyEmulatedUnpackOutput, Error> =
        unpack_kkrunchy_emulated(&packed, None);
    assert!(
        matches!(emulator_attempt, Err(Error::EmulatorNotConfigured { .. })),
        "without an emulator provider, the emulated path must surface a PR-WELCOME error",
    );
    let target_pct_bp: u32 = 9_000;
    eprintln!(
        "kkrunchy v0.8-w4c gap: {target_bp} bp ({target_pct:.2}%) target vs {actual_bp} bp ({actual_pct:.2}%) structural; \
         provider-backed unpack required to close the gap",
        target_bp = target_pct_bp,
        target_pct = f64::from(target_pct_bp) / 100.0,
        actual_bp = structural_report.recovery_pct_basis_points,
        actual_pct = structural_report.pct(),
    );
}

#[test]
fn test_kkrunchy_hello_byte_recovery_via_header_reconstruction_emulator() {
    let Some(original): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skipping: hello.exe corpus fixture missing");
        return;
    };
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.packed.kkrunchy.exe") else {
        eprintln!("skipping: kkrunchy k7 corpus fixture missing");
        return;
    };
    assert_eq!(original.len(), 1024, "hand-rolled hello.exe is 1024 bytes");

    let provider: KkrunchyHeaderReconstructionEmulator =
        KkrunchyHeaderReconstructionEmulator::new();
    let out: KkrunchyEmulatedUnpackOutput =
        unpack_kkrunchy_emulated(&packed, Some(&provider)).expect("emulated unpack");
    assert_eq!(out.provider_label, "kkrunchy-header-reconstruction");
    assert_eq!(out.reconstructed_image.len(), original.len());
    let recon_report: KkrunchyByteRecoveryReport =
        compute_byte_recovery(&original, &out.reconstructed_image);
    eprintln!(
        "kkrunchy v0.9-a3 header-reconstruction byte recovery: {} / {} matching ({:.2}%) [recovered_len={}]",
        recon_report.matching_bytes,
        recon_report.original_len,
        recon_report.pct(),
        recon_report.recovered_len,
    );
    assert!(
        recon_report.recovery_pct_basis_points >= 9_000,
        "v0.9-a3 byte-recovery must clear 90.00%; got {:.2}% ({} / {})",
        recon_report.pct(),
        recon_report.matching_bytes,
        recon_report.original_len,
    );
    assert_eq!(out.recovered_imports.len(), 1);
    assert_eq!(out.recovered_imports[0].0, "kernel32.dll");
    assert_eq!(out.recovered_imports[0].1.len(), 3);
}
