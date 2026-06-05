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

use disrobe_pass_native::{
    DisFilterStreamSizes, Error, KkrunchyByteRecoveryReport, KkrunchyClassicStream,
    KkrunchyEmulatedUnpackOutput, KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo,
    KkrunchyUnpackOutput, KkrunchyVariant, Packer, PackerDetection, UnpackerStatus,
    compute_byte_recovery, detect_packers, dis_filter, dis_unfilter, locate_classic_stream,
    parse_kkrunchy_header, unpack_kkrunchy, unpack_kkrunchy_emulated,
};

const CLASSIC_MEASURED_FLOOR_BP: u32 = 10_000;

const K7_MEASURED_FLOOR_BP: u32 = 644;

const HELLO_ORIGINAL: &[u8] = include_bytes!("../../../corpus/native/packers/kkrunchy/hello.exe");
const HELLO_PACKED_K7: &[u8] =
    include_bytes!("../../../corpus/native/packers/kkrunchy/hello.packed.kkrunchy.exe");
const HELLO_PACKED_CLASSIC: &[u8] =
    include_bytes!("../../../corpus/native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe");

#[test]
fn kkrunchy_packer_status_is_implemented_classic_floor_verified() {
    assert_eq!(Packer::Kkrunchy.label(), "kkrunchy");
    assert_eq!(
        Packer::Kkrunchy.unpacker_status(),
        UnpackerStatus::Implemented,
        "the classic 0.23a depacker reconstructs the OEP image byte-exact vs the independent \
         pre-packed hello.exe original (100.00% measured by classic_cca_recovers_real_fixture_payload), \
         so kkrunchy is honestly Implemented; the k7 PAQ-backend ceiling is a documented per-variant \
         tail surfaced via KkrunchyVariant::recovery_ceiling_basis_points(), not a fake unpack.",
    );
    assert!(!Packer::Kkrunchy.is_grey_zone());
    assert_eq!(
        KkrunchyVariant::Classic023A.recovery_ceiling_basis_points(),
        10_000,
        "classic ceiling is the verified 100.00% floor",
    );
    assert_eq!(
        KkrunchyVariant::K7Variant023A2.recovery_ceiling_basis_points(),
        K7_MEASURED_FLOOR_BP,
        "k7 ceiling is the honest 6.44% structural floor, never rounded up to the classic 100%",
    );
    assert_eq!(
        KkrunchyVariant::UnknownVersion.recovery_ceiling_basis_points(),
        0,
        "unknown variant claims no decode",
    );
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
    let packed: &[u8] = HELLO_PACKED_K7;
    assert_eq!(packed.len(), 5632, "k7 fixture must be 5632 bytes");

    let hits: Vec<PackerDetection> = detect_packers(packed);
    assert!(
        hits.iter()
            .any(|h: &PackerDetection| h.packer == Packer::Kkrunchy),
        "real k7 sample must classify as kkrunchy",
    );

    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed).expect("k7 header parse");
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

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(packed).expect("structural unpack");
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
    let packed: &[u8] = HELLO_PACKED_CLASSIC;
    assert_eq!(packed.len(), 4608, "classic fixture must be 4608 bytes");

    let hits: Vec<PackerDetection> = detect_packers(packed);
    assert!(
        hits.iter()
            .any(|h: &PackerDetection| h.packer == Packer::Kkrunchy),
        "real classic sample must classify as kkrunchy",
    );

    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed).expect("classic header parse");
    assert_eq!(
        header.variant,
        KkrunchyVariant::Classic023A,
        "classic stub (mov ebp prologue) must fingerprint as Classic023A",
    );
    assert_eq!(header.number_of_sections, 1, "single packed section");

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(packed).expect("structural unpack");
    assert!(!out.packed_payload.is_empty());
}

#[test]
fn locate_classic_stream_finds_real_range_coder_seed() {
    let packed: &[u8] = HELLO_PACKED_CLASSIC;
    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed).expect("classic header parse");
    let loc: KkrunchyClassicStream =
        locate_classic_stream(packed, &header).expect("locate CCA stream in classic image");
    assert_eq!(
        loc.stream_offset, 0xD4,
        "the classic stub seeds src = image_base + 0xD4 via `mov [ebp], imm32`; \
         the located stream offset must match that structurally-derived seed exactly",
    );
    assert!(
        loc.recovered_size > 256,
        "the located stream must decode a non-trivial payload (import bootstrap + DisFilter body), got {}",
        loc.recovered_size,
    );
}

#[test]
fn classic_cca_recovers_real_fixture_payload() {
    let packed: &[u8] = HELLO_PACKED_CLASSIC;
    assert_eq!(packed.len(), 4608, "classic fixture must be 4608 bytes");
    let original: &[u8] = HELLO_ORIGINAL;
    assert_eq!(original.len(), 1024, "hand-rolled hello.exe is 1024 bytes");

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(packed).expect("classic structural+CCA unpack");
    assert_eq!(out.header.variant, KkrunchyVariant::Classic023A);
    assert!(
        out.note.contains("CCA range-coder stream"),
        "note must document the located CCA stream path (got: {})",
        out.note,
    );

    let report: KkrunchyByteRecoveryReport = compute_byte_recovery(original, &out.packed_payload);
    eprintln!(
        "kkrunchy classic byte recovery vs 1024 B original: {} / {} matching ({:.2}%) \
         [recovered_len={}] -- the recovered payload is the on-disk OEP image reconstructed by \
         replaying the depacker stub through the in-house stub_emu interpreter and rebuilding the \
         stripped import table from the recovered descriptor + bootstrap name list.",
        report.matching_bytes,
        report.original_len,
        report.pct(),
        report.recovered_len,
    );

    assert!(
        report.recovery_pct_basis_points >= CLASSIC_MEASURED_FLOOR_BP,
        "classic byte recovery regressed below the measured floor: {:.2}% < {:.2}% \
         (the stub_emu replay reconstructs the OEP image byte-exact; a regression here means the \
         emulator, the PE reconstruction, or the import-table rebuild broke)",
        report.pct(),
        f64::from(CLASSIC_MEASURED_FLOOR_BP) / 100.0,
    );

    let real_import_markers: [&[u8]; 4] = [
        b"kernel32.dll",
        b"GetStdHandle",
        b"WriteFile",
        b"ExitProcess",
    ];
    for marker in real_import_markers {
        assert!(
            out.packed_payload
                .windows(marker.len())
                .any(|w: &[u8]| w == marker),
            "decoded payload must contain the verbatim import name {:?} recovered from the REAL \
             classic stream -- this is the anti-circular witness that the decoder decoded real bytes, \
             not its own encoder output",
            std::str::from_utf8(marker).unwrap_or("<bin>"),
        );
    }
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
    let packed: &[u8] = HELLO_PACKED_K7;
    let err: Error = unpack_kkrunchy_emulated(packed, None).unwrap_err();
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
    let packed: &[u8] = HELLO_PACKED_K7;
    let provider: FakePassthroughEmulator = FakePassthroughEmulator;
    let out: KkrunchyEmulatedUnpackOutput =
        unpack_kkrunchy_emulated(packed, Some(&provider)).expect("emulated unpack");
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
    let original: &[u8] = HELLO_ORIGINAL;
    let packed: &[u8] = HELLO_PACKED_K7;
    assert_eq!(original.len(), 1024, "hand-rolled hello.exe is 1024 bytes");

    let out: KkrunchyUnpackOutput = unpack_kkrunchy(packed).expect("structural unpack");
    let structural_report: KkrunchyByteRecoveryReport =
        compute_byte_recovery(original, &out.packed_payload);
    eprintln!(
        "kkrunchy structural-only byte recovery: {} / {} matching ({:.2}%) [recovered_len={}]",
        structural_report.matching_bytes,
        structural_report.original_len,
        structural_report.pct(),
        structural_report.recovered_len,
    );

    let emulator_attempt: Result<KkrunchyEmulatedUnpackOutput, Error> =
        unpack_kkrunchy_emulated(packed, None);
    assert!(
        matches!(emulator_attempt, Err(Error::EmulatorNotConfigured { .. })),
        "without an emulator provider, the emulated path must surface a PR-WELCOME error",
    );

    assert!(
        structural_report.recovery_pct_basis_points >= K7_MEASURED_FLOOR_BP,
        "k7 byte recovery regressed below the measured honest floor: {:.2}% < {:.2}% \
         (the K7 stub's MMX context-mixing arithmetic-decode core is replayed bit-exact by stub_emu, \
         but the stage-2 LZ pass does not reconstruct the OEP .text within the safety step budget, so \
         the honest recovery is the structural floor; a regression here means structural parsing broke)",
        structural_report.pct(),
        f64::from(K7_MEASURED_FLOOR_BP) / 100.0,
    );

    assert!(
        out.note.contains("not implemented")
            || out.note.contains("backend")
            || out.note.contains("compression"),
        "k7 must honestly disclose the unresolved backend rather than surface a fabricated image",
    );

    let recovered_is_real_section: bool = !out.packed_payload.is_empty()
        && packed
            .windows(out.packed_payload.len().min(64))
            .any(|w: &[u8]| w == &out.packed_payload[..out.packed_payload.len().min(64)]);
    assert!(
        recovered_is_real_section,
        "the honest structural payload must be the verbatim packed kkrunchy section recovered from \
         the input, never an encoder-echoed or zero-coincidence buffer masquerading as a decode",
    );
}
