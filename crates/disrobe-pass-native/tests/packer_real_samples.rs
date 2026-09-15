#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_precision_loss
)]

use disrobe_pass_native::packers::{
    AspackRecovery, AspackReport, CarvedSection, PecompactRecovery, PecompactReport,
    RecoveredSection, SectionRecovery, YodasCrypterCarve, YodasCrypterReport, YodasProtectorReport,
    carve_yodas_protector, recover_yodas_crypter_carve, unpack_aspack, unpack_pecompact,
    unpack_yodas_crypter,
};

macro_rules! sample {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/native/packers/",
            $name
        ))
    };
}

const YODAC_ACCESSENUM_PACKED: &[u8] = sample!("yodas_crypter/AccessEnum.packed.yodascrypter.exe");
const YODAC_ACCESSENUM_ORIG: &[u8] = sample!("yodas_crypter/AccessEnum.original.exe");
const YODAC_CLOCKRES_PACKED: &[u8] = sample!("yodas_crypter/Clockres.packed.yodascrypter.exe");
const YODAC_CLOCKRES_ORIG: &[u8] = sample!("yodas_crypter/Clockres.original.exe");

const YODAP_ACCESSENUM_PACKED: &[u8] =
    sample!("yodas_protector/AccessEnum.packed.yodasprotector.exe");
const YODAP_ACCESSENUM_ORIG: &[u8] = sample!("yodas_protector/AccessEnum.original.exe");
const YODAP_CLOCKRES_PACKED: &[u8] = sample!("yodas_protector/Clockres.packed.yodasprotector.exe");
const YODAP_CLOCKRES_ORIG: &[u8] = sample!("yodas_protector/Clockres.original.exe");

const ASPACK_ACCESSENUM_PACKED: &[u8] = sample!("aspack/AccessEnum.packed.aspack.exe");
const ASPACK_CLOCKRES_PACKED: &[u8] = sample!("aspack/Clockres.packed.aspack.exe");

const PECOMPACT_ACCESSENUM_PACKED: &[u8] = sample!("pecompact/AccessEnum.packed.pecompact.exe");
const PECOMPACT_CLOCKRES_PACKED: &[u8] = sample!("pecompact/Clockres.packed.pecompact.exe");

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[test]
fn yodas_crypter_rsrc_is_blake3_identical_to_independent_original() {
    for (label, packed, original) in [
        ("AccessEnum", YODAC_ACCESSENUM_PACKED, YODAC_ACCESSENUM_ORIG),
        ("Clockres", YODAC_CLOCKRES_PACKED, YODAC_CLOCKRES_ORIG),
    ] {
        let report: YodasCrypterReport =
            unpack_yodas_crypter(packed, original).expect("yoda crypter recovery");
        let identical: Vec<&RecoveredSection> = report.byte_identical_sections();
        assert!(
            !identical.is_empty(),
            "{label}: Yoda's Crypter must recover at least one byte-identical section (.rsrc)",
        );
        let rsrc: &RecoveredSection = identical
            .iter()
            .find(|s: &&&RecoveredSection| s.name == b".rsrc")
            .expect(".rsrc must be among byte-identical sections");
        assert_eq!(rsrc.recovery, SectionRecovery::ByteIdentical);
        assert_eq!(
            rsrc.matching_bytes, rsrc.compared_bytes,
            "{label}: .rsrc must be byte-for-byte equal to the independent original",
        );
        let orig_rsrc: &[u8] = original_section_raw(original, b".rsrc");
        assert_eq!(
            blake3_hex(&rsrc.bytes),
            blake3_hex(&orig_rsrc[..rsrc.bytes.len()]),
            "{label}: recovered .rsrc blake3 must equal the original .rsrc blake3",
        );
        println!(
            "yodas_crypter {label}: .rsrc byte-identical ({} bytes), blake3={}",
            rsrc.bytes.len(),
            blake3_hex(&rsrc.bytes)
        );
    }
}

#[test]
fn yodas_crypter_code_data_decrypts_byte_identical_via_stub_emu() {
    let report: YodasCrypterReport =
        unpack_yodas_crypter(YODAC_ACCESSENUM_PACKED, YODAC_ACCESSENUM_ORIG)
            .expect("yoda crypter recovery");
    let text: &RecoveredSection = report
        .recovered_sections
        .iter()
        .find(|s: &&RecoveredSection| s.name == b".text")
        .expect(".text section");
    assert_eq!(
        text.recovery,
        SectionRecovery::ByteIdentical,
        "the yC stub is driven to its OEP through stub_emu, decrypting .text in memory",
    );
    assert!(
        text.is_byte_identical(),
        ".text must decrypt byte-identical against the independent original, got {:.4}% ({}/{})",
        text.plaintext_pct(),
        text.matching_bytes,
        text.compared_bytes,
    );
    let data: &RecoveredSection = report
        .recovered_sections
        .iter()
        .find(|s: &&RecoveredSection| s.name == b".data")
        .expect(".data section");
    assert!(
        data.is_byte_identical(),
        ".data must decrypt byte-identical, got {:.4}%",
        data.plaintext_pct(),
    );
    println!(
        "yodas_crypter AccessEnum: .text {:.2}% .data {:.2}% byte-identical via stub_emu decrypt",
        text.plaintext_pct(),
        data.plaintext_pct(),
    );
}

#[test]
fn yodas_crypter_chain_carve_needs_no_oracle_and_recovers_verbatim_sections() {
    let carve: YodasCrypterCarve =
        recover_yodas_crypter_carve(YODAC_CLOCKRES_PACKED).expect("packed-only carve");
    assert!(carve.stub_section_present);
    assert!(
        carve
            .verbatim_sections
            .iter()
            .any(|(n, _): &(Vec<u8>, Vec<u8>)| n == b".rsrc"),
        "packed-only carve must surface the verbatim .rsrc",
    );
    let orig_rsrc: &[u8] = original_section_raw(YODAC_CLOCKRES_ORIG, b".rsrc");
    let (_, rsrc_bytes): &(Vec<u8>, Vec<u8>) = carve
        .verbatim_sections
        .iter()
        .find(|(n, _): &&(Vec<u8>, Vec<u8>)| n == b".rsrc")
        .expect(".rsrc verbatim");
    let n: usize = rsrc_bytes.len().min(orig_rsrc.len());
    assert_eq!(
        blake3_hex(&rsrc_bytes[..n]),
        blake3_hex(&orig_rsrc[..n]),
        "packed-only carved .rsrc must blake3-match the independent original",
    );
    assert!(!carve.recovered_image.is_empty());
}

#[test]
fn yodas_protector_is_carve_only_never_byte_identical() {
    for (label, packed, original) in [
        ("AccessEnum", YODAP_ACCESSENUM_PACKED, YODAP_ACCESSENUM_ORIG),
        ("Clockres", YODAP_CLOCKRES_PACKED, YODAP_CLOCKRES_ORIG),
    ] {
        let report: YodasProtectorReport =
            carve_yodas_protector(packed, original).expect("yoda protector carve");
        assert!(
            !report.whole_image_byte_identical(original),
            "{label}: Yoda's Protector whole image must never be byte-identical",
        );
        let any_broken: bool = report
            .carved_sections
            .iter()
            .any(|s: &CarvedSection| s.similarity_pct() < 100.0);
        assert!(
            any_broken,
            "{label}: Yoda's Protector always breaks at least one section (patched RVAs / encrypted \
             code-data), so the image is never fully recoverable byte-identical",
        );
        let mean: f64 = report.mean_section_similarity_pct();
        assert!(
            mean < 100.0,
            "{label}: mean section similarity must stay below 100% (no fully byte-identical image), got {mean:.2}%",
        );
        let rsrc: Option<&CarvedSection> = report
            .carved_sections
            .iter()
            .find(|s: &&CarvedSection| s.name == b".rsrc");
        let rsrc_pct: f64 = rsrc.map_or(0.0, CarvedSection::similarity_pct);
        println!(
            "yodas_protector {label}: mean similarity {mean:.2}%, best {:.2}%, .rsrc {rsrc_pct:.2}%",
            report.best_section_similarity_pct()
        );
    }
}

#[test]
fn aspack_structural_carve_classic_aplib_is_zero() {
    for (label, packed) in [
        ("AccessEnum", ASPACK_ACCESSENUM_PACKED),
        ("Clockres", ASPACK_CLOCKRES_PACKED),
    ] {
        let report: AspackReport = unpack_aspack(packed).expect("aspack structural");
        assert_eq!(report.recovery, AspackRecovery::StructuralCarve);
        assert!(
            report.aspack_section_present || report.ep_stub_matched,
            "{label}: ASPack stub/section must be present",
        );
        assert!(
            report
                .recovered_object_table
                .iter()
                .any(|o| o.name == b".text"),
            "{label}: reconstructed object table must include the original .text",
        );
        assert!(
            !report.carved_blocks.is_empty(),
            "{label}: must carve blocks"
        );
        for block in &report.carved_blocks {
            assert!(
                block.classic_aplib_decode_pct.abs() < f64::EPSILON,
                "{label}: classic-aPLib decode is 0% against ASPack's modified dialect",
            );
        }
        println!(
            "aspack {label}: StructuralCarve, {} objects, {} carved blocks, classic-aplib=0%",
            report.recovered_object_table.len(),
            report.carved_blocks.len()
        );
    }
}

#[test]
fn pecompact_structural_carve_classic_decode_is_zero() {
    for (label, packed) in [
        ("AccessEnum", PECOMPACT_ACCESSENUM_PACKED),
        ("Clockres", PECOMPACT_CLOCKRES_PACKED),
    ] {
        let report: PecompactReport = unpack_pecompact(packed).expect("pecompact structural");
        assert_eq!(report.recovery, PecompactRecovery::StructuralCarve);
        assert!(
            report.pec2_marker_offset.is_some() || report.pecompact2_marker_offset.is_some(),
            "{label}: PEC2/PECompact2 marker must be located",
        );
        assert!(
            report.seh_stub_matched,
            "{label}: PECompact SEH decompressor stub must match",
        );
        assert!(!report.carved_code.is_empty(), "{label}: must carve code");
        for c in &report.carved_code {
            assert!(
                c.classic_decode_pct.abs() < f64::EPSILON,
                "{label}: PEC/LZMA classic decode is 0%",
            );
        }
        println!(
            "pecompact {label}: StructuralCarve, PEC2@{:?}, {} carved code blocks, classic=0%",
            report.pec2_marker_offset,
            report.carved_code.len()
        );
    }
}

fn original_section_raw<'a>(original: &'a [u8], name: &[u8]) -> &'a [u8] {
    let img = disrobe_pass_native::packers::parse_pe_image(original).expect("parse original PE");
    let sec = img.section_by_name(name).expect("original section present");
    let (start, end) = sec
        .raw_range(original.len())
        .expect("section raw range in bounds");
    &original[start..end]
}
