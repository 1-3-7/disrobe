#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use disrobe_pass_native::packers::aspack_phase2::{
    AspackPhaseTwoOutput, unpack_aspack_phase2_emulated,
};
use disrobe_pass_native::packers::pecompact_phase2::{
    PecompactPhaseTwoOutput, unpack_pecompact_phase2_emulated,
};
use packer_fixture::{PackerFixture, enforce_something_was_graded, load_fixture};

fn decoder_for(family: &str) -> &'static str {
    if family == "aspack" {
        "ASPack"
    } else {
        "PECompact"
    }
}

fn corpus(family: &str, name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: decoder_for(family),
        family,
        name,
    })
}

fn assert_aspack(label: &str, packed_n: &str, orig_n: &str, content_floor: f64, whole_floor: f64) {
    let Some(packed): Option<Vec<u8>> = corpus("aspack", packed_n) else {
        eprintln!("skip aspack {label}: {packed_n} missing");
        return;
    };
    let Some(orig): Option<Vec<u8>> = corpus("aspack", orig_n) else {
        eprintln!("skip aspack {label}: {orig_n} missing");
        return;
    };
    let out: AspackPhaseTwoOutput =
        unpack_aspack_phase2_emulated(&packed, Some(&orig)).expect("aspack phase2 must succeed");
    let content: f64 = out.content_recovery_pct.unwrap_or(0.0);
    let whole: f64 = out.whole_image_recovery_pct.unwrap_or(0.0);
    println!(
        "ASPACK {label}: oep={:?} content={content:.2}% whole={whole:.2}% calls={}",
        out.oep_estimate.map(|v: u64| format!("{v:#x}")),
        out.host_calls.len()
    );
    assert!(
        out.oep_estimate.is_some(),
        "{label}: emulation must reach the OEP transfer, not stall in the stub",
    );
    assert!(
        content > 0.0,
        "{label}: emulated byte-recovery MUST beat the 1st-pass structural 0%",
    );
    assert!(
        content >= content_floor,
        "{label}: ASPack content (.text/.rdata/.data/.rsrc) recovery must be >= {content_floor:.1}%; got {content:.2}%",
    );
    assert!(
        whole >= whole_floor,
        "{label}: ASPack whole-image recovery must be >= {whole_floor:.1}%; got {whole:.2}%",
    );
}

fn assert_pecompact(
    label: &str,
    packed_n: &str,
    orig_n: &str,
    content_floor: f64,
    whole_floor: f64,
) {
    let Some(packed): Option<Vec<u8>> = corpus("pecompact", packed_n) else {
        eprintln!("skip pecompact {label}: {packed_n} missing");
        return;
    };
    let Some(orig): Option<Vec<u8>> = corpus("pecompact", orig_n) else {
        eprintln!("skip pecompact {label}: {orig_n} missing");
        return;
    };
    let out: PecompactPhaseTwoOutput = unpack_pecompact_phase2_emulated(&packed, Some(&orig))
        .expect("pecompact phase2 must succeed");
    let content: f64 = out.content_recovery_pct.unwrap_or(0.0);
    let whole: f64 = out.whole_image_recovery_pct.unwrap_or(0.0);
    println!(
        "PECOMPACT {label}: oep={:?} seh={} content={content:.2}% whole={whole:.2}% calls={}",
        out.oep_estimate.map(|v: u64| format!("{v:#x}")),
        out.seh_dispatched,
        out.host_calls.len()
    );
    assert!(
        out.seh_dispatched,
        "{label}: PECompact must transfer into its decompressor via SEH dispatch",
    );
    assert!(
        out.oep_estimate.is_some(),
        "{label}: emulation must reach the OEP transfer, not stall in the stub",
    );
    assert!(
        content > 0.0,
        "{label}: emulated byte-recovery MUST beat the 1st-pass structural 0%",
    );
    assert!(
        content >= content_floor,
        "{label}: PECompact content (.text/.rdata/.data) recovery must be >= {content_floor:.1}%; got {content:.2}%",
    );
    assert!(
        whole >= whole_floor,
        "{label}: PECompact whole-image recovery must be >= {whole_floor:.1}%; got {whole:.2}%",
    );
}

#[test]
fn aspack_clockres_byte_recovery() {
    assert_aspack(
        "Clockres",
        "Clockres.packed.aspack.exe",
        "Clockres.original.exe",
        99.3,
        94.8,
    );
}

#[test]
fn aspack_accessenum_byte_recovery() {
    assert_aspack(
        "AccessEnum",
        "AccessEnum.packed.aspack.exe",
        "AccessEnum.original.exe",
        97.5,
        92.3,
    );
}

#[test]
fn pecompact_clockres_byte_recovery() {
    assert_pecompact(
        "Clockres",
        "Clockres.packed.pecompact.exe",
        "Clockres.original.exe",
        99.3,
        92.4,
    );
}

#[test]
fn pecompact_accessenum_byte_recovery() {
    assert_pecompact(
        "AccessEnum",
        "AccessEnum.packed.pecompact.exe",
        "AccessEnum.original.exe",
        95.6,
        90.5,
    );
}

#[test]
fn emulated_beats_structural_zero_on_all_fixtures() {
    let aspack: &[(&str, &str, &str)] = &[
        (
            "Clockres",
            "Clockres.packed.aspack.exe",
            "Clockres.original.exe",
        ),
        (
            "AccessEnum",
            "AccessEnum.packed.aspack.exe",
            "AccessEnum.original.exe",
        ),
    ];
    let pecompact: &[(&str, &str, &str)] = &[
        (
            "Clockres",
            "Clockres.packed.pecompact.exe",
            "Clockres.original.exe",
        ),
        (
            "AccessEnum",
            "AccessEnum.packed.pecompact.exe",
            "AccessEnum.original.exe",
        ),
    ];
    let mut aspack_tested: usize = 0;
    for (label, p, o) in aspack {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus("aspack", p), corpus("aspack", o))
        else {
            continue;
        };
        let out: AspackPhaseTwoOutput =
            unpack_aspack_phase2_emulated(&packed, Some(&orig)).expect("aspack");
        aspack_tested += 1;
        assert!(
            out.content_recovery_pct.unwrap_or(0.0) > 50.0,
            "aspack {label}: emulated content recovery must materially beat 0%",
        );
    }
    let mut pecompact_tested: usize = 0;
    for (label, p, o) in pecompact {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus("pecompact", p), corpus("pecompact", o))
        else {
            continue;
        };
        let out: PecompactPhaseTwoOutput =
            unpack_pecompact_phase2_emulated(&packed, Some(&orig)).expect("pecompact");
        pecompact_tested += 1;
        assert!(
            out.content_recovery_pct.unwrap_or(0.0) > 50.0,
            "pecompact {label}: emulated content recovery must materially beat 0%",
        );
    }
    enforce_something_was_graded("ASPack", aspack_tested, "aspack");
    enforce_something_was_graded("PECompact", pecompact_tested, "pecompact");
}

fn assert_iat_byte_identical_to_original(
    label: &str,
    recovered: &[u8],
    orig: &[u8],
) -> (usize, usize) {
    use disrobe_pass_native::packers::parse_pe_image;
    use disrobe_pass_native::packers::pe_sections::{PeImage, read_u32};
    let img: PeImage = parse_pe_image(orig).expect("orig pe");
    let iat_dir = img.data_directories.get(12).copied();
    let Some(iat) = iat_dir else {
        return (0, 0);
    };
    if iat.virtual_address == 0 || iat.size == 0 {
        return (0, 0);
    }
    let mut matched: usize = 0;
    let mut total: usize = 0;
    for slot in 0..(iat.size / 4) {
        let rva: u32 = iat.virtual_address + slot * 4;
        let rec_v: u32 = read_u32(recovered, rva as usize).unwrap_or(0xffff_ffff);
        let raw_off: usize = rva_to_raw(&img, rva);
        let orig_v: u32 = read_u32(orig, raw_off).unwrap_or(0xdead_beef);
        if orig_v == 0 {
            continue;
        }
        total += 1;
        if rec_v == orig_v {
            matched += 1;
        }
    }
    println!("{label}: IAT slots byte-identical to original {matched}/{total}");
    (matched, total)
}

fn rva_to_raw(img: &disrobe_pass_native::packers::pe_sections::PeImage, rva: u32) -> usize {
    for s in &img.sections {
        let span: u32 = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
            return (s.raw_pointer + (rva - s.virtual_address)) as usize;
        }
    }
    usize::MAX / 2
}

#[test]
fn aspack_iat_reconstructed_byte_identical() {
    let cases: &[(&str, &str)] = &[
        ("Clockres.packed.aspack.exe", "Clockres.original.exe"),
        ("AccessEnum.packed.aspack.exe", "AccessEnum.original.exe"),
    ];
    let mut tested: usize = 0;
    for (packed_n, orig_n) in cases {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus("aspack", packed_n), corpus("aspack", orig_n))
        else {
            continue;
        };
        let out: AspackPhaseTwoOutput =
            unpack_aspack_phase2_emulated(&packed, Some(&orig)).expect("aspack");
        let (matched, total): (usize, usize) =
            assert_iat_byte_identical_to_original(packed_n, &out.recovered_memory_image, &orig);
        assert!(total >= 64, "{packed_n}: IAT must hold a real import table");
        assert!(
            matched * 100 >= total * 98,
            "{packed_n}: reconstructed IAT must be >=98% byte-identical to the original on-disk IAT; got {matched}/{total}",
        );
        tested += 1;
    }
    assert!(
        tested > 0,
        "no aspack fixtures present for IAT verification"
    );
}

#[test]
fn aspack_import_descriptors_match_original_bytes() {
    use disrobe_pass_native::packers::{parse_pe_image, section_recovery::build_loaded_image};

    let cases: [(&str, &str, f64, f64); 2] = [
        (
            "AccessEnum.packed.aspack.exe",
            "AccessEnum.original.exe",
            97.67,
            92.42,
        ),
        (
            "Clockres.packed.aspack.exe",
            "Clockres.original.exe",
            99.42,
            94.88,
        ),
    ];
    for (packed_name, original_name, content_floor, whole_floor) in cases {
        let packed: Vec<u8> = corpus("aspack", packed_name).expect("packed ASPack fixture");
        let original: Vec<u8> = corpus("aspack", original_name).expect("original ASPack fixture");
        let output: AspackPhaseTwoOutput =
            unpack_aspack_phase2_emulated(&packed, Some(&original)).expect("ASPack phase two");
        let content: f64 = output.content_recovery_pct.expect("content recovery score");
        let whole: f64 = output
            .whole_image_recovery_pct
            .expect("whole-image recovery score");
        println!("{packed_name}: content={content:.8}% whole={whole:.8}%");
        assert!(
            content >= content_floor,
            "{packed_name}: content recovery must be at least {content_floor:.2}%; got {content:.8}%",
        );
        assert!(
            whole >= whole_floor,
            "{packed_name}: whole-image recovery must be at least {whole_floor:.2}%; got {whole:.8}%",
        );
        let original_image = parse_pe_image(&original).expect("original PE");
        let recovered_image = parse_pe_image(&output.recovered_memory_image).expect("recovered PE");
        let original_memory: Vec<u8> =
            build_loaded_image(&original, output.recovered_memory_image.len())
                .expect("original loaded image");
        let original_dir = original_image.data_directories[1];
        let recovered_dir = recovered_image.data_directories[1];
        assert_eq!(
            recovered_dir.virtual_address, original_dir.virtual_address,
            "{packed_name}: import directory RVA",
        );
        assert_eq!(
            recovered_dir.size, original_dir.size,
            "{packed_name}: import directory size",
        );
        let import_rva: usize = usize::try_from(original_dir.virtual_address)
            .expect("import directory RVA must fit usize");
        let import_size: usize =
            usize::try_from(original_dir.size).expect("import directory size must fit usize");
        let recovered_end: usize = import_rva
            .checked_add(import_size)
            .expect("recovered import directory range");
        assert!(
            recovered_end <= original_memory.len(),
            "{packed_name}: original import directory must fit loaded image",
        );
        assert!(
            recovered_end <= output.recovered_memory_image.len(),
            "{packed_name}: recovered import directory must fit memory image",
        );
        assert_eq!(
            &output.recovered_memory_image[import_rva..recovered_end],
            &original_memory[import_rva..recovered_end],
            "{packed_name}: import descriptor bytes must match the original image",
        );
    }
}

#[test]
fn pecompact_iat_reconstructed_byte_identical() {
    let cases: &[(&str, &str)] = &[
        ("Clockres.packed.pecompact.exe", "Clockres.original.exe"),
        ("AccessEnum.packed.pecompact.exe", "AccessEnum.original.exe"),
    ];
    let mut tested: usize = 0;
    for (packed_n, orig_n) in cases {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus("pecompact", packed_n), corpus("pecompact", orig_n))
        else {
            continue;
        };
        let out: PecompactPhaseTwoOutput =
            unpack_pecompact_phase2_emulated(&packed, Some(&orig)).expect("pecompact");
        let (matched, total): (usize, usize) =
            assert_iat_byte_identical_to_original(packed_n, &out.recovered_memory_image, &orig);
        assert!(total >= 64, "{packed_n}: IAT must hold a real import table");
        assert!(
            matched * 100 >= total * 98,
            "{packed_n}: reconstructed IAT must be >=98% byte-identical to the original on-disk IAT; got {matched}/{total}",
        );
        tested += 1;
    }
    assert!(
        tested > 0,
        "no pecompact fixtures present for IAT verification"
    );
}

#[test]
fn aspack_section_report_isolates_residual_to_non_text() {
    use disrobe_pass_native::packers::section_recovery::{GranuleRecovery, SectionRole};
    let cases: &[(&str, &str)] = &[
        ("Clockres.packed.aspack.exe", "Clockres.original.exe"),
        ("AccessEnum.packed.aspack.exe", "AccessEnum.original.exe"),
    ];
    let mut tested: usize = 0;
    for (packed_n, orig_n) in cases {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus("aspack", packed_n), corpus("aspack", orig_n))
        else {
            continue;
        };
        let out: AspackPhaseTwoOutput =
            unpack_aspack_phase2_emulated(&packed, Some(&orig)).expect("aspack");
        let report = out.section_report.as_ref().expect("section report present");
        let standalone: f64 = out.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (report.content_recovery_pct() - standalone).abs() < 0.01,
            "{packed_n}: report content {:.4}% must agree with standalone {standalone:.4}%",
            report.content_recovery_pct(),
        );
        let text: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".text")
            .expect(".text row present");
        assert_eq!(text.role, SectionRole::Content);
        assert!(
            text.is_byte_identical(),
            "{packed_n}: .text must recover byte-identically ({}/{} = {:.2}%)",
            text.matching,
            text.compared,
            text.recovery_pct(),
        );
        let worst = report.mismatching_content_sections();
        assert!(
            !worst.iter().any(|s: &&GranuleRecovery| s.name == ".text"),
            "{packed_n}: .text must never appear in the mismatch list",
        );
        tested += 1;
    }
    enforce_something_was_graded("ASPack", tested, "aspack");
}
