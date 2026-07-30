#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::packers::section_recovery::build_loaded_image;
use disrobe_pass_native::packers::{
    Detection, Packer, RecoveredImage, RecoveryOracle, detect, recover_detected,
};
use packer_fixture::{PackerFixture, load_fixture};

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

fn text_recovery_vs_original(recovered: &[u8], original: &[u8]) -> (usize, usize) {
    let img: PeImage = parse_pe_image(original).expect("orig pe");
    let cap: usize = img.size_of_image as usize;
    let baseline: Vec<u8> = build_loaded_image(original, cap).expect("baseline");
    let Some(text) = img.sections.iter().find(|s| s.name_trimmed() == b".text") else {
        return (0, 0);
    };
    let off: usize = text.virtual_address as usize;
    let span_end: usize = (off + text.virtual_size as usize)
        .min(recovered.len())
        .min(baseline.len());
    let mut matching: usize = 0;
    let mut total: usize = 0;
    for j in off..span_end {
        total += 1;
        if recovered[j] == baseline[j] {
            matching += 1;
        }
    }
    (matching, total)
}

fn assert_auto_surface(
    family: &str,
    packer: Packer,
    packed_n: &str,
    orig_n: &str,
    text_floor_pct: u64,
) {
    let Some(packed): Option<Vec<u8>> = corpus(family, packed_n) else {
        eprintln!("skip {family} {packed_n}: missing");
        return;
    };
    let Some(orig): Option<Vec<u8>> = corpus(family, orig_n) else {
        eprintln!("skip {family} {orig_n}: missing");
        return;
    };

    let detections: Vec<Detection> = detect(&packed);
    assert!(
        detections.iter().any(|d: &Detection| d.packer == packer),
        "{packed_n}: detect must flag {}",
        packer.label()
    );

    let surfaced: Vec<RecoveredImage> = recover_detected(&packed, &detections);
    let recovered: &RecoveredImage = surfaced
        .iter()
        .find(|r: &&RecoveredImage| r.packer == packer.label())
        .unwrap_or_else(|| {
            panic!(
                "{packed_n}: auto path must surface an oracle-gated recovered image for {}",
                packer.label()
            )
        });

    assert_eq!(
        recovered.oracle,
        RecoveryOracle::NestedPeMagic,
        "{packed_n}: recovery must be gated by a real nested PE header"
    );
    assert!(
        recovered.recovered_len > 0x8000,
        "{packed_n}: surfaced image must be a full memory image, got {} bytes",
        recovered.recovered_len
    );

    let (matched, total): (usize, usize) = text_recovery_vs_original(&recovered.image, &orig);
    assert!(total > 0, "{packed_n}: original .text must be locatable");
    println!(
        "{family} {packed_n}: surfaced .text vs ORIGINAL {matched}/{total} = {:.2}% (note: {})",
        100.0 * matched as f64 / total as f64,
        recovered.note
    );
    assert!(
        (matched as u64) * 100 >= total as u64 * text_floor_pct,
        "{packed_n}: surfaced .text must recover >= {text_floor_pct}% vs the ORIGINAL pre-pack \
         binary; got {matched}/{total}",
    );
}

#[test]
fn aspack_clockres_auto_surfaces_recovered_image() {
    assert_auto_surface(
        "aspack",
        Packer::AsPack,
        "Clockres.packed.aspack.exe",
        "Clockres.original.exe",
        99,
    );
}

#[test]
fn aspack_accessenum_auto_surfaces_recovered_image() {
    assert_auto_surface(
        "aspack",
        Packer::AsPack,
        "AccessEnum.packed.aspack.exe",
        "AccessEnum.original.exe",
        97,
    );
}

#[test]
fn pecompact_clockres_auto_surfaces_recovered_image() {
    assert_auto_surface(
        "pecompact",
        Packer::PeCompact,
        "Clockres.packed.pecompact.exe",
        "Clockres.original.exe",
        99,
    );
}

#[test]
fn pecompact_accessenum_auto_surfaces_recovered_image() {
    assert_auto_surface(
        "pecompact",
        Packer::PeCompact,
        "AccessEnum.packed.pecompact.exe",
        "AccessEnum.original.exe",
        95,
    );
}
