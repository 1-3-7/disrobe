#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::packer_fixture;

use disrobe_core::chain::{ChildArtifact, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_native::chain_detector::PACKER_PASS;
use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::packers::section_recovery::build_loaded_image;
use disrobe_pass_native::packers::{Detection, Packer, detect};
use packer_fixture::{PackerFixture, require_committed};

fn decoder_for(family: &str) -> &'static str {
    if family == "aspack" {
        "ASPack"
    } else {
        "PECompact"
    }
}

fn corpus(family: &str, name: &str) -> Vec<u8> {
    require_committed(PackerFixture {
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
    let packed: Vec<u8> = corpus(family, packed_n);
    let orig: Vec<u8> = corpus(family, orig_n);

    let detections: Vec<Detection> = detect(&packed);
    assert!(
        detections.iter().any(|d: &Detection| d.packer == packer),
        "{packed_n}: detect must flag {}",
        packer.label()
    );

    let artifact: Artifact = Artifact::new(Rung::Raw, packed, [0u8; 32]);
    let children: Vec<ChildArtifact> = PACKER_PASS
        .extract_children(&artifact)
        .unwrap_or_else(|error| panic!("{packed_n}: the auto chain must unpack: {error}"));
    let recovered: &[u8] = &children
        .iter()
        .find(|child: &&ChildArtifact| child.handle.relative_path == "recovered-image.bin")
        .unwrap_or_else(|| {
            panic!(
                "{packed_n}: the auto chain must surface a recovered image for {}",
                packer.label()
            )
        })
        .bytes;

    assert_eq!(
        recovered.get(..2),
        Some(&b"MZ"[..]),
        "{packed_n}: the recovered image must open with a real PE header"
    );
    assert!(
        recovered.len() > 0x8000,
        "{packed_n}: surfaced image must be a full memory image, got {} bytes",
        recovered.len()
    );

    let (matched, total): (usize, usize) = text_recovery_vs_original(recovered, &orig);
    assert!(total > 0, "{packed_n}: original .text must be locatable");
    println!(
        "{family} {packed_n}: surfaced .text vs ORIGINAL {matched}/{total} = {:.2}%",
        100.0 * matched as f64 / total as f64
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
