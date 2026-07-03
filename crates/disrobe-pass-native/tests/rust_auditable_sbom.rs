#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::io::Read;

use disrobe_pass_native::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use disrobe_pass_native::{AuditableSbom, parse_auditable_section};

const REAL_AUDITABLE: &[u8] = include_bytes!("../../../corpus/native/formats/hello.auditable.exe");

#[test]
fn auditable_section_parses_minimal_json_payload() {
    let blob: &[u8] = br#"{"packages":[{"name":"tokio","version":"1.40.0","source":"crates.io"}]}"#;
    let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
    assert_eq!(sbom.crates.len(), 1);
    assert_eq!(sbom.crates[0].name, "tokio");
}

fn inflate_zlib(compressed: &[u8]) -> Vec<u8> {
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(compressed);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).expect("zlib inflate .dep-v0");
    out
}

#[test]
fn real_auditable_embedded_binary_round_trip() {
    let image: PeImage = parse_pe_image(REAL_AUDITABLE).expect("parse auditable PE");
    let section: &PeSection = image
        .section_by_name(b".dep-v0")
        .expect("cargo-auditable embeds the SBOM in a .dep-v0 section");
    let (start, end): (usize, usize) = section
        .raw_range(REAL_AUDITABLE.len())
        .expect(".dep-v0 raw range must lie inside the image");
    let raw: &[u8] = &REAL_AUDITABLE[start..end];
    assert_eq!(
        &raw[..2],
        &[0x78, 0x9C],
        "cargo-auditable stores the SBOM as a zlib stream (0x789c)"
    );

    let json: Vec<u8> = inflate_zlib(raw);
    let sbom: AuditableSbom = parse_auditable_section(&json).expect("parse real .dep-v0 SBOM");
    assert!(
        sbom.crates.iter().any(|c| c.name == "adler2"),
        "the real embedded SBOM must list the adler2 dependency; got {:?}",
        sbom.crates
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<&str>>()
    );
    assert!(
        sbom.crates
            .iter()
            .any(|c| c.name == "disrobe_audit_fixture"),
        "the SBOM must list the root crate too"
    );
    let adler: &disrobe_pass_native::AuditableCrate = sbom
        .crates
        .iter()
        .find(|c| c.name == "adler2")
        .expect("adler2 present");
    assert!(
        !adler.version.is_empty() && adler.version.starts_with('2'),
        "the dependency version must be recovered (adler2 2.x); got {:?}",
        adler.version
    );
    assert!(
        REAL_AUDITABLE.len() < 256 * 1024,
        "fixture under 256KB budget"
    );
}
