#![allow(clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::aot::{AotReport, AotSection, ReadyToRunHeader, detect};

fn real_sample() -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(std::env::var_os("DISROBE_AOT_SAMPLE")?);
    std::fs::read(path).ok()
}

#[test]
fn a_real_native_aot_image_is_recognized_by_its_ready_to_run_header() {
    let Some(image): Option<Vec<u8>> = real_sample() else {
        println!("SKIP: set DISROBE_AOT_SAMPLE to a native aot executable to run this");
        return;
    };
    let report: AotReport = detect(&image);
    let header: &ReadyToRunHeader = report
        .ready_to_run
        .as_ref()
        .expect("a native aot image must yield a ready-to-run header");
    assert!(
        report.is_native_aot,
        "the header alone must be enough to recognize the image"
    );
    assert!(
        header.major_version > 0 && header.major_version <= 64,
        "the recovered version must be plausible, got {}",
        header.major_version
    );
    assert!(
        header.sections.len() >= 8,
        "a real image carries a populated section table, got {}",
        header.sections.len()
    );
    assert!(
        header.sections.iter().any(|s: &AotSection| !s.is_empty()),
        "at least one section must span bytes"
    );
    for section in &header.sections {
        assert!(
            section.end_rva >= section.start_rva,
            "section {} runs backwards",
            section.id
        );
        assert!(
            usize::try_from(section.end_rva).unwrap_or(usize::MAX) <= image.len() * 2,
            "section {} lands implausibly far outside the image",
            section.id
        );
    }
    let signature: [u8; 4] = disrobe_pass_dotnet::aot::READY_TO_RUN_SIGNATURE.to_le_bytes();
    let first_raw_hit: usize = image
        .windows(4)
        .position(|w: &[u8]| w == signature)
        .expect("the signature must occur at least once");
    assert!(
        first_raw_hit < usize::try_from(header.file_offset).unwrap_or(usize::MAX),
        "this image carries an earlier signature match inside code at 0x{first_raw_hit:x}; \
         accepting it would mean the checks past the signature do nothing"
    );
    println!(
        "recovered ready-to-run header at 0x{:x}: version {}.{}, {} sections \
         (rejected an earlier signature match at 0x{:x})",
        header.file_offset,
        header.major_version,
        header.minor_version,
        header.sections.len(),
        first_raw_hit
    );
}

#[test]
fn the_pass_entry_point_reaches_a_verdict_on_a_real_native_aot_image() {
    let Some(image): Option<Vec<u8>> = real_sample() else {
        println!("SKIP: set DISROBE_AOT_SAMPLE to a native aot executable to run this");
        return;
    };
    match disrobe_pass_dotnet::pass::analyze(&image) {
        Ok(summary) => println!("pass reached a verdict: native_aot={}", summary.native_aot),
        Err(error) => panic!(
            "the pass refuses a real native aot image instead of reporting it: {error}. \
             detection that no entry point can reach is not a capability"
        ),
    }
}

#[test]
fn a_real_native_aot_image_yields_type_names_the_source_declared() {
    let Some(image): Option<Vec<u8>> = real_sample() else {
        println!("SKIP: set DISROBE_AOT_SAMPLE to a native aot executable to run this");
        return;
    };
    let report: AotReport = detect(&image);
    let names: &[String] = &report.recovered_names;
    assert!(
        names.len() >= 100,
        "a real image carries hundreds of metadata names, got {}",
        names.len()
    );
    for declared in ["Widget", "IGauge", "Thermometer"] {
        assert!(
            names.iter().any(|n: &String| n == declared),
            "the probe source declares `{declared}` and the metadata still carries it, \
             so the reader must surface it; recovered {} names",
            names.len()
        );
    }
    assert!(
        names.windows(2).all(|w: &[String]| w[0] < w[1]),
        "names must be sorted and deduplicated so a caller can search them"
    );
    println!(
        "recovered {} unique metadata names from a stripped native aot image",
        names.len()
    );
}

#[test]
fn the_metadata_length_prefix_decodes_the_documented_widths() {
    use disrobe_pass_dotnet::aot::decode_metadata_unsigned;
    assert_eq!(decode_metadata_unsigned(&[0x0c], 0), Some((6, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x16], 0), Some((11, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x1e], 0), Some((15, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x00], 0), Some((0, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x01, 0x01], 0), Some((64, 2)));
    assert_eq!(decode_metadata_unsigned(&[0x01], 0), None);
    assert_eq!(decode_metadata_unsigned(&[], 0), None);
    assert_eq!(decode_metadata_unsigned(&[0x0f], 0), None);
}

#[test]
fn the_name_needles_alone_do_not_recognize_a_real_image() {
    let Some(image): Option<Vec<u8>> = real_sample() else {
        println!("SKIP: set DISROBE_AOT_SAMPLE to a native aot executable to run this");
        return;
    };
    let report: AotReport = detect(&image);
    assert!(
        report.recovered_symbols.is_empty(),
        "this records what the shipped needles actually match on a real image: {:?}",
        report.recovered_symbols
    );
}
