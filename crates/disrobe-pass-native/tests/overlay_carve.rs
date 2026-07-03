#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fs;
use std::path::PathBuf;

use disrobe_binfmt::ExtractionQuota;
use disrobe_pass_native::packers::overlay::route_overlay_archive;
use disrobe_pass_native::packers::pe_sections::parse_pe_image;
use disrobe_pass_native::{
    OverlayArchiveKind, OverlayClass, PeOverlayReport, analyze_pe_overlay, carve_pe_overlay,
    normalize_pe,
};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push(rel);
    fs::read(&p).ok()
}

fn require(rel: &str) -> Vec<u8> {
    corpus(rel).unwrap_or_else(|| panic!("committed corpus sample missing: corpus/{rel}"))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn known_stored_zip(entry_name: &str, payload: &[u8]) -> Vec<u8> {
    let name: &[u8] = entry_name.as_bytes();
    let crc: u32 = crc32(payload);
    let size: u32 = payload.len() as u32;
    let name_len: u16 = name.len() as u16;
    let mut out: Vec<u8> = Vec::new();

    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(payload);

    let central_offset: u32 = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);

    let central_size: u32 = out.len() as u32 - central_offset;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn real_pe_plus_known_tail_carves_byte_identically() {
    let original: Vec<u8> = require("native/packers/upx/hello.original.exe");
    let clean_report: PeOverlayReport = analyze_pe_overlay(&original).expect("analyze original");
    assert_eq!(
        clean_report.overlay_len, 0,
        "the chosen base fixture must itself be overlay-free"
    );
    let real_image_end: u64 = clean_report.image_end;
    assert_eq!(real_image_end, original.len() as u64);

    let payload: &[u8] = b"disrobe-overlay-oracle-known-zip-entry-contents";
    let zip: Vec<u8> = known_stored_zip("hello.txt", payload);
    let padding: Vec<u8> = vec![0u8; 2048];

    let mut tail: Vec<u8> = Vec::new();
    tail.extend_from_slice(&zip);
    tail.extend_from_slice(&padding);

    let mut inflated: Vec<u8> = original.clone();
    inflated.extend_from_slice(&tail);

    let report: PeOverlayReport = analyze_pe_overlay(&inflated).expect("analyze inflated");

    assert_eq!(
        report.image_end, real_image_end,
        "image_end must be computed exactly to the real PE's section end"
    );
    assert_eq!(report.overlay_offset, real_image_end);
    assert_eq!(report.overlay_len, tail.len() as u64);
    assert_eq!(report.file_len, inflated.len() as u64);

    let carved: &[u8] = carve_pe_overlay(&inflated).expect("carve overlay");
    assert_eq!(
        carved,
        &tail[..],
        "carved overlay bytes must equal the exact known appended tail"
    );

    assert!(
        report.has_appended_archive,
        "the appended zip must be classified as an archive: {:?}",
        report.segments
    );
    let saw_zip: bool = report.segments.iter().any(|s| {
        matches!(
            s.class,
            OverlayClass::AppendedArchive {
                archive: OverlayArchiveKind::Zip,
                ..
            }
        )
    });
    assert!(saw_zip, "zip segment missing: {:?}", report.segments);
    let saw_padding: bool = report
        .segments
        .iter()
        .any(|s| matches!(s.class, OverlayClass::ConstantPadding { fill_byte: 0, .. }));
    assert!(
        saw_padding,
        "the trailing zero padding must be classified as constant-padding: {:?}",
        report.segments
    );

    let normalized: Vec<u8> = normalize_pe(&inflated).expect("normalize");
    assert_eq!(
        normalized.len(),
        real_image_end as usize,
        "normalized PE must shed the entire overlay"
    );
    parse_pe_image(&normalized).expect("normalized PE must re-parse clean");

    let original_image = parse_pe_image(&original).expect("parse original");
    let normalized_image = parse_pe_image(&normalized).expect("parse normalized");
    assert_eq!(
        original_image.sections.len(),
        normalized_image.sections.len()
    );
    for (orig, norm) in original_image
        .sections
        .iter()
        .zip(normalized_image.sections.iter())
    {
        let (os, oe): (usize, usize) = orig
            .raw_range(original.len())
            .expect("original section range");
        let (ns, ne): (usize, usize) = norm
            .raw_range(normalized.len())
            .expect("normalized section range");
        assert_eq!(
            &original[os..oe],
            &normalized[ns..ne],
            "section {} raw bytes must be byte-identical after normalization",
            String::from_utf8_lossy(orig.name_trimmed())
        );
    }

    let tempdir: tempfile::TempDir = tempfile::tempdir().expect("create overlay temp dir");
    let out_dir: PathBuf = tempdir.path().to_path_buf();
    let extraction = route_overlay_archive(&inflated, &out_dir, ExtractionQuota::default_safe())
        .expect("route overlay archive")
        .expect("overlay must route into the container layer");
    let extracted_entry = extraction
        .entries
        .iter()
        .find(|e| e.name.ends_with("hello.txt"))
        .expect("the known zip entry must be extracted");
    let disk: &PathBuf = extracted_entry
        .disk_path
        .as_ref()
        .expect("extracted entry must be written to disk");
    let recovered: Vec<u8> = fs::read(disk).expect("read extracted entry");
    assert_eq!(
        recovered, payload,
        "the container layer must recover the exact known zip-entry contents"
    );
}

#[test]
fn real_signed_pe_splits_overlay_into_authenticode() {
    let signed: Vec<u8> = require("native/packers/aspack/AccessEnum.original.exe");
    let report: PeOverlayReport = analyze_pe_overlay(&signed).expect("analyze signed pe");

    assert_eq!(report.image_end, 167_936, "AccessEnum section end");
    assert_eq!(report.file_len, signed.len() as u64);
    assert_eq!(
        report.overlay_len,
        signed.len() as u64 - 167_936,
        "overlay = file_len - image_end"
    );

    let carved: &[u8] = carve_pe_overlay(&signed).expect("carve");
    assert_eq!(
        carved,
        &signed[167_936..],
        "carved overlay must equal bytes after image_end"
    );

    let auth = report
        .segments
        .iter()
        .find(|s| matches!(s.class, OverlayClass::Authenticode { .. }))
        .expect("the WIN_CERTIFICATE in the overlay must be classified as Authenticode");
    if let OverlayClass::Authenticode {
        declared_length,
        revision,
        length,
        ..
    } = auth.class
    {
        assert_eq!(declared_length, 6968, "WIN_CERTIFICATE dwLength");
        assert_eq!(revision, 0x0200, "WIN_CERT_REVISION_2_0");
        assert_eq!(
            length, 6968,
            "cert occupies the full security-directory span"
        );
    }
    assert_eq!(
        auth.offset, 168_000,
        "cert begins at the security-directory file offset"
    );

    let normalized: Vec<u8> = normalize_pe(&signed).expect("normalize signed pe");
    assert_eq!(normalized.len(), 167_936);
    parse_pe_image(&normalized).expect("normalized signed PE must re-parse clean");

    let original_image = parse_pe_image(&signed).expect("parse signed");
    let normalized_image = parse_pe_image(&normalized).expect("parse normalized");
    for (orig, norm) in original_image
        .sections
        .iter()
        .zip(normalized_image.sections.iter())
    {
        let (os, oe): (usize, usize) = orig.raw_range(signed.len()).expect("orig range");
        let (ns, ne): (usize, usize) = norm.raw_range(normalized.len()).expect("norm range");
        assert_eq!(
            &signed[os..oe],
            &normalized[ns..ne],
            "section bytes must survive normalization byte-for-byte"
        );
    }
}

#[test]
fn inflation_ratio_reflects_padding() {
    let original: Vec<u8> = require("native/packers/upx/hello.original.exe");
    let mut inflated: Vec<u8> = original.clone();
    inflated.extend(std::iter::repeat_n(0u8, original.len()));
    let report: PeOverlayReport = analyze_pe_overlay(&inflated).expect("analyze");
    assert!(
        (report.inflation_ratio - 2.0).abs() < 1e-6,
        "doubling the file with padding must yield ~2.0x inflation, got {}",
        report.inflation_ratio
    );
    assert_eq!(report.segments.len(), 1);
    assert!(matches!(
        report.segments[0].class,
        OverlayClass::ConstantPadding { fill_byte: 0, .. }
    ));
}
