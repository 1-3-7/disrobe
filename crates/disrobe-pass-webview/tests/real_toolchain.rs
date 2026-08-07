#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_binfmt::{ContainerKind, ExtractedEntry, ExtractionResult, extract_to};
use disrobe_pass_webview::{
    CarveReport, Compression, Error, IntegrityStatus, RecoveredAsset, WebviewFamily, carve_report,
};

fn corpus_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.push("corpus");
    root.push("webview");
    root
}

fn read_fixture(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(relative);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing corpus fixture {}: {e}; the grade cannot run without the real build",
            path.display()
        )
    })
}

fn read_tree(relative: &str, key_prefix: &str) -> BTreeMap<String, Vec<u8>> {
    let root: PathBuf = corpus_root().join(relative);
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    collect_tree(&root, &root, key_prefix, &mut out);
    assert!(
        !out.is_empty(),
        "the reference tree {} is empty, so any comparison against it would pass vacuously",
        root.display()
    );
    out
}

fn collect_tree(root: &Path, dir: &Path, key_prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    let entries: fs::ReadDir = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reference tree {} is unreadable: {e}", dir.display()));
    for entry in entries {
        let entry: fs::DirEntry = entry.expect("directory entry");
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_tree(root, &path, key_prefix, out);
            continue;
        }
        let relative: String = path
            .strip_prefix(root)
            .expect("child of the reference root")
            .to_string_lossy()
            .replace('\\', "/");
        out.insert(
            format!("{key_prefix}{relative}"),
            fs::read(&path).expect("file"),
        );
    }
}

fn assets_map(report: &CarveReport) -> BTreeMap<String, Vec<u8>> {
    report
        .assets
        .iter()
        .map(|asset: &RecoveredAsset| (asset.path.clone(), asset.bytes.clone()))
        .collect()
}

fn assert_tree_identity(report: &CarveReport, expected: &BTreeMap<String, Vec<u8>>, label: &str) {
    let recovered: BTreeMap<String, Vec<u8>> = assets_map(report);
    let recovered_keys: Vec<&String> = recovered.keys().collect();
    let expected_keys: Vec<&String> = expected.keys().collect();
    assert_eq!(
        recovered_keys, expected_keys,
        "{label}: the recovered path set must equal the source tree exactly, because a partial \
         carve recovers a plausible prefix and would pass a subset check"
    );
    for (key, want) in expected {
        let got: &Vec<u8> = recovered.get(key).expect("key present");
        assert_eq!(
            got,
            want,
            "{label}: {key} recovered {} bytes that differ from the source file ({} bytes)",
            got.len(),
            want.len()
        );
    }
}

#[test]
fn a_real_wails_build_recovers_its_frontend_byte_identically() {
    let image: Vec<u8> = read_fixture("wails/wvfix.exe");
    let expected: BTreeMap<String, Vec<u8>> = read_tree("wails/frontend/dist", "frontend/dist/");
    let report: CarveReport = carve_report(&image).expect("carve the wails build");
    assert_eq!(
        report.family,
        WebviewFamily::Wails,
        "the wails runtime strings in a real build are the evidence for the family"
    );
    assert_tree_identity(&report, &expected, "wails");
}

#[test]
fn a_real_tauri_build_recovers_its_frontend_byte_identically() {
    let image: Vec<u8> = read_fixture("tauri/wvfix.exe");
    let expected: BTreeMap<String, Vec<u8>> = read_tree("tauri/dist", "");
    let report: CarveReport = carve_report(&image).expect("carve the tauri build");
    assert_eq!(report.family, WebviewFamily::Tauri);
    assert_tree_identity(&report, &expected, "tauri");
    assert_eq!(
        report
            .assets
            .iter()
            .find(|asset: &&RecoveredAsset| asset.path == "empty.txt")
            .map(|asset: &RecoveredAsset| asset.bytes.len()),
        Some(0),
        "the toolchain stores a zero-length asset as a one-byte compressed stream, so reporting \
         that byte back would hand the caller content the source file never had"
    );
}

#[test]
fn a_real_tauri_build_reports_the_encoding_its_toolchain_applied() {
    let image: Vec<u8> = read_fixture("tauri/wvfix.exe");
    let report: CarveReport = carve_report(&image).expect("carve the tauri build");
    for asset in &report.assets {
        assert_eq!(
            asset.compression,
            Compression::Brotli,
            "{}: the reported encoding must describe how the bytes were recovered",
            asset.path
        );
    }
}

#[test]
fn a_real_tauri_build_reports_every_asset_without_integrity_metadata() {
    let image: Vec<u8> = read_fixture("tauri/wvfix.exe");
    let report: CarveReport = carve_report(&image).expect("carve the tauri build");
    assert!(!report.assets.is_empty());
    for asset in &report.assets {
        assert_eq!(
            asset.integrity,
            IntegrityStatus::Absent,
            "{}: an embedded asset map carries no digest, so claiming a verdict would invent one",
            asset.path
        );
        assert!(!asset.executable);
    }
    assert!(report.symlinks.is_empty());
}

#[test]
fn a_real_tauri_v1_build_recovers_its_frontend_byte_identically() {
    let image: Vec<u8> = read_fixture("tauri-v1/wvfix1.exe");
    let expected: BTreeMap<String, Vec<u8>> = read_tree("tauri-v1/dist", "");
    let report: CarveReport = carve_report(&image).expect("carve the tauri v1 build");
    assert_eq!(report.family, WebviewFamily::Tauri);
    assert_tree_identity(&report, &expected, "tauri-v1");
}

#[test]
fn a_truncated_image_yields_a_typed_error_rather_than_a_panic() {
    let image: Vec<u8> = read_fixture("tauri/wvfix.exe");
    let mut refused: usize = 0;
    for divisor in [2usize, 3, 4, 8, 16, 64] {
        let cut: usize = image.len() / divisor;
        match carve_report(&image[..cut]) {
            Ok(report) => assert!(
                report.assets.is_empty(),
                "a cut at {cut} bytes recovered {} assets from an image whose asset region is not \
                 present",
                report.assets.len()
            ),
            Err(_) => refused += 1,
        }
    }
    assert!(
        refused >= 4,
        "most truncations of a real image must be refused outright, not answered"
    );

    let mut lengths: Vec<u8> = image;
    for offset in (0..lengths.len()).step_by(4096) {
        lengths[offset] = 0xFF;
    }
    if let Ok(report) = carve_report(&lengths) {
        assert!(report.recovered <= report.declared);
        for asset in &report.assets {
            assert!(
                !asset.path.starts_with('/')
                    && !asset.path.contains("..")
                    && !asset.path.contains(':'),
                "a mutated image produced the escaping key {}",
                asset.path
            );
        }
    }
}

fn tar_member(name: &str, body: &[u8]) -> Vec<u8> {
    let mut header: Vec<u8> = vec![0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size: String = format!("{:011o}\0", body.len());
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte: &u8| u32::from(*byte)).sum();
    let field: String = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(field.as_bytes());
    let mut out: Vec<u8> = header;
    out.extend_from_slice(body);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

#[test]
fn a_package_is_named_then_carved_once_its_member_is_extracted() {
    let image: Vec<u8> = read_fixture("tauri/wvfix.exe");
    let expected: BTreeMap<String, Vec<u8>> = read_tree("tauri/dist", "");
    let mut archive: Vec<u8> = tar_member("wvfix.exe", &image);
    archive.extend_from_slice(&[0u8; 1024]);

    match carve_report(&archive) {
        Err(Error::PackagedContainer { container }) => assert_eq!(container, "tar"),
        other => panic!("a package must be named rather than parsed as an image, got {other:?}"),
    }

    let out_dir: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join("webview-package-reach");
    let _ = fs::remove_dir_all(&out_dir);
    let result: ExtractionResult = extract_to(ContainerKind::Tar, &archive, &out_dir)
        .expect("the container reader unwraps the package");
    let member: PathBuf = result
        .entries
        .iter()
        .find_map(|entry: &ExtractedEntry| entry.disk_path.clone())
        .expect("the package holds a member on disk");
    let inner: Vec<u8> = fs::read(&member).expect("read the extracted member");
    assert_eq!(inner, image, "the member must arrive byte-identical");
    let report: CarveReport = carve_report(&inner).expect("carve the extracted member");
    assert_tree_identity(&report, &expected, "packaged");
}
