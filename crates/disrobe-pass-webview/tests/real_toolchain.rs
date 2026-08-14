#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_binfmt::{ContainerKind, ExtractedEntry, ExtractionResult, extract_to};
use disrobe_pass_webview::{
    CarveReport, Compression, Error, FamilyEvidence, IntegrityStatus, RecoveredAsset,
    WebviewFamily, carve_report, classify, classify_all, detect_family,
};
use sha2::{Digest, Sha256};

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

const MANIFEST_NAME: &str = "MANIFEST.toml";

const RECORDED_DIGESTS: [(&str, &str); 3] = [
    (
        "tauri/wvfix.exe",
        "f85e04343ff8c23d3cf2d0ac743e90c6c98185004baacbf6b7ea794612e2c78e",
    ),
    (
        "tauri-v1/wvfix1.exe",
        "20fdf90304909dcd747112c4cf635d6a3ed858b458d6e6b3a366f7fa803f6829",
    ),
    (
        "wails/wvfix.exe",
        "02f3910461b9890fca774e07105722637938504e0e3ac2d108a0b17e780ac91f",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureRecord {
    path: String,
    family: String,
    tree: String,
}

fn manifest_path() -> PathBuf {
    corpus_root().join(MANIFEST_NAME)
}

fn manifest_text() -> String {
    let path: PathBuf = manifest_path();
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing fixture manifest {}: {e}; without it nothing records which family each \
             committed build was produced as",
            path.display()
        )
    })
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    let after_key: &str = line.strip_prefix(key)?.trim_start();
    let after_equals: &str = after_key.strip_prefix('=')?.trim();
    let inner: &str = after_equals.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.replace("\\\"", "\""))
}

fn fixture_blocks(text: &str) -> Vec<Vec<&str>> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for raw in text.lines() {
        let line: &str = raw.trim();
        if line == "[[fixture]]" {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(Vec::new());
            continue;
        }
        if line.starts_with('[') {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push(line);
        }
    }
    if let Some(block) = current.take() {
        blocks.push(block);
    }
    blocks
}

fn manifest_fixtures() -> Vec<FixtureRecord> {
    let text: String = manifest_text();
    fixture_blocks(&text)
        .into_iter()
        .map(|block: Vec<&str>| {
            let field = |key: &str| -> String {
                block
                    .iter()
                    .find_map(|line: &&str| quoted_value(line, key))
                    .unwrap_or_default()
            };
            FixtureRecord {
                path: field("path"),
                family: field("family"),
                tree: field("tree"),
            }
        })
        .collect()
}

fn collect_images(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let entries: fs::ReadDir = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("corpus directory {} is unreadable: {e}", dir.display()));
    for entry in entries {
        let entry: fs::DirEntry = entry.expect("directory entry");
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_images(root, &path, out);
            continue;
        }
        if path
            .extension()
            .is_some_and(|ext: &OsStr| ext.eq_ignore_ascii_case("exe"))
        {
            out.insert(
                path.strip_prefix(root)
                    .expect("child of the corpus root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn discovered_images() -> BTreeSet<String> {
    let root: PathBuf = corpus_root();
    let mut out: BTreeSet<String> = BTreeSet::new();
    collect_images(&root, &root, &mut out);
    out
}

fn graded_fixtures() -> Vec<FixtureRecord> {
    let records: Vec<FixtureRecord> = manifest_fixtures();
    let discovered: BTreeSet<String> = discovered_images();
    assert!(
        !discovered.is_empty(),
        "no application image was found under {}, so every grade that loops over the committed \
         builds would pass over an empty set",
        corpus_root().display()
    );
    let declared: BTreeSet<String> = records
        .iter()
        .map(|record: &FixtureRecord| record.path.clone())
        .collect();
    assert_eq!(
        declared,
        discovered,
        "the fixture manifest {} and the committed images disagree, so the manifest no longer \
         records what the tree holds",
        manifest_path().display()
    );
    assert_eq!(
        records.len(),
        declared.len(),
        "the manifest declares one image twice, which would let a single record stand in for two \
         builds"
    );
    for record in &records {
        assert!(
            !record.family.is_empty(),
            "{}: the manifest records no family, so a detection grade would have nothing to \
             compare against",
            record.path
        );
        let tree: PathBuf = corpus_root().join(&record.tree);
        assert!(
            tree.is_dir(),
            "{}: the manifest names the source tree {}, which is not a directory",
            record.path,
            tree.display()
        );
    }
    records
}

fn fixture_named(path: &str) -> FixtureRecord {
    graded_fixtures()
        .into_iter()
        .find(|record: &FixtureRecord| record.path == path)
        .unwrap_or_else(|| {
            panic!(
                "the manifest {} declares no fixture `{path}`, so this grade has no reference \
                 build",
                manifest_path().display()
            )
        })
}

fn declared_family(record: &FixtureRecord) -> WebviewFamily {
    match record.family.as_str() {
        "electron" => WebviewFamily::Electron,
        "tauri" => WebviewFamily::Tauri,
        "wails" => WebviewFamily::Wails,
        other => panic!(
            "{}: the manifest declares the family `{other}`, which names no family this pass can \
             report",
            record.path
        ),
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_digest(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn assert_named_family(path: &str, markers: &[&'static str]) {
    let record: FixtureRecord = fixture_named(path);
    let image: Vec<u8> = read_fixture(&record.path);
    let want: WebviewFamily = declared_family(&record);
    let evidence: FamilyEvidence = classify(&image).unwrap_or_else(|| {
        panic!("{path}: the detection surface named no family at all for a real build of one")
    });
    assert_eq!(
        evidence.family, want,
        "{path}: the toolchain recorded in the manifest built a {want} application, so detection \
         must name {want}"
    );
    assert_eq!(
        detect_family(&image),
        Some(want),
        "{path}: the family helper must agree with the ranked evidence it reads"
    );
    assert_eq!(
        evidence.markers.as_slice(),
        markers,
        "{path}: the marker set is the whole evidence for the family, so a needle that starts \
         matching a different run of bytes changes what the verdict rests on while leaving the \
         verdict itself intact"
    );
}

#[test]
fn every_committed_build_matches_its_recorded_digest() {
    let records: Vec<FixtureRecord> = graded_fixtures();
    let pinned: BTreeMap<&str, &str> = RECORDED_DIGESTS.iter().copied().collect();
    assert_eq!(
        pinned.len(),
        RECORDED_DIGESTS.len(),
        "one image is pinned twice, so a second entry silently never runs"
    );
    let pinned_paths: BTreeSet<String> = pinned
        .keys()
        .map(|path: &&str| (*path).to_owned())
        .collect();
    let declared: BTreeSet<String> = records
        .iter()
        .map(|record: &FixtureRecord| record.path.clone())
        .collect();
    assert_eq!(
        pinned_paths, declared,
        "every committed build must carry a recorded digest, because a build that is graded but \
         never pinned can be replaced without anything noticing"
    );
    for record in &records {
        let bytes: Vec<u8> = read_fixture(&record.path);
        let want: &str = pinned
            .get(record.path.as_str())
            .expect("pinned path set equals the declared path set");
        assert_eq!(
            hex_digest(&bytes),
            *want,
            "{}: the committed image is not the build these grades were written against, so every \
             result below describes a different binary",
            record.path
        );
    }
}

#[test]
fn a_real_tauri_build_is_named_tauri_by_the_public_detection_surface() {
    assert_named_family(
        "tauri/wvfix.exe",
        &[
            "tauri-internals",
            "tauri-localhost",
            "tauri-scheme",
            "is-tauri",
            "wry-webview",
        ],
    );
}

#[test]
fn a_real_tauri_v1_build_is_named_tauri_by_the_public_detection_surface() {
    assert_named_family(
        "tauri-v1/wvfix1.exe",
        &[
            "tauri-localhost",
            "tauri-global",
            "tauri-scheme",
            "wry-webview",
        ],
    );
}

#[test]
fn a_real_wails_build_is_named_wails_by_the_public_detection_surface() {
    assert_named_family(
        "wails/wvfix.exe",
        &[
            "wails-runtime-route",
            "wails-invoke",
            "wails-module-path",
            "wails-window-runtime",
        ],
    );
}

#[test]
fn a_real_build_raises_no_evidence_for_a_family_it_is_not() {
    let records: Vec<FixtureRecord> = graded_fixtures();
    for record in &records {
        let image: Vec<u8> = read_fixture(&record.path);
        let want: WebviewFamily = declared_family(record);
        let ranked: Vec<FamilyEvidence> = classify_all(&image);
        let first: &FamilyEvidence = ranked.first().unwrap_or_else(|| {
            panic!(
                "{}: a real build of a {want} application produced no evidence at all",
                record.path
            )
        });
        assert_eq!(
            first.family, want,
            "{}: the declared family must rank first, because a caller reads the top entry",
            record.path
        );
        let foreign: Vec<&'static str> = ranked
            .iter()
            .filter(|evidence: &&FamilyEvidence| evidence.family != want)
            .map(|evidence: &FamilyEvidence| evidence.family.label())
            .collect();
        assert!(
            foreign.is_empty(),
            "{}: a real {want} build raised evidence for {foreign:?} as well, so a needle in \
             another family's table matches bytes this build really contains",
            record.path
        );
    }
}

#[test]
fn no_real_embedded_build_is_mistaken_for_an_archive() {
    let records: Vec<FixtureRecord> = graded_fixtures();
    for record in &records {
        let image: Vec<u8> = read_fixture(&record.path);
        for evidence in classify_all(&image) {
            assert!(
                !evidence.archive_verified,
                "{}: the archive header scan claimed a parsed archive inside a {} byte image that \
                 embeds its frontend instead, and a false header sends the carve down the archive \
                 path",
                record.path,
                image.len()
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
