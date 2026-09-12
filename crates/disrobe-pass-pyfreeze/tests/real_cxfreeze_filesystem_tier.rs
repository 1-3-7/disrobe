#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyfreeze::common::manifest::{EntryKind, EntryOrigin, EntryRecord};
use disrobe_pass_pyfreeze::cxfreeze::{self, CxFreezeExtraction, CxFreezeRecovery};
use disrobe_pass_pyfreeze::pass::{self, PyfreezeOutput};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, RecoveredModule, detect_bytes};

const REFERENCE_LIBRARY_ZIP: &str = "corpus/python/freezers/cxfreeze/extracted/library.zip";
const REFERENCE_SOURCE_DIR: &str = "corpus/python/decompile/playground";

const ZIP_TIER_MEMBER: &str = "edge_cases_3_6.pyc";

const FILESYSTEM_TIER: [(&str, &str); 6] = [
    ("hello/__init__.pyc", "edge_cases_3_8.pyc"),
    ("hello/__main__.pyc", "edge_cases_3_9.pyc"),
    ("hello/deep/nested/leaf.pyc", "edge_cases_3_10.pyc"),
    ("pkg2/__init__.pyc", "edge_cases_3_11.pyc"),
    ("pkg2/data.pyc", "edge_cases_3_9.pyc"),
    ("pkg2/mod.pyc", "edge_cases_3_12.pyc"),
];

const FILESYSTEM_NATIVE: &str = "pkg2/_speedup.pyd";
const FILESYSTEM_RESOURCE: &str = "pkg2/data/table.json";

const GRADED_MODULE: &str = "hello/__init__.pyc";
const GRADED_REFERENCE_SOURCE: &str = "edge_cases_3_8.py";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn repo_file(relative: &str) -> PathBuf {
    let mut path: PathBuf = repo_root();
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

fn reference_bytecode() -> BTreeMap<String, Vec<u8>> {
    let path: PathBuf = repo_file(REFERENCE_LIBRARY_ZIP);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is the committed CPython bytecode this gate grades against; a run that cannot read \
             it compared nothing and must fail rather than report a pass: {error}",
            path.display()
        )
    });
    let mut archive: zip::ZipArchive<Cursor<Vec<u8>>> =
        zip::ZipArchive::new(Cursor::new(bytes)).expect("the committed reference is a zip");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for index in 0..archive.len() {
        let mut member: zip::read::ZipFile<'_> = archive.by_index(index).expect("read member");
        let name: String = member.name().to_owned();
        let mut body: Vec<u8> = Vec::new();
        member.read_to_end(&mut body).expect("read member body");
        out.insert(name, body);
    }
    for (_, source) in FILESYSTEM_TIER {
        assert!(
            out.contains_key(source),
            "the committed reference must carry `{source}`; it holds {:?}",
            out.keys().collect::<Vec<&String>>()
        );
    }
    assert!(out.contains_key(ZIP_TIER_MEMBER));
    out
}

fn write_file(path: &Path, body: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent directory");
    }
    std::fs::write(path, body).expect("write file");
}

fn build_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    {
        let mut writer: zip::ZipWriter<Cursor<&mut Vec<u8>>> =
            zip::ZipWriter::new(Cursor::new(&mut buffer));
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in members {
            writer.start_file(*name, options).expect("start member");
            writer.write_all(body).expect("write member");
        }
        writer.finish().expect("finish zip");
    }
    buffer
}

fn scratch(tag: &str) -> ScratchDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xCF50_0000);
    let purpose: String = format!(
        "disrobe-cxfreeze-fs-tier-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    ScratchDir::create(&purpose).expect("create scratch dir")
}

fn assemble_default_layout(root: &Path) -> PathBuf {
    let bodies: BTreeMap<String, Vec<u8>> = reference_bytecode();
    let binary: PathBuf = root.join("hello.exe");
    write_file(&binary, b"MZ\x90\x00cx_Freeze stub launcher\x00");

    let lib: PathBuf = root.join("lib");
    let zip_member: &[u8] = bodies
        .get(ZIP_TIER_MEMBER)
        .expect("reference carries the zip-tier member");
    write_file(
        &lib.join("library.zip"),
        &build_zip(&[(ZIP_TIER_MEMBER, zip_member)]),
    );
    write_file(
        &lib.join("frozen_application_license.txt"),
        b"cx_Freeze frozen application license\n",
    );

    for (placed, source) in FILESYSTEM_TIER {
        let body: &Vec<u8> = bodies.get(source).expect("reference carries the member");
        write_file(
            &lib.join(placed.replace('/', std::path::MAIN_SEPARATOR_STR)),
            body,
        );
    }
    write_file(
        &lib.join(FILESYSTEM_NATIVE.replace('/', std::path::MAIN_SEPARATOR_STR)),
        b"MZ\x90\x00not a parsable image\x00",
    );
    write_file(
        &lib.join(FILESYSTEM_RESOURCE.replace('/', std::path::MAIN_SEPARATOR_STR)),
        b"{\"rows\": []}\n",
    );
    binary
}

fn extract_layout(tag: &str) -> (ScratchDir, ScratchDir, PyfreezeOutput) {
    let dist: ScratchDir = scratch(&format!("{tag}-dist"));
    let binary: PathBuf = assemble_default_layout(dist.path());
    let out: ScratchDir = scratch(&format!("{tag}-out"));
    let output: PyfreezeOutput = pass::extract(&binary, out.path()).unwrap_or_else(|error| {
        panic!(
            "the cx_Freeze default layout at {} must extract: {error}",
            dist.path().display()
        )
    });
    (dist, out, output)
}

fn top_level_definitions(source: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in source.lines() {
        for keyword in ["def ", "class "] {
            let Some(rest): Option<&str> = line.strip_prefix(keyword) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    assert!(
        out.len() >= 8,
        "the reference source must expose a real definition set to grade against, found {out:?}"
    );
    out
}

#[test]
fn the_default_layout_still_detects_as_cxfreeze() {
    let dist: ScratchDir = scratch("detect-dist");
    let binary: PathBuf = assemble_default_layout(dist.path());
    let bytes: Vec<u8> = std::fs::read(&binary).expect("read stub");
    let detection: Detection = detect_bytes(&bytes, Some(&binary));
    assert_eq!(
        detection.kind,
        FreezerKind::CxFreeze,
        "a cx_Freeze default layout must reach the cx_Freeze extractor; got {detection:?}"
    );
}

#[test]
fn every_package_module_cxfreeze_places_on_the_filesystem_is_inventoried() {
    let (_dist, _out, output): (ScratchDir, ScratchDir, PyfreezeOutput) = extract_layout("inv");
    let sibling: BTreeSet<&str> = output
        .manifest
        .entries
        .iter()
        .filter(|entry: &&EntryRecord| entry.origin == EntryOrigin::SiblingFile)
        .map(|entry: &EntryRecord| entry.name.as_str())
        .collect();
    let placed: BTreeSet<&str> = FILESYSTEM_TIER
        .iter()
        .map(|(placed, _): &(&str, &str)| *placed)
        .collect();
    let found: usize = placed
        .iter()
        .filter(|name: &&&str| sibling.contains(*name))
        .count();
    assert_eq!(
        found,
        placed.len(),
        "cx_Freeze places every package on the filesystem by default, so {}/{} of them must be \
         inventoried; the manifest carries {sibling:?}",
        found,
        placed.len()
    );
    let native: &EntryRecord = output
        .manifest
        .entries
        .iter()
        .find(|entry: &&EntryRecord| entry.name == FILESYSTEM_NATIVE)
        .expect("a nested native extension must be inventoried");
    assert_eq!(native.kind, EntryKind::NativeExtension);
    assert_eq!(native.origin, EntryOrigin::SiblingFile);
    let resource: &EntryRecord = output
        .manifest
        .entries
        .iter()
        .find(|entry: &&EntryRecord| entry.name == FILESYSTEM_RESOURCE)
        .expect("a nested package resource must be inventoried");
    assert_eq!(resource.kind, EntryKind::Resource);
}

#[test]
fn the_filesystem_tier_carries_its_python_version_and_disk_path() {
    let (_dist, _out, output): (ScratchDir, ScratchDir, PyfreezeOutput) = extract_layout("meta");
    for (placed, _) in FILESYSTEM_TIER {
        let entry: &EntryRecord = output
            .manifest
            .entries
            .iter()
            .find(|entry: &&EntryRecord| entry.name == placed)
            .unwrap_or_else(|| panic!("{placed} must be inventoried"));
        assert_eq!(
            (entry.python_major, entry.python_minor),
            (Some(3), Some(14)),
            "{placed} carries a real CPython 3.14 header, so the manifest must resolve it"
        );
        let disk: &str = entry
            .source_path
            .as_deref()
            .unwrap_or_else(|| panic!("{placed} must record the file it was indexed from"));
        assert!(
            Path::new(disk).is_file(),
            "{placed} must point at the real on-disk file, got {disk}"
        );
        assert!(entry.size > 0, "{placed} must record a real size");
    }
}

#[test]
fn every_filesystem_package_module_is_decompiled_and_the_zip_tier_is_unchanged() {
    let (_dist, _out, output): (ScratchDir, ScratchDir, PyfreezeOutput) = extract_layout("recover");
    let recovered: BTreeSet<&str> = output
        .recovery
        .modules
        .iter()
        .map(|module: &RecoveredModule| module.name.as_str())
        .collect();
    let placed: Vec<&str> = FILESYSTEM_TIER
        .iter()
        .map(|(placed, _): &(&str, &str)| *placed)
        .collect();
    let found: usize = placed
        .iter()
        .filter(|name: &&&str| recovered.contains(*name))
        .count();
    assert_eq!(
        found,
        placed.len(),
        "{}/{} filesystem package modules were decompiled; recovered={recovered:?}",
        found,
        placed.len()
    );
    assert!(
        recovered.contains(ZIP_TIER_MEMBER),
        "the library.zip tier must keep working alongside the filesystem tier; recovered={recovered:?}"
    );
}

#[test]
fn a_filesystem_module_recovers_the_definitions_its_original_source_declares() {
    let (_dist, _out, output): (ScratchDir, ScratchDir, PyfreezeOutput) = extract_layout("grade");
    let module: &RecoveredModule = output
        .recovery
        .modules
        .iter()
        .find(|module: &&RecoveredModule| module.name == GRADED_MODULE)
        .unwrap_or_else(|| panic!("{GRADED_MODULE} must be recovered"));
    assert!(
        module.recovered_directly,
        "{GRADED_MODULE} must decompile rather than fall back; reason={:?}",
        module.fallback_reason
    );
    let reference_path: PathBuf =
        repo_file(&format!("{REFERENCE_SOURCE_DIR}/{GRADED_REFERENCE_SOURCE}"));
    let reference: String =
        std::fs::read_to_string(&reference_path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{} is the original source this gate grades the recovered module against; a run \
                 that cannot read it compared nothing and must fail: {error}",
                reference_path.display()
            )
        });
    let expected: BTreeSet<String> = top_level_definitions(&reference);
    let missing: Vec<&String> = expected
        .iter()
        .filter(|name: &&String| !module.source.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "{}/{} definitions from {GRADED_REFERENCE_SOURCE} survived into the module recovered from \
         the cx_Freeze filesystem tier; missing {missing:?}",
        expected.len() - missing.len(),
        expected.len()
    );
}

#[test]
fn two_extractions_of_one_layout_publish_the_same_entry_sequence() {
    let dist: ScratchDir = scratch("determinism-dist");
    let binary: PathBuf = assemble_default_layout(dist.path());
    let mut sequences: Vec<Vec<(String, EntryOrigin)>> = Vec::new();
    for run in 0..2u8 {
        let out: ScratchDir = scratch(&format!("determinism-out-{run}"));
        let extraction: CxFreezeExtraction = cxfreeze::detect_and_extract(&binary, out.path())
            .expect("the layout must extract on every run");
        sequences.push(
            extraction
                .manifest
                .entries
                .iter()
                .map(|entry: &EntryRecord| (entry.name.clone(), entry.origin))
                .collect(),
        );
    }
    assert_eq!(
        sequences[0], sequences[1],
        "two extractions of one cx_Freeze layout must publish one entry sequence"
    );
    let filesystem_names: Vec<&String> = sequences[0]
        .iter()
        .filter(|(_, origin): &&(String, EntryOrigin)| *origin == EntryOrigin::SiblingFile)
        .map(|(name, _): &(String, EntryOrigin)| name)
        .collect();
    let mut sorted: Vec<&String> = filesystem_names.clone();
    sorted.sort();
    assert_eq!(
        filesystem_names, sorted,
        "the filesystem tier must be published in sorted order, not in directory-read order"
    );
    let sibling_of_directory: usize = filesystem_names
        .iter()
        .position(|name: &&String| name.as_str() == "pkg2/data.pyc")
        .expect("the layout carries a file whose name prefixes a sibling directory");
    let inside_directory: usize = filesystem_names
        .iter()
        .position(|name: &&String| name.as_str() == FILESYSTEM_RESOURCE)
        .expect("the layout carries a file inside that sibling directory");
    assert!(
        sibling_of_directory < inside_directory,
        "`pkg2/data.pyc` sorts before `{FILESYSTEM_RESOURCE}` while depth-first directory order \
         emits it after, so this ordering is what proves the sort ran"
    );
}

#[test]
fn the_recovery_report_states_how_much_of_the_filesystem_tier_it_decompiled() {
    let dist: ScratchDir = scratch("report-dist");
    let binary: PathBuf = assemble_default_layout(dist.path());
    let out: ScratchDir = scratch("report-out");
    let extraction: CxFreezeExtraction =
        cxfreeze::detect_and_extract(&binary, out.path()).expect("extract");
    assert_eq!(
        extraction.filesystem_bytecode().count(),
        FILESYSTEM_TIER.len(),
        "the extraction must see every filesystem bytecode file"
    );
    assert_eq!(
        extraction.filesystem_symlinks_skipped, 0,
        "a layout with no symlink must report none skipped rather than leave the count unset"
    );
    assert_eq!(
        extraction.filesystem_entries.len(),
        FILESYSTEM_TIER.len() + 3,
        "the walk covers the bytecode tier plus the license, the nested extension and the nested \
         resource, and never the library.zip it already extracted"
    );
    let recovery: CxFreezeRecovery = extraction.recover();
    assert_eq!(
        recovery.filesystem_bytecode_attempted,
        FILESYSTEM_TIER.len()
    );
    assert_eq!(
        recovery.filesystem_bytecode_capped, 0,
        "a layout below the cap must report nothing capped"
    );
    assert!(
        recovery.filesystem_bytecode_attempted <= cxfreeze::MAX_FILESYSTEM_BYTECODE_ATTEMPTS,
        "the filesystem decompile tier must stay inside its cap"
    );
}

#[test]
fn a_layout_past_the_filesystem_decompile_cap_reports_the_remainder_instead_of_running_it() {
    let dist: ScratchDir = scratch("cap-dist");
    let binary: PathBuf = assemble_default_layout(dist.path());
    let magic: u32 =
        disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY314).expect("known magic");
    let mut body: Vec<u8> = magic.to_le_bytes().to_vec();
    body.resize(16, 0);
    let over: usize = cxfreeze::MAX_FILESYSTEM_BYTECODE_ATTEMPTS + 3;
    for index in 0..over {
        write_file(
            &dist
                .path()
                .join("lib")
                .join("bulk")
                .join(format!("m{index:05}.pyc")),
            &body,
        );
    }
    let out: ScratchDir = scratch("cap-out");
    let extraction: CxFreezeExtraction =
        cxfreeze::detect_and_extract(&binary, out.path()).expect("extract");
    let seen: usize = extraction.filesystem_bytecode().count();
    assert_eq!(
        seen,
        over + FILESYSTEM_TIER.len(),
        "every filesystem bytecode file must still be inventoried past the decompile cap"
    );
    let recovery: CxFreezeRecovery = extraction.recover();
    assert_eq!(
        recovery.filesystem_bytecode_attempted,
        cxfreeze::MAX_FILESYSTEM_BYTECODE_ATTEMPTS,
        "the decompile tier must stop exactly at its cap"
    );
    assert_eq!(
        recovery.filesystem_bytecode_capped,
        seen - cxfreeze::MAX_FILESYSTEM_BYTECODE_ATTEMPTS,
        "the remainder must be reported, never silently dropped"
    );
    assert!(
        !recovery.bytecode_failures.is_empty(),
        "a truncated bytecode file must be reported as a failure, never counted as recovered"
    );
}
