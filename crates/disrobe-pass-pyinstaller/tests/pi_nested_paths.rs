#![allow(clippy::expect_used, clippy::panic)]
use std::path::{Component, Path};

use disrobe_pass_pyinstaller::{
    DependencyReference, EntryType, ExtractOutput, ExtractedEntry, MEI_MAGIC, TocEntry,
    TocNameStatus, extract_archive, find_cookie, walk_toc,
};
use disrobe_py_marshal::PyVersion;
use serde::Deserialize;

const ARCHIVE: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyinstaller/nested_paths/nested_paths.bin");
const REFERENCE: &str = include_str!(
    "../../../corpus/python/freezers/pyinstaller/nested_paths/nested_paths.expected.json"
);

const COOKIE_LEN_V21: usize = 88;

#[derive(Debug, Deserialize)]
struct Reference {
    entries: Vec<ReferenceEntry>,
    options: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReferenceEntry {
    name: String,
    typecode: String,
    payload_hex: String,
}

impl ReferenceEntry {
    fn payload(&self) -> Vec<u8> {
        let bytes: &[u8] = self.payload_hex.as_bytes();
        assert!(
            bytes.len().is_multiple_of(2),
            "payload hex must be byte aligned",
        );
        bytes
            .chunks_exact(2)
            .map(|pair: &[u8]| {
                let text: &str =
                    core::str::from_utf8(pair).expect("payload hex is ascii by construction");
                u8::from_str_radix(text, 16).expect("payload hex digit")
            })
            .collect()
    }

    fn slash_name(&self) -> String {
        self.name.replace('\\', "/")
    }
}

fn reference() -> Reference {
    serde_json::from_str(REFERENCE).expect("the PyInstaller-produced reference must parse")
}

fn extracted() -> ExtractOutput {
    extract_archive(ARCHIVE).expect("the real archive must extract")
}

#[test]
fn every_nested_entry_the_reference_reader_sees_is_recovered_byte_for_byte() {
    let reference: Reference = reference();
    let output: ExtractOutput = extracted();
    let payload_entries: Vec<&ReferenceEntry> = reference
        .entries
        .iter()
        .filter(|entry: &&ReferenceEntry| entry.typecode != "d")
        .collect();
    let denominator: usize = payload_entries.len();
    assert_eq!(
        denominator, 5,
        "the reference archive carries five payload-bearing entries",
    );

    let header_len: usize = PyVersion::new(3, 10).pyc_header_len();
    let mut recovered: usize = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for expected in payload_entries {
        let wanted: String = expected.slash_name();
        let Some(found): Option<&ExtractedEntry> = output
            .entries
            .iter()
            .find(|candidate: &&ExtractedEntry| candidate.toc.name == wanted)
        else {
            missing.push(wanted);
            continue;
        };
        assert_eq!(
            found.toc.raw_name, expected.name,
            "the exact TOC text must be kept beside the usable path",
        );
        let body: &[u8] = if found.toc.entry_type.is_pyc_carrier() {
            found
                .data
                .get(header_len..)
                .expect("a reconstructed pyc is longer than its header")
        } else {
            found.data.as_slice()
        };
        assert_eq!(
            body,
            expected.payload().as_slice(),
            "'{wanted}' payload differs from what PyInstaller's own CArchiveReader extracts",
        );
        recovered += 1;
    }
    assert!(
        missing.is_empty(),
        "recovered {recovered}/{denominator} reference entries; missing {missing:?}",
    );
    assert_eq!(
        recovered, denominator,
        "{recovered}/{denominator} recovered"
    );
}

#[test]
fn a_windows_nested_destination_is_not_reported_as_an_escape() {
    let output: ExtractOutput = extracted();
    let nested: &ExtractedEntry = output
        .entries
        .iter()
        .find(|candidate: &&ExtractedEntry| candidate.toc.name == "vendor/native/_speedup.pyd")
        .expect("the nested extension module must be recovered");
    assert_eq!(
        nested.toc.name_status,
        TocNameStatus::Preserved,
        "a back slash is how CArchiveWriter stores a nested destination on Windows, so decoding \
         it is not a containment rewrite",
    );
    assert_eq!(nested.toc.entry_type, EntryType::Binary);
}

#[test]
fn no_recovered_name_carries_a_windows_separator() {
    let output: ExtractOutput = extracted();
    for entry in &output.entries {
        assert!(
            !entry.toc.name.contains('\\'),
            "'{}' still carries the on-wire separator; deptree and onedir join these names as \
             forward-slash paths",
            entry.toc.name,
        );
    }
}

#[test]
fn the_multipackage_dependency_names_the_executable_that_holds_it() {
    let output: ExtractOutput = extracted();
    assert_eq!(
        output.dependencies,
        vec![DependencyReference {
            entry_name: "mypkg/data/shared.bin".to_owned(),
            referenced_executable: Some("../app_b/app_b.exe".to_owned()),
        }],
        "a MERGE build stores '<reference>:<name>'; both halves must survive so an analyst \
         knows which sibling executable carries the payload",
    );
    assert!(
        !output
            .entries
            .iter()
            .any(|entry: &ExtractedEntry| entry.toc.entry_type == EntryType::Dependency),
        "a dependency entry carries no bytes of its own and must not masquerade as a payload",
    );
}

#[test]
fn runtime_options_are_recovered_exactly_as_written() {
    let reference: Reference = reference();
    let output: ExtractOutput = extracted();
    assert_eq!(
        output.runtime_options, reference.options,
        "CArchiveWriter writes OPTION entries without normalizing them, so they must come back \
         verbatim",
    );
    assert_eq!(output.runtime_options.len(), 1);
}

fn assemble_carchive(entries: &[(u8, &str, &[u8])], pyver: u32) -> Vec<u8> {
    let mut data_region: Vec<u8> = Vec::new();
    let mut toc_region: Vec<u8> = Vec::new();
    for (type_byte, name, payload) in entries {
        let position: u32 = u32::try_from(data_region.len()).expect("position fits u32");
        let length: u32 = u32::try_from(payload.len()).expect("length fits u32");
        data_region.extend_from_slice(payload);
        let name_bytes: &[u8] = name.as_bytes();
        let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("name fits u32");
        toc_region.extend_from_slice(&entry_size.to_be_bytes());
        toc_region.extend_from_slice(&position.to_be_bytes());
        toc_region.extend_from_slice(&length.to_be_bytes());
        toc_region.extend_from_slice(&length.to_be_bytes());
        toc_region.push(0u8);
        toc_region.push(*type_byte);
        toc_region.extend_from_slice(name_bytes);
    }
    let toc_offset: u32 = u32::try_from(data_region.len()).expect("toc offset fits u32");
    let toc_length: u32 = u32::try_from(toc_region.len()).expect("toc length fits u32");
    let package_len: u32 =
        toc_offset + toc_length + u32::try_from(COOKIE_LEN_V21).expect("cookie fits u32");
    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(&data_region);
    archive.extend_from_slice(&toc_region);
    archive.extend_from_slice(MEI_MAGIC);
    archive.extend_from_slice(&package_len.to_be_bytes());
    archive.extend_from_slice(&toc_offset.to_be_bytes());
    archive.extend_from_slice(&toc_length.to_be_bytes());
    archive.extend_from_slice(&pyver.to_be_bytes());
    let mut libname: Vec<u8> = b"python312.dll".to_vec();
    libname.resize(64, 0u8);
    archive.extend_from_slice(&libname);
    archive
}

#[test]
fn one_escaping_name_does_not_deny_the_rest_of_the_archive() {
    let entries: [(u8, &str, &[u8]); 3] = [
        (b'x', "..\\..\\evil.pyc", b"first entry is hostile"),
        (b'x', "mypkg\\data\\ok.bin", b"second entry is ordinary"),
        (b'b', "vendor\\native\\fast.pyd", b"third entry is ordinary"),
    ];
    let archive: Vec<u8> = assemble_carchive(&entries, 312);
    let output: ExtractOutput = extract_archive(&archive)
        .expect("a single escaping name must not deny recovery of the whole archive");
    assert_eq!(
        output.entries.len(),
        3,
        "the two well-formed entries that follow the hostile one must still be recovered",
    );

    let hostile: &ExtractedEntry = output
        .entries
        .first()
        .expect("the hostile entry is retained, not dropped");
    assert_eq!(hostile.toc.name_status, TocNameStatus::Contained);
    assert_eq!(hostile.toc.raw_name, "..\\..\\evil.pyc");
    assert_eq!(hostile.toc.name, "__/__/evil.pyc");
    assert_eq!(hostile.data, b"first entry is hostile");

    let ordinary: &ExtractedEntry = output
        .entries
        .iter()
        .find(|candidate: &&ExtractedEntry| candidate.toc.name == "mypkg/data/ok.bin")
        .expect("the ordinary nested entry must be recovered");
    assert_eq!(ordinary.toc.name_status, TocNameStatus::Preserved);
}

fn escapes_root(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let path: &Path = Path::new(name);
    path.has_root()
        || path.is_absolute()
        || path
            .components()
            .any(|component: Component<'_>| !matches!(component, Component::Normal(_)))
}

#[test]
fn no_hostile_toc_name_can_produce_a_path_that_leaves_an_output_root() {
    let hostile: [&str; 12] = [
        "..",
        "../../../../etc/passwd",
        "..\\..\\windows\\system32\\evil.dll",
        "/etc/passwd",
        "\\\\server\\share\\evil.dll",
        "C:\\Windows\\System32\\evil.dll",
        "C:relative.dll",
        "//double//slash//x",
        "./././x",
        "a/./../b",
        ":",
        "",
    ];
    let entries: Vec<(u8, &str, &[u8])> = hostile
        .iter()
        .map(|name: &&str| (b'x', *name, b"payload".as_slice()))
        .collect();
    let archive: Vec<u8> = assemble_carchive(&entries, 312);
    let cookie: disrobe_pass_pyinstaller::Cookie =
        find_cookie(&archive).expect("the constructed cookie must be located");
    let walked: Vec<TocEntry> =
        walk_toc(&archive, &cookie).expect("a hostile name must never abort the walk");
    assert_eq!(
        walked.len(),
        hostile.len(),
        "every hostile entry must survive the walk as a contained record",
    );
    for entry in &walked {
        assert!(
            !escapes_root(&entry.name),
            "'{}' (from raw {:?}) is not contained under an output root",
            entry.name,
            entry.raw_name,
        );
        assert_eq!(
            entry.name_status,
            TocNameStatus::Contained,
            "'{:?}' was rewritten, so it must be recorded as contained",
            entry.raw_name,
        );
    }
}

#[cfg(feature = "chain")]
mod chain_surface {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS;

    use super::ARCHIVE;

    #[test]
    fn the_auto_manifest_reports_nested_paths_options_and_dependencies() {
        let input: Artifact = Artifact::new(Rung::Raw, ARCHIVE.to_vec(), [0u8; 32]);
        let output: Artifact = PYINSTALLER_PASS
            .run(&input)
            .expect("the pass must extract the real nested-path archive");
        let manifest: String = String::from_utf8(output.envelope.as_slice().to_vec())
            .expect("the manifest is utf-8 text");
        for expected in [
            "mypkg/data/config.json",
            "certifi/cacert.pem",
            "vendor/native/_speedup.pyd",
            "runtime-option \"pyi-disable-windowed-traceback\"",
            "dependency mypkg/data/shared.bin in=../app_b/app_b.exe",
        ] {
            assert!(
                manifest.contains(expected),
                "the auto manifest must report {expected:?}; got:\n{manifest}",
            );
        }
    }
}
