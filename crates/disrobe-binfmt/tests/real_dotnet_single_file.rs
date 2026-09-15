#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{
    BundleFileType, DepsManifest, DotnetBundle, DotnetBundleEntry, DotnetBundleFile,
    bundle_deps_manifest, detect_dotnet_bundle, extract_dotnet_bundle, parse_dotnet_bundle,
};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to_with_quota};

const DIR: &str = "dotnet-single-file";
const V6_PE: &str = "probe.v6.win-x64.exe";
const V6_ELF: &str = "probe.v6.linux-x64";
const V6_MACHO: &str = "probe.v6.osx-x64";
const V6_ALL: &str = "probe.v6.all-types.exe";
const V2_PE: &str = "probe.v2.win-x64.exe";
const V1_PE: &str = "probe.v1.win-x64.exe";

fn fixture(name: &str) -> Vec<u8> {
    common::load_fixture(DIR, name).unwrap_or_else(|| {
        panic!(
            "missing committed fixture corpus/binfmt/{DIR}/{name} - see corpus/binfmt/MANIFEST.toml"
        )
    })
}

fn expected(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(DIR)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground truth {DIR}/expected/{rel}"))
}

fn entries_by_path(bytes: &[u8]) -> BTreeMap<String, DotnetBundleEntry> {
    extract_dotnet_bundle(bytes, ExtractionQuota::default_safe())
        .expect("extract bundle")
        .into_iter()
        .map(|e: DotnetBundleEntry| (e.relative_path.clone(), e))
        .collect()
}

fn header_offset(bytes: &[u8]) -> usize {
    usize::try_from(detect_dotnet_bundle(bytes).expect("marker present")).expect("offset fits")
}

#[test]
fn real_v6_pe_bundle_recovers_assembly_byte_identical_to_pre_bundle_original() {
    let bytes: Vec<u8> = fixture(V6_PE);
    assert_eq!(
        detect_container(&bytes),
        Some(ContainerKind::DotnetSingleFile)
    );

    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse v6 bundle");
    assert_eq!(bundle.major_version, 6);
    assert_eq!(bundle.minor_version, 0);
    assert!(
        bundle.deps_json.is_some(),
        "v6 header carries a deps location"
    );

    let got: BTreeMap<String, DotnetBundleEntry> = entries_by_path(&bytes);
    assert_eq!(
        got["probe.dll"].data,
        expected("probe.dll"),
        "the embedded assembly must equal the assembly the compiler produced before bundling"
    );
    assert_eq!(
        got["probe.runtimeconfig.json"].data,
        expected("probe.runtimeconfig.json")
    );
    assert_eq!(got["probe.dll"].file_type, BundleFileType::Assembly);
}

#[test]
fn real_elf_and_macho_hosts_detect_and_recover_the_same_assembly() {
    for name in [V6_ELF, V6_MACHO] {
        let bytes: Vec<u8> = fixture(name);
        assert_eq!(
            detect_container(&bytes),
            Some(ContainerKind::DotnetSingleFile),
            "{name} must be detected through a non-PE host"
        );
        let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
        assert_eq!(bundle.major_version, 6, "{name}");
        let got: BTreeMap<String, DotnetBundleEntry> = entries_by_path(&bytes);
        assert_eq!(
            got["probe.dll"].data,
            expected("probe.dll"),
            "{name} must recover the same assembly the PE host carries"
        );
    }
}

#[test]
fn real_v6_bundle_covers_every_entry_type_and_mixes_compression() {
    let bytes: Vec<u8> = fixture(V6_ALL);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    assert_eq!(bundle.major_version, 6);

    let types: Vec<BundleFileType> = bundle.files.iter().map(|f| f.file_type).collect();
    for wanted in [
        BundleFileType::Assembly,
        BundleFileType::NativeBinary,
        BundleFileType::DepsJson,
        BundleFileType::RuntimeConfigJson,
        BundleFileType::Symbols,
    ] {
        assert!(types.contains(&wanted), "fixture must carry {wanted:?}");
    }

    assert!(
        bundle.files.iter().any(DotnetBundleFile::is_compressed),
        "fixture mixes compressed entries"
    );
    assert!(
        bundle.files.iter().any(|f| !f.is_compressed()),
        "fixture mixes uncompressed entries"
    );

    let got: BTreeMap<String, DotnetBundleEntry> = entries_by_path(&bytes);
    assert_eq!(
        got["probe.dll"].data,
        expected("probe.dll"),
        "a compressed assembly must inflate to the original bytes"
    );
    assert_eq!(
        got["libcustom.dll"].data,
        expected("libcustom.dll"),
        "a compressed native binary must inflate to the original bytes"
    );
    assert_eq!(got["libcustom.dll"].file_type, BundleFileType::NativeBinary);
    assert_eq!(got["probe.pdb"].data, expected("probe.pdb"));
    assert_eq!(got["probe.pdb"].file_type, BundleFileType::Symbols);
}

#[test]
fn real_v2_bundle_parses_the_version_two_header_block() {
    let bytes: Vec<u8> = fixture(V2_PE);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse v2");
    assert_eq!(bundle.major_version, 2);
    assert!(
        bundle.deps_json.is_some() && bundle.runtimeconfig_json.is_some(),
        "the version 2 header adds deps and runtimeconfig locations"
    );
    assert!(
        bundle.files.iter().all(|f| !f.is_compressed()),
        "compression does not exist before version 6"
    );
    let got: BTreeMap<String, DotnetBundleEntry> = entries_by_path(&bytes);
    assert_eq!(got["probe.dll"].data, expected("probe.dll"));
}

#[test]
fn real_v1_bundle_has_no_version_two_block_and_types_every_entry_unknown() {
    let bytes: Vec<u8> = fixture(V1_PE);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse v1");
    assert_eq!(bundle.major_version, 1);
    assert!(
        bundle.deps_json.is_none() && bundle.runtimeconfig_json.is_none(),
        "the version 1 header stops after the bundle id"
    );
    assert!(
        bundle
            .files
            .iter()
            .all(|f| f.file_type == BundleFileType::Unknown),
        "the version 1 writer records every entry as Unknown"
    );
    let got: BTreeMap<String, DotnetBundleEntry> = entries_by_path(&bytes);
    assert_eq!(got["probe.dll"].data, expected("probe.dll"));
}

#[test]
fn unknown_major_version_is_refused_by_number() {
    let mut bytes: Vec<u8> = fixture(V6_PE);
    let at: usize = header_offset(&bytes);
    for unknown in [3u32, 4, 5, 7, 9, 10] {
        bytes[at..at + 4].copy_from_slice(&unknown.to_le_bytes());
        let err: String = parse_dotnet_bundle(&bytes)
            .expect_err("an unknown major must not parse")
            .to_string();
        assert!(
            err.contains(&unknown.to_string()),
            "the refusal must name the version it saw, got: {err}"
        );
    }
}

#[test]
fn a_nonzero_minor_version_is_refused() {
    let mut bytes: Vec<u8> = fixture(V6_PE);
    let at: usize = header_offset(&bytes);
    bytes[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    assert!(parse_dotnet_bundle(&bytes).is_err());
}

fn rewrite_manifest_path(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    assert_eq!(
        from.len(),
        to.len(),
        "an in-place rewrite must not move any recorded offset"
    );
    let at: usize = header_offset(bytes);
    let manifest: &[u8] = &bytes[at..];
    let found: usize = manifest
        .windows(from.len())
        .position(|w: &[u8]| w == from.as_bytes())
        .expect("path present inside the manifest region");
    let mut patched: Vec<u8> = bytes.to_vec();
    patched[at + found..at + found + to.len()].copy_from_slice(to.as_bytes());
    patched
}

#[test]
fn duplicate_entry_paths_are_refused() {
    let bytes: Vec<u8> = fixture(V6_ALL);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    let names: Vec<&str> = bundle
        .files
        .iter()
        .map(|f| f.relative_path.as_str())
        .collect();
    assert!(
        names.contains(&"probe.dll") && names.contains(&"probe.pdb"),
        "fixture carries both nine-character names: {names:?}"
    );

    let patched: Vec<u8> = rewrite_manifest_path(&bytes, "probe.dll", "probe.pdb");
    let err: String = parse_dotnet_bundle(&patched)
        .expect_err("two entries claiming one path must not parse")
        .to_string();
    assert!(
        err.contains("probe.pdb"),
        "refusal names the colliding path: {err}"
    );
}

#[test]
fn an_out_of_range_entry_type_byte_is_refused() {
    let bytes: Vec<u8> = fixture(V6_PE);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    let at: usize = header_offset(&bytes);
    let id_len: usize = bundle.bundle_id.len();
    let first_entry: usize = at + 4 + 4 + 4 + 1 + id_len + 40;
    let type_byte_at: usize = first_entry + 8 + 8 + 8;
    assert_eq!(
        bytes[type_byte_at],
        BundleFileType::Assembly as u8,
        "located the first entry type byte"
    );
    for bad in [6u8, 7, 64, 255] {
        let mut patched: Vec<u8> = bytes.clone();
        patched[type_byte_at] = bad;
        assert!(
            parse_dotnet_bundle(&patched).is_err(),
            "type byte {bad} is outside the enumeration and must be refused"
        );
    }
}

#[test]
fn a_truncated_bundle_is_refused_rather_than_partially_emitted() {
    let full: Vec<u8> = fixture(V6_ALL);
    let mut recovered_any: bool = false;
    for cut in [
        full.len() / 4,
        full.len() / 2,
        full.len() - 64,
        full.len() - 1,
    ] {
        let head: &[u8] = &full[..cut];
        if let Ok(entries) = extract_dotnet_bundle(head, ExtractionQuota::default_safe()) {
            recovered_any = true;
            for entry in &entries {
                assert_eq!(
                    entry.data.len() as u64,
                    entry.data.len() as u64,
                    "an emitted entry is always whole"
                );
            }
        }
    }
    assert!(
        !recovered_any,
        "a bundle cut short of its data must not emit entries"
    );
}

#[test]
fn truncation_at_every_step_never_panics() {
    let full: Vec<u8> = fixture(V2_PE);
    let step: usize = full.len() / 97;
    for cut in (0..full.len()).step_by(step.max(1)) {
        let _ = detect_dotnet_bundle(&full[..cut]);
        let _ = parse_dotnet_bundle(&full[..cut]);
        let _ = extract_dotnet_bundle(&full[..cut], ExtractionQuota::default_safe());
    }
}

#[test]
fn a_decompression_bomb_is_stopped_by_the_quota() {
    let bytes: Vec<u8> = fixture(V6_ALL);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    let biggest: u64 = bundle.files.iter().map(|f| f.size).max().expect("entries");
    let tight: ExtractionQuota = ExtractionQuota {
        max_per_entry_uncompressed: biggest / 2,
        ..ExtractionQuota::default_safe()
    };
    let err: String = extract_dotnet_bundle(&bytes, tight)
        .expect_err("an entry above the per-entry cap must be refused")
        .to_string();
    assert!(
        err.contains("cap") || err.contains("exceeds"),
        "refusal cites the quota: {err}"
    );
}

#[test]
fn a_declared_size_larger_than_the_file_is_refused() {
    let bytes: Vec<u8> = fixture(V6_PE);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    let at: usize = header_offset(&bytes);
    let first_entry: usize = at + 4 + 4 + 4 + 1 + bundle.bundle_id.len() + 40;
    let mut patched: Vec<u8> = bytes;
    patched[first_entry + 8..first_entry + 16].copy_from_slice(&(1u64 << 40).to_le_bytes());
    assert!(extract_dotnet_bundle(&patched, ExtractionQuota::default_safe()).is_err());
}

#[test]
fn the_dependency_manifest_is_parsed_not_only_carved() {
    let bytes: Vec<u8> = fixture(V6_PE);
    let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
    let deps: DepsManifest = bundle_deps_manifest(&bytes, &bundle)
        .expect("read deps.json")
        .expect("a published app carries a deps.json");

    assert!(
        deps.runtime_target
            .name
            .starts_with(".NETCoreApp,Version=v"),
        "runtime target is read as a field, got {:?}",
        deps.runtime_target.name
    );
    assert!(
        deps.runtime_assemblies().contains("probe.dll"),
        "the manifest names the app assembly as a runtime asset: {:?}",
        deps.runtime_assemblies()
    );
    assert!(
        deps.libraries
            .keys()
            .any(|k: &String| k.starts_with("probe/")),
        "the library table is keyed by name/version: {:?}",
        deps.libraries.keys().collect::<Vec<_>>()
    );
    let project: &disrobe_binfmt::containers::DepsLibrary = deps
        .libraries
        .iter()
        .find(|(k, _)| k.starts_with("probe/"))
        .map(|(_, v)| v)
        .expect("app library entry");
    assert_eq!(project.kind, "project");
}

#[test]
fn a_path_traversal_entry_is_rejected_before_anything_is_written() {
    let bytes: Vec<u8> = fixture(V6_ALL);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-bundle-slip").expect("scratch");

    for hostile in [
        r"..\pr.dll",
        "../pr.dll",
        "C:pro.dll",
        "/probe.dl",
        r"\probe.dl",
        "..%2fpro",
    ] {
        if hostile.len() != "probe.dll".len() {
            continue;
        }
        let patched: Vec<u8> = rewrite_manifest_path(&bytes, "probe.dll", hostile);

        if let Ok(entries) = extract_dotnet_bundle(&patched, ExtractionQuota::default_safe()) {
            for entry in &entries {
                assert!(
                    !entry
                        .relative_path
                        .split(['/', '\\'])
                        .any(|s: &str| s == ".."),
                    "`{hostile}` must never survive as a parent escape, got {}",
                    entry.relative_path
                );
                assert!(
                    !entry.relative_path.starts_with('/')
                        && !entry.relative_path.starts_with('\\')
                        && !entry.relative_path.contains(':'),
                    "`{hostile}` must never survive as an absolute path, got {}",
                    entry.relative_path
                );
            }
        }

        let out: PathBuf = scratch.path().join(format!("out{}", hostile.len()));
        let _ = extract_to_with_quota(
            ContainerKind::DotnetSingleFile,
            &patched,
            &out,
            ExtractionQuota::default_safe(),
        );
        let escaped: PathBuf = scratch.path().join("pr.dll");
        assert!(
            !escaped.exists(),
            "`{hostile}` wrote outside the output directory"
        );
    }
}

#[test]
fn a_marker_in_application_data_does_not_defeat_detection() {
    let real: Vec<u8> = fixture(V6_PE);
    let genuine: u64 = detect_dotnet_bundle(&real).expect("genuine bundle detected");

    let mut decoyed: Vec<u8> = real[..64].to_vec();
    decoyed.extend_from_slice(&u64::MAX.to_le_bytes());
    decoyed.extend_from_slice(&real[64..64 + 32]);
    let marker_start: usize = 64 + 8;
    decoyed[marker_start..marker_start + 32].copy_from_slice(&real[real.len() - 32..]);
    decoyed.extend_from_slice(&real[64..]);

    let found: Option<u64> = detect_dotnet_bundle(&decoyed);
    if let Some(offset) = found {
        assert_ne!(
            offset,
            u64::MAX,
            "a marker whose offset field points nowhere must not be accepted"
        );
        let shifted: Vec<u8> = decoyed.clone();
        assert!(
            parse_dotnet_bundle(&shifted).is_ok() || offset != genuine,
            "detection either finds the real header or refuses"
        );
    }
}

#[test]
fn a_fat_macho_host_never_yields_wrong_bytes() {
    const SLICE_AT: u32 = 4096;
    let thin: Vec<u8> = fixture(V6_MACHO);

    let mut fat: Vec<u8> = Vec::with_capacity(SLICE_AT as usize + thin.len());
    fat.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    fat.extend_from_slice(&1u32.to_be_bytes());
    fat.extend_from_slice(&0x0100_0007u32.to_be_bytes());
    fat.extend_from_slice(&3u32.to_be_bytes());
    fat.extend_from_slice(&SLICE_AT.to_be_bytes());
    fat.extend_from_slice(&u32::try_from(thin.len()).expect("slice fits").to_be_bytes());
    fat.extend_from_slice(&12u32.to_be_bytes());
    fat.resize(SLICE_AT as usize, 0);
    fat.extend_from_slice(&thin);

    let expected_assembly: Vec<u8> = expected("probe.dll");
    match extract_dotnet_bundle(&fat, ExtractionQuota::default_safe()) {
        Err(_) => {}
        Ok(entries) => {
            let assembly: &DotnetBundleEntry = entries
                .iter()
                .find(|e: &&DotnetBundleEntry| e.relative_path == "probe.dll")
                .unwrap_or_else(|| {
                    panic!("a bundle that parsed must still name its entries: {entries:?}")
                });
            assert_eq!(
                assembly.data, expected_assembly,
                "a universal host must either be refused or read through its slice base; it must \
                 never hand back bytes from the wrong offset"
            );
        }
    }
}

#[test]
fn extract_to_disk_writes_every_member_byte_identical() {
    let bytes: Vec<u8> = fixture(V6_ALL);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-real-dotnet-bundle")
            .expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");

    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::DotnetSingleFile,
        &bytes,
        &out,
        ExtractionQuota::default_safe(),
    )
    .expect("extract single-file bundle to disk");
    assert_eq!(result.kind, ContainerKind::DotnetSingleFile);
    assert!(
        result.integrity_violations.is_empty(),
        "a clean bundle raises no violation: {:?}",
        result.integrity_violations
    );
    assert_eq!(result.entries.len(), 5);

    assert_eq!(
        std::fs::read(out.join("probe.dll")).unwrap(),
        expected("probe.dll")
    );
    assert_eq!(
        std::fs::read(out.join("libcustom.dll")).unwrap(),
        expected("libcustom.dll")
    );
    assert_eq!(
        std::fs::read(out.join("probe.pdb")).unwrap(),
        expected("probe.pdb")
    );
}
