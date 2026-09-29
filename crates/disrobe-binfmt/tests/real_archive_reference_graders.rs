#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract::{ExtractionResult, extract_to_with_quota};
use disrobe_binfmt::quota::ExtractionQuota;

use common::requirement::{CABEXTRACT, SEVEN_ZIP, describe_run, locate, unmeasured};

const fn bounded_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_per_entry_ratio: 4096,
        max_aggregate_ratio: 4096,
        ..ExtractionQuota::default_safe()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn walk_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries: std::fs::ReadDir = std::fs::read_dir(&dir)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", dir.display()));
        for entry in entries {
            let entry: std::fs::DirEntry = entry.expect("read dir entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative: PathBuf = path
                .strip_prefix(root)
                .expect("walked path stays under root")
                .to_path_buf();
            let key: String = relative
                .components()
                .map(|component: std::path::Component<'_>| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let bytes: Vec<u8> = std::fs::read(&path)
                .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
            out.insert(key, bytes);
        }
    }
    out
}

fn disrobe_members(result: &ExtractionResult) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &result.entries {
        let Some(disk_path): Option<&PathBuf> = entry.disk_path.as_ref() else {
            continue;
        };
        let bytes: Vec<u8> = std::fs::read(disk_path).unwrap_or_else(|error: std::io::Error| {
            panic!("read recovered {}: {error}", disk_path.display())
        });
        out.insert(entry.name.clone(), bytes);
    }
    out
}

fn extract_with_disrobe(kind: ContainerKind, bytes: &[u8], out_dir: &Path) -> ExtractionResult {
    extract_to_with_quota(kind, bytes, out_dir, bounded_quota())
        .unwrap_or_else(|error: disrobe_binfmt::Error| panic!("disrobe extraction failed: {error}"))
}

fn members_match(
    reference: &BTreeMap<String, Vec<u8>>,
    recovered: &BTreeMap<String, Vec<u8>>,
    checked_names: &[&str],
) -> Result<(), String> {
    for name in checked_names {
        let want: &Vec<u8> = reference
            .get(*name)
            .ok_or_else(|| format!("reference extractor never produced {name}"))?;
        let got: &Vec<u8> = recovered
            .get(*name)
            .ok_or_else(|| format!("disrobe never produced {name}"))?;
        if got != want {
            return Err(format!(
                "{name}: disrobe SHA-256 {} does not match the reference extractor's {}",
                sha256_hex(got),
                sha256_hex(want)
            ));
        }
    }
    Ok(())
}

fn run_seven_zip_extract(seven_zip: &Path, archive: &Path, out_dir: &Path) -> Output {
    std::fs::create_dir_all(out_dir).expect("create reference output dir");
    let mut out_arg: std::ffi::OsString = std::ffi::OsString::from("-o");
    out_arg.push(out_dir.as_os_str());
    Command::new(seven_zip)
        .arg("x")
        .arg("-y")
        .arg(out_arg)
        .arg(archive)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "this process cannot start the located 7-Zip binary {} ({error})",
                seven_zip.display()
            )
        })
}

fn seed_repo_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let root: PathBuf = common::repository_root();
    let sources: [(&str, &str); 3] = [
        ("crates/disrobe-binfmt/src/quota.rs", "a_quota_source.rs"),
        ("crates/disrobe-binfmt/Cargo.toml", "b_manifest.toml"),
        ("README.md", "c_readme.md"),
    ];
    std::fs::create_dir_all(dir).expect("mk seed dir");
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for (relative, seed_name) in sources {
        let body: Vec<u8> = std::fs::read(root.join(relative))
            .unwrap_or_else(|error| panic!("read repository file {relative}: {error}"));
        std::fs::write(dir.join(seed_name), &body).expect("write seed file");
        files.push((seed_name.to_owned(), body));
    }
    files
}

#[test]
fn real_sevenz_solid_archive_of_repository_files_matches_the_reference_extractor() {
    let graded: String =
        "byte-exact recovery of a solid 7z archive holding real repository files, \
                           checked against 7-Zip's own extractor on the same bytes"
            .to_owned();
    let seven_zip: PathBuf = match locate(&SEVEN_ZIP) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(&SEVEN_ZIP, &graded, &reason);
            return;
        }
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_sevenz_solid_reference")
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let files: Vec<(String, Vec<u8>)> = seed_repo_files(&seed_dir);
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    let archive: PathBuf = seed_dir.join("solid.7z");
    let build_output: Output = Command::new(&seven_zip)
        .args(["a", "-t7z", "-ms=on", "-m0=LZMA2"])
        .arg(&archive)
        .args(names.iter().copied())
        .current_dir(&seed_dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("this process cannot start 7-Zip to build the solid archive: {error}")
        });
    assert!(
        build_output.status.success(),
        "7-Zip refused to build the solid archive: {}",
        describe_run(&seven_zip, &["a", "-t7z", "-ms=on"], &build_output)
    );
    let archive_bytes: Vec<u8> = std::fs::read(&archive).expect("read solid archive");

    let reference_dir: PathBuf = scratch.path().join("reference");
    let reference_output: Output = run_seven_zip_extract(&seven_zip, &archive, &reference_dir);
    assert!(
        reference_output.status.success(),
        "7-Zip refused to extract its own solid archive: {}",
        describe_run(&seven_zip, &["x"], &reference_output)
    );
    let reference: BTreeMap<String, Vec<u8>> = walk_files(&reference_dir);

    let disrobe_out: PathBuf = scratch.path().join("disrobe_out");
    let result: ExtractionResult =
        extract_with_disrobe(ContainerKind::SevenZ, &archive_bytes, &disrobe_out);
    assert!(
        result.integrity_violations.is_empty(),
        "unexpected violations extracting the solid archive: {:?}",
        result.integrity_violations
    );
    let recovered: BTreeMap<String, Vec<u8>> = disrobe_members(&result);
    members_match(&reference, &recovered, &names)
        .expect("member bytes must match 7-Zip's own extraction");
}

#[test]
fn a_flipped_byte_in_the_sevenz_recovery_is_caught_by_the_reference_comparison() {
    let mut reference: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    reference.insert(
        "a_quota_source.rs".to_owned(),
        b"authentic content".to_vec(),
    );
    let mut recovered: BTreeMap<String, Vec<u8>> = reference.clone();
    recovered
        .get_mut("a_quota_source.rs")
        .expect("recovered entry")[0] ^= 0xFF;
    let outcome: Result<(), String> = members_match(&reference, &recovered, &["a_quota_source.rs"]);
    assert!(
        outcome.is_err(),
        "a single corrupted byte in disrobe's recovered member must fail the reference comparison"
    );
}

const RAR_FIXTURES: [&str; 10] = [
    "store-rar4.rar",
    "store-rar5.rar",
    "normal-rar4.rar",
    "normal-rar5.rar",
    "ppmd-rar4.rar",
    "multiblock-rar5.rar",
    "filter-e8e9-rar5.rar",
    "filter-delta-rar5.rar",
    "filter-e8-rar3.rar",
    "lowdist-reset-rar3.rar",
];

#[test]
fn real_rar_fixtures_match_the_reference_extractor_member_for_member() {
    let graded: String = "byte-exact recovery of the committed RAR fixtures, checked against \
                           7-Zip's own RAR reader on the same bytes"
        .to_owned();
    let seven_zip: PathBuf = match locate(&SEVEN_ZIP) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(&SEVEN_ZIP, &graded, &reason);
            return;
        }
    };
    for fixture in RAR_FIXTURES {
        let archive: PathBuf = common::fixture_path("rar", fixture);
        let bytes: Vec<u8> = std::fs::read(&archive)
            .unwrap_or_else(|error| panic!("read corpus/binfmt/rar/{fixture}: {error}"));

        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&format!("disrobe_rar_reference_{fixture}"))
                .expect("create scratch directory");
        let reference_dir: PathBuf = scratch.path().join("reference");
        let reference_output: Output = run_seven_zip_extract(&seven_zip, &archive, &reference_dir);
        assert!(
            reference_output.status.success(),
            "7-Zip refused to extract {fixture}: {}",
            describe_run(&seven_zip, &["x"], &reference_output)
        );
        let reference: BTreeMap<String, Vec<u8>> = walk_files(&reference_dir);

        let disrobe_out: PathBuf = scratch.path().join("disrobe_out");
        let result: ExtractionResult =
            extract_with_disrobe(ContainerKind::Rar, &bytes, &disrobe_out);
        assert!(
            result.integrity_violations.is_empty(),
            "{fixture}: unexpected violations {:?}",
            result.integrity_violations
        );
        let recovered: BTreeMap<String, Vec<u8>> = disrobe_members(&result);
        let names: Vec<&str> = reference.keys().map(String::as_str).collect();
        members_match(&reference, &recovered, &names)
            .unwrap_or_else(|error| panic!("{fixture}: {error}"));
    }
}

#[test]
fn a_flipped_byte_in_a_rar_recovery_is_caught_by_the_reference_comparison() {
    let mut reference: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    reference.insert(
        "hello.txt".to_owned(),
        b"the reference tool's own bytes".to_vec(),
    );
    let mut recovered: BTreeMap<String, Vec<u8>> = reference.clone();
    recovered.get_mut("hello.txt").expect("recovered entry")[3] ^= 0x01;
    let outcome: Result<(), String> = members_match(&reference, &recovered, &["hello.txt"]);
    assert!(
        outcome.is_err(),
        "a single corrupted byte in disrobe's recovered RAR member must fail the reference \
         comparison"
    );
}

#[test]
fn the_hostile_delta_filter_member_is_refused_by_disrobe_and_by_the_reference_extractor() {
    let graded: String = "the refusal decision for a RAR member whose delta filter names zero \
                           channels, cross-checked against 7-Zip's own decode of the same bytes"
        .to_owned();
    let seven_zip: PathBuf = match locate(&SEVEN_ZIP) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(&SEVEN_ZIP, &graded, &reason);
            return;
        }
    };
    let fixture: &str = "hostile-filter-staticdata-rar3.rar";
    let archive: PathBuf = common::fixture_path("rar", fixture);
    let bytes: Vec<u8> = std::fs::read(&archive)
        .unwrap_or_else(|error| panic!("read corpus/binfmt/rar/{fixture}: {error}"));

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_rar_hostile_reference")
            .expect("create scratch directory");
    let reference_dir: PathBuf = scratch.path().join("reference");
    let reference_output: Output = run_seven_zip_extract(&seven_zip, &archive, &reference_dir);
    let reference_member: PathBuf = reference_dir.join("poc_b76.txt");
    let reference_produced_plaintext: bool = reference_output.status.success()
        && reference_member.is_file()
        && std::fs::metadata(&reference_member)
            .is_ok_and(|metadata: std::fs::Metadata| metadata.len() > 0);
    assert!(
        !reference_produced_plaintext,
        "the reference extractor unexpectedly recovered plaintext for a member whose filter \
         record names zero channels: {}",
        describe_run(&seven_zip, &["x"], &reference_output)
    );

    let disrobe_out: PathBuf = scratch.path().join("disrobe_out");
    let result: ExtractionResult = extract_with_disrobe(ContainerKind::Rar, &bytes, &disrobe_out);
    assert!(
        !disrobe_out.join("poc_b76.txt").exists(),
        "disrobe must not publish member bytes for a filter record naming zero channels"
    );
    assert!(
        result
            .integrity_violations
            .iter()
            .any(|violation: &String| violation.contains("poc_b76.txt")),
        "disrobe's refusal list must name poc_b76.txt: {:?}",
        result.integrity_violations
    );
}

fn build_duplicate_name_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
    let folder: &mut cab::FolderBuilder = builder.add_folder(cab::CompressionType::MsZip);
    for (name, _) in files {
        folder.add_file(*name);
    }
    let mut writer: cab::CabinetWriter<std::io::Cursor<Vec<u8>>> = builder
        .build(std::io::Cursor::new(Vec::new()))
        .expect("build cabinet");
    let mut index: usize = 0;
    while let Some(mut file) = writer.next_file().expect("next cab file") {
        std::io::Write::write_all(&mut file, files[index].1).expect("write cab member");
        index += 1;
    }
    writer.finish().expect("finish cabinet").into_inner()
}

#[test]
fn real_cab_with_a_duplicate_name_leaves_the_solo_member_matching_the_reference_extractor() {
    let graded: String = "byte-exact recovery of the one unambiguous member in a cabinet that \
                           also carries two members sharing a name, checked against cabextract's \
                           own extractor on the same bytes"
        .to_owned();
    let cabextract: PathBuf = match locate(&CABEXTRACT) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(&CABEXTRACT, &graded, &reason);
            return;
        }
    };
    let files: [(&str, &[u8]); 3] = [
        ("dup.txt", b"first body written under the shared name"),
        (
            "solo.txt",
            b"the one member whose name is unique in this cabinet",
        ),
        (
            "dup.txt",
            b"second, different body under the same shared name",
        ),
    ];
    let bytes: Vec<u8> = build_duplicate_name_cab(&files);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_cab_duplicate_reference")
            .expect("create scratch directory");
    let cab_path: PathBuf = scratch.path().join("duplicate.cab");
    std::fs::write(&cab_path, &bytes).expect("write cabinet");

    let reference_dir: PathBuf = scratch.path().join("reference");
    std::fs::create_dir_all(&reference_dir).expect("create reference output dir");
    let reference_output: Output = Command::new(&cabextract)
        .arg("-d")
        .arg(&reference_dir)
        .arg(&cab_path)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "this process cannot start the located cabextract binary {} ({error})",
                cabextract.display()
            )
        });
    let reference_solo: PathBuf = reference_dir.join("solo.txt");
    assert!(
        reference_solo.is_file(),
        "cabextract must recover the unambiguous member: {}",
        describe_run(&cabextract, &["-d"], &reference_output)
    );
    let mut reference: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    reference.insert(
        "solo.txt".to_owned(),
        std::fs::read(&reference_solo).expect("read reference solo.txt"),
    );

    let disrobe_out: PathBuf = scratch.path().join("disrobe_out");
    let result: ExtractionResult = extract_with_disrobe(ContainerKind::Cab, &bytes, &disrobe_out);
    let recovered: BTreeMap<String, Vec<u8>> = disrobe_members(&result);
    members_match(&reference, &recovered, &["solo.txt"])
        .expect("the unambiguous member must match cabextract's own extraction");
    assert!(
        result
            .integrity_violations
            .iter()
            .any(|violation: &String| violation.contains("dup.txt")),
        "disrobe's refusal list must name the duplicated member dup.txt: {:?}",
        result.integrity_violations
    );
}

#[test]
fn a_flipped_byte_in_a_cab_recovery_is_caught_by_the_reference_comparison() {
    let mut reference: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    reference.insert(
        "solo.txt".to_owned(),
        b"the reference tool's own bytes".to_vec(),
    );
    let mut recovered: BTreeMap<String, Vec<u8>> = reference.clone();
    recovered.get_mut("solo.txt").expect("recovered entry")[5] ^= 0x10;
    let outcome: Result<(), String> = members_match(&reference, &recovered, &["solo.txt"]);
    assert!(
        outcome.is_err(),
        "a single corrupted byte in disrobe's recovered CAB member must fail the reference \
         comparison"
    );
}
