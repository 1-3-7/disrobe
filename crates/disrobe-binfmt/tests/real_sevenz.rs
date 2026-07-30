#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract::{ExtractedEntry, ExtractionResult, extract_to_with_quota};
use disrobe_binfmt::quota::ExtractionQuota;

use common::requirement::{SEVEN_ZIP, describe_run, locate, unmeasured};

const fn bounded_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_per_entry_ratio: 4096,
        max_aggregate_ratio: 4096,
        ..ExtractionQuota::default_safe()
    }
}

fn seed_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut text: Vec<u8> = Vec::new();
    for _ in 0..60 {
        text.extend_from_slice(b"hello disrobe seven zip lzma round trip oracle line\n");
    }
    let mut prose: Vec<u8> = Vec::new();
    for _ in 0..90 {
        prose.extend_from_slice(b"the quick brown fox jumps over the lazy dog 0123456789\n");
    }
    let mut binary: Vec<u8> = Vec::with_capacity(8192);
    for i in 0..8192u32 {
        binary.push((i.wrapping_mul(2_654_435_761).rotate_left(7) & 0xff) as u8);
    }
    let files: Vec<(String, Vec<u8>)> = vec![
        ("alpha.txt".to_owned(), text),
        ("beta.txt".to_owned(), prose),
        ("gamma.bin".to_owned(), binary),
    ];
    std::fs::create_dir_all(dir).expect("mk seed dir");
    for (name, body) in &files {
        std::fs::write(dir.join(name), body).expect("write seed");
    }
    files
}

fn build_archive(
    seven_zip: &Path,
    seed_dir: &Path,
    out: &Path,
    method: &str,
) -> Result<(), String> {
    if out.exists() {
        std::fs::remove_file(out).ok();
    }
    let method_switch: String = format!("-m0={method}");
    let archive: String = out.display().to_string();
    let arguments: [&str; 7] = [
        "a",
        "-t7z",
        method_switch.as_str(),
        archive.as_str(),
        "alpha.txt",
        "beta.txt",
        "gamma.bin",
    ];
    let output: Output = Command::new(seven_zip)
        .args(arguments)
        .current_dir(seed_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|error: std::io::Error| {
            format!(
                "this process cannot start the located 7-Zip binary {} ({error}), so no reference \
                 archive was written",
                seven_zip.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "the located 7-Zip binary refused to write the reference archive: {}",
            describe_run(seven_zip, &arguments, &output)
        ));
    }
    if !out.is_file() {
        return Err(format!(
            "the located 7-Zip binary reported success but wrote no file at {}: {}",
            out.display(),
            describe_run(seven_zip, &arguments, &output)
        ));
    }
    Ok(())
}

fn assert_round_trip(archive_bytes: &[u8], originals: &[(String, Vec<u8>)], label: &str) {
    let purpose: String = format!("disrobe_sevenz_extract_{label}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let out_dir: PathBuf = scratch.path().join("out");
    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::SevenZ,
        archive_bytes,
        &out_dir,
        bounded_quota(),
    )
    .expect("extract 7z");
    assert_eq!(result.kind, ContainerKind::SevenZ);
    assert!(
        result.integrity_violations.is_empty(),
        "{label}: unexpected violations {:?}",
        result.integrity_violations
    );
    for (name, body) in originals {
        let entry: &ExtractedEntry = result
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.name == *name)
            .unwrap_or_else(|| panic!("{label}: missing entry {name} in {:?}", result.entries));
        let disk: &PathBuf = entry
            .disk_path
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: entry {name} has no disk path"));
        let recovered: Vec<u8> = std::fs::read(disk).expect("read extracted");
        assert_eq!(
            &recovered,
            body,
            "{label}: byte-exact mismatch for {name} (got {} bytes, want {})",
            recovered.len(),
            body.len()
        );
        assert_eq!(
            entry.uncompressed_size,
            body.len() as u64,
            "{label}: size metadata mismatch for {name}"
        );
    }
}

fn round_trips_against_the_real_writer(method: &str, label: &str, description: &str) {
    let graded: String =
        format!("byte-exact recovery of a {description} 7z archive built by the real 7-Zip writer");
    let seven_zip: PathBuf = match locate(&SEVEN_ZIP) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(&SEVEN_ZIP, &graded, &reason);
            return;
        }
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("disrobe_sevenz_seed_{label}"))
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let archive: PathBuf = seed_dir.join(format!("out_{label}.7z"));
    if let Err(reason) = build_archive(&seven_zip, &seed_dir, &archive, method) {
        unmeasured(&SEVEN_ZIP, &graded, &reason);
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&archive).expect("read archive");
    assert_round_trip(&bytes, &originals, label);
}

#[test]
fn real_sevenz_lzma2_round_trips() {
    round_trips_against_the_real_writer("LZMA2", "lzma2", "LZMA2");
}

#[test]
fn real_sevenz_lzma_round_trips() {
    round_trips_against_the_real_writer("LZMA", "lzma", "LZMA");
}

#[test]
fn real_sevenz_stored_round_trips() {
    round_trips_against_the_real_writer("Copy", "stored", "stored");
}
