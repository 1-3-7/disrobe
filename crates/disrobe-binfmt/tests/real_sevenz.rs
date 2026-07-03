#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract::{ExtractedEntry, ExtractionResult, extract_to_with_quota};
use disrobe_binfmt::quota::ExtractionQuota;

const fn bounded_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_per_entry_ratio: 4096,
        max_aggregate_ratio: 4096,
        ..ExtractionQuota::default_safe()
    }
}

fn which(tool: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            for ext in ["", ".exe"] {
                let candidate: PathBuf = dir.join(format!("{tool}{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn find_seven_zip() -> Option<PathBuf> {
    for name in ["7z", "7za", "7zz", "7zr"] {
        if let Some(found) = which(name) {
            return Some(found);
        }
    }
    if cfg!(windows) {
        let candidates: [&str; 2] = [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ];
        return candidates
            .iter()
            .map(PathBuf::from)
            .find(|p: &PathBuf| p.is_file());
    }
    None
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

fn build_archive(seven_zip: &Path, seed_dir: &Path, out: &Path, method: &str) -> bool {
    if out.exists() {
        std::fs::remove_file(out).ok();
    }
    let Ok(status) = Command::new(seven_zip)
        .arg("a")
        .arg("-t7z")
        .arg(format!("-m0={method}"))
        .arg(out)
        .arg("alpha.txt")
        .arg("beta.txt")
        .arg("gamma.bin")
        .current_dir(seed_dir)
        .status()
    else {
        return false;
    };
    status.success() && out.is_file()
}

fn assert_round_trip(archive_bytes: &[u8], originals: &[(String, Vec<u8>)], label: &str) {
    let out_dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_sevenz_extract_{label}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out_dir);
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
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn real_sevenz_lzma2_round_trips() {
    let Some(seven_zip): Option<PathBuf> = find_seven_zip() else {
        eprintln!("skipping real_sevenz_lzma2_round_trips: 7-Zip not installed");
        return;
    };
    let seed_dir: PathBuf = std::env::temp_dir().join("disrobe_sevenz_seed_lzma2");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let archive: PathBuf = seed_dir.join("out_lzma2.7z");
    if !build_archive(&seven_zip, &seed_dir, &archive, "LZMA2") {
        eprintln!("skipping real_sevenz_lzma2_round_trips: 7-Zip could not build the archive");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&archive).expect("read archive");
    assert_round_trip(&bytes, &originals, "lzma2");
}

#[test]
fn real_sevenz_lzma_round_trips() {
    let Some(seven_zip): Option<PathBuf> = find_seven_zip() else {
        eprintln!("skipping real_sevenz_lzma_round_trips: 7-Zip not installed");
        return;
    };
    let seed_dir: PathBuf = std::env::temp_dir().join("disrobe_sevenz_seed_lzma");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let archive: PathBuf = seed_dir.join("out_lzma.7z");
    if !build_archive(&seven_zip, &seed_dir, &archive, "LZMA") {
        eprintln!("skipping real_sevenz_lzma_round_trips: 7-Zip could not build the archive");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&archive).expect("read archive");
    assert_round_trip(&bytes, &originals, "lzma");
}

#[test]
fn real_sevenz_stored_round_trips() {
    let Some(seven_zip): Option<PathBuf> = find_seven_zip() else {
        eprintln!("skipping real_sevenz_stored_round_trips: 7-Zip not installed");
        return;
    };
    let seed_dir: PathBuf = std::env::temp_dir().join("disrobe_sevenz_seed_copy");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let archive: PathBuf = seed_dir.join("out_copy.7z");
    if !build_archive(&seven_zip, &seed_dir, &archive, "Copy") {
        eprintln!("skipping real_sevenz_stored_round_trips: 7-Zip could not build the archive");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&archive).expect("read archive");
    assert_round_trip(&bytes, &originals, "stored");
}
