#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_binfmt::container::{ContainerKind, detect_container};
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

fn find_makecab() -> Option<PathBuf> {
    if let Some(found) = which("makecab") {
        return Some(found);
    }
    if cfg!(windows) {
        let candidate: PathBuf = PathBuf::from(r"C:\Windows\System32\makecab.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn seed_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut text: Vec<u8> = Vec::new();
    for _ in 0..60 {
        text.extend_from_slice(b"hello disrobe cabinet mszip round trip oracle line\n");
    }
    let mut prose: Vec<u8> = Vec::new();
    for _ in 0..90 {
        prose.extend_from_slice(b"the quick brown fox jumps over the lazy dog 0123456789\n");
    }
    let mut binary: Vec<u8> = Vec::with_capacity(8192);
    for i in 0..8192u32 {
        binary.push((i.wrapping_mul(2_246_822_519).rotate_left(11) & 0xff) as u8);
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

fn build_cab(
    makecab: &Path,
    seed_dir: &Path,
    out_dir: &Path,
    cab_name: &str,
    compression: &str,
    compress: bool,
    names: &[&str],
) -> Option<PathBuf> {
    std::fs::create_dir_all(out_dir).expect("mk out dir");
    let mut ddf: String = String::new();
    push_line(&mut ddf, &format!(".Set CabinetNameTemplate={cab_name}"));
    push_line(
        &mut ddf,
        &format!(".Set DiskDirectory1={}", out_dir.display()),
    );
    push_line(&mut ddf, &format!(".Set CompressionType={compression}"));
    push_line(
        &mut ddf,
        &format!(".Set Compress={}", if compress { "on" } else { "off" }),
    );
    push_line(&mut ddf, ".Set Cabinet=on");
    for name in names {
        push_line(&mut ddf, &format!("{}", seed_dir.join(name).display()));
    }
    let ddf_path: PathBuf = out_dir.join(format!("{cab_name}.ddf"));
    std::fs::write(&ddf_path, ddf).expect("write ddf");
    let Ok(status) = Command::new(makecab)
        .arg("/F")
        .arg(&ddf_path)
        .current_dir(out_dir)
        .status()
    else {
        return None;
    };
    if !status.success() {
        return None;
    }
    let cab_path: PathBuf = out_dir.join(cab_name);
    cab_path.is_file().then_some(cab_path)
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn assert_round_trip(cab_bytes: &[u8], originals: &[(String, Vec<u8>)], label: &str) {
    assert_eq!(
        detect_container(cab_bytes),
        Some(ContainerKind::Cab),
        "{label}: not detected as CAB"
    );
    let purpose: String = format!("disrobe_cab_extract_{label}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let out_dir: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to_with_quota(ContainerKind::Cab, cab_bytes, &out_dir, bounded_quota())
            .expect("extract cab");
    assert_eq!(result.kind, ContainerKind::Cab);
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
    }
}

#[test]
fn real_cab_mszip_round_trips() {
    let Some(makecab): Option<PathBuf> = find_makecab() else {
        eprintln!("skipping real_cab_mszip_round_trips: makecab not installed");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_cab_seed_mszip")
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let out_dir: PathBuf = scratch.path().join("out");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let names: Vec<&str> = vec!["alpha.txt", "beta.txt", "gamma.bin"];
    let Some(cab): Option<PathBuf> = build_cab(
        &makecab,
        &seed_dir,
        &out_dir,
        "disrobe_mszip.cab",
        "MSZIP",
        true,
        &names,
    ) else {
        panic!("makecab failed to build MSZIP cabinet");
    };
    let bytes: Vec<u8> = std::fs::read(&cab).expect("read cab");
    assert_round_trip(&bytes, &originals, "mszip");
}

#[test]
fn real_cab_stored_round_trips() {
    let Some(makecab): Option<PathBuf> = find_makecab() else {
        eprintln!("skipping real_cab_stored_round_trips: makecab not installed");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_cab_seed_store")
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let out_dir: PathBuf = scratch.path().join("out");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let names: Vec<&str> = vec!["alpha.txt", "beta.txt", "gamma.bin"];
    let Some(cab): Option<PathBuf> = build_cab(
        &makecab,
        &seed_dir,
        &out_dir,
        "disrobe_store.cab",
        "MSZIP",
        false,
        &names,
    ) else {
        panic!("makecab failed to build stored cabinet");
    };
    let bytes: Vec<u8> = std::fs::read(&cab).expect("read cab");
    assert_round_trip(&bytes, &originals, "stored");
}

#[test]
fn real_cab_lzx_round_trips_or_walls_honestly() {
    let Some(makecab): Option<PathBuf> = find_makecab() else {
        eprintln!("skipping real_cab_lzx_round_trips_or_walls_honestly: makecab not installed");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_cab_seed_lzx")
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let out_dir: PathBuf = scratch.path().join("out");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let names: Vec<&str> = vec!["alpha.txt", "beta.txt", "gamma.bin"];
    let Some(cab): Option<PathBuf> = build_cab(
        &makecab,
        &seed_dir,
        &out_dir,
        "disrobe_lzx.cab",
        "LZX",
        true,
        &names,
    ) else {
        panic!("makecab failed to build LZX cabinet");
    };
    let bytes: Vec<u8> = std::fs::read(&cab).expect("read cab");
    assert_eq!(
        detect_container(&bytes),
        Some(ContainerKind::Cab),
        "lzx cab not detected"
    );
    let extract_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_cab_lzx_out")
            .expect("create scratch directory");
    let extract_out: PathBuf = extract_scratch.path().join("out");
    let outcome: disrobe_binfmt::Result<ExtractionResult> =
        extract_to_with_quota(ContainerKind::Cab, &bytes, &extract_out, bounded_quota());
    match outcome {
        Err(disrobe_binfmt::Error::Cab(_)) => {}
        Err(other) => panic!("lzx cab: expected structured Cab error wall, got {other:?}"),
        Ok(result) => {
            for (name, body) in &originals {
                let entry: &ExtractedEntry = result
                    .entries
                    .iter()
                    .find(|e: &&ExtractedEntry| e.name == *name)
                    .unwrap_or_else(|| {
                        panic!("lzx cab claimed success but {name} missing from extraction")
                    });
                let disk: &PathBuf = entry
                    .disk_path
                    .as_ref()
                    .unwrap_or_else(|| panic!("lzx cab entry {name} has no disk path"));
                let recovered: Vec<u8> = std::fs::read(disk).expect("read lzx extracted");
                assert_eq!(
                    &recovered, body,
                    "lzx cab claimed success but byte mismatch for {name}"
                );
            }
        }
    }
}
