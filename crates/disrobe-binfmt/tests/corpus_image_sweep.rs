#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};

use common::requirement::corpus_path;
use disrobe_binfmt::error::Error;
use disrobe_binfmt::rewrite::{ImagePlan, PlanCoverage, plan_native_image};

const MAX_DIRECTORIES: usize = 8_192;
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_NATIVE_IMAGES: usize = 274;

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut files: Vec<PathBuf> = Vec::new();
    let mut visited: usize = 0;

    while let Some(directory) = pending.pop() {
        visited += 1;
        assert!(
            visited <= MAX_DIRECTORIES,
            "the corpus walk visited more than {MAX_DIRECTORIES} directories"
        );
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(std::result::Result::ok) {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn looks_native(bytes: &[u8], path: &Path) -> bool {
    let Some(magic) = bytes.get(..4) else {
        return false;
    };
    if magic.starts_with(b"MZ") || magic == b"\x7fELF" {
        return true;
    }
    let word: u32 = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
    if matches!(word, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE) {
        return true;
    }
    path.extension()
        .is_some_and(|extension: &std::ffi::OsStr| extension == "o" || extension == "obj")
}

#[test]
fn every_native_image_in_the_committed_corpus_re_emits_without_drift() {
    let root: PathBuf = corpus_path("");
    let files: Vec<PathBuf> = walk(&root);
    assert!(
        files.len() >= 3_000,
        "the corpus walk found {} file(s); a walk that finds almost nothing measures almost \
         nothing",
        files.len()
    );

    let mut planned: usize = 0;
    let mut detector_refused: Vec<String> = Vec::new();
    let mut writer_refused: Vec<String> = Vec::new();
    let mut drifted: Vec<String> = Vec::new();

    for path in &files {
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_IMAGE_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if !looks_native(&bytes, path) {
            continue;
        }
        let relative: String = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        match plan_native_image(&bytes) {
            Ok(plan) => {
                planned += 1;
                let coverage: PlanCoverage = plan.coverage();
                assert!(
                    coverage.is_complete(),
                    "{relative}: structure {} plus opaque {} must account for every one of {} \
                     bytes",
                    coverage.structure_bytes,
                    coverage.opaque_bytes,
                    coverage.file_len
                );
                assert!(
                    coverage.structure_bytes > 0,
                    "{relative}: a plan that types no byte is a byte copy, not a model"
                );
                match emit(&plan, &bytes) {
                    Ok(true) => {}
                    Ok(false) => drifted.push(format!("{relative}: re-emission differs")),
                    Err(error) => drifted.push(format!("{relative}: re-emission failed: {error}")),
                }
            }
            Err(Error::NativeParse(message)) => {
                detector_refused.push(format!("{relative}: {message}"));
            }
            Err(other) => writer_refused.push(format!("{relative}: {other}")),
        }
    }

    assert!(
        drifted.is_empty(),
        "{} of {planned} planned native image(s) did not re-emit byte for byte:\n  {}",
        drifted.len(),
        drifted.join("\n  ")
    );
    assert!(
        writer_refused.is_empty(),
        "{} native image(s) reached the writer and were refused by it; a refusal here is a \
         capability gap that must be named in this case before it is accepted:\n  {}",
        writer_refused.len(),
        writer_refused.join("\n  ")
    );
    assert!(
        planned >= MIN_NATIVE_IMAGES,
        "the sweep planned {planned} native image(s) out of {} corpus file(s), fewer than the \
         {MIN_NATIVE_IMAGES} this tree tracks; {} were turned away by the format detector before \
         the writer saw them:\n  {}",
        files.len(),
        detector_refused.len(),
        detector_refused.join("\n  ")
    );
}

fn emit(plan: &ImagePlan, bytes: &[u8]) -> Result<bool, Error> {
    let emitted: Vec<u8> = plan.emit(bytes)?;
    Ok(emitted == bytes)
}
