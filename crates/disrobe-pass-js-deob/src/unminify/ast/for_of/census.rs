#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use super::{ForOfStats, recover};

const CENSUS_STACK_BYTES: usize = 512 * 1024 * 1024;
const OVERSIZED_BYTES: u64 = 4 * 1024 * 1024;
const PINNED_FILES_SCANNED: usize = 144;
const PINNED_FILES_OVERSIZED: usize = 1;
const PINNED_CONVERSIONS: usize = 3;
const PINNED_FILES_WITH_A_CONVERSION: usize = 3;
const PINNED_CONVERSION_MEMBERS: &[&str] = &[
    "babel-preset-env/obfuscated.megafile.js#0:[10, 20]",
    "closure/obfuscated.megafile.simple.js#0:a",
    "closure/obfuscated.megafile.whitespace.js#0:[10,20]",
];

#[derive(Debug, Default, PartialEq, Eq)]
struct Census {
    files_scanned: usize,
    files_oversized: usize,
    files_panicked: usize,
    conversions: usize,
    files_with_a_conversion: usize,
    conversion_members: Vec<String>,
}

fn repository_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn javascript_files(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries): Result<std::fs::ReadDir, _> = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|extension: &std::ffi::OsStr| extension == "js")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn take_census(root: &Path) -> Census {
    let mut census: Census = Census::default();
    for path in javascript_files(root) {
        let Ok(metadata): Result<std::fs::Metadata, _> = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > OVERSIZED_BYTES {
            census.files_oversized += 1;
            continue;
        }
        let Ok(source): Result<String, _> = std::fs::read_to_string(&path) else {
            continue;
        };
        census.files_scanned += 1;
        let outcome: std::thread::Result<ForOfStats> =
            std::panic::catch_unwind(|| recover(&source).1);
        let Ok(stats): std::thread::Result<ForOfStats> = outcome else {
            census.files_panicked += 1;
            continue;
        };
        if stats.loops_converted == 0 {
            continue;
        }
        census.conversions += stats.loops_converted;
        census.files_with_a_conversion += 1;
        let relative: String = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (ordinal, subject) in stats.index_loop_subjects.into_iter().enumerate() {
            census
                .conversion_members
                .push(format!("{relative}#{ordinal}:{subject}"));
        }
    }
    census.conversion_members.sort();
    census
}

fn census_on_a_large_stack(root: PathBuf) -> Census {
    let handle: std::thread::JoinHandle<Census> = std::thread::Builder::new()
        .stack_size(CENSUS_STACK_BYTES)
        .spawn(move || take_census(&root))
        .expect("the census thread must start");
    handle.join().expect("the census thread must finish")
}

#[test]
fn the_index_loop_conversion_census_matches_its_pinned_baseline() {
    let root: PathBuf = repository_root().join("corpus/js");
    assert!(
        root.is_dir(),
        "the JavaScript corpus is absent at {}, so this census cannot report a result",
        root.display()
    );
    let census: Census = census_on_a_large_stack(root);
    assert_eq!(
        census.files_panicked, 0,
        "the unminifier panicked on {} corpus file(s)",
        census.files_panicked
    );
    assert_eq!(
        (census.files_scanned, census.files_oversized),
        (PINNED_FILES_SCANNED, PINNED_FILES_OVERSIZED),
        "the census input population changed"
    );
    assert_eq!(
        census.conversion_members.len(),
        census.conversions,
        "every counted index-loop conversion must have one exact member identity"
    );
    let expected_members: Vec<String> = PINNED_CONVERSION_MEMBERS
        .iter()
        .map(|member: &&str| (*member).to_owned())
        .collect();
    assert_eq!(
        census.conversion_members, expected_members,
        "the exact index-loop conversion population changed"
    );
    assert_eq!(
        (census.conversions, census.files_with_a_conversion),
        (PINNED_CONVERSIONS, PINNED_FILES_WITH_A_CONVERSION),
        "the index-loop conversion count changed"
    );
}
