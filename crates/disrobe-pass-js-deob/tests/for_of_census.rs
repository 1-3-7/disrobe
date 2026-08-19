#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const CENSUS_STACK_BYTES: usize = 512 * 1024 * 1024;
const OVERSIZED_BYTES: u64 = 4 * 1024 * 1024;

const PINNED_FILES_SCANNED: usize = 144;
const PINNED_FILES_OVERSIZED: usize = 1;
const PINNED_CONVERSIONS: usize = 6;
const PINNED_FILES_WITH_A_CONVERSION: usize = 4;

#[derive(Debug, Default, PartialEq, Eq)]
struct Census {
    files_scanned: usize,
    files_oversized: usize,
    files_panicked: usize,
    conversions: usize,
    files_with_a_conversion: usize,
    subjects: BTreeMap<String, usize>,
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
                .is_some_and(|ext: &std::ffi::OsStr| ext == "js")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn for_of_heads(text: &str) -> Vec<String> {
    let mut heads: Vec<String> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let needle: &[u8] = b" of ";
    let mut index: usize = 0;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            let tail: &str = &text[index + needle.len()..];
            let end: usize = tail.find([')', ';', '\n']).unwrap_or(0);
            if end > 0 {
                heads.push(tail[..end].trim().to_owned());
            }
        }
        index += 1;
    }
    heads.sort();
    heads
}

fn subjects_introduced(input: &str, recovered: &str) -> Vec<String> {
    let before: Vec<String> = for_of_heads(input);
    let mut remaining: Vec<String> = before;
    let mut introduced: Vec<String> = Vec::new();
    for head in for_of_heads(recovered) {
        if let Some(position) = remaining.iter().position(|seen: &String| *seen == head) {
            remaining.remove(position);
        } else {
            introduced.push(head);
        }
    }
    introduced
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
        let outcome: std::thread::Result<(String, AstUnminifyStats)> =
            std::panic::catch_unwind(|| unminify_ast(&source));
        let Ok((recovered, stats)): std::thread::Result<(String, AstUnminifyStats)> = outcome
        else {
            census.files_panicked += 1;
            continue;
        };
        if stats.index_loops_to_for_of == 0 {
            continue;
        }
        census.conversions += stats.index_loops_to_for_of;
        census.files_with_a_conversion += 1;
        for subject in subjects_introduced(&source, &recovered) {
            *census.subjects.entry(subject).or_insert(0) += 1;
        }
    }
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
        "the unminifier panicked on {} corpus file(s); a census cannot price a policy while any \
         input is unreadable",
        census.files_panicked
    );
    assert_eq!(
        (census.files_scanned, census.files_oversized),
        (PINNED_FILES_SCANNED, PINNED_FILES_OVERSIZED),
        "the corpus denominator moved; a conversion count is only comparable against the same \
         file set. Update the pinned figures in the same commit that changes the corpus"
    );
    assert_eq!(
        (census.conversions, census.files_with_a_conversion),
        (PINNED_CONVERSIONS, PINNED_FILES_WITH_A_CONVERSION),
        "index-loop to for-of conversions moved. Subjects observed: {:?}",
        census.subjects
    );
}
