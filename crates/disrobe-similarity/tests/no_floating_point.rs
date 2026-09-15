#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const FLOAT_WIDTHS: [u32; 2] = [32, 64];

const SCANNED_DIRECTORIES: [&str; 2] = ["src", "tests"];

const ARITHMETIC_LINT: &str = "deny(clippy::float_arithmetic)";

fn is_word_character(value: char) -> bool {
    value.is_alphanumeric() || value == '_'
}

fn names_token(text: &str, needle: &str) -> bool {
    text.match_indices(needle)
        .any(|(offset, matched): (usize, &str)| {
            let before: Option<char> = text
                .get(..offset)
                .and_then(|head: &str| head.chars().next_back());
            let after: Option<char> = text
                .get(offset.saturating_add(matched.len())..)
                .and_then(|tail: &str| tail.chars().next());
            !before.is_some_and(is_word_character) && !after.is_some_and(is_word_character)
        })
}

fn collect_rust_sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut ordered: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry: fs::DirEntry| entry.path())
        .collect();
    ordered.sort();
    for path in ordered {
        if path.is_dir() {
            collect_rust_sources(&path, found);
        } else if path
            .extension()
            .is_some_and(|suffix: &std::ffi::OsStr| suffix == "rs")
        {
            found.push(path);
        }
    }
}

fn crate_sources() -> Vec<PathBuf> {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut found: Vec<PathBuf> = Vec::new();
    for directory in SCANNED_DIRECTORIES {
        collect_rust_sources(&root.join(directory), &mut found);
    }
    found
}

#[test]
fn no_source_file_in_this_crate_names_a_floating_point_type() {
    let sources: Vec<PathBuf> = crate_sources();
    assert!(
        sources.len() >= 10,
        "the scan found only {} files, so it is not reading this crate",
        sources.len()
    );

    let needles: Vec<String> = FLOAT_WIDTHS
        .iter()
        .map(|width: &u32| format!("f{width}"))
        .collect();
    for path in &sources {
        let text: String = fs::read_to_string(path).expect("a crate source file is readable");
        for needle in &needles {
            assert!(
                !names_token(&text, needle),
                "{} names {needle}, and a reduction over that type is not portable",
                path.display()
            );
        }
    }
}

#[test]
fn the_crate_root_denies_floating_point_arithmetic() {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text: String = fs::read_to_string(&root).expect("the crate root is readable");
    assert!(
        text.contains(ARITHMETIC_LINT),
        "{} must keep the lint that rejects float arithmetic the token scan cannot see, \
         such as an inferred literal",
        root.display()
    );
}

#[test]
fn the_token_scan_would_notice_a_floating_point_type() {
    let widths: Vec<String> = FLOAT_WIDTHS
        .iter()
        .map(|width: &u32| format!("f{width}"))
        .collect();
    for needle in &widths {
        assert!(names_token(&format!("let ratio: {needle} = 1;"), needle));
        assert!(names_token(&format!("value as {needle}"), needle));
        assert!(names_token(&format!("{needle}::MAX"), needle));
        assert!(!names_token(&format!("0x{needle}0"), needle));
        assert!(!names_token(&format!("of{needle}set"), needle));
    }
}
