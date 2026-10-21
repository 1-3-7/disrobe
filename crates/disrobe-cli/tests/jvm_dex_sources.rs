#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{run_disrobe, temp_dir};

fn corpus(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push(rel);
    path
}

fn java_files(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read sources tree") {
            let path: PathBuf = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "java") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn dex_decompilation_writes_one_source_per_top_level_class_and_the_tree_compiles() {
    let scratch = temp_dir("dex-sources");
    let out: PathBuf = scratch.path().join("out");
    let dex: PathBuf = corpus("corpus/jvm/dex/EdgeCases.dex");
    let run = run_disrobe(&[
        "jvm",
        "decompile",
        dex.to_str().expect("utf-8 path"),
        "--out",
        out.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "jvm decompile failed: {}", run.stderr);
    let combined: PathBuf = out.join("EdgeCases.java");
    assert!(combined.is_file(), "the combined listing is still written");
    let sources: PathBuf = out.join("sources");
    let files: Vec<PathBuf> = java_files(&sources);
    assert!(
        files.contains(&sources.join("EdgeCases.java")),
        "EdgeCases.java is emitted at the package root: {files:?}"
    );
    let record_tag: PathBuf = sources.join("com/android/tools/r8/RecordTag.java");
    assert!(
        files.contains(&record_tag),
        "the D8 synthetic lives in its own package directory: {files:?}"
    );
    let edge_cases_prefix: PathBuf = sources.join("EdgeCases");
    let stray: Vec<&PathBuf> = files
        .iter()
        .filter(|f: &&PathBuf| {
            **f != record_tag
                && !f
                    .to_str()
                    .is_some_and(|s: &str| s.starts_with(edge_cases_prefix.to_str().unwrap_or("")))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "every emitted file is EdgeCases, one of its nest members, or the D8 synthetic: {stray:?}"
    );
    let classes: PathBuf = scratch.path().join("classes");
    std::fs::create_dir_all(&classes).expect("classes dir");
    let javac = Command::new("javac")
        .arg("-proc:none")
        .arg("-nowarn")
        .arg("-cp")
        .arg(corpus("corpus/jvm/megafile/EdgeCases-baseline.jar"))
        .arg("-d")
        .arg(&classes)
        .args(&files)
        .output()
        .expect("javac on PATH");
    let stderr: String = String::from_utf8_lossy(&javac.stderr).into_owned();
    let errors: usize = stderr
        .lines()
        .filter(|line: &&str| line.contains(".java:") && line.contains(": error:"))
        .count();
    assert_eq!(
        errors, WHOLE_TREE_JAVAC_ERRORS,
        "javac errors over the emitted tree moved from the pinned count; the pin only ratchets down:\n{stderr}"
    );
}

const WHOLE_TREE_JAVAC_ERRORS: usize = 17;

#[test]
fn a_source_path_that_escapes_the_output_directory_is_refused_by_name() {
    let mut sources: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    disrobe_pass_jvm::merge_rendered_source(
        &mut sources,
        "../escape/Evil.java".to_owned(),
        "class Evil {}\n".to_owned(),
    );
    let scratch = temp_dir("dex-sources-escape");
    let root: PathBuf = scratch.path().join("sources");
    let error = disrobe_pass_jvm::write_source_tree(&root, &sources)
        .expect_err("a traversal path is refused");
    assert!(error.to_string().contains("../escape/Evil.java"), "{error}");
    assert!(!root.exists(), "nothing is written when a path is refused");
}
