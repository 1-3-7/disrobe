#![allow(clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

const NEEDLES: [&str; 3] = ["push(\"target\")", "target/debug", "target\\\\debug"];

fn test_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

#[test]
fn no_integration_test_builds_a_workspace_relative_path_to_the_binary() {
    let root: PathBuf = test_directory();
    let entries: std::fs::ReadDir =
        std::fs::read_dir(&root).expect("the integration test directory must be readable");
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("a directory entry must be readable").path();
        if path
            .extension()
            .and_then(|ext: &std::ffi::OsStr| ext.to_str())
            != Some("rs")
        {
            continue;
        }
        if path
            .file_name()
            .and_then(|name: &std::ffi::OsStr| name.to_str())
            == Some("binary_resolution_is_target_dir_agnostic.rs")
        {
            continue;
        }
        scanned += 1;
        let text: String = std::fs::read_to_string(&path).expect("a test source must be readable");
        if NEEDLES.iter().any(|needle: &&str| text.contains(needle)) {
            offenders.push(
                path.file_name()
                    .and_then(|name: &std::ffi::OsStr| name.to_str())
                    .unwrap_or("?")
                    .to_owned(),
            );
        }
    }
    assert!(
        scanned > 40,
        "the scan must have found the integration tests; it saw only {scanned} source file(s) \
         under {}",
        root.display()
    );
    assert!(
        offenders.is_empty(),
        "these tests build a path to the disrobe binary from the workspace root instead of walking \
         up from the running test executable, so every one of them fails under a custom \
         CARGO_TARGET_DIR, which is what every parallel lane in this repository sets: {offenders:?}"
    );
}

#[test]
fn the_resolver_finds_the_binary_beside_the_running_test_executable() {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        assert!(
            dir.pop(),
            "walking up from {} never reached a debug or release directory; the resolver every \
             integration test uses depends on that walk terminating",
            exe.display()
        );
    }
    let profile: &Path = dir.as_path();
    assert!(
        profile.is_dir(),
        "the resolved profile directory must exist: {}",
        profile.display()
    );
    assert!(
        exe.starts_with(profile),
        "the resolved profile directory must be an ancestor of the running test executable, \
         because that is what makes the resolver independent of where the target directory sits; \
         resolved {} is not an ancestor of {}",
        profile.display(),
        exe.display()
    );
    let manifest_relative: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        });
    if profile != manifest_relative {
        assert!(
            !exe.starts_with(&manifest_relative),
            "this run uses a target directory outside the manifest, so a manifest-relative path \
             cannot be an ancestor of the test executable; that is the case the twenty-one \
             rewritten resolvers used to fail"
        );
    }
}
