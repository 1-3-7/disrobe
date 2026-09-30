use std::path::{Path, PathBuf};

pub(crate) const TOOLCHAIN_CAPABILITY: &str = "disrobe-pass-native::toolchain-capability";

pub(crate) fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

#[allow(dead_code)]
pub(crate) fn committed(relative: &str) -> Vec<u8> {
    let path: PathBuf = repo_path(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the committed fixture {relative} is required but cannot be read at {}: {error}",
            path.display()
        )
    })
}

#[allow(dead_code)]
pub(crate) fn local_only(relative: &str, graded: &str) -> Option<Vec<u8>> {
    let path: PathBuf = repo_path(relative);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            local_input_absent(relative, graded, &error.to_string());
            None
        }
    }
}

#[allow(dead_code)]
pub(crate) fn local_only_path(relative: &str, graded: &str) -> Option<PathBuf> {
    let path: PathBuf = repo_path(relative);
    if path.is_file() {
        return Some(path);
    }
    local_input_absent(relative, graded, "not a regular file");
    None
}

fn local_input_absent(relative: &str, graded: &str, reason: &str) {
    tool_unavailable(
        &format!("disrobe-pass-native::local::{relative}"),
        graded,
        &format!("the local-only input {relative} ({reason})"),
    );
}

#[allow(dead_code)]
pub(crate) fn toolchain_capability_absent(graded: &str, absent: &str) {
    tool_unavailable(TOOLCHAIN_CAPABILITY, graded, absent);
}

#[allow(dead_code)]
pub(crate) fn tool_unavailable(prerequisite: &str, graded: &str, absent: &str) {
    if let Err(error) = disrobe_testkit::require::<()>(prerequisite, absent, None) {
        panic!("{graded} cannot report success: {error}");
    }
}
