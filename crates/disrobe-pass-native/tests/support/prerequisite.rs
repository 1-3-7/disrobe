use std::path::{Path, PathBuf};

pub(crate) const REQUIRE_LOCAL_CORPUS_VAR: &str = "DISROBE_REQUIRE_NATIVE_LOCAL_CORPUS";
pub(crate) const REQUIRE_TOOLCHAIN_VAR: &str = "DISROBE_REQUIRE_NATIVE_TOOLCHAIN";

fn demanded(variable: &str) -> bool {
    std::env::var_os(variable).is_some_and(|value: std::ffi::OsString| {
        !matches!(
            value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off" | "optional"
        )
    })
}

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
    assert!(
        !demanded(REQUIRE_LOCAL_CORPUS_VAR),
        "{REQUIRE_LOCAL_CORPUS_VAR} requires the local-only input {relative} for {graded}, but it \
         is unavailable: {reason}"
    );
    eprintln!(
        "UNGRADED: {graded} needs the local-only input {relative}, which is unavailable ({reason}); \
         set {REQUIRE_LOCAL_CORPUS_VAR}=1 to fail instead"
    );
}

#[allow(dead_code)]
pub(crate) fn toolchain_capability_absent(graded: &str, absent: &str) {
    tool_unavailable(REQUIRE_TOOLCHAIN_VAR, graded, absent);
}

#[allow(dead_code)]
pub(crate) fn tool_unavailable(variable: &str, graded: &str, absent: &str) {
    assert!(
        !demanded(variable),
        "{variable} makes this tool mandatory for this run, so {graded} cannot report success: \
         {absent}"
    );
    eprintln!(
        "UNGRADED: {graded} measured nothing because {absent}; set {variable}=1 to fail instead"
    );
}
