#![allow(clippy::panic)]

use std::path::PathBuf;

const REQUIRE_LOCAL_CORPUS_VAR: &str = "DISROBE_REQUIRE_NUITKA_LOCAL_CORPUS";

fn corpus_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/python/nuitka")
        .join(relative)
}

pub(crate) fn read_tracked(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the tracked Nuitka fixture {} does not read ({error}); restore it with git checkout, \
             because this test never regenerates fixtures",
            path.display()
        )
    })
}

pub(crate) fn read_local_only(relative: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_path(relative);
    if let Ok(bytes) = std::fs::read(&path) {
        return Some(bytes);
    }
    assert!(
        std::env::var_os(REQUIRE_LOCAL_CORPUS_VAR).is_none(),
        "{REQUIRE_LOCAL_CORPUS_VAR} is set, so the local-only Nuitka fixture {} must exist",
        path.display()
    );
    eprintln!(
        "UNGRADED: the local-only Nuitka fixture {} is absent; set {REQUIRE_LOCAL_CORPUS_VAR}=1 \
         to fail instead",
        path.display()
    );
    None
}
