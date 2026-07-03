#![allow(dead_code, unreachable_pub)]
use std::path::PathBuf;

pub fn corpus_binfmt_root() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("binfmt");
    p
}

pub fn load_fixture(format_dir: &str, filename: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_binfmt_root().join(format_dir).join(filename);
    std::fs::read(&path).ok()
}

pub fn fixture_path(format_dir: &str, filename: &str) -> PathBuf {
    corpus_binfmt_root().join(format_dir).join(filename)
}
