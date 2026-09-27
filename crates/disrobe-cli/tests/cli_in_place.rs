#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, run_disrobe_in, temp_path, write_bytes};

#[test]
fn in_place_rewrites_input_file_for_py_deob() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("inplace", "py");
    let original: &[u8] = b"x = 1\n";
    write_bytes(&src, original);
    let original_len: u64 = std::fs::metadata(&src).expect("stat").len();
    assert_eq!(original_len, original.len() as u64);

    let r: Run = run_disrobe(&["--in-place", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);

    let after: Vec<u8> = std::fs::read(&src).expect("read after");
    assert!(
        !after.is_empty(),
        "in-place rewrite must leave file non-empty"
    );
    let manifest_sibling: PathBuf = src.with_extension("manifest.json");
    assert!(
        !manifest_sibling.exists(),
        "--in-place must NOT create sibling manifest at {}",
        manifest_sibling.display()
    );
}

#[test]
fn without_in_place_writes_mirror_path() {
    let (src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("noninplace", "py");
    write_bytes(&src, b"y = 2\n");
    let original: Vec<u8> = std::fs::read(&src).expect("read");

    let r: Run = run_disrobe_in(src_scratch.path(), &["py", "deob", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);

    let after: Vec<u8> = std::fs::read(&src).expect("read after");
    assert_eq!(after, original, "default path must not mutate input");
    let stem: String = src
        .file_stem()
        .expect("scratch source has a stem")
        .to_string_lossy()
        .into_owned();
    let mirror: PathBuf = src_scratch
        .path()
        .join("out")
        .join(format!("{stem}.deobfuscated.py"));
    assert!(
        mirror.is_file(),
        "the default output must land under out/ in the working directory: {}",
        mirror.display()
    );
}
