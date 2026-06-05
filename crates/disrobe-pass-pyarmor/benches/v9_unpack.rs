#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::path::{Path, PathBuf};

const SAMPLE_REL: &str = "corpus/generated/pyarmor/v9-default/hello.py";

fn main() {
    divan::main();
}

#[divan::bench]
fn v9_unpack_default(bencher: divan::Bencher) {
    let Some((text, path)): Option<(String, PathBuf)> = load_optional_sample(SAMPLE_REL) else {
        eprintln!("skip: {SAMPLE_REL} not present");
        return;
    };
    bencher.bench_local(|| {
        let _ = divan::black_box(disrobe_pass_pyarmor::unpack_wrapper_text(
            divan::black_box(&text),
            divan::black_box(&path),
        ));
    });
}

fn load_optional_sample(rel: &str) -> Option<(String, PathBuf)> {
    let candidates: [PathBuf; 3] = [
        Path::new(rel).to_owned(),
        PathBuf::from("..").join("..").join(rel),
        PathBuf::from("..").join(rel),
    ];
    for p in candidates {
        if p.is_file()
            && let Ok(text) = std::fs::read_to_string(&p)
        {
            return Some((text, p));
        }
    }
    None
}
