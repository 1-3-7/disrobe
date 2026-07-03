use std::path::{Path, PathBuf};

const SAMPLE_REL: &str = "corpus/python/pyinstaller/playground-mid.exe";

fn main() {
    divan::main();
}

#[divan::bench]
fn cookie_find_real_onefile(bencher: divan::Bencher) {
    let Some(bytes): Option<Vec<u8>> = load_optional_sample(SAMPLE_REL) else {
        return;
    };
    bencher.bench_local(|| {
        let _ = divan::black_box(disrobe_pass_pyinstaller::find_cookie(divan::black_box(
            &bytes,
        )));
    });
}

fn load_optional_sample(rel: &str) -> Option<Vec<u8>> {
    let candidates: [PathBuf; 3] = [
        Path::new(rel).to_owned(),
        PathBuf::from("..").join("..").join(rel),
        PathBuf::from("..").join(rel),
    ];
    for p in candidates {
        if p.is_file() {
            let Ok(bytes): core::result::Result<Vec<u8>, std::io::Error> = std::fs::read(&p) else {
                continue;
            };
            return Some(bytes);
        }
    }
    None
}
