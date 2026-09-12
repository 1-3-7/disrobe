const SAMPLE_REL: &str = "corpus/python/freezers/pyinstaller/gauntlet/hello.exe";

fn main() {
    divan::main();
}

#[divan::bench]
#[allow(clippy::panic)]
fn cookie_find_real_onefile(bencher: divan::Bencher) {
    let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(SAMPLE_REL);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read required {SAMPLE_REL}: {error}"));
    bencher.bench_local(|| {
        let cookie: disrobe_pass_pyinstaller::Cookie = disrobe_pass_pyinstaller::find_cookie(
            divan::black_box(&bytes),
        )
        .unwrap_or_else(|error: disrobe_pass_pyinstaller::Error| {
            panic!("find required {SAMPLE_REL} cookie: {error}")
        });
        divan::black_box(cookie)
    });
}
