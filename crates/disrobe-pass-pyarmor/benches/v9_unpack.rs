#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::path::PathBuf;

const SAMPLE_REL: &str = "corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py";

fn main() {
    divan::main();
}

#[divan::bench]
fn v9_unpack_default(bencher: divan::Bencher) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(SAMPLE_REL);
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read required {SAMPLE_REL}: {error}"));
    let options: disrobe_pass_pyarmor::UnpackOptions = disrobe_pass_pyarmor::UnpackOptions {
        strict: true,
        ..Default::default()
    };
    let unpack = || -> disrobe_pass_pyarmor::UnpackOutput {
        disrobe_pass_pyarmor::unpack_wrapper_text_with_options(
            divan::black_box(&text),
            divan::black_box(&path),
            &options,
        )
        .unwrap_or_else(|error: disrobe_pass_pyarmor::Error| {
            panic!("unpack required {SAMPLE_REL}: {error}")
        })
    };
    let recovered: disrobe_pass_pyarmor::UnpackOutput = unpack();
    let pyc: disrobe_py_marshal::PycFile =
        disrobe_py_marshal::read_pyc(recovered.pyc.as_deref().expect("strict recovery emits pyc"))
            .expect("recovered pyc parses");
    assert_eq!(
        pyc.header.version,
        disrobe_py_marshal::PyVersion::new(3, 14)
    );
    assert!(matches!(pyc.code, disrobe_py_marshal::Object::Code(_)));
    for expected in [
        "add",
        "classify",
        "Counter",
        "increment",
        "main",
        "disrobe-vmc-oracle-12345",
    ] {
        assert!(
            recovered
                .plaintext
                .windows(expected.len())
                .any(|bytes: &[u8]| bytes == expected.as_bytes()),
            "missing known plaintext: {expected}"
        );
    }
    bencher.bench_local(|| divan::black_box(unpack()));
}
