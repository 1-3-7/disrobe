#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::path::PathBuf;

use disrobe_pass_native::{DecompileOutput, DecompilerBackend, Error, run};

#[test]
fn binary_ninja_without_override_returns_license_required() {
    let tmp: PathBuf = std::env::temp_dir();
    let dummy: PathBuf = tmp.join("disrobe-native-binja-input.bin");
    std::fs::write(&dummy, b"MZ").expect("write");
    let res: Result<DecompileOutput, Error> = run(DecompilerBackend::BinaryNinja, &dummy, &tmp);
    assert!(matches!(res, Err(Error::LicenseRequired("binja"))));
}

#[test]
#[ignore = "FIXTURE PENDING: Binary Ninja headless license required"]
fn real_binja_headless_decompile() {}
