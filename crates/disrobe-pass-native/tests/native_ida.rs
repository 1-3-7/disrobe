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
fn ida_without_override_returns_license_required() {
    let tempdir: tempfile::TempDir = tempfile::tempdir().expect("create temp dir");
    let tmp: PathBuf = tempdir.path().to_path_buf();
    let dummy: PathBuf = tmp.join("disrobe-native-ida-input.bin");
    std::fs::write(&dummy, b"\x7FELF").expect("write");
    let res: Result<DecompileOutput, Error> = run(DecompilerBackend::Ida, &dummy, &tmp);
    assert!(matches!(res, Err(Error::LicenseRequired("ida"))));
}

#[test]
#[ignore = "toolchain: needs a licensed IDA Pro headless install, which no runner provisions"]
fn real_ida_headless_decompile() {}
