#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_pyarmor::{
    Detection, ProtectionKind, UnpackOptions, UnpackOutput, detect_from_wrapper,
    unpack_wrapper_text_with_options,
};

fn make_tmp_dir(name: &str) -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!("disrobe-pyarmor-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn escape_bytes(payload: &[u8]) -> String {
    use core::fmt::Write as _;
    payload
        .iter()
        .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
            let _ = write!(s, "\\x{b:02x}");
            s
        })
}

fn synth_v6v7_super_wrapper() -> (String, Vec<u8>) {
    let mut payload: Vec<u8> = vec![0u8; 64];
    payload[..8].copy_from_slice(b"PYARMOR\0");
    payload[9] = 3;
    payload[10] = 11;
    let escaped: String = escape_bytes(&payload);
    let text: String = format!(
        "from pyarmor_runtime_000000 import pyarmor\npyarmor(__name__, __file__, b'{escaped}')\n"
    );
    (text, payload)
}

#[test]
fn v7_super_detect_via_wrapper_call_form() {
    let (text, _payload): (String, Vec<u8>) = synth_v6v7_super_wrapper();
    let (det, _): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("v7 wrapper must detect");
    assert_eq!(det.protection, ProtectionKind::SuperMode);
}

#[test]
fn v7_super_without_allow_dynamic_returns_dynamic_required_error() {
    let (text, _): (String, Vec<u8>) = synth_v6v7_super_wrapper();
    let tmp: PathBuf = make_tmp_dir("v7-super-no-dynamic");
    let wrapper: PathBuf = tmp.join("hello_v7_super.py");
    fs::write(&wrapper, &text).expect("write wrapper");
    let runtime_dir: PathBuf = tmp.join("pytransform");
    fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
    fs::write(runtime_dir.join("_pytransform.dll"), b"STUB").expect("write stub");

    let opts: UnpackOptions = UnpackOptions::default();
    let res: Result<UnpackOutput, _> = unpack_wrapper_text_with_options(&text, &wrapper, &opts);
    assert!(res.is_err(), "v7 super without allow_dynamic must error");
    let msg: String = format!("{}", res.expect_err("must error"));
    assert!(
        msg.contains("DR-PYARM-0016") || msg.contains("allow-dynamic") || msg.contains("dynamic"),
        "expected dynamic-required error, got: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn v7_super_diagnostic_records_super_mode_in_detection_string() {
    let (text, _): (String, Vec<u8>) = synth_v6v7_super_wrapper();
    let (det, _): (Detection, Vec<u8>) = detect_from_wrapper(&text).expect("detect");
    assert!(det.diagnostics.iter().any(|d| d.contains("super-mode")));
}
