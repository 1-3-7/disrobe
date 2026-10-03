#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_deob::{PeelResult, peel};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const PYTHON_TIMEOUT: Duration = Duration::from_secs(30);
const PYTHON_CAPTURE_BYTES: usize = 1024;
const STORED_PAYLOAD_LEN: usize = 0x0741;
const ADLER_MODULUS: u32 = 65_521;

fn observed_payload() -> String {
    let mut payload: String = "print(list(b'\\101\\a'))\n".to_owned();
    assert!(
        payload.len() <= STORED_PAYLOAD_LEN,
        "payload prefix exceeds stored block"
    );
    payload.push_str(&"#".repeat(STORED_PAYLOAD_LEN - payload.len()));
    payload
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % ADLER_MODULUS;
        b = (b + a) % ADLER_MODULUS;
    }
    (b << 16) | a
}

fn stored_zlib(payload: &[u8]) -> Vec<u8> {
    let payload_len: u16 = u16::try_from(payload.len()).expect("stored payload must fit u16");
    let mut stream: Vec<u8> = Vec::with_capacity(payload.len() + 11);
    stream.extend_from_slice(&[0x78, 0x01, 0x01]);
    stream.extend_from_slice(&payload_len.to_le_bytes());
    stream.extend_from_slice(&(!payload_len).to_le_bytes());
    stream.extend_from_slice(payload);
    stream.extend_from_slice(&adler32(payload).to_be_bytes());
    stream
}

fn authored_source() -> String {
    let payload: String = observed_payload();
    let stream: Vec<u8> = stored_zlib(payload.as_bytes());
    let mut literal: String = String::with_capacity(stream.len() * 4);
    for (index, byte) in stream.iter().copied().enumerate() {
        match index {
            3 => literal.push_str("\\101"),
            4 => literal.push_str("\\a"),
            _ => write!(literal, "\\x{byte:02x}").expect("write authored byte literal"),
        }
    }
    format!("import zlib\nexec(zlib.decompress(b'{literal}'))\n")
}

fn python_output(python: &Path, source: &str, label: &str) -> String {
    let scratch: ScratchDir = ScratchDir::create("disrobe_python_bytes_literal")
        .expect("create isolated CPython source directory");
    let source_path: PathBuf = scratch.path().join("bytes_literal.py");
    std::fs::write(&source_path, source).expect("write authored or recovered Python source");
    let output: ToolOutput = tool_output(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-I")
            .arg("-X")
            .arg("utf8")
            .arg(&source_path)
            .current_dir(scratch.path().to_path_buf())
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .capture_limits(PYTHON_CAPTURE_BYTES, PYTHON_CAPTURE_BYTES)
            .reap_descendants_on_exit(),
    )
    .unwrap_or_else(|error| panic!("{label}: CPython launch failed: {error}"));
    assert!(
        output.success,
        "{label}: CPython rejected source; stdout={} stderr={}",
        output.stdout_text(),
        output.stderr_text()
    );
    output.stdout_text().replace("\r\n", "\n")
}

#[test]
fn public_peel_recovers_octal_and_named_byte_escapes() {
    let python: PathBuf = common::require_python_312();
    let authored: String = authored_source();
    assert!(
        authored.contains("\\101\\a"),
        "the authored input must reach the public peeler through both escapes"
    );
    let expected: String = python_output(&python, &authored, "authored reference");
    assert_eq!(expected, "[65, 7]\n");

    let recovered: PeelResult = peel(authored.as_bytes())
        .expect("public peeler must decode the authored zlib bytes literal");
    assert!(recovered.recovered, "public peeler reported no recovery");
    assert_eq!(recovered.final_source, observed_payload());
    assert_eq!(
        python_output(&python, &recovered.final_source, "recovered source"),
        expected
    );

    let mutated: String = recovered.final_source.replacen("\\101", "\\102", 1);
    assert_ne!(
        mutated, recovered.final_source,
        "recovered source must retain the observed octal byte literal"
    );
    assert_ne!(
        python_output(&python, &mutated, "byte literal mutation"),
        expected,
        "the independent CPython oracle must reject a changed recovered byte"
    );
}
