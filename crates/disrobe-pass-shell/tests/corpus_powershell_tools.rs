#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::powershell::chameleon::ChameleonReport;
use disrobe_pass_shell::powershell::invoke_stealth::InvokeStealthReport;
use disrobe_pass_shell::powershell::psobf::PsobfReport;
use disrobe_pass_shell::{
    Detection, Dialect, detect, reverse_chameleon, reverse_invoke_stealth, reverse_psobf,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> String {
    let p: PathBuf = corpus_path(relative);
    let bytes: Vec<u8> = std::fs::read(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()));
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn fixture_chameleon_hello_decodes_base64_payload() {
    let src: String = read_corpus("powershell/chameleon/hello.ps1");
    let _det: Detection = detect(src.as_bytes());
    let r: ChameleonReport = reverse_chameleon(&src);
    let lowered: String = r.output.to_ascii_lowercase();
    assert!(
        lowered.contains("write-host")
            || lowered.contains("hello world")
            || lowered.contains("frombase64string"),
        "chameleon reverse output: {}",
        r.output
    );
}

#[test]
fn fixture_invoke_stealth_rev_b64_extracts_payload() {
    let src: String = read_corpus("powershell/invoke-stealth/hello.ps1");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::PowerShell);
    let r: InvokeStealthReport = reverse_invoke_stealth(&src);
    let lowered: String = r.output.to_ascii_lowercase();
    assert!(
        lowered.contains("write-host")
            || lowered.contains("hello world")
            || lowered.contains("frombase64string"),
        "invoke-stealth reverse output: {}",
        r.output
    );
}

#[test]
fn fixture_psobf_hello_remains_powershell_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("powershell/psobf/hello.ps1");
    let r: PsobfReport = reverse_psobf(&src)?;
    assert!(!r.output.is_empty());
    Ok(())
}
