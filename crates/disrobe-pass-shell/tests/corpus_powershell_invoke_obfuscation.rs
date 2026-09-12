#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    Detection, Dialect, Family, InvokeObfuscationLevel, ReverseReport, detect, reverse_compress,
    reverse_encoding, reverse_launcher, reverse_string, reverse_token,
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
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn fixture_invoke_obf_token_hello_round_trip() {
    let src: String = read_corpus("powershell/invoke-obfuscation/token/hello.ps1");
    let r: ReverseReport = reverse_token(&src);
    assert_eq!(r.level, InvokeObfuscationLevel::Token);
}

#[test]
fn fixture_invoke_obf_string_hello_resolves_format_op() {
    let src: String = read_corpus("powershell/invoke-obfuscation/string/hello.ps1");
    let r: ReverseReport = reverse_string(&src);
    assert!(
        r.output.contains("Write-Host") || r.output.to_ascii_lowercase().contains("write-host"),
        "reverse_string failed to fold format op: {}",
        r.output
    );
}

#[test]
fn fixture_invoke_obf_encoding_hello_decodes_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("powershell/invoke-obfuscation/encoding/hello.ps1");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::PowerShell);
    assert_eq!(det.family, Family::InvokeObfuscationEncoding);
    let r: ReverseReport = reverse_encoding(&src)?;
    assert!(r.output.contains("Write-Host"), "decoded: {}", r.output);
    assert!(r.output.contains("hello world"), "decoded: {}", r.output);
    Ok(())
}

#[test]
fn fixture_invoke_obf_compress_hello_inflates_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("powershell/invoke-obfuscation/compress/hello.ps1");
    let r: ReverseReport = reverse_compress(&src)?;
    assert!(r.output.contains("Write-Host"), "inflated: {}", r.output);
    assert!(r.output.contains("hello world"), "inflated: {}", r.output);
    Ok(())
}

#[test]
fn fixture_invoke_obf_launcher_hello_canonicalises_flags() {
    let src: String = read_corpus("powershell/invoke-obfuscation/launcher/hello.ps1");
    let r: ReverseReport = reverse_launcher(&src);
    assert!(
        r.output.contains("-WindowStyle Hidden") || r.output.contains("-w hidden"),
        "launcher output: {}",
        r.output
    );
}

#[test]
fn fixture_invoke_obf_encoding_megafile_decodes_first_token() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("powershell/invoke-obfuscation/encoding/edge_cases.ps1");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::PowerShell);
    assert_eq!(det.family, Family::InvokeObfuscationEncoding);
    let r: ReverseReport = reverse_encoding(&src)?;
    assert!(
        r.output.contains("CmdletBinding") || r.output.contains("param("),
        "megafile decode preview: {}",
        &r.output.chars().take(200).collect::<String>()
    );
    Ok(())
}

#[test]
fn fixture_invoke_obf_compress_megafile_inflates_first_token() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("powershell/invoke-obfuscation/compress/edge_cases.ps1");
    let r: ReverseReport = reverse_compress(&src)?;
    assert!(
        r.output.contains("CmdletBinding") || r.output.contains("param("),
        "megafile inflate preview: {}",
        &r.output.chars().take(200).collect::<String>()
    );
    Ok(())
}
