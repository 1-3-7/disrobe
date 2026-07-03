#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{BashfuscatorLevel, BashfuscatorReport, reverse_bashfuscator};

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
fn real_obfuscate_hello_recovers_echo_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/obfuscate/hello.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("echo") && out_lower.contains("hello") && out_lower.contains("world"),
        "expected swapcase recovery to yield 'echo ... hello world', got: {}",
        r.output
    );
    assert!(
        r.steps
            .iter()
            .any(|s: &String| s.starts_with("obfuscate-swapcase")),
        "no swapcase step recorded; steps={:?}",
        r.steps
    );
    Ok(())
}

#[test]
fn real_compress_hello_recovers_gzip_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/hello.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("echo") && out_lower.contains("hello world"),
        "gzip recovery must produce 'echo ... hello world' plaintext, got: {}",
        r.output
    );
    assert!(
        r.steps
            .iter()
            .any(|s: &String| s == "compress-gzip-inflate"),
        "no gzip-inflate step recorded; steps={:?}",
        r.steps
    );
    Ok(())
}

#[test]
fn real_obfuscate_edge_cases_recovers_long_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/obfuscate/edge_cases.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("hello world") && out_lower.contains("function"),
        "expected swapcase recovery to include 'hello world' and 'function' markers from megafile, got first 200: {}",
        &r.output.chars().take(200).collect::<String>()
    );
    Ok(())
}

#[test]
fn real_compress_edge_cases_recovers_long_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/edge_cases.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("hello world"),
        "expected gzip recovery to include 'hello world', got first 200: {}",
        &r.output.chars().take(200).collect::<String>()
    );
    Ok(())
}

#[test]
fn real_token_hello_recovers_echo_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/token/hello.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("echo") && out_lower.contains("hello world"),
        "token-level recovery must produce 'echo ... hello world' plaintext, got: {}",
        r.output
    );
    Ok(())
}

#[test]
fn real_string_hello_recovers_echo_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/string/hello.sh");
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::String, &src)?;
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("echo") && out_lower.contains("hello world"),
        "string-level recovery must produce 'echo ... hello world' plaintext, got: {}",
        r.output
    );
    Ok(())
}
