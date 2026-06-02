#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    BashfuscatorLevel, BashfuscatorReport, Detection, Dialect, detect, reverse_bashfuscator,
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
fn fixture_bashfuscator_token_hello_is_bash_dialect_and_progress_or_wall()
-> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/token/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
    assert!(
        !r.steps.is_empty() || !r.walls.is_empty(),
        "expected at least some peel steps or an honest wall on token fixture; got: {r:?}"
    );
    Ok(())
}

#[test]
fn fixture_bashfuscator_string_hello_is_bash_dialect_and_progress_or_wall()
-> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/string/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::String, &src)?;
    assert!(
        !r.steps.is_empty() || !r.walls.is_empty(),
        "expected at least some peel steps or an honest wall on string fixture; got: {r:?}"
    );
    Ok(())
}

#[test]
fn fixture_bashfuscator_obfuscate_hello_recovers_echo_hello_world() -> disrobe_pass_shell::Result<()>
{
    let src: String = read_corpus("bash/bashfuscator/obfuscate/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    let lower: String = r.output.to_ascii_lowercase();
    assert!(
        lower.contains("echo") && lower.contains("hello") && lower.contains("world"),
        "obfuscate-level swapcase peel must recover 'echo ... hello world', got: {}",
        r.output
    );
    assert!(
        r.steps
            .iter()
            .any(|s: &String| s.starts_with("obfuscate-swapcase")),
        "missing obfuscate-swapcase step in {:?}",
        r.steps
    );
    Ok(())
}

#[test]
fn fixture_bashfuscator_compress_hello_recovers_gzip_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    let lower: String = r.output.to_ascii_lowercase();
    assert!(
        lower.contains("echo") || lower.contains("hello") || lower.contains("world"),
        "compress-level peel must recover the gzip payload tokens, got: {}",
        r.output
    );
    assert!(
        r.steps
            .iter()
            .any(|s: &String| s == "compress-gzip-inflate"),
        "missing compress-gzip-inflate step in {:?}",
        r.steps
    );
    Ok(())
}

#[test]
fn fixture_bashfuscator_obfuscate_megafile_recovers_function_marker()
-> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/obfuscate/edge_cases.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    let lower: String = r.output.to_ascii_lowercase();
    assert!(
        lower.contains("hello world") && lower.contains("function"),
        "obfuscate-level swapcase peel on megafile must surface 'hello world' AND 'function' markers; output first 400: {}",
        r.output.chars().take(400).collect::<String>()
    );
    Ok(())
}

#[test]
fn fixture_bashfuscator_compress_megafile_recovers_function_marker()
-> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/edge_cases.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    let lower: String = r.output.to_ascii_lowercase();
    assert!(
        lower.contains("hello world"),
        "compress-level peel on megafile must surface 'hello world'; output first 400: {}",
        r.output.chars().take(400).collect::<String>()
    );
    Ok(())
}
