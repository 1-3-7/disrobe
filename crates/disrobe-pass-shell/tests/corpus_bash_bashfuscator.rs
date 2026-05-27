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
fn fixture_bashfuscator_token_hello_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/token/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::Token);
    Ok(())
}

#[test]
fn fixture_bashfuscator_string_hello_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/string/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::String, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::String);
    Ok(())
}

#[test]
fn fixture_bashfuscator_obfuscate_hello_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/obfuscate/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::Obfuscate);
    Ok(())
}

#[test]
fn fixture_bashfuscator_compress_hello_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/hello.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::Compress);
    Ok(())
}

#[test]
fn fixture_bashfuscator_obfuscate_megafile_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/obfuscate/edge_cases.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::Obfuscate);
    Ok(())
}

#[test]
fn fixture_bashfuscator_compress_megafile_is_bash_dialect() -> disrobe_pass_shell::Result<()> {
    let src: String = read_corpus("bash/bashfuscator/compress/edge_cases.sh");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    assert_eq!(r.level, BashfuscatorLevel::Compress);
    Ok(())
}
