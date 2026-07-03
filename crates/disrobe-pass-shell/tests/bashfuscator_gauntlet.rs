#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_shell::{
    BashfuscatorLevel, BashfuscatorReport, Detection, Dialect, detect, reverse_bashfuscator,
};

fn gauntlet_path(name: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root must exist");
    workspace_root
        .join("corpus")
        .join("shell")
        .join("bash")
        .join("bashfuscator")
        .join("gauntlet")
        .join(name)
}

fn read_gauntlet(name: &str) -> String {
    let p: PathBuf = gauntlet_path(name);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

fn token_set(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t: &&str| t.len() >= 2)
        .map(str::to_owned)
        .collect()
}

fn recovery_ratio(recovered: &str, clean: &str) -> f64 {
    let clean_tokens: Vec<String> = token_set(clean);
    if clean_tokens.is_empty() {
        return 0.0;
    }
    let recovered_set: BTreeSet<String> = token_set(recovered).into_iter().collect();
    let hit: usize = clean_tokens
        .iter()
        .filter(|t: &&String| recovered_set.contains(*t))
        .count();
    hit as f64 / clean_tokens.len() as f64
}

const MARKER: &str = "DISROBE_GAUNTLET_MARKER";

#[test]
fn gauntlet_fixtures_are_real_obfuscation_marker_hidden() {
    for name in ["obfuscate.sh", "compress.sh", "token.sh"] {
        let src: String = read_gauntlet(name);
        assert!(
            !src.contains(MARKER),
            "{name} leaks the cleartext marker; it is not genuinely obfuscated"
        );
        let det: Detection = detect(src.as_bytes());
        assert_eq!(
            det.dialect,
            Dialect::Bash,
            "{name} must be detected as Bash"
        );
        assert!(
            src.contains("${@") || src.contains("${*") || src.contains("$'\\"),
            "{name} must carry Bashfuscator mutator soup"
        );
    }
}

#[test]
fn gauntlet_obfuscate_swapcase_recovers_full_clean_original() -> disrobe_pass_shell::Result<()> {
    let clean: String = read_gauntlet("clean_original.sh");
    let src: String = read_gauntlet("obfuscate.sh");
    let report: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, &src)?;
    assert!(
        report
            .steps
            .iter()
            .any(|s: &String| s.starts_with("obfuscate-swapcase")),
        "case-swap peel must run; steps={:?}",
        report.steps
    );
    assert!(
        report.output.contains(MARKER),
        "swapcase recovery must restore the exact marker; got: {}",
        report.output
    );
    for keyword in [
        "greeting",
        "for",
        "do",
        "echo",
        "iteration",
        "done",
        "if",
        "then",
        "printf",
        "verified",
        "fi",
    ] {
        assert!(
            report.output.contains(keyword),
            "swapcase recovery missing structural keyword `{keyword}`; got: {}",
            report.output
        );
    }
    let ratio: f64 = recovery_ratio(&report.output, &clean);
    assert!(
        ratio >= 0.85,
        "swapcase recovery vs clean original too low: {:.1}% (expected >=85%)",
        ratio * 100.0
    );
    Ok(())
}

#[test]
fn gauntlet_compress_gzip_recovers_full_clean_original() -> disrobe_pass_shell::Result<()> {
    let clean: String = read_gauntlet("clean_original.sh");
    let src: String = read_gauntlet("compress.sh");
    let report: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Compress, &src)?;
    assert!(
        report
            .steps
            .iter()
            .any(|s: &String| s == "compress-base64-decode"),
        "must base64-decode the compressed blob; steps={:?}",
        report.steps
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s: &String| s == "compress-gzip-inflate"),
        "must gzip-inflate the payload; steps={:?}",
        report.steps
    );
    assert!(
        report.output.contains(MARKER),
        "gzip recovery must restore the exact marker; got: {}",
        report.output
    );
    for keyword in [
        "greeting",
        "for",
        "do",
        "echo",
        "iteration",
        "done",
        "if",
        "then",
        "printf",
        "verified",
        "fi",
    ] {
        assert!(
            report.output.contains(keyword),
            "gzip recovery missing structural keyword `{keyword}`; got: {}",
            report.output
        );
    }
    let ratio: f64 = recovery_ratio(&report.output, &clean);
    assert!(
        ratio >= 0.85,
        "gzip recovery vs clean original too low: {:.1}% (expected >=85%)",
        ratio * 100.0
    );
    Ok(())
}

#[test]
fn gauntlet_token_forcode_recovers_full_clean_original() -> disrobe_pass_shell::Result<()> {
    let clean: String = read_gauntlet("clean_original.sh");
    let src: String = read_gauntlet("token.sh");
    let report: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
    assert!(
        report
            .steps
            .iter()
            .any(|s: &String| s.starts_with("eval-token-array-lookup:")),
        "ForCode peel must reach the token-array lookup stage; steps={:?}",
        report.steps
    );
    assert!(
        report.output.contains("DISROBE_GAUNTLET_MARKER"),
        "ForCode base-N index decode must restore the exact marker verbatim; got: {}",
        report.output
    );
    for keyword in [
        "greeting",
        "for",
        "do",
        "echo",
        "iteration",
        "done",
        "if",
        "then",
        "printf",
        "verified",
        "fi",
    ] {
        assert!(
            report.output.contains(keyword),
            "ForCode recovery missing structural keyword `{keyword}`; got: {}",
            report.output
        );
    }
    let ratio: f64 = recovery_ratio(&report.output, &clean);
    assert!(
        ratio >= 0.95,
        "ForCode token-array recovery vs clean original too low: {:.1}% (expected >=95%)",
        ratio * 100.0
    );
    Ok(())
}

#[test]
fn gauntlet_clean_original_is_not_obfuscated() {
    let clean: String = read_gauntlet("clean_original.sh");
    assert!(
        clean.contains(MARKER),
        "clean original must hold the cleartext marker"
    );
    assert!(
        !clean.contains("${@,,}") && !clean.contains("${*~}"),
        "clean original must be free of Bashfuscator mutators"
    );
}
