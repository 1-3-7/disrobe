#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, OutputKind, Pass};
use disrobe_core::provenance::Language;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_shell::chain_detector::{SHELL_PASS, ShellDetector};
use disrobe_pass_shell::detect::{Detection, Dialect, Family, decode_script_bytes, detect};

fn corpus_bytes(relative: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("shell")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "corpus/shell/{relative} is tracked in git; read {} failed: {e}",
            path.display()
        )
    })
}

fn claim(bytes: &[u8]) -> Option<DetectVerdict> {
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    Detector::detect(&ShellDetector, &ctx)
}

fn recover(relative: &str, language: Language) -> String {
    let bytes: Vec<u8> = corpus_bytes(relative);
    let verdict: DetectVerdict =
        claim(&bytes).unwrap_or_else(|| panic!("shell.deob must claim {relative}"));
    assert!(
        verdict.confidence > 0.85,
        "{relative} must outrank the 0.85 windows-script report of scriptlang.classify, got {}",
        verdict.confidence
    );
    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let output: Artifact = SHELL_PASS
        .run(&input)
        .unwrap_or_else(|e| panic!("shell.deob must recover {relative}: {e}"));
    match SHELL_PASS.output_kind(&output) {
        OutputKind::Source { language: got, .. } => {
            assert_eq!(got, language, "{relative} output language");
        }
        other => panic!("{relative}: expected source output, got {other:?}"),
    }
    String::from_utf8(output.envelope).expect("recovered script is utf-8")
}

#[test]
fn chameleon_base64_and_random_case_output_is_claimed_and_decoded() {
    let recovered: String = recover("powershell/chameleon/hello.ps1", Language::PowerShell);
    assert!(
        recovered.contains("Write-Host \"hello world\"") && !recovered.contains("fRoMBAse64"),
        "{recovered}"
    );
}

#[test]
fn chameleon_renamed_identifiers_are_claimed_and_renamed() {
    let recovered: String = recover("powershell/chameleon/rename_real.ps1", Language::PowerShell);
    assert!(
        !recovered
            .contains("O0JhKob7rARtxUkELIxvVoU25ctiBdmML59pnGGsPwC2rUqFfWPQfHFXNH95XtYt8sGK8T"),
        "{recovered}"
    );
    assert!(recovered.contains("Add-Two"), "{recovered}");
}

#[test]
fn invoke_obfuscation_ast_get_command_indirection_is_unwrapped() {
    let recovered: String = recover(
        "powershell/invoke-obfuscation/ast/hello.ps1",
        Language::PowerShell,
    );
    assert!(
        recovered.starts_with("Write-Host") && !recovered.contains("Get-Command"),
        "{recovered}"
    );
    assert!(recovered.contains("'hello world'"), "{recovered}");
}

#[test]
fn invoke_obfuscation_string_and_token_format_operators_are_folded() {
    for relative in [
        "powershell/invoke-obfuscation/string/hello.ps1",
        "powershell/invoke-obfuscation/token/hello.ps1",
    ] {
        let recovered: String = recover(relative, Language::PowerShell);
        assert!(
            recovered.contains("Write-Host") && recovered.contains("hello world"),
            "{relative}: {recovered}"
        );
        assert!(!recovered.contains(" -f "), "{relative}: {recovered}");
    }
}

#[test]
fn invoke_obfuscation_compress_is_claimed_and_inflated() {
    let recovered: String = recover(
        "powershell/invoke-obfuscation/compress/hello.ps1",
        Language::PowerShell,
    );
    assert!(
        recovered.contains("Write-Host") && recovered.contains("hello world"),
        "{recovered}"
    );
    let megafile: String = recover(
        "powershell/invoke-obfuscation/compress/edge_cases.ps1",
        Language::PowerShell,
    );
    assert!(megafile.contains("CmdletBinding"), "{megafile}");
}

#[test]
fn an_encoded_command_recovers_as_powershell_even_when_the_payload_carries_no_markers() {
    let recovered: String = recover(
        "powershell/invoke-obfuscation/encoding/hello.ps1",
        Language::PowerShell,
    );
    assert_eq!(recovered, "Write-Host \"hello world\"");
}

#[test]
fn invoke_stealth_reversed_base64_is_claimed_without_its_banner() {
    let bytes: Vec<u8> = corpus_bytes("powershell/invoke-stealth/hello.ps1");
    let detection: Detection = detect(&bytes);
    assert_eq!(detection.family, Family::InvokeStealth);
    let recovered: String = recover("powershell/invoke-stealth/hello.ps1", Language::PowerShell);
    assert!(
        recovered.contains("Write-Host \"hello world\""),
        "{recovered}"
    );
}

#[test]
fn psobf_output_with_a_utf8_encoded_utf16_bom_is_decoded_and_claimed() {
    let bytes: Vec<u8> = corpus_bytes("powershell/psobf/hello.ps1");
    assert!(bytes.starts_with(&[0xC3, 0xBF, 0xC3, 0xBE]));
    let decoded: String = decode_script_bytes(&bytes).expect("utf-16 text behind the bom");
    assert!(decoded.starts_with("<obfus%W%r"), "{decoded:?}");
    let detection: Detection = detect(&bytes);
    assert_eq!(detection.dialect, Dialect::PowerShell);
    assert_eq!(detection.family, Family::Psobf);
    let recovered: String = recover("powershell/psobf/hello.ps1", Language::PowerShell);
    assert_eq!(recovered, "Write-Host hello world");
}

#[test]
fn caret_escaped_batch_is_claimed_and_unescaped() {
    let recovered: String = recover("batch/caret/hello.bat", Language::Batch);
    assert!(!recovered.contains('^'), "{recovered}");
    assert!(recovered.contains("echo hello world"), "{recovered}");
}

#[test]
fn arithmetic_and_for_laundered_batch_is_claimed_ahead_of_the_windows_script_report() {
    let seta: String = recover("batch/seta/hello.bat", Language::Batch);
    assert!(
        seta.contains("set PORT=4443") && seta.contains("set SHIFT=8"),
        "{seta}"
    );
    let forsubstr: String = recover("batch/forsubstr/hello.bat", Language::Batch);
    assert!(forsubstr.contains("hello world"), "{forsubstr}");
}

#[test]
fn plain_scripts_stay_below_the_windows_script_report() {
    for relative in [
        "powershell/megafile/edge_cases.ps1",
        "powershell/chameleon/rename_original.ps1",
        "batch/baseline/hello.bat",
    ] {
        let bytes: Vec<u8> = corpus_bytes(relative);
        let detection: Detection = detect(&bytes);
        assert!(!detection.obfuscation_constructs, "{relative}");
        assert!(
            claim(&bytes).is_none_or(|v: DetectVerdict| v.confidence < 0.85),
            "{relative} must leave the plain-script report to scriptlang.classify"
        );
    }
}

#[test]
fn a_claimed_script_that_recovers_nothing_is_refused_rather_than_republished() {
    let bytes: Vec<u8> = corpus_bytes("batch/baseline/hello.bat");
    assert!(claim(&bytes).is_some());
    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let error: String = SHELL_PASS
        .run(&input)
        .expect_err("an unobfuscated script has nothing to recover")
        .to_string();
    assert!(error.contains("DR-SHELL-0928"), "{error}");
}

#[test]
fn source_in_other_languages_that_mentions_powershell_words_is_not_claimed() {
    let javascript: &[u8] =
        b"const IEX = 'Invoke-Expression';\nfunction run(cmd) {\n  return $(cmd).text();\n}\n";
    assert!(claim(javascript).is_none());
    let csharp: &[u8] = b"using System.IO.Compression;\nclass A { void F(Stream s) { var z = new GZipStream(s, CompressionMode.Decompress); } }\n";
    assert!(claim(csharp).is_none());
    let c_source: &[u8] = b"int f(int x) { return x & ('a' + 'b'); }\n";
    assert!(claim(c_source).is_none());
    let binary: Vec<u8> = [b"MZ\x90\x00".as_slice(), b"@echo o^ff\r\n".as_slice()].concat();
    let detection: Detection = detect(&binary);
    assert!(!detection.obfuscation_constructs);
    assert!(claim(&binary).is_none_or(|v: DetectVerdict| v.confidence < 0.85));
}
