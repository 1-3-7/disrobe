#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::{PeelOptions, peel_eval_chain};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

fn php_bin() -> Option<String> {
    let candidate: &str = "php";
    let out: std::io::Result<std::process::Output> =
        Command::new(candidate).arg("--version").output();
    match out {
        Ok(o) if o.status.success() => Some(candidate.to_owned()),
        _ => None,
    }
}

fn run_php_source(php: &str, source: &[u8]) -> (bool, Vec<u8>) {
    let unique: String = format!("disrobe_php_oracle_{}_{}", std::process::id(), next_seq());
    let (scratch, mut f): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&unique, "php").expect("create temp php");
    let path: PathBuf = scratch.path().to_path_buf();
    f.write_all(source).expect("write temp php");
    drop(f);
    let out: std::process::Output = Command::new(php)
        .arg("-d")
        .arg("error_reporting=0")
        .arg("-d")
        .arg("display_errors=0")
        .arg(&path)
        .output()
        .expect("spawn php");
    (out.status.success(), out.stdout)
}

use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn generate_loader(php: &str, builder_php: &str) -> Vec<u8> {
    let (ok, stdout): (bool, Vec<u8>) = run_php_source(php, builder_php.as_bytes());
    assert!(ok, "loader generator script failed to run under php");
    stdout
}

fn peel_to_source(loader: &[u8]) -> String {
    let report = peel_eval_chain(loader, PeelOptions::default()).unwrap_or_else(|e| {
        panic!(
            "peel failed: {e}\nloader was:\n{}",
            String::from_utf8_lossy(loader)
        )
    });
    String::from_utf8_lossy(&report.final_source).into_owned()
}

fn behavioral_roundtrip(php: &str, payload: &str, builder_php: &str) {
    let original_full: String = format!("<?php {payload}");
    let (orig_ok, orig_out): (bool, Vec<u8>) = run_php_source(php, original_full.as_bytes());
    assert!(
        orig_ok,
        "original payload did not execute cleanly under php"
    );

    let loader: Vec<u8> = generate_loader(php, builder_php);
    let recovered_inner: String = peel_to_source(&loader);

    let recovered_full: String = if recovered_inner.trim_start().starts_with("<?php") {
        recovered_inner
    } else {
        format!("<?php {recovered_inner}")
    };
    let (rec_ok, rec_out): (bool, Vec<u8>) = run_php_source(php, recovered_full.as_bytes());
    assert!(
        rec_ok,
        "recovered source failed to execute under php:\n{recovered_full}"
    );
    assert_eq!(
        rec_out, orig_out,
        "recovered source produced different output than the original payload"
    );
}

const PAYLOAD: &str = "echo 'recovered-and-re-executed:' . (7 * 6);";

#[test]
fn oracle_multi_statement_b64_gzinflate_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_multi_statement_b64_gzinflate_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode(gzdeflate($payload));
echo "<?php\n";
echo "\$a = '$blob';\n";
echo "\$b = base64_decode(\$a);\n";
echo "\$c = gzinflate(\$b);\n";
echo "eval(\$c);\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_multi_statement_gzuncompress_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_multi_statement_gzuncompress_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode(gzcompress($payload));
echo "<?php\n";
echo "\$data = '$blob';\n";
echo "\$step1 = base64_decode(\$data);\n";
echo "\$step2 = gzuncompress(\$step1);\n";
echo "eval(\$step2);\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_str_rot13_over_base64_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_str_rot13_over_base64_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = str_rot13(base64_encode($payload));
echo "<?php\n";
echo "\$e = '$blob';\n";
echo "\$d = base64_decode(str_rot13(\$e));\n";
echo "eval(\$d);\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_concat_function_name_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_concat_function_name_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$decoder = 'bas' . 'e64_' . 'decode';\n";
echo "\$runner = 'ev' . 'al';\n";
echo "\$runner(\$decoder('$blob'));\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_chr_concat_function_name_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_chr_concat_function_name_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$a = chr(101) . chr(118) . chr(97) . chr(108);\n";
echo "\$d = chr(98).chr(97).chr(115).chr(101).chr(54).chr(52).chr(95).chr(100).chr(101).chr(99).chr(111).chr(100).chr(101);\n";
echo "\$a(\$d('$blob'));\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_hex_chr_concat_function_name_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_hex_chr_concat_function_name_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$a = chr(0x65) . chr(0x76) . chr(0x61) . chr(0x6c);\n";
echo "\$d = chr(0x62).chr(0x61).chr(0x73).chr(0x65).chr(0x36).chr(0x34).chr(0x5f).chr(0x64).chr(0x65).chr(0x63).chr(0x6f).chr(0x64).chr(0x65);\n";
echo "\$a(\$d('$blob'));\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_globals_indirection_function_call_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_globals_indirection_function_call_loader: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$GLOBALS['r'] = 'ev' . 'al';\n";
echo "\$GLOBALS['d'] = 'base64_' . 'decode';\n";
echo "\$GLOBALS['r'](\$GLOBALS['d']('$blob'));\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_preg_replace_e_modifier_loader() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_preg_replace_e_modifier_loader: php not on PATH");
        return;
    };
    let payload: &str = "echo 'preg-e-recovered:' . (3 + 4);";
    let builder: &str = r#"<?php
$payload = "echo 'preg-e-recovered:' . (3 + 4);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "preg_replace('/(.*)/e', base64_decode('$blob'), '');\n";
"#;
    let original_full: String = format!("<?php {payload}");
    let (orig_ok, orig_out): (bool, Vec<u8>) = run_php_source(&php, original_full.as_bytes());
    assert!(orig_ok, "original preg-e payload did not run");
    let loader: Vec<u8> = generate_loader(&php, builder);
    let recovered: String = peel_to_source(&loader);
    let recovered_full: String = if recovered.trim_start().starts_with("<?php") {
        recovered
    } else {
        format!("<?php {recovered}")
    };
    let (rec_ok, rec_out): (bool, Vec<u8>) = run_php_source(&php, recovered_full.as_bytes());
    assert!(rec_ok, "recovered preg-e source failed:\n{recovered_full}");
    assert_eq!(
        rec_out, orig_out,
        "preg_replace/e recovered body did not re-execute to the same output"
    );
}

#[test]
fn oracle_deep_chain_strrev_b64_gzinflate_multi_statement() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_deep_chain: php not on PATH");
        return;
    };
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = strrev(base64_encode(gzdeflate($payload)));
echo "<?php\n";
echo "\$p = '$blob';\n";
echo "\$q = strrev(\$p);\n";
echo "\$r = base64_decode(\$q);\n";
echo "\$s = gzinflate(\$r);\n";
echo "eval(\$s);\n";
"#;
    behavioral_roundtrip(&php, PAYLOAD, builder);
}

#[test]
fn oracle_plain_source_passes_through_unchanged() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP oracle_plain_source: php not on PATH");
        return;
    };
    let plain: &[u8] = b"<?php echo 'no obfuscation here:' . (1 + 1);";
    let (ok, out): (bool, Vec<u8>) = run_php_source(&php, plain);
    assert!(ok);
    let report = peel_eval_chain(plain, PeelOptions::default());
    if let Ok(r) = report {
        let recovered: String = String::from_utf8_lossy(&r.final_source).into_owned();
        let recovered_full: String = if recovered.trim_start().starts_with("<?php") {
            recovered
        } else {
            format!("<?php {recovered}")
        };
        let (rok, rout): (bool, Vec<u8>) = run_php_source(&php, recovered_full.as_bytes());
        assert!(rok);
        assert_eq!(rout, out, "plain source must round-trip behaviorally");
    }
}
