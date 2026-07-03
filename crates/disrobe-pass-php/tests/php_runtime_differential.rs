#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

mod common;

use disrobe_pass_php::{RecoveryStage, recover_php};
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_php() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("DISROBE_PHP_BIN") {
        let p: PathBuf = PathBuf::from(explicit);
        if p.exists() {
            return Some(p);
        }
    }
    let probe: std::io::Result<std::process::Output> =
        Command::new("php").arg("--version").output();
    match probe {
        Ok(out) if out.status.success() => Some(PathBuf::from("php")),
        _ => None,
    }
}

static RUN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn run_php_source(php: &Path, source: &str) -> Option<String> {
    let seq: u64 = RUN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_php_diff_{}_{}.php",
        std::process::id(),
        seq
    ));
    std::fs::write(&tmp, source).ok()?;
    let out: std::io::Result<std::process::Output> = Command::new(php).arg(&tmp).output();
    let _ = std::fs::remove_file(&tmp);
    let out: std::process::Output = out.ok()?;
    if !out.status.success() {
        eprintln!(
            "php run failed: {}\n--- source ---\n{source}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn wrap_recovered(recovered: &str) -> String {
    let trimmed: &str = recovered.trim_start();
    if trimmed.starts_with("<?php") || trimmed.starts_with("<?") {
        recovered.to_owned()
    } else {
        format!("<?php {recovered}")
    }
}

fn assert_runtime_equivalent(label: &str, obfuscated: &[u8], expected_marker: &str) {
    let Some(php): Option<PathBuf> = find_php() else {
        eprintln!("skip {label}: php not on PATH (set DISROBE_PHP_BIN)");
        return;
    };

    let obf_source: String = String::from_utf8_lossy(obfuscated).into_owned();
    let obf_stdout: String = run_php_source(&php, &obf_source)
        .unwrap_or_else(|| panic!("{label}: obfuscated loader did not run cleanly under php"));
    assert!(
        obf_stdout.contains(expected_marker),
        "{label}: obfuscated loader stdout lacks the ground-truth marker {expected_marker:?}; got {obf_stdout:?}"
    );

    let report = recover_php(obfuscated, None)
        .unwrap_or_else(|e: disrobe_pass_php::Error| panic!("{label}: recover failed: {e}"));
    assert_ne!(
        report.stage,
        RecoveryStage::PlainSource,
        "{label}: a real obfuscated loader must not be reported as plain source"
    );
    assert!(
        !report.output.is_empty(),
        "{label}: recovery produced no source to grade"
    );

    let recovered_source: String = wrap_recovered(&report.output);
    let recovered_stdout: String = run_php_source(&php, &recovered_source).unwrap_or_else(|| {
        panic!("{label}: recovered source did not run cleanly under php:\n{recovered_source}")
    });

    assert_eq!(
        recovered_stdout, obf_stdout,
        "{label}: recovered source is not behaviorally equivalent to the obfuscated loader under the real php runtime\n--- recovered ---\n{recovered_source}"
    );
}

const MARKER: &str = "DISROBE-PHP-DIFF-9F3A";

fn marker_payload() -> String {
    format!("echo '{MARKER}';")
}

#[test]
fn base64_gzinflate_eval_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_eval_chain(&marker_payload());
    assert_runtime_equivalent("base64+gzinflate", &blob, MARKER);
}

#[test]
fn base64_only_eval_runtime_equivalent() {
    let blob: Vec<u8> = common::build_b64_only_eval(&marker_payload());
    assert_runtime_equivalent("base64-only", &blob, MARKER);
}

#[test]
fn rot13_interposed_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_rot13_interposed_chain(&marker_payload());
    assert_runtime_equivalent("gzinflate(str_rot13(base64))", &blob, MARKER);
}

#[test]
fn strrev_wrapped_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_b64_wrapping_strrev_chain(&marker_payload());
    assert_runtime_equivalent("base64(strrev)", &blob, MARKER);
}

#[test]
fn split_literal_b64_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_split_literal_b64_chain(&marker_payload());
    assert_runtime_equivalent("base64(concat-literals)", &blob, MARKER);
}

#[test]
fn fopo_loader_runtime_equivalent() {
    let blob: Vec<u8> = common::build_fopo(&marker_payload());
    assert_runtime_equivalent("fopo", &blob, MARKER);
}

#[test]
fn better_php_obf_variable_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_better_php_obf(&marker_payload());
    assert_runtime_equivalent("better-php-obfuscator", &blob, MARKER);
}

#[test]
fn str_rot13_base64_loader_runtime_equivalent() {
    let blob: Vec<u8> = common::build_str_rot13_b64(&marker_payload());
    assert_runtime_equivalent("base64(str_rot13)", &blob, MARKER);
}

#[test]
fn array_indexed_function_dispatch_runtime_equivalent() {
    let blob: Vec<u8> = common::build_array_indexed_dispatch(&marker_payload());
    assert_runtime_equivalent("array-indexed dispatch", &blob, MARKER);
}

#[test]
fn strtr_custom_alphabet_base64_runtime_equivalent() {
    let blob: Vec<u8> = common::build_strtr_custom_alphabet_chain(&marker_payload());
    assert_runtime_equivalent("base64(strtr custom alphabet)", &blob, MARKER);
}

#[test]
fn xor_keystream_loop_runtime_equivalent() {
    let blob: Vec<u8> = common::build_loop_xor_chain(&marker_payload());
    assert_runtime_equivalent("xor-keystream-loop", &blob, MARKER);
}

#[test]
fn rc4_static_key_loop_runtime_equivalent() {
    let blob: Vec<u8> = common::build_rc4_static_key_chain(&marker_payload());
    assert_runtime_equivalent("rc4-static-key", &blob, MARKER);
}

#[test]
fn runtime_sourced_key_walls_and_recovered_body_is_never_fabricated() {
    let Some(php): Option<PathBuf> = find_php() else {
        eprintln!("skip runtime-key wall: php not on PATH (set DISROBE_PHP_BIN)");
        return;
    };
    let loader: &[u8] =
        b"<?php $k=$_GET['k']; ev\x61l(gzinflate(base64_decode($k . 'cGF5bG9hZA==')));";
    let report = recover_php(loader, None).expect("recover runtime-key loader");
    assert!(
        !report.output.contains(MARKER),
        "a $_GET-sourced key is absent from the file; recovery must wall, never fabricate a body; got:\n{}",
        report.output
    );
    assert_eq!(
        run_php_source(&php, "<?php echo 'wall-pin-ok';").as_deref(),
        Some("wall-pin-ok"),
        "php oracle sanity check failed"
    );
}
