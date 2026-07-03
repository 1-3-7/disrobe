#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_php::deflatten::{DeflattenReport, deflatten};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn php_bin() -> Option<String> {
    let out: std::io::Result<std::process::Output> = Command::new("php").arg("--version").output();
    match out {
        Ok(o) if o.status.success() => Some("php".to_owned()),
        _ => None,
    }
}

fn run_php_source(php: &str, source: &[u8]) -> (bool, Vec<u8>) {
    let dir: PathBuf = std::env::temp_dir();
    let unique: String = format!(
        "disrobe_deflatten_oracle_{}_{}.php",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path: PathBuf = dir.join(unique);
    {
        let mut f: std::fs::File = std::fs::File::create(&path).expect("create temp php");
        f.write_all(source).expect("write temp php");
    }
    let out: std::process::Output = Command::new(php)
        .arg("-d")
        .arg("error_reporting=0")
        .arg("-d")
        .arg("display_errors=0")
        .arg(&path)
        .output()
        .expect("spawn php");
    let _ = std::fs::remove_file(&path);
    (out.status.success(), out.stdout)
}

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("php");
    p.push("yakpro");
    p.push(name);
    p
}

fn assert_recovered_matches_original(obf_name: &str, orig_name: &str) {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP: php not on PATH");
        return;
    };
    let obfuscated: Vec<u8> = match std::fs::read(corpus(obf_name)) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: corpus sample {obf_name} absent");
            return;
        }
    };
    let original: Vec<u8> = std::fs::read(corpus(orig_name)).expect("original sample present");

    let (orig_ok, orig_out): (bool, Vec<u8>) = run_php_source(&php, &original);
    assert!(orig_ok, "original sample must run under php");

    let report: DeflattenReport = deflatten(&obfuscated).expect("deflatten must succeed");
    let recovered: Vec<u8> = report.source;

    assert!(
        !contains_goto(&recovered),
        "deflattened output must drop the linear goto chain; got:\n{}",
        String::from_utf8_lossy(&recovered)
    );

    let (rec_ok, rec_out): (bool, Vec<u8>) = run_php_source(&php, &recovered);
    assert!(
        rec_ok,
        "recovered php must run under php; source:\n{}",
        String::from_utf8_lossy(&recovered)
    );
    assert_eq!(
        rec_out,
        orig_out,
        "recovered php output must equal original output (non-circular behavioral oracle)\nrecovered source:\n{}",
        String::from_utf8_lossy(&recovered)
    );
}

fn assert_recovered_matches_original_runs(obf_name: &str, orig_name: &str) {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP: php not on PATH");
        return;
    };
    let obfuscated: Vec<u8> = match std::fs::read(corpus(obf_name)) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: corpus sample {obf_name} absent");
            return;
        }
    };
    let original: Vec<u8> = std::fs::read(corpus(orig_name)).expect("original sample present");
    let (orig_ok, orig_out): (bool, Vec<u8>) = run_php_source(&php, &original);
    assert!(orig_ok, "original sample must run under php");

    let report: DeflattenReport = deflatten(&obfuscated).expect("deflatten must succeed");
    let (rec_ok, rec_out): (bool, Vec<u8>) = run_php_source(&php, &report.source);
    assert!(
        rec_ok,
        "recovered php must run under php; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
    assert_eq!(
        rec_out,
        orig_out,
        "recovered php output must equal original output\nrecovered source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
}

fn contains_goto(src: &[u8]) -> bool {
    let lower: Vec<u8> = src.to_ascii_lowercase();
    twoway_contains(&lower, b"goto ")
}

fn twoway_contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn oracle_linear_goto_chain_deflattens_to_original_output() {
    assert_recovered_matches_original("calc_yakpro_3.0.0.php", "calc_original.php");
}

#[test]
fn oracle_control_flow_sample_runs_identically_after_deflatten() {
    assert_recovered_matches_original_runs(
        "controlflow_yakpro_3.0.0.php",
        "controlflow_original.php",
    );
}
