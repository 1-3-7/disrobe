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

use disrobe_pass_php::restructure::{RestructureReport, restructure};

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
        "disrobe_restructure_oracle_{}_{}.php",
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

fn goto_count(src: &[u8]) -> usize {
    let lower: Vec<u8> = src.to_ascii_lowercase();
    let needle: &[u8] = b"goto ";
    lower.windows(needle.len()).filter(|w| *w == needle).count()
}

#[test]
fn oracle_controlflow_restructures_and_runs_identically() {
    let Some(php): Option<String> = php_bin() else {
        eprintln!("SKIP: php not on PATH");
        return;
    };
    let obfuscated: Vec<u8> = match std::fs::read(corpus("controlflow_yakpro_3.0.0.php")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: corpus sample absent");
            return;
        }
    };
    let original: Vec<u8> = std::fs::read(corpus("controlflow_original.php")).expect("original");
    let (orig_ok, orig_out): (bool, Vec<u8>) = run_php_source(&php, &original);
    assert!(orig_ok, "original must run");

    let report: RestructureReport = restructure(&obfuscated).expect("restructure");
    let (rec_ok, rec_out): (bool, Vec<u8>) = run_php_source(&php, &report.source);
    assert!(
        rec_ok,
        "restructured php must run; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
    assert_eq!(
        rec_out,
        orig_out,
        "restructured output must equal original output\nsource:\n{}",
        String::from_utf8_lossy(&report.source)
    );

    assert!(
        report.whiles_recovered >= 1,
        "the for/while loop must be recovered to a native while; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
    assert!(
        report.ifs_recovered >= 1,
        "the if/else must be recovered to native if/else; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );

    let before: usize = goto_count(&obfuscated);
    let after: usize = goto_count(&report.source);
    assert!(
        after < before,
        "restructure must reduce goto count: before={before} after={after}"
    );
}
