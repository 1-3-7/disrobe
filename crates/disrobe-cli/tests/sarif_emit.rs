#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const OS_SYSTEM_REDUCE: &[u8] = b"\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x94\x8c\x02id\x85\x94R\x94.";

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn temp_pickle(bytes: &[u8]) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path: PathBuf = std::env::temp_dir().join(format!("disrobe-sarif-emit-{pid}-{seq}.pkl"));
    std::fs::write(&path, bytes).expect("write temp pickle");
    path
}

#[test]
fn pickle_safety_sarif_reaches_scanner() {
    let path: PathBuf = temp_pickle(OS_SYSTEM_REDUCE);
    let out: std::process::Output = Command::new(cli_binary())
        .args(["pickle", "safety", "--sarif"])
        .arg(&path)
        .output()
        .expect("run disrobe pickle safety --sarif");
    let _ = std::fs::remove_file(&path);

    assert!(
        out.status.success(),
        "non-zero exit: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout: String = String::from_utf8(out.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout).expect("stdout parses as json");

    assert_eq!(v["version"], "2.1.0");
    assert_eq!(
        v["$schema"],
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    );
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "disrobe");

    let results: &Vec<Value> = v["runs"][0]["results"]
        .as_array()
        .expect("results array present");
    assert!(
        results
            .iter()
            .any(|r: &Value| r["ruleId"] == "reduce.payload" && r["level"] == "error"),
        "expected an error-level reduce.payload result, got: {stdout}"
    );

    let rules: &Vec<Value> = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array present");
    assert!(
        rules.iter().any(|r: &Value| r["id"] == "reduce.payload"),
        "expected reduce.payload rule in driver.rules"
    );
}

#[test]
fn benign_pickle_sarif_is_clean_log() {
    let path: PathBuf = temp_pickle(b"\x80\x02K\x01.");
    let out: std::process::Output = Command::new(cli_binary())
        .args(["pickle", "safety", "--sarif"])
        .arg(&path)
        .output()
        .expect("run disrobe pickle safety --sarif on benign");
    let _ = std::fs::remove_file(&path);

    assert!(out.status.success());
    let stdout: String = String::from_utf8(out.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout).expect("stdout parses as json");

    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].is_string());
    assert_eq!(
        v["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .len(),
        0
    );
    assert!(v["runs"][0]["tool"]["driver"].get("rules").is_none());
}
