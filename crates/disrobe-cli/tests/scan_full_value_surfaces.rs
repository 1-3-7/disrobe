#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("release")
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

fn planted_key() -> String {
    format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
}

fn fixture() -> (disrobe_core::scratch::ScratchDir, PathBuf, String) {
    let key: String = planted_key();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-scan-full-value")
            .expect("create scratch directory");
    let path: PathBuf = scratch.path().join("keys.txt");
    std::fs::write(&path, format!("aws_access_key_id = {key}\n")).expect("write fixture");
    (scratch, path, key)
}

fn run(args: &[&str], path: &PathBuf) -> String {
    let out: std::process::Output = Command::new(cli_binary())
        .arg("scan")
        .args(args)
        .arg(path)
        .output()
        .expect("run disrobe scan");
    assert!(
        out.status.success(),
        "non-zero exit for {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn scan_findings(json: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(json).expect("json parse");
    v["findings"].as_array().expect("findings array").clone()
}

#[test]
fn the_full_value_reaches_text_json_ndjson_and_sarif_by_default() {
    let (_scratch, path, key): (disrobe_core::scratch::ScratchDir, PathBuf, String) = fixture();

    let json: String = run(&["--json"], &path);
    let findings: Vec<Value> = scan_findings(&json);
    let aws: &Value = findings
        .iter()
        .find(|f: &&Value| f["code"] == "DR-SEC-AWS-AKID")
        .unwrap_or_else(|| {
            panic!("the fixture must produce an aws access-key finding, got: {findings:?}")
        });
    assert_eq!(
        aws["value"].as_str(),
        Some(key.as_str()),
        "json must expose the match in its own field"
    );

    let text: String = run(&[], &path);
    assert!(
        text.lines().any(|line: &str| line.contains(key.as_str())),
        "text must print the full value, got:\n{text}"
    );
    let row: &str = text
        .lines()
        .find(|line: &&str| line.contains(key.as_str()))
        .expect("value row");
    for column in [
        "error",
        "DR-SEC-AWS-AKID",
        "AWS access key id",
        "keys.txt",
        "@",
    ] {
        assert!(
            row.contains(column),
            "text row must carry {column}, got: {row}"
        );
    }

    let ndjson: String = run(&["--ndjson"], &path);
    assert_eq!(
        ndjson
            .lines()
            .filter(|l: &&str| !l.trim().is_empty())
            .count(),
        1,
        "ndjson must be one line per report"
    );
    assert_eq!(
        scan_findings(&ndjson)
            .iter()
            .filter_map(|f: &Value| f["value"].as_str().map(str::to_owned))
            .find(|v: &String| v == &key),
        Some(key.clone()),
        "ndjson must carry the full value: {ndjson}"
    );

    let sarif: String = run(&["--sarif"], &path);
    let log: Value = serde_json::from_str(&sarif).expect("sarif parse");
    let results: &Vec<Value> = log["runs"][0]["results"]
        .as_array()
        .expect("sarif results array");
    let aws_result: &Value = results
        .iter()
        .find(|r: &&Value| r["ruleId"] == "DR-SEC-AWS-AKID")
        .unwrap_or_else(|| panic!("sarif must carry the aws result, got: {results:?}"));
    assert!(
        aws_result["message"]["text"]
            .as_str()
            .expect("sarif message")
            .contains(key.as_str()),
        "sarif must carry the full value: {aws_result}"
    );
    let region: &Value = &aws_result["locations"][0]["physicalLocation"]["region"];
    assert_eq!(
        region["byteOffset"].as_u64(),
        aws["offset"].as_u64(),
        "sarif must carry the same byte offset json reports: {region}"
    );
    assert!(
        region["byteOffset"].as_u64().is_some(),
        "the sarif region must exist at all: {aws_result}"
    );
}

#[test]
fn frisk_default_shows_the_full_value_and_redaction_flags_still_hide_it() {
    let (_scratch, path, key): (disrobe_core::scratch::ScratchDir, PathBuf, String) = fixture();
    let dir: PathBuf = path.parent().expect("fixture parent").to_path_buf();

    let plain: std::process::Output = Command::new(cli_binary())
        .arg("frisk")
        .arg("--format")
        .arg("json")
        .arg(&dir)
        .output()
        .expect("run disrobe frisk");
    assert!(plain.status.success(), "frisk must succeed");
    let plain_text: String = String::from_utf8(plain.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&plain_text).expect("json parse");
    let secret: &Value = v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|f: &&Value| f["rule_id"] == "DR-SEC-AWS-AKID")
        .expect("the fixture must produce a DR-SEC-AWS-AKID finding");
    assert_eq!(
        secret["value"].as_str(),
        Some(key.as_str()),
        "frisk must default to the full value for DR-SEC-* rules"
    );

    for flag in [
        vec!["--redact".to_owned()],
        vec!["--redact-key".to_owned(), "pinned".to_owned()],
    ] {
        let redacted: std::process::Output = Command::new(cli_binary())
            .arg("frisk")
            .arg("--format")
            .arg("json")
            .args(&flag)
            .arg(&dir)
            .output()
            .expect("run disrobe frisk");
        assert!(redacted.status.success(), "redacted frisk must succeed");
        let body: String = String::from_utf8(redacted.stdout).expect("utf8 stdout");
        assert!(
            !body.contains(key.as_str()),
            "opt-in redaction {flag:?} must still hide the value:\n{body}"
        );
        assert!(
            body.contains("[REDACTED:"),
            "opt-in redaction {flag:?} must still emit sentinels:\n{body}"
        );
    }
}
