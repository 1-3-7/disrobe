#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

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

struct Planted {
    slack: String,
    sendgrid: String,
    telegram: String,
    discord: String,
    aws: String,
    github: String,
    pem: String,
}

impl Planted {
    fn build() -> Self {
        Self {
            slack: format!(
                "https://hooks.slack.com/services/{}/{}/{}",
                "T00000000", "B11111111", "abcdefghijklmnopqrstuvwx"
            ),
            sendgrid: format!("{}.{}.{}", "SG", "A".repeat(22), "B".repeat(43)),
            telegram: format!("{}{}{}", "123456789", ":A", "A".repeat(34)),
            discord: format!(
                "https://discord.com/api/webhooks/{}/{}",
                "123456789012345678",
                "a".repeat(64)
            ),
            aws: format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB"),
            github: format!("{}{}", "ghp_", "0123456789abcdefghijklmnopqrstuvwxyz"),
            pem: format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                "A".repeat(64)
            ),
        }
    }

    fn full_leak(&self) -> [&str; 4] {
        [
            self.slack.as_str(),
            self.sendgrid.as_str(),
            self.telegram.as_str(),
            self.discord.as_str(),
        ]
    }

    fn all_literals(&self) -> [&str; 7] {
        [
            self.slack.as_str(),
            self.sendgrid.as_str(),
            self.telegram.as_str(),
            self.discord.as_str(),
            self.aws.as_str(),
            self.github.as_str(),
            self.pem.as_str(),
        ]
    }
}

fn corpus() -> (disrobe_core::scratch::ScratchDir, PathBuf, Planted) {
    let planted: Planted = Planted::build();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-frisk-redact")
            .expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    std::fs::write(
        dir.join("keys.txt"),
        format!("aws key = {}\ntoken: {}\n", planted.aws, planted.github),
    )
    .expect("write keys.txt");
    std::fs::write(
        dir.join("hooks.env"),
        format!(
            "SLACK_HOOK={}\nSENDGRID_API_KEY={}\nTELEGRAM_BOT={}\nDISCORD_HOOK={}\n",
            planted.slack, planted.sendgrid, planted.telegram, planted.discord
        ),
    )
    .expect("write hooks.env");
    std::fs::write(dir.join("private.pem"), planted.pem.as_bytes()).expect("write private key");
    std::fs::write(
        dir.join("nested.json"),
        format!(
            r#"{{"array":["{}"],"object":{{"bare":"{}"}}}}"#,
            planted.aws, planted.github
        ),
    )
    .expect("write nested JSON");
    let mut binary: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x80];
    binary.extend_from_slice(format!("prefix={} suffix", planted.aws).as_bytes());
    std::fs::write(dir.join("binary.bin"), binary).expect("write binary fixture");
    (scratch, dir, planted)
}

fn frisk(dir: &PathBuf, args: &[&str]) -> String {
    let out: std::process::Output = Command::new(cli_binary())
        .arg("frisk")
        .args(args)
        .arg(dir)
        .output()
        .expect("run disrobe frisk");
    assert!(
        out.status.success(),
        "non-zero exit for {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn scan(path: &PathBuf, args: &[&str]) -> String {
    let out: std::process::Output = Command::new(cli_binary())
        .arg("scan")
        .args(args)
        .arg(path)
        .output()
        .expect("run disrobe scan");
    assert!(
        out.status.success(),
        "non-zero scan exit for {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn locations(json: &str) -> Vec<(String, String, u64, u64)> {
    let v: Value = serde_json::from_str(json).expect("json parse");
    let findings: &Vec<Value> = v["findings"].as_array().expect("findings array");
    let mut locs: Vec<(String, String, u64, u64)> = findings
        .iter()
        .map(|f: &Value| {
            (
                f["rule_id"].as_str().unwrap_or_default().to_owned(),
                f["path"].as_str().unwrap_or_default().to_owned(),
                f["line"].as_u64().unwrap_or_default(),
                f["column"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    locs.sort();
    locs
}

fn finding_value(json: &str, rule_id: &str) -> Option<String> {
    let v: Value = serde_json::from_str(json).expect("json parse");
    v["findings"].as_array()?.iter().find_map(|f: &Value| {
        (f["rule_id"] == rule_id && f["category"] == "secret")
            .then(|| f["value"].as_str().unwrap_or_default().to_owned())
    })
}

#[test]
fn redact_produces_zero_leak_across_text_json_sarif_with_location_parity() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();

    let plain_json: String = frisk(&dir, &["--format", "json"]);
    let plain_value: Value = serde_json::from_str(&plain_json).expect("plain report JSON");
    assert!(
        plain_value["non_utf8_files"]
            .as_u64()
            .is_some_and(|count: u64| count >= 1)
    );

    for secret in planted.full_leak() {
        assert!(
            plain_json.contains(secret),
            "positive control: unredacted json must contain the full planted secret {secret}"
        );
    }
    for rule in ["DR-SEC-AWS-AKID", "DR-SEC-GH-PAT"] {
        assert!(
            finding_value(&plain_json, rule).is_some(),
            "positive control: {rule} must be detected as a secret finding"
        );
    }

    let redacted_json: String = frisk(&dir, &["--format", "json", "--redact"]);
    let redacted_text: String = frisk(&dir, &["--format", "text", "--redact"]);
    let redacted_sarif: String = frisk(&dir, &["--format", "sarif", "--redact"]);

    for (label, output) in [
        ("json", &redacted_json),
        ("text", &redacted_text),
        ("sarif", &redacted_sarif),
    ] {
        for secret in planted.all_literals() {
            assert!(
                !output.contains(secret),
                "redacted {label} output leaked the planted secret {secret}\n---\n{output}"
            );
        }
        assert!(
            output.contains("[REDACTED:"),
            "redacted {label} output must carry sentinels"
        );
    }

    serde_json::from_str::<Value>(&redacted_sarif).expect("redacted sarif is valid json");

    assert_eq!(
        locations(&plain_json),
        locations(&redacted_json),
        "the (rule,file,line,col) multiset must be identical between redacted and unredacted runs"
    );

    let aws_value: String = finding_value(&redacted_json, "DR-SEC-AWS-AKID").expect("aws finding");
    assert!(
        aws_value.starts_with("[REDACTED:"),
        "the preview of a secret-scan secret must also be replaced by a sentinel: {aws_value}"
    );

    let rescan_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-frisk-redact-rescan")
            .expect("create rescan scratch directory");
    let redacted_path: PathBuf = rescan_scratch.path().join("redacted.json");
    std::fs::write(&redacted_path, redacted_json.as_bytes()).expect("write redacted output");
    let scan_rescan: Value =
        serde_json::from_str(&scan(&redacted_path, &["--json"])).expect("scan rescan JSON");
    assert!(
        scan_rescan["findings"]
            .as_array()
            .is_some_and(
                |findings: &Vec<Value>| findings.iter().all(|finding: &Value| {
                    finding["kind"] == Value::String("high_entropy_generic".to_owned())
                        && planted.all_literals().iter().all(|secret: &&str| {
                            !finding["value"]
                                .as_str()
                                .is_some_and(|value: &str| value.contains(secret))
                        })
                })
            ),
        "scan found a concrete secret in redacted output: {scan_rescan}"
    );
    let frisk_rescan: Value = serde_json::from_str(&frisk(&redacted_path, &["--format", "json"]))
        .expect("frisk rescan JSON");
    assert!(
        frisk_rescan["findings"]
            .as_array()
            .is_some_and(
                |findings: &Vec<Value>| findings.iter().all(|finding: &Value| {
                    finding["category"] != Value::String("secret".to_owned())
                })
            ),
        "frisk found a secret in redacted output"
    );
}

#[test]
fn redaction_is_deterministic_across_runs_without_a_key() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();
    let public_redactor: disrobe_core::Redactor = disrobe_core::Redactor::new();
    assert_eq!(
        public_redactor.token("abc"),
        "[REDACTED:ba7816bf8f01cfea414140de]"
    );

    let first: String = frisk(&dir, &["--format", "json", "--redact"]);
    let second: String = frisk(&dir, &["--format", "json", "--redact"]);

    for secret in planted.all_literals() {
        assert!(
            !first.contains(secret),
            "deterministic redaction still leaked {secret}"
        );
    }
    assert_eq!(
        first, second,
        "unsalted redaction must yield byte-identical output across runs"
    );
}

#[test]
fn scan_redaction_is_opt_in_and_preserves_finding_identity() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();
    let path: PathBuf = dir.join("keys.txt");

    let plain: String = scan(&path, &["--json"]);
    let redacted: String = scan(&path, &["--json", "--redact"]);

    assert!(plain.contains(planted.aws.as_str()));
    assert!(!redacted.contains(planted.aws.as_str()));
    assert!(redacted.contains("[REDACTED:"));

    let plain_json: Value = serde_json::from_str(&plain).expect("plain json");
    let redacted_json: Value = serde_json::from_str(&redacted).expect("redacted json");
    assert_eq!(
        plain_json["findings"].as_array().map(Vec::len),
        redacted_json["findings"].as_array().map(Vec::len)
    );
    assert_eq!(
        plain_json["findings"][0]["offset"],
        redacted_json["findings"][0]["offset"]
    );
}

#[test]
fn suppression_and_baseline_filter_before_redaction() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();
    let aws_token: String = disrobe_core::Redactor::new().token(planted.aws.as_str());

    let suppressed: String = frisk(
        &dir,
        &[
            "--format",
            "json",
            "--suppress",
            planted.aws.as_str(),
            "--redact",
        ],
    );
    assert!(!suppressed.contains(aws_token.as_str()));

    let baseline: String = frisk(&dir, &["--emit-baseline"]);
    let baseline_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-frisk-redact-baseline")
            .expect("create baseline scratch directory");
    let baseline_path: PathBuf = baseline_scratch.path().join("baseline.json");
    std::fs::write(&baseline_path, baseline).expect("write baseline");
    let filtered: String = frisk(
        &dir,
        &[
            "--format",
            "json",
            "--baseline",
            baseline_path.to_str().expect("baseline path"),
            "--redact",
        ],
    );
    let filtered_json: Value = serde_json::from_str(&filtered).expect("filtered report JSON");
    assert_eq!(filtered_json["total"], 0);
    assert!(!filtered.contains("[REDACTED:"));
}

#[test]
fn configuration_enables_redaction_for_frisk_and_scan() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();
    let config_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-frisk-redact-config")
            .expect("create config scratch directory");
    let config_path: PathBuf = config_scratch.path().join("disrobe.toml");
    std::fs::write(&config_path, "[output]\nredact = true\n").expect("write config");
    let config: &str = config_path.to_str().expect("config path");

    let frisked: String = frisk(&dir, &["--config", config, "--format", "json"]);
    let scanned: String = scan(&dir.join("keys.txt"), &["--config", config, "--json"]);
    for output in [&frisked, &scanned] {
        assert!(!output.contains(planted.aws.as_str()));
        assert!(output.contains("[REDACTED:"));
    }
}

#[test]
fn custom_pattern_matches_are_redacted_by_value() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-frisk-redact-custom")
            .expect("create custom pattern scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let planted: &str = "client-secret-ABCDEFGHIJKL";
    let target: PathBuf = dir.join("custom.txt");
    let patterns: PathBuf = dir.join("patterns.txt");
    std::fs::write(&target, format!("credential={planted}\n")).expect("write custom target");
    std::fs::write(&patterns, "client-secret=client-secret-[A-Z]{12}\n")
        .expect("write custom patterns");
    let pattern_path: &str = patterns.to_str().expect("pattern path");

    let plain: String = frisk(&target, &["--format", "json", "--pattern", pattern_path]);
    let redacted: String = frisk(
        &target,
        &["--format", "json", "--pattern", pattern_path, "--redact"],
    );

    assert!(
        plain.contains(planted),
        "positive control must expose the custom match"
    );
    assert!(
        !redacted.contains(planted),
        "custom pattern value leaked: {redacted}"
    );
    assert!(redacted.contains("[REDACTED:"));
}
