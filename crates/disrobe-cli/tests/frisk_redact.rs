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

    fn all_literals(&self) -> [&str; 6] {
        [
            self.slack.as_str(),
            self.sendgrid.as_str(),
            self.telegram.as_str(),
            self.discord.as_str(),
            self.aws.as_str(),
            self.github.as_str(),
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
}

#[test]
fn keyed_redaction_is_deterministic_across_runs() {
    let (_scratch, dir, planted): (disrobe_core::scratch::ScratchDir, PathBuf, Planted) = corpus();

    let first: String = frisk(&dir, &["--format", "json", "--redact-key", "shared-key"]);
    let second: String = frisk(&dir, &["--format", "json", "--redact-key", "shared-key"]);

    for secret in planted.all_literals() {
        assert!(
            !first.contains(secret),
            "keyed redaction still leaked {secret}"
        );
    }
    assert_eq!(
        first, second,
        "a fixed --redact-key must yield byte-identical redacted output across runs"
    );
}
