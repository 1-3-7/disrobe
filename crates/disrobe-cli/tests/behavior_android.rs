#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn fixture(name: &str) -> String {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(name);
    path.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn the_plant_apk_summarises_into_categories_with_mobile_attack_ids() {
    let run = run_disrobe(&["behavior", &fixture("audit-plants.apk"), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("behavior json");
    let categories: Vec<String> = value["categories"]
        .as_array()
        .expect("categories")
        .iter()
        .map(|c: &serde_json::Value| c["category"].as_str().expect("category").to_owned())
        .collect();
    for expected in [
        "network",
        "filesystem",
        "process_exec",
        "crypto",
        "anti_analysis",
        "dynamic_code",
        "privacy",
    ] {
        assert!(categories.contains(&expected.to_owned()), "{categories:?}");
    }
    let attack_ids: Vec<String> = value["attack_ids"]
        .as_array()
        .expect("attack ids")
        .iter()
        .map(|id: &serde_json::Value| id.as_str().expect("id").to_owned())
        .collect();
    for expected in [
        "T1407",
        "T1414",
        "T1418",
        "T1426",
        "T1429",
        "T1430",
        "T1512",
        "T1582",
        "T1623.001",
        "T1633.001",
    ] {
        assert!(attack_ids.contains(&expected.to_owned()), "{attack_ids:?}");
    }
    let privacy: &serde_json::Value = value["categories"]
        .as_array()
        .expect("categories")
        .iter()
        .find(|c: &&serde_json::Value| c["category"] == "privacy")
        .expect("privacy category");
    let signals: Vec<String> = privacy["evidence"]
        .as_array()
        .expect("evidence")
        .iter()
        .map(|e: &serde_json::Value| e["signal"].as_str().expect("signal").to_owned())
        .collect();
    assert!(
        signals
            .iter()
            .any(|s: &String| s.contains("Lcom/planted/audit/Plants;->smsSend")),
        "{signals:?}"
    );
    assert!(
        privacy["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|e: &serde_json::Value| e["source"] == "dex"),
        "{privacy}"
    );
    let text = run_disrobe(&["behavior", &fixture("audit-plants.apk")]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("privacy"), "{}", text.stdout);
    assert!(text.stdout.contains("ATT&CK:"), "{}", text.stdout);
}

#[test]
fn the_control_apk_has_no_notable_behavior() {
    let run = run_disrobe(&["behavior", &fixture("audit-control.apk")]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.contains("no notable behaviors detected"),
        "{}",
        run.stdout
    );
}
