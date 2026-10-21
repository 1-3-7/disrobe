#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
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
    let sources: BTreeSet<&str> = privacy["evidence"]
        .as_array()
        .expect("evidence")
        .iter()
        .map(|e: &serde_json::Value| e["source"].as_str().expect("source"))
        .collect();
    assert_eq!(sources, BTreeSet::from(["dex", "manifest"]), "{privacy}");
    assert!(
        signals
            .iter()
            .any(|s: &String| s == "uses-permission android.permission.SEND_SMS"),
        "the declared SMS permission is manifest evidence: {signals:?}"
    );
    assert!(
        attack_ids.contains(&"T1636.004".to_owned())
            && attack_ids.contains(&"T1624.001".to_owned()),
        "READ_SMS and RECEIVE_BOOT_COMPLETED map to their techniques: {attack_ids:?}"
    );
    let text = run_disrobe(&["behavior", &fixture("audit-plants.apk")]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("privacy"), "{}", text.stdout);
    assert!(text.stdout.contains("ATT&CK:"), "{}", text.stdout);
}

#[test]
fn the_control_apk_carries_only_manifest_evidence() {
    let run = run_disrobe(&["behavior", &fixture("audit-control.apk"), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("behavior json");
    let sources: BTreeSet<String> = value["categories"]
        .as_array()
        .expect("categories")
        .iter()
        .flat_map(|c: &serde_json::Value| c["evidence"].as_array().expect("evidence").clone())
        .map(|e: serde_json::Value| e["source"].as_str().expect("source").to_owned())
        .collect();
    assert_eq!(
        sources,
        BTreeSet::from(["manifest".to_owned()]),
        "the control declares the same permissions but its code triggers no rule"
    );
}

#[test]
fn call_graph_pairs_name_the_methods_that_reach_a_source_and_a_sink() {
    let run = run_disrobe(&["behavior", &fixture("audit-flows.apk"), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("behavior json");
    let signals: Vec<String> = value["categories"]
        .as_array()
        .expect("categories")
        .iter()
        .flat_map(|c: &serde_json::Value| c["evidence"].as_array().expect("evidence").clone())
        .filter(|e: &serde_json::Value| e["source"] == "callgraph")
        .map(|e: serde_json::Value| e["signal"].as_str().expect("signal").to_owned())
        .collect();
    let entries: BTreeSet<String> = signals
        .iter()
        .map(|s: &String| {
            s.split(" reaches ")
                .next()
                .expect("entry")
                .rsplit("->")
                .next()
                .expect("method")
                .split('(')
                .next()
                .expect("name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        entries,
        BTreeSet::from([
            "clipboardToSms".to_owned(),
            "imeiToSms".to_owned(),
            "imsiToLog".to_owned(),
            "locationToLog".to_owned(),
            "separateSourceAndSink".to_owned(),
        ]),
        "every method that reaches both a source and a sink is named, sourceOnly is not: {signals:?}"
    );
    assert!(
        signals
            .iter()
            .any(|s: &String| s.contains("separateSourceAndSink") && s.contains("(depth 1)")),
        "{signals:?}"
    );
}

#[test]
fn the_control_apk_has_no_call_graph_pairs() {
    let run = run_disrobe(&["behavior", &fixture("audit-control.apk"), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        !run.stdout.contains("\"callgraph\""),
        "no method in the control reaches a source and a sink: {}",
        run.stdout
    );
}
