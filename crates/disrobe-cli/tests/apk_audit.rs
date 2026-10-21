#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn fixture(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(name);
    path
}

#[test]
fn apk_json_carries_the_code_pattern_audit_anchored_to_methods() {
    let run = run_disrobe(&[
        "apk",
        fixture("audit-plants.apk").to_str().expect("utf-8 path"),
        "--json",
    ]);
    assert_eq!(run.code, 0, "apk failed: {}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("json output");
    let audit: &serde_json::Value = &value["audit"];
    assert_eq!(audit["dex_files"], 1);
    assert_eq!(audit["truncated"], false);
    let findings: &Vec<serde_json::Value> = audit["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 51, "{findings:#?}");
    let hardcoded: &serde_json::Value = findings
        .iter()
        .find(|f: &&serde_json::Value| f["rule_id"] == "DR-APK-CRYPTO-HARDCODED-KEY")
        .expect("the hardcoded key plant is reported");
    assert_eq!(hardcoded["class"], "Lcom/planted/audit/Plants;");
    assert_eq!(hardcoded["method"], "cryptoHardcodedKey");
    assert_eq!(hardcoded["category"], "WeakCrypto");
    assert_eq!(hardcoded["severity"], "High");
    assert!(
        hardcoded["evidence"]
            .as_str()
            .is_some_and(|e: &str| e.contains("0123456789abcdef")),
        "{hardcoded}"
    );
}

#[test]
fn apk_text_lists_each_audit_finding_and_the_control_has_none() {
    let plants = run_disrobe(&[
        "apk",
        fixture("audit-plants.apk").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(plants.code, 0, "{}", plants.stderr);
    assert!(
        plants.stdout.contains("  audit:        51 findings over"),
        "{}",
        plants.stdout
    );
    assert!(
        plants.stdout.contains(
            "DR-APK-SSL-TRUST-ALL [high] Lcom/planted/audit/Plants$TrustAll;->checkServerTrusted"
        ),
        "{}",
        plants.stdout
    );
    let control = run_disrobe(&[
        "apk",
        fixture("audit-control.apk").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(control.code, 0, "{}", control.stderr);
    assert!(
        control.stdout.contains("  audit:        0 findings over"),
        "{}",
        control.stdout
    );
    assert!(!control.stdout.contains("DR-APK-"), "{}", control.stdout);
}

#[test]
fn apk_text_names_native_library_checks_by_path() {
    let run = run_disrobe(&[
        "apk",
        fixture("audit-native.apk").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "apk failed: {}", run.stderr);
    assert!(
        run.stdout.contains("and 4 native libraries"),
        "{}",
        run.stdout
    );
    for abi in ["arm64-v8a", "x86_64"] {
        for (rule, evidence) in [
            ("DR-APK-NATIVE-PTRACE", "imports ptrace"),
            (
                "DR-APK-NATIVE-TRACER-PID",
                "reads the tracer pid: TracerPid, /proc/self/status",
            ),
            (
                "DR-APK-NATIVE-FRIDA-CHECK",
                "frida indicator literals: frida-agent, re.frida.server, gum-js-loop, linjector",
            ),
            (
                "DR-APK-NATIVE-MEMORY-WATCH",
                "imports inotify_add_watch and names /proc/self/mem, /proc/self/maps",
            ),
        ] {
            let line: String = format!("    {rule} [info] lib/{abi}/libantidebug.so: {evidence}");
            assert!(
                run.stdout.contains(&line),
                "missing {line:?} in\n{}",
                run.stdout
            );
        }
        assert!(
            !run.stdout.contains(&format!("] lib/{abi}/libclean.so:")),
            "the control library is silent:\n{}",
            run.stdout
        );
    }
}
