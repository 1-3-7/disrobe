#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_jvm::{AndroidAuditReport, AuditFinding, audit_android_apk};

const PLANTS: &str = "Lcom/planted/audit/Plants;";

const EXPECTED: &[(&str, &str, &str)] = &[
    (PLANTS, "cryptoWeakCipher", "DR-APK-CRYPTO-WEAK-CIPHER"),
    (PLANTS, "cryptoEcb", "DR-APK-CRYPTO-ECB"),
    (PLANTS, "cryptoBareAes", "DR-APK-CRYPTO-ECB"),
    (PLANTS, "cryptoRsaNoOaep", "DR-APK-CRYPTO-RSA-NO-OAEP"),
    (PLANTS, "cryptoWeakHash", "DR-APK-CRYPTO-WEAK-HASH"),
    (PLANTS, "cryptoSeededRandom", "DR-APK-CRYPTO-SEEDED-RANDOM"),
    (
        PLANTS,
        "cryptoInsecureRandom",
        "DR-APK-CRYPTO-INSECURE-RANDOM",
    ),
    (PLANTS, "cryptoHardcodedKey", "DR-APK-CRYPTO-HARDCODED-KEY"),
    (PLANTS, "cryptoStaticIv", "DR-APK-CRYPTO-STATIC-IV"),
    (PLANTS, "sslWeakProtocol", "DR-APK-SSL-WEAK-PROTOCOL"),
    (
        PLANTS,
        "sslApacheAllowAllField",
        "DR-APK-SSL-HOSTNAME-ALLOW-ALL",
    ),
    (
        PLANTS,
        "sslApacheAllowAllCtor",
        "DR-APK-SSL-HOSTNAME-ALLOW-ALL",
    ),
    (
        PLANTS,
        "storageWorldAccessible",
        "DR-APK-STORAGE-WORLD-ACCESSIBLE",
    ),
    (PLANTS, "storageExternal", "DR-APK-STORAGE-EXTERNAL"),
    (PLANTS, "storageSdcardPath", "DR-APK-STORAGE-SDCARD-PATH"),
    (PLANTS, "storageTempFile", "DR-APK-STORAGE-TEMP-FILE"),
    (PLANTS, "sqlDynamicQuery", "DR-APK-SQL-DYNAMIC-QUERY"),
    (PLANTS, "webviewJavascript", "DR-APK-WEBVIEW-JAVASCRIPT"),
    (PLANTS, "webviewFileAccess", "DR-APK-WEBVIEW-FILE-ACCESS"),
    (
        PLANTS,
        "webviewMixedContent",
        "DR-APK-WEBVIEW-MIXED-CONTENT",
    ),
    (
        PLANTS,
        "webviewSavePassword",
        "DR-APK-WEBVIEW-SAVE-PASSWORD",
    ),
    (PLANTS, "webviewJsInterface", "DR-APK-WEBVIEW-JS-INTERFACE"),
    (PLANTS, "webviewDebugging", "DR-APK-WEBVIEW-DEBUGGING"),
    (PLANTS, "logCall", "DR-APK-LOG-CALL"),
    (PLANTS, "logSensitive", "DR-APK-LOG-SENSITIVE"),
    (PLANTS, "execCommand", "DR-APK-EXEC-COMMAND"),
    (PLANTS, "rootSuCommand", "DR-APK-ROOT-SU-COMMAND"),
    (PLANTS, "rootDetection", "DR-APK-ROOT-DETECTION"),
    (PLANTS, "emulatorCheck", "DR-APK-EMULATOR-CHECK"),
    (PLANTS, "debuggerCheck", "DR-APK-DEBUGGER-CHECK"),
    (PLANTS, "dynamicCodeLoading", "DR-APK-DYNAMIC-CODE-LOADING"),
    (PLANTS, "nativeLoadPath", "DR-APK-NATIVE-LOAD-PATH"),
    (PLANTS, "reflection", "DR-APK-REFLECTION"),
    (PLANTS, "deviceIdentifier", "DR-APK-DEVICE-IDENTIFIER"),
    (
        PLANTS,
        "deviceIdentifierAndroidId",
        "DR-APK-DEVICE-IDENTIFIER",
    ),
    (PLANTS, "deviceIdentifierSerial", "DR-APK-DEVICE-IDENTIFIER"),
    (PLANTS, "smsSend", "DR-APK-SMS-SEND"),
    (PLANTS, "clipboardRead", "DR-APK-CLIPBOARD-READ"),
    (PLANTS, "audioCapture", "DR-APK-AUDIO-CAPTURE"),
    (PLANTS, "cameraCapture", "DR-APK-CAMERA-CAPTURE"),
    (PLANTS, "locationAccess", "DR-APK-LOCATION-ACCESS"),
    (PLANTS, "installedApps", "DR-APK-INSTALLED-APPS"),
    (PLANTS, "signatureCheck", "DR-APK-SIGNATURE-CHECK"),
    (PLANTS, "fridaCheck", "DR-APK-FRIDA-CHECK"),
    (PLANTS, "playIntegrity", "DR-APK-PLAY-INTEGRITY"),
    (PLANTS, "safetyNetAttest", "DR-APK-SAFETYNET-ATTEST"),
    (
        "Lcom/planted/audit/Plants$TrustAll;",
        "checkClientTrusted",
        "DR-APK-SSL-TRUST-ALL",
    ),
    (
        "Lcom/planted/audit/Plants$TrustAll;",
        "checkServerTrusted",
        "DR-APK-SSL-TRUST-ALL",
    ),
    (
        "Lcom/planted/audit/Plants$TrustAll;",
        "getAcceptedIssuers",
        "DR-APK-SSL-TRUST-ALL",
    ),
    (
        "Lcom/planted/audit/Plants$AllowAllHosts;",
        "verify",
        "DR-APK-SSL-HOSTNAME-ALLOW-ALL",
    ),
    (
        "Lcom/planted/audit/Plants$IgnoreSslErrors;",
        "onReceivedSslError",
        "DR-APK-SSL-WEBVIEW-IGNORE-ERROR",
    ),
];

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/recon/android-audit")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn sites(report: &AndroidAuditReport) -> BTreeSet<(String, String, String)> {
    report
        .findings
        .iter()
        .map(|f: &AuditFinding| (f.class.clone(), f.method.clone(), f.rule_id.clone()))
        .collect()
}

#[test]
fn every_planted_pattern_is_reported_at_its_method_and_nothing_else() {
    let report: AndroidAuditReport =
        audit_android_apk(&fixture("audit-plants.apk")).expect("audit the plant apk");
    let want: BTreeSet<(String, String, String)> = EXPECTED
        .iter()
        .map(|(class, method, rule): &(&str, &str, &str)| {
            (
                (*class).to_owned(),
                (*method).to_owned(),
                (*rule).to_owned(),
            )
        })
        .collect();
    let got: BTreeSet<(String, String, String)> = sites(&report);
    let missing: Vec<&(String, String, String)> = want.difference(&got).collect();
    let extra: Vec<&(String, String, String)> = got.difference(&want).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "missing {missing:?}\nextra {extra:?}\nall {:#?}",
        report.findings
    );
    assert_eq!(
        report.findings.len(),
        EXPECTED.len(),
        "each plant is reported exactly once: {:#?}",
        report.findings
    );
    assert!(!report.truncated);
    assert_eq!(report.dex_files, 1);
    assert!(
        report
            .findings
            .iter()
            .all(|f: &AuditFinding| !f.evidence.is_empty() && !f.descriptor.is_empty()),
        "every finding carries anchored evidence"
    );
}

#[test]
fn the_control_build_of_the_same_api_families_is_silent() {
    let report: AndroidAuditReport =
        audit_android_apk(&fixture("audit-control.apk")).expect("audit the control apk");
    assert!(
        report.findings.is_empty(),
        "the control uses every API family safely: {:#?}",
        report.findings
    );
    assert!(
        report.methods_scanned >= 20,
        "the control's methods were scanned: {}",
        report.methods_scanned
    );
}

#[test]
fn a_dex_without_android_api_calls_is_silent() {
    let path: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/jvm/dex/Hello.dex");
    let dex: Vec<u8> = std::fs::read(&path).expect("read Hello.dex");
    let mut apk: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    {
        let mut writer: zip::ZipWriter<&mut std::io::Cursor<Vec<u8>>> =
            zip::ZipWriter::new(&mut apk);
        writer
            .start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .expect("start classes.dex");
        std::io::Write::write_all(&mut writer, &dex).expect("write classes.dex");
        writer.finish().expect("finish zip");
    }
    let report: AndroidAuditReport =
        audit_android_apk(apk.get_ref()).expect("audit the wrapped dex");
    assert!(report.methods_scanned > 0);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn native_libraries_are_audited_per_abi_and_the_control_library_is_silent() {
    let report: AndroidAuditReport =
        audit_android_apk(&fixture("audit-native.apk")).expect("audit the native fixture");
    assert_eq!(report.native_libs, 4, "{report:#?}");
    let mut by_lib: BTreeSet<(String, String)> = BTreeSet::new();
    for finding in &report.findings {
        if finding.class.starts_with("lib/") {
            assert!(finding.method.is_empty() && finding.pc == 0, "{finding:?}");
            by_lib.insert((finding.class.clone(), finding.rule_id.clone()));
        }
    }
    let mut expected: BTreeSet<(String, String)> = BTreeSet::new();
    for abi in ["arm64-v8a", "x86_64"] {
        for rule in [
            "DR-APK-NATIVE-PTRACE",
            "DR-APK-NATIVE-TRACER-PID",
            "DR-APK-NATIVE-FRIDA-CHECK",
            "DR-APK-NATIVE-MEMORY-WATCH",
        ] {
            expected.insert((format!("lib/{abi}/libantidebug.so"), rule.to_owned()));
        }
    }
    assert_eq!(by_lib, expected, "{report:#?}");
    let dex_rules: BTreeSet<String> = report
        .findings
        .iter()
        .filter(|f: &&AuditFinding| !f.class.starts_with("lib/"))
        .map(|f: &AuditFinding| f.rule_id.clone())
        .collect();
    assert!(
        dex_rules.is_empty(),
        "the Java side only loads the libraries by name and triggers no rule: {report:#?}"
    );
}
