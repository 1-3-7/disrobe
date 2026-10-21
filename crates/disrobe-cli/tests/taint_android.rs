#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn extract_dex(apk: &str, into: &std::path::Path) -> String {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(apk);
    let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("open apk");
    let mut entry: zip::read::ZipFile<'_> = zip.by_name("classes.dex").expect("classes.dex");
    let mut dex: Vec<u8> = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut dex).expect("read classes.dex");
    let out: PathBuf = into.join(format!("{apk}.classes.dex"));
    std::fs::write(&out, dex).expect("write dex");
    out.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn android_sources_reach_android_sinks_only_where_the_value_is_passed() {
    let scratch = temp_dir("taint-android");
    let dex: String = extract_dex("audit-flows.apk", scratch.path());
    let run = run_disrobe(&["taint", &dex, "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("taint json");
    assert_eq!(value["source_lang"], "dalvik");
    let findings: &Vec<serde_json::Value> = value["findings"].as_array().expect("findings");
    let mut flows: Vec<(String, String, String)> = findings
        .iter()
        .map(|f: &serde_json::Value| {
            (
                f["function"].as_str().expect("function").to_owned(),
                f["source_symbol"].as_str().expect("source").to_owned(),
                f["sink_symbol"].as_str().expect("sink").to_owned(),
            )
        })
        .collect();
    flows.sort();
    let expected: Vec<(String, String, String)> = vec![
        (
            "com.planted.audit.Flows.clipboardToSms".to_owned(),
            "android.content.ClipboardManager.getText".to_owned(),
            "android.telephony.SmsManager.sendTextMessage".to_owned(),
        ),
        (
            "com.planted.audit.Flows.imeiToSms".to_owned(),
            "android.telephony.TelephonyManager.getDeviceId".to_owned(),
            "android.telephony.SmsManager.sendTextMessage".to_owned(),
        ),
        (
            "com.planted.audit.Flows.imsiToLog".to_owned(),
            "android.telephony.TelephonyManager.getSubscriberId".to_owned(),
            "android.util.Log.d".to_owned(),
        ),
        (
            "com.planted.audit.Flows.locationToLog".to_owned(),
            "android.location.LocationManager.getLastKnownLocation".to_owned(),
            "android.util.Log.i".to_owned(),
        ),
    ];
    assert_eq!(
        flows, expected,
        "the four real flows and nothing from separateSourceAndSink or sourceOnly"
    );
}

#[test]
fn the_plant_apk_has_no_source_to_sink_flow() {
    let scratch = temp_dir("taint-android-plants");
    let dex: String = extract_dex("audit-plants.apk", scratch.path());
    let run = run_disrobe(&["taint", &dex]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("flows: 0"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("android.telephony.telephonymanager.getdeviceid"),
        "the android defaults are in force for a dex input: {}",
        run.stdout
    );
}
