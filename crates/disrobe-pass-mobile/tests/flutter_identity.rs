#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};

use disrobe_core::scratch::scratch_root;
use disrobe_pass_mobile::flutter::{
    DartSdkRelease, FlutterContainer, FlutterIdentityReport, FlutterLibrary, FlutterLibraryRole,
    SnapshotStampSource, flutter_identity,
};
use disrobe_pass_mobile::{
    DartGraphRecoveryOptions, DartGraphRecoveryReport, DartGraphRecoveryStatus,
    recover_dart_pinned_elf,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const ENGINE_PREREQUISITE: &str = "disrobe-pass-mobile::flutter-engine-3.44.6";
const ENGINE_JAR_NAME: &str =
    "arm64_v8a_release-1.0.0-83675ed27633283e7fc296c8bca22e841224c096.jar";
const ENGINE_JAR_URL: &str = "https://storage.googleapis.com/download.flutter.io/io/flutter/arm64_v8a_release/1.0.0-83675ed27633283e7fc296c8bca22e841224c096/arm64_v8a_release-1.0.0-83675ed27633283e7fc296c8bca22e841224c096.jar";
const ENGINE_JAR_SHA256: &str = "8bd930bb3533ce7c14367734c4cc4070b459493b23f6e8ded823617d2c8a6696";
const REAL_LIBRARIES: [&str; 4] = [
    "pinned_graph_fixture/receipt_validator_arm64.so",
    "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    "pinned_graph_fixture/voucher_validator_arm64.so",
    "disrobe_sample/libapp_arm64.so",
];

fn flutter_corpus(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/flutter")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    let path: PathBuf = flutter_corpus(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn json(relative: &str) -> Value {
    serde_json::from_slice(&read(relative)).expect("committed json")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing"))
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("zip entry");
        writer.write_all(bytes).expect("zip write");
    }
    writer.finish().expect("zip finish").into_inner()
}

fn library<'a>(report: &'a FlutterIdentityReport, path: &str) -> &'a FlutterLibrary {
    report
        .libraries
        .iter()
        .find(|library: &&FlutterLibrary| library.path == path)
        .unwrap_or_else(|| panic!("{path} missing from {:?}", report.libraries))
}

fn assert_engine_releases(report: &FlutterIdentityReport, oracle: &Value) {
    assert!(
        report.flutter_releases.iter().any(|release| {
            release.flutter_version == text(oracle, "flutter_version")
                && release.dart_version.as_deref() == Some(text(oracle, "dart_version"))
        }),
        "{:?}",
        report.flutter_releases
    );
    assert!(report.flutter_releases.iter().all(|release| {
        release.engine_revision == text(oracle, "flutter_engine_revision")
            && release.dart_revision == text(oracle, "dart_sdk_revision")
    }));
}

fn identify(bytes: &[u8]) -> FlutterIdentityReport {
    flutter_identity(bytes).expect("identity report")
}

#[test]
fn real_builds_resolve_to_the_sdk_that_built_them() {
    let oracle: Value = json("pinned_graph_fixture/oracle.json");
    let hash: &str = text(&oracle, "snapshot_compatibility_hash");
    let built_by: DartSdkRelease = DartSdkRelease {
        dart_version: text(&oracle, "dart_version").to_owned(),
        dart_revision: text(&oracle, "dart_sdk_revision").to_owned(),
    };
    for relative in REAL_LIBRARIES {
        let report: FlutterIdentityReport = identify(&read(relative));
        assert_eq!(report.container, FlutterContainer::Library, "{relative}");
        assert!(report.flutter_detected, "{relative}");
        assert_eq!(report.snapshot_hash.as_deref(), Some(hash), "{relative}");
        assert!(
            report.dart_sdk_releases.contains(&built_by),
            "{relative}: {:?}",
            report.dart_sdk_releases
        );
        assert!(
            report
                .flutter_releases_with_dart
                .iter()
                .any(|version: &String| version == text(&oracle, "flutter_version")),
            "{relative}: {:?}",
            report.flutter_releases_with_dart
        );
        let [app]: &[FlutterLibrary; 1] =
            report.libraries.as_slice().try_into().expect("one library");
        assert_eq!(app.role, FlutterLibraryRole::App);
        assert_eq!(app.architecture.as_deref(), Some("arm64"));
        let symbols: Vec<Option<&str>> = app
            .snapshots
            .iter()
            .map(|stamp| stamp.symbol.as_deref())
            .collect();
        assert_eq!(
            symbols,
            [
                Some("_kDartIsolateSnapshotData"),
                Some("_kDartVmSnapshotData")
            ],
            "{relative}"
        );
        assert!(
            app.snapshots
                .iter()
                .all(|stamp| stamp.source == SnapshotStampSource::Symbol
                    && stamp.features.last().map(String::as_str) == Some("compressed-pointers")),
            "{relative}"
        );
        assert!(
            report.findings.is_empty(),
            "{relative}: {:?}",
            report.findings
        );
    }
}

#[test]
fn a_changed_snapshot_hash_claims_no_sdk() {
    let oracle: Value = json("pinned_graph_fixture/oracle.json");
    let hash: &str = text(&oracle, "snapshot_compatibility_hash");
    let mutated_hash: String = format!("b{}", &hash[1..]);
    let mut bytes: Vec<u8> = read(REAL_LIBRARIES[0]);
    let mut replaced: usize = 0;
    let mut at: usize = 0;
    while let Some(found) = bytes[at..]
        .windows(hash.len())
        .position(|window: &[u8]| window == hash.as_bytes())
    {
        let start: usize = at + found;
        bytes[start..start + hash.len()].copy_from_slice(mutated_hash.as_bytes());
        replaced += 1;
        at = start + hash.len();
    }
    assert_eq!(replaced, 2, "both snapshot headers carry the hash");
    let report: FlutterIdentityReport = identify(&bytes);
    assert_eq!(report.snapshot_hash.as_deref(), Some(mutated_hash.as_str()));
    assert!(report.dart_sdk_releases.is_empty());
    assert!(report.flutter_releases_with_dart.is_empty());
    assert!(
        report.findings.iter().any(
            |finding: &String| finding.contains("is not the hash of a stable Dart SDK release")
        ),
        "{:?}",
        report.findings
    );
}

#[test]
fn an_unpinned_snapshot_names_its_dart_release_when_recovery_refuses() {
    let reference: Value = json("identity/reference.json");
    let hash: &str = text(&reference, "snapshot_hash");
    let other: &str = text(&reference, "other_snapshot_hash");
    let mut bytes: Vec<u8> = read(REAL_LIBRARIES[0]);
    let mut at: usize = 0;
    while let Some(found) = bytes[at..]
        .windows(hash.len())
        .position(|window: &[u8]| window == hash.as_bytes())
    {
        let start: usize = at + found;
        bytes[start..start + hash.len()].copy_from_slice(other.as_bytes());
        at = start + hash.len();
    }
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default()).expect("report");
    assert_eq!(report.status, DartGraphRecoveryStatus::UnsupportedVersion);
    assert!(
        report
            .name_mode_reason
            .ends_with("(Dart 3.5.0, 3.5.1, 3.5.2, 3.5.3, 3.5.4)"),
        "{}",
        report.name_mode_reason
    );
    let versions: Vec<String> = identify(&bytes)
        .dart_sdk_releases
        .into_iter()
        .map(|release: DartSdkRelease| release.dart_version)
        .collect();
    assert_eq!(versions, ["3.5.0", "3.5.1", "3.5.2", "3.5.3", "3.5.4"]);
}

#[test]
fn an_apk_pairs_each_abi_and_names_the_flutter_release() {
    let oracle: Value = json("pinned_graph_fixture/oracle.json");
    let reference: Value = json("identity/reference.json");
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("lib/arm64-v8a/libapp.so", &read(REAL_LIBRARIES[0])),
        (
            "lib/arm64-v8a/libflutter.so",
            &read("identity/libflutter_arm64.so"),
        ),
        (
            "lib/armeabi-v7a/libapp.so",
            &read("identity/libapp_armv7.so"),
        ),
        (
            "lib/armeabi-v7a/libflutter.so",
            &read("identity/libflutter_armv7.so"),
        ),
        ("lib/x86_64/libapp.so", &read("identity/libapp_x86_64.so")),
    ]);
    let report: FlutterIdentityReport = identify(&apk);
    assert_eq!(report.container, FlutterContainer::Apk);
    assert_eq!(report.libraries.len(), 5);
    assert_eq!(
        report.snapshot_hash.as_deref(),
        Some(text(&reference, "snapshot_hash"))
    );
    assert_eq!(
        report.dart_version.as_deref(),
        Some(text(&oracle, "dart_version"))
    );
    assert_eq!(
        report.engine_revision.as_deref(),
        Some(text(&oracle, "flutter_engine_revision"))
    );
    assert_engine_releases(&report, &oracle);
    assert_eq!(
        report.findings,
        ["x86_64: an app snapshot without a Flutter engine"]
    );
    for (path, name) in [
        ("lib/arm64-v8a/libflutter.so", "libflutter_arm64.so"),
        ("lib/armeabi-v7a/libapp.so", "libapp_armv7.so"),
        ("lib/armeabi-v7a/libflutter.so", "libflutter_armv7.so"),
        ("lib/x86_64/libapp.so", "libapp_x86_64.so"),
    ] {
        assert_eq!(
            library(&report, path).build_id.as_deref(),
            Some(text(&reference["libraries"][name], "build_id")),
            "{path}"
        );
    }
    let armv7: &FlutterLibrary = library(&report, "lib/armeabi-v7a/libapp.so");
    assert_eq!(armv7.abi.as_deref(), Some("armeabi-v7a"));
    assert_eq!(armv7.architecture.as_deref(), Some("arm"));
    assert_eq!(armv7.snapshots.len(), 2);
    assert!(armv7.snapshots.iter().all(|stamp| {
        stamp
            .features
            .ends_with(&["arm".to_owned(), "android".to_owned()])
    }));
    let engine: &FlutterLibrary = library(&report, "lib/arm64-v8a/libflutter.so");
    assert_eq!(engine.role, FlutterLibraryRole::Engine);
    assert_eq!(engine.dart_versions.len(), 1);
    assert_eq!(engine.dart_versions[0].target, "android_arm64");
    assert_eq!(engine.dart_versions[0].channel, "stable");
    assert_eq!(engine.hash_strings, [text(&reference, "snapshot_hash")]);
    assert!(
        engine
            .revision_strings
            .iter()
            .any(|revision: &String| revision == text(&reference, "engine_revision"))
    );
}

#[test]
fn an_engine_stamped_for_another_sdk_claims_no_hash() {
    let reference: Value = json("identity/reference.json");
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("lib/arm64-v8a/libapp.so", &read(REAL_LIBRARIES[0])),
        (
            "lib/arm64-v8a/libflutter.so",
            &read("identity/libflutter_other_arm64.so"),
        ),
    ]);
    let report: FlutterIdentityReport = identify(&apk);
    assert_eq!(report.snapshot_hash, None);
    assert!(report.dart_sdk_releases.is_empty());
    let mut expected: Vec<&str> = vec![
        text(&reference, "snapshot_hash"),
        text(&reference, "other_snapshot_hash"),
    ];
    expected.sort_unstable();
    assert_eq!(report.snapshot_hash_candidates, expected);
    assert!(
        report
            .findings
            .iter()
            .any(|finding: &String| finding.contains("disagree on the Dart snapshot hash")),
        "{:?}",
        report.findings
    );
}

#[test]
fn an_ipa_reads_the_mach_o_frameworks() {
    let reference: Value = json("identity/reference.json");
    let ipa: Vec<u8> = zip_of(&[
        ("Payload/Runner.app/Info.plist", b"bplist00"),
        (
            "Payload/Runner.app/Frameworks/App.framework/App",
            &read("identity/App_ios_arm64"),
        ),
        (
            "Payload/Runner.app/Frameworks/Flutter.framework/Flutter",
            &read("identity/Flutter_ios_arm64"),
        ),
    ]);
    let report: FlutterIdentityReport = identify(&ipa);
    assert_eq!(report.container, FlutterContainer::Ipa);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        report.snapshot_hash.as_deref(),
        Some(text(&reference, "snapshot_hash"))
    );
    assert_eq!(
        report.engine_revision.as_deref(),
        Some(text(&reference, "engine_revision"))
    );
    let app: &FlutterLibrary = library(&report, "Payload/Runner.app/Frameworks/App.framework/App");
    assert_eq!(app.format.as_deref(), Some("macho"));
    assert_eq!(app.abi.as_deref(), Some("arm64"));
    assert_eq!(
        app.build_id.as_deref(),
        Some(text(&reference["libraries"]["App_ios_arm64"], "uuid"))
    );
    assert_eq!(app.snapshots.len(), 2);
    assert!(
        app.snapshots
            .iter()
            .all(|stamp| stamp.source == SnapshotStampSource::Symbol)
    );
    let engine: &FlutterLibrary = library(
        &report,
        "Payload/Runner.app/Frameworks/Flutter.framework/Flutter",
    );
    assert_eq!(
        engine.build_id.as_deref(),
        Some(text(&reference["libraries"]["Flutter_ios_arm64"], "uuid"))
    );
    assert_eq!(engine.dart_versions[0].target, "ios_arm64");
}

#[test]
fn a_universal_app_reports_each_slice() {
    let reference: Value = json("identity/reference.json");
    let report: FlutterIdentityReport = identify(&read("identity/App_ios_universal"));
    let slices: Vec<(&str, &str, usize)> = report
        .libraries
        .iter()
        .map(|library: &FlutterLibrary| {
            (
                library.abi.as_deref().expect("abi"),
                library.build_id.as_deref().expect("uuid"),
                library.snapshots.len(),
            )
        })
        .collect();
    let expected_slices: &Value = &reference["libraries"]["App_ios_universal"]["slices"];
    assert_eq!(
        slices,
        [
            ("arm64", text(expected_slices, "arm64"), 2),
            ("x86_64", text(expected_slices, "x86_64"), 2)
        ]
    );
    assert_eq!(
        report.snapshot_hash.as_deref(),
        Some(text(&reference, "snapshot_hash"))
    );
}

#[test]
fn inputs_without_flutter_are_answered_or_refused_by_name() {
    let mut stripped: Vec<u8> = read("identity/libapp_armv7.so");
    for index in 0..stripped.len().saturating_sub(4) {
        if stripped[index..index + 4] == [0xf5, 0xf5, 0xdc, 0xdc] {
            stripped[index] = 0;
        }
    }
    let report: FlutterIdentityReport = identify(&stripped);
    assert!(!report.flutter_detected);
    assert!(report.libraries.is_empty());
    let archive: FlutterIdentityReport = identify(&zip_of(&[("readme.txt", b"hello")]));
    assert_eq!(archive.container, FlutterContainer::Archive);
    assert!(!archive.flutter_detected);
    let error: String = flutter_identity(b"plain text, not a library")
        .expect_err("refused")
        .to_string();
    assert!(error.starts_with("DR-MOB-0065"), "{error}");
}

#[test]
fn corrupted_inputs_never_panic() {
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        (
            "lib/armeabi-v7a/libapp.so",
            &read("identity/libapp_armv7.so"),
        ),
        (
            "lib/armeabi-v7a/libflutter.so",
            &read("identity/libflutter_armv7.so"),
        ),
    ]);
    let seeds: [Vec<u8>; 3] = [
        apk,
        read("identity/App_ios_universal"),
        read("identity/libapp_x86_64.so"),
    ];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..400_usize {
        let seed: &Vec<u8> = &seeds[round % seeds.len()];
        let mut bytes: Vec<u8> = seed.clone();
        let len: u64 = u64::try_from(bytes.len()).expect("length");
        if round % 4 == 3 {
            bytes.truncate(usize::try_from(next() % len).expect("cut"));
        } else {
            for _ in 0..=(next() % 16) {
                let index: usize = usize::try_from(next() % len).expect("index");
                bytes[index] = u8::try_from(next() & 0xff).expect("byte");
            }
        }
        let _outcome: Result<FlutterIdentityReport, _> = flutter_identity(&bytes);
    }
}

#[test]
fn the_official_release_engine_names_its_flutter_release() {
    let Some(jar): Option<Vec<u8>> = official_engine_jar() else {
        return;
    };
    let oracle: Value = json("pinned_graph_fixture/oracle.json");
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(jar.as_slice())).expect("engine jar");
    let mut engine: Vec<u8> = Vec::new();
    archive
        .by_name("lib/arm64-v8a/libflutter.so")
        .expect("libflutter.so in the engine jar")
        .read_to_end(&mut engine)
        .expect("read libflutter.so");
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("lib/arm64-v8a/libapp.so", &read(REAL_LIBRARIES[0])),
        ("lib/arm64-v8a/libflutter.so", &engine),
    ]);
    let report: FlutterIdentityReport = identify(&apk);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        report.snapshot_hash.as_deref(),
        Some(text(&oracle, "snapshot_compatibility_hash"))
    );
    assert_eq!(
        report.dart_version.as_deref(),
        Some(text(&oracle, "dart_version"))
    );
    assert_eq!(
        report.engine_revision.as_deref(),
        Some(text(&oracle, "flutter_engine_revision"))
    );
    assert_engine_releases(&report, &oracle);
    let engine_library: &FlutterLibrary = library(&report, "lib/arm64-v8a/libflutter.so");
    assert_eq!(
        engine_library.hash_strings,
        [text(&oracle, "snapshot_compatibility_hash")]
    );
    assert_eq!(engine_library.dart_versions[0].target, "android_arm64");
}

fn official_engine_jar() -> Option<Vec<u8>> {
    let path: PathBuf = scratch_root()
        .join("flutter-engine-cache")
        .join(ENGINE_JAR_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let digest: String = Sha256::digest(&bytes).iter().fold(
                String::with_capacity(64),
                |mut text: String, byte: &u8| {
                    let _: std::fmt::Result = write!(text, "{byte:02x}");
                    text
                },
            );
            assert_eq!(
                digest,
                ENGINE_JAR_SHA256,
                "{} is not the pinned Flutter 3.44.6 engine jar",
                path.display()
            );
            Some(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let what: String = format!(
                "the Flutter 3.44.6 android-arm64 release engine jar (sha256 {ENGINE_JAR_SHA256}) at {}; populate it with: curl -sSfL -o \"{}\" \"{ENGINE_JAR_URL}\"",
                path.display(),
                path.display()
            );
            match disrobe_testkit::require::<()>(ENGINE_PREREQUISITE, &what, None) {
                Ok(_) => None,
                Err(error) => panic!("{ENGINE_PREREQUISITE}: {error}"),
            }
        }
        Err(error) => panic!("{}: {error}", path.display()),
    }
}
