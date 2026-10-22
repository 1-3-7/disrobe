#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_jvm::{
    AndroidIdentity, AndroidIdentityHit, AndroidIdentityKind, identify_android,
};

fn corpus(rel: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn identify(rel: &str) -> AndroidIdentity {
    identify_android(&corpus(rel), Some(rel))
        .unwrap_or_else(|| panic!("{rel} is an Android or JVM artifact"))
}

fn names(identity: &AndroidIdentity, kind: AndroidIdentityKind) -> BTreeSet<String> {
    identity
        .hits
        .iter()
        .filter(|h: &&AndroidIdentityHit| h.kind == kind)
        .map(|h: &AndroidIdentityHit| h.name.clone())
        .collect()
}

#[test]
fn a_d8_built_dex_names_its_version_and_writer() {
    let identity: AndroidIdentity = identify("jvm/dex/EdgeCases.dex");
    assert_eq!(identity.format, "dex");
    assert_eq!(identity.dex_files, 1);
    assert_eq!(
        names(&identity, AndroidIdentityKind::Format),
        BTreeSet::from(["dex 035".to_owned()])
    );
    assert_eq!(
        names(&identity, AndroidIdentityKind::Compiler),
        BTreeSet::from(["d8/r8".to_owned()])
    );
    assert!(
        names(&identity, AndroidIdentityKind::Obfuscator).is_empty(),
        "{:#?}",
        identity.hits
    );
    let kotlin: AndroidIdentity = identify("jvm/dex/EdgeCasesKt.dex");
    assert_eq!(
        names(&kotlin, AndroidIdentityKind::Format),
        BTreeSet::from(["dex 039".to_owned()])
    );
    assert_eq!(
        names(&kotlin, AndroidIdentityKind::Compiler),
        BTreeSet::from(["d8/r8".to_owned()])
    );
}

#[test]
fn r8_minified_names_are_reported_and_the_clean_build_is_not() {
    let minified: AndroidIdentity = identify("jvm/dex/obfuscators/r8/Widget-r8.dex");
    assert_eq!(
        names(&minified, AndroidIdentityKind::Obfuscator),
        BTreeSet::from(["ProGuard/R8 renaming".to_owned()]),
        "{:#?}",
        minified.hits
    );
    let clean: AndroidIdentity = identify("jvm/dex/obfuscators/r8/Widget-clean.dex");
    assert!(
        names(&clean, AndroidIdentityKind::Obfuscator).is_empty(),
        "{:#?}",
        clean.hits
    );
}

#[test]
fn the_plant_apk_names_its_signatures_and_anti_analysis_checks() {
    let plants: AndroidIdentity = identify("recon/android-audit/audit-plants.apk");
    assert_eq!(plants.format, "apk");
    assert_eq!(
        names(&plants, AndroidIdentityKind::Signature),
        BTreeSet::from([
            "v1 (JAR signing)".to_owned(),
            "v2".to_owned(),
            "v3".to_owned()
        ]),
        "{:#?}",
        plants.hits
    );
    assert_eq!(
        names(&plants, AndroidIdentityKind::AntiAnalysis),
        BTreeSet::from([
            "attestation call".to_owned(),
            "debugger check".to_owned(),
            "dynamic code loading".to_owned(),
            "emulator check".to_owned(),
            "instrumentation check".to_owned(),
            "root check".to_owned(),
            "signature check".to_owned(),
        ]),
        "{:#?}",
        plants.hits
    );
    assert!(
        plants
            .hits
            .iter()
            .all(|h: &AndroidIdentityHit| !h.detail.is_empty()),
        "every hit carries evidence"
    );
    let control: AndroidIdentity = identify("recon/android-audit/audit-control.apk");
    assert!(
        names(&control, AndroidIdentityKind::AntiAnalysis).is_empty(),
        "{:#?}",
        control.hits
    );
    assert_eq!(
        names(&control, AndroidIdentityKind::Compiler),
        BTreeSet::from(["d8/r8".to_owned()])
    );
}

#[test]
fn an_allatori_class_names_its_obfuscator() {
    let identity: AndroidIdentity = identify("jvm/allatori/AllatoriStrings.class");
    assert_eq!(identity.format, "class");
    assert_eq!(identity.class_files, 1);
    assert_eq!(
        names(&identity, AndroidIdentityKind::Obfuscator),
        BTreeSet::from(["Allatori".to_owned()]),
        "{:#?}",
        identity.hits
    );
}

#[test]
fn a_zip_without_dex_manifest_or_classes_is_not_an_android_artifact() {
    let mut zip: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    {
        let mut writer: zip::ZipWriter<&mut std::io::Cursor<Vec<u8>>> =
            zip::ZipWriter::new(&mut zip);
        writer
            .start_file("readme.txt", zip::write::SimpleFileOptions::default())
            .expect("start entry");
        std::io::Write::write_all(&mut writer, b"plain archive").expect("write entry");
        writer.finish().expect("finish zip");
    }
    assert!(identify_android(zip.get_ref(), Some("plain.zip")).is_none());
    assert!(identify_android(b"not an archive at all", None).is_none());
}

#[test]
fn obfuscapk_builds_name_the_smali_writer_and_the_obfuscator_helpers() {
    let plain: AndroidIdentity = identify("recon/android-audit/audit-plants.apk");
    assert_eq!(
        names(&plain, AndroidIdentityKind::Compiler),
        BTreeSet::from(["d8/r8".to_owned()])
    );
    assert!(
        !names(&plain, AndroidIdentityKind::Obfuscator).contains("Obfuscapk"),
        "{:#?}",
        plain.hits
    );
    for (variant, obfuscator) in [
        ("goto", false),
        ("reorder", false),
        ("callind", false),
        ("strings", true),
        ("advreflection", true),
        ("full", true),
    ] {
        let identity: AndroidIdentity =
            identify(&format!("recon/android-audit/obfuscapk/{variant}.apk"));
        assert_eq!(
            names(&identity, AndroidIdentityKind::Compiler),
            BTreeSet::from(["dexlib 2.x".to_owned()]),
            "{variant} was rebuilt by apktool's dexlib writer"
        );
        assert_eq!(
            names(&identity, AndroidIdentityKind::Obfuscator).contains("Obfuscapk"),
            obfuscator,
            "{variant}: Obfuscapk is named exactly when one of its helper classes is present: {:#?}",
            identity.hits
        );
    }
}

#[test]
fn a_split_bundle_is_identified_through_its_base_member() {
    let plants: AndroidIdentity = identify("recon/android-audit/audit-plants.apk");
    for (name, base) in [
        ("audit.xapk", "com.planted.audit.apk"),
        ("audit.apkm", "base.apk"),
    ] {
        let bundle: AndroidIdentity = identify(&format!("recon/android-audit/bundles/{name}"));
        assert_eq!(bundle.format, "apk-bundle", "{name}");
        assert_eq!(bundle.dex_files, 2, "{name}: both members' dex files");
        let format: &AndroidIdentityHit = bundle
            .hits
            .iter()
            .find(|h: &&AndroidIdentityHit| {
                h.kind == AndroidIdentityKind::Format && h.name == "split APK bundle"
            })
            .unwrap_or_else(|| panic!("{name}: bundle hit in {:#?}", bundle.hits));
        assert_eq!(
            format.detail,
            format!("2 member APK(s), base {base}, merged for analysis"),
            "{name}"
        );
        assert_eq!(
            names(&bundle, AndroidIdentityKind::Signature),
            names(&plants, AndroidIdentityKind::Signature),
            "{name}: the base member's signing schemes"
        );
        assert_eq!(
            names(&bundle, AndroidIdentityKind::AntiAnalysis),
            names(&plants, AndroidIdentityKind::AntiAnalysis),
            "{name}: the plants' checks survive the merge"
        );
    }
}
