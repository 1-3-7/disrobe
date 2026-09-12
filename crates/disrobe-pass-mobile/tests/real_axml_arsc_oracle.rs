#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Read as _};
use std::path::PathBuf;

use disrobe_pass_mobile::arsc::{self, ArscResources};
use disrobe_pass_mobile::axml::{self, AxmlDocument};

fn read_fixture(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

fn entry(apk: &[u8], name: &str) -> Vec<u8> {
    let cur: Cursor<&[u8]> = Cursor::new(apk);
    let mut z = zip::ZipArchive::new(cur).expect("open apk");
    let mut f = z.by_name(name).unwrap_or_else(|_| panic!("entry {name}"));
    let mut b: Vec<u8> = Vec::new();
    f.read_to_end(&mut b).expect("read entry");
    b
}

fn doc_of(apk: &[u8]) -> AxmlDocument {
    axml::parse(&entry(apk, "AndroidManifest.xml")).expect("parse manifest")
}

fn arsc_of(apk: &[u8]) -> ArscResources {
    arsc::parse(&entry(apk, "resources.arsc")).expect("parse arsc")
}

#[test]
fn v1_manifest_matches_aapt2_xmltree() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let doc: AxmlDocument = doc_of(&apk);

    assert_eq!(
        doc.namespaces.len(),
        1,
        "one xmlns binding (android), got {:?}",
        doc.namespaces
    );
    let ns = &doc.namespaces[0];
    assert_eq!(ns.prefix, "android");
    assert_eq!(ns.uri, "http://schemas.android.com/apk/res/android");

    assert_eq!(doc.root.name, "manifest");

    let attr = |n: &str| -> Option<String> {
        doc.root
            .attributes
            .iter()
            .find(|a| a.name == n)
            .map(|a| a.value.clone())
    };
    assert_eq!(attr("versionCode").as_deref(), Some("1"));
    assert_eq!(attr("versionName").as_deref(), Some("1.0"));
    assert_eq!(attr("compileSdkVersion").as_deref(), Some("34"));
    assert_eq!(attr("compileSdkVersionCodename").as_deref(), Some("14"));
    assert_eq!(attr("package").as_deref(), Some("com.disrobe.fixture"));
    assert_eq!(attr("platformBuildVersionCode").as_deref(), Some("34"));
    assert_eq!(attr("platformBuildVersionName").as_deref(), Some("14"));

    let android_prefixed: Vec<&str> = doc
        .root
        .attributes
        .iter()
        .filter(|a| a.prefix.as_deref() == Some("android"))
        .map(|a| a.name.as_str())
        .collect();
    assert!(
        android_prefixed.contains(&"versionCode")
            && android_prefixed.contains(&"compileSdkVersion"),
        "android: prefix recovered on framework attrs: {android_prefixed:?}"
    );

    let app = doc
        .root
        .children
        .iter()
        .find(|c| c.name == "application")
        .expect("application child");
    assert_eq!(app.prefix, None);
    assert_eq!(
        app.attributes
            .iter()
            .find(|a| a.name == "label")
            .map(|a| (a.prefix.as_deref(), a.value.as_str())),
        Some((Some("android"), "DisrobeFixture")),
        "android:label string attribute recovered"
    );
}

#[test]
fn v1_manifest_serializes_to_canonical_xml() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let doc: AxmlDocument = doc_of(&apk);
    let xml: String = doc.to_xml();

    assert!(
        xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
        "namespace declared in serialized xml:\n{xml}"
    );
    assert!(
        xml.contains("android:versionCode=\"1\""),
        "android:versionCode present:\n{xml}"
    );
    assert!(
        xml.contains("android:compileSdkVersion=\"34\""),
        "android:compileSdkVersion present:\n{xml}"
    );
    assert!(
        xml.contains("package=\"com.disrobe.fixture\""),
        "package present:\n{xml}"
    );
    assert!(
        xml.contains("android:label=\"DisrobeFixture\""),
        "android:label present:\n{xml}"
    );
    assert!(
        xml.contains("<application") && xml.contains("</manifest>"),
        "well-formed nesting:\n{xml}"
    );
    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
        "xml prolog present"
    );
}

#[test]
fn v1_arsc_resolves_string_app_name() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let table: ArscResources = arsc_of(&apk);

    let pkg = table
        .packages
        .iter()
        .find(|p| p.name == "com.disrobe.fixture")
        .expect("package");
    assert_eq!(pkg.id, 0x7f);

    assert_eq!(
        table.resolve(0x7f01_0000).as_deref(),
        Some("com.disrobe.fixture:string/app_name"),
        "aapt2 ground truth: resource 0x7f010000 string/app_name"
    );
    let entry = pkg
        .entries
        .iter()
        .find(|e| e.id == 0x7f01_0000)
        .expect("entry");
    assert_eq!(entry.value.as_deref(), Some("DisrobeFixture"));
}

#[test]
fn rich_manifest_matches_aapt2_xmltree() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-rich.apk");
    let doc: AxmlDocument = doc_of(&apk);

    assert_eq!(doc.root.name, "manifest");
    let root_attr = |n: &str| -> Option<String> {
        doc.root
            .attributes
            .iter()
            .find(|a| a.name == n)
            .map(|a| a.value.clone())
    };
    assert_eq!(root_attr("versionCode").as_deref(), Some("7"));
    assert_eq!(root_attr("versionName").as_deref(), Some("2.5"));
    assert_eq!(root_attr("package").as_deref(), Some("com.disrobe.rich"));

    let find = |name: &str| -> &axml::AxmlElement {
        doc.root
            .descendants()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("element {name}"))
    };

    let uses_sdk = find("uses-sdk");
    assert_eq!(
        uses_sdk
            .attributes
            .iter()
            .find(|a| a.name == "minSdkVersion")
            .map(|a| a.value.as_str()),
        Some("24")
    );
    assert_eq!(
        uses_sdk
            .attributes
            .iter()
            .find(|a| a.name == "targetSdkVersion")
            .map(|a| a.value.as_str()),
        Some("34")
    );

    let perm = find("uses-permission");
    assert_eq!(
        perm.attributes
            .iter()
            .find(|a| a.name == "name")
            .map(|a| a.value.as_str()),
        Some("android.permission.INTERNET")
    );

    let activity = find("activity");
    assert_eq!(
        activity
            .attributes
            .iter()
            .find(|a| a.name == "exported")
            .map(|a| a.value.as_str()),
        Some("true"),
        "android:exported=true typed-bool"
    );
    assert_eq!(
        activity
            .attributes
            .iter()
            .find(|a| a.name == "name")
            .map(|a| a.value.as_str()),
        Some("com.disrobe.rich.MainActivity")
    );

    let service = find("service");
    assert_eq!(
        service
            .attributes
            .iter()
            .find(|a| a.name == "exported")
            .map(|a| a.value.as_str()),
        Some("false")
    );
    assert_eq!(
        service
            .attributes
            .iter()
            .find(|a| a.name == "name")
            .map(|a| a.value.as_str()),
        Some(".SyncService")
    );
}

#[test]
fn rich_application_label_resolves_via_arsc_reference() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-rich.apk");
    let doc: AxmlDocument = doc_of(&apk);
    let table: ArscResources = arsc_of(&apk);

    let app = doc
        .root
        .descendants()
        .find(|e| e.name == "application")
        .expect("application");
    let label = app
        .attributes
        .iter()
        .find(|a| a.name == "label")
        .expect("label attr");

    assert_eq!(
        label.resource_id,
        Some(0x7f03_0000),
        "android:label is a TYPE_REFERENCE to 0x7f030000 (aapt2 ground truth @0x7f030000)"
    );
    assert_eq!(
        label.formatted_value(Some(&table)),
        "@com.disrobe.rich:string/app_name",
        "reference resolves to @package:string/app_name via the arsc table"
    );
    assert_eq!(
        label.formatted_value(None),
        "@0x7f030000",
        "without the table the reference stays a raw id"
    );
}

#[test]
fn rich_manifest_serialized_with_resources_resolves_reference() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-rich.apk");
    let doc: AxmlDocument = doc_of(&apk);
    let table: ArscResources = arsc_of(&apk);

    let xml: String = doc.to_xml_with_resources(Some(&table));
    assert!(
        xml.contains("android:label=\"@com.disrobe.rich:string/app_name\""),
        "label reference resolved in serialized xml:\n{xml}"
    );
    assert!(
        xml.contains("android:debuggable=\"true\"")
            && xml.contains("android:allowBackup=\"false\""),
        "typed bools rendered:\n{xml}"
    );
    assert!(
        xml.contains("<intent-filter>") && xml.contains("<action"),
        "nested intent filter serialized:\n{xml}"
    );
}

#[test]
fn rich_arsc_resolves_all_three_types() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-rich.apk");
    let table: ArscResources = arsc_of(&apk);

    assert_eq!(
        table.resolve(0x7f01_0000).as_deref(),
        Some("com.disrobe.rich:bool/is_debug"),
        "aapt2: 0x7f010000 bool/is_debug"
    );
    assert_eq!(
        table.resolve(0x7f02_0000).as_deref(),
        Some("com.disrobe.rich:integer/max_count"),
        "aapt2: 0x7f020000 integer/max_count"
    );
    assert_eq!(
        table.resolve(0x7f03_0000).as_deref(),
        Some("com.disrobe.rich:string/app_name"),
        "aapt2: 0x7f030000 string/app_name"
    );
    assert_eq!(
        table.resolve(0x7f03_0001).as_deref(),
        Some("com.disrobe.rich:string/extra"),
        "aapt2: 0x7f030001 string/extra"
    );

    let pkg = &table.packages[0];
    let bool_val = pkg
        .entries
        .iter()
        .find(|e| e.id == 0x7f01_0000)
        .and_then(|e| e.value.clone());
    assert_eq!(bool_val.as_deref(), Some("true"), "bool/is_debug = true");
    let int_val = pkg
        .entries
        .iter()
        .find(|e| e.id == 0x7f02_0000)
        .and_then(|e| e.value.clone());
    assert_eq!(int_val.as_deref(), Some("42"), "integer/max_count = 42");
    let str_val = pkg
        .entries
        .iter()
        .find(|e| e.id == 0x7f03_0001)
        .and_then(|e| e.value.clone());
    assert_eq!(
        str_val.as_deref(),
        Some("Extra Value"),
        "string/extra value"
    );
}

#[test]
fn unresolvable_reference_stays_honest() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-rich.apk");
    let table: ArscResources = arsc_of(&apk);
    assert_eq!(
        table.resolve(0x7f99_0000),
        None,
        "an id with no entry must not be fabricated into a name"
    );
}
