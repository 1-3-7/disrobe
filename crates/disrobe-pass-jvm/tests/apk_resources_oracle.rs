#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::{
    ApkResourceReport, AxmlTree, CertificateInfo, ResourceTable, analyze_apk_resources,
    decode_manifest, parse_arsc, parse_axml,
};

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("apk");
    p.push(name);
    p
}

fn read(name: &str) -> Vec<u8> {
    fs::read(corpus(name)).unwrap_or_else(|e: std::io::Error| panic!("read fixture {name}: {e}"))
}

fn entry(apk: &[u8], name: &str) -> Vec<u8> {
    use std::io::{Cursor, Read};
    let cursor: Cursor<&[u8]> = Cursor::new(apk);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor).expect("zip open");
    let mut f: zip::read::ZipFile<'_> = zip.by_name(name).expect("entry present");
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf).expect("read entry");
    buf
}

const ORACLE_CERT_SHA256: &str = "F8:B7:66:4F:AD:A9:B0:F3:9D:7A:97:2A:BB:28:C1:37:09:5C:65:32:09:1E:98:DF:4F:11:3B:31:BF:23:D4:9C";
const ORACLE_SUBJECT: &str = "CN=Disrobe Fixture,O=disrobe,C=US";

#[test]
fn manifest_serializes_with_decoded_values() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let manifest: Vec<u8> = entry(&apk, "AndroidManifest.xml");
    let arsc_bytes: Vec<u8> = entry(&apk, "resources.arsc");
    let table: ResourceTable = parse_arsc(&arsc_bytes).expect("arsc parses");
    let xml: String = decode_manifest(&manifest, Some(&table)).expect("manifest decodes");

    assert!(
        xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
        "namespace declaration must serialize; got:\n{xml}"
    );
    assert!(
        xml.contains("<manifest"),
        "root element present; got:\n{xml}"
    );
    assert!(
        xml.contains("package=\"com.disrobe.fixture\""),
        "package attr decoded; got:\n{xml}"
    );
    assert!(
        xml.contains("android:versionCode=\"1\""),
        "INT_DEC versionCode must decode to 1; got:\n{xml}"
    );
    assert!(
        xml.contains("android:versionName=\"1.0\""),
        "STRING versionName must decode to 1.0; got:\n{xml}"
    );
    assert!(
        xml.contains("android:compileSdkVersion=\"34\""),
        "INT_DEC compileSdkVersion must decode to 34; got:\n{xml}"
    );
    assert!(
        xml.contains("platformBuildVersionCode=\"34\""),
        "no-namespace INT_DEC attr must decode; got:\n{xml}"
    );
    assert!(
        xml.contains("<application") && xml.contains("android:label=\"DisrobeFixture\""),
        "child application element + label string must serialize; got:\n{xml}"
    );
    assert!(
        xml.contains("</application>") && xml.contains("</manifest>"),
        "closing tags must serialize; got:\n{xml}"
    );
}

#[test]
fn resource_table_maps_ids_to_names() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let arsc_bytes: Vec<u8> = entry(&apk, "resources.arsc");
    let table: ResourceTable = parse_arsc(&arsc_bytes).expect("arsc parses");

    assert_eq!(table.packages.len(), 1, "one package");
    let pkg: &disrobe_pass_jvm::ResTablePackage = &table.packages[0];
    assert_eq!(pkg.id, 0x7f, "package id 0x7f");
    assert_eq!(pkg.name, "com.disrobe.fixture", "package name");
    assert_eq!(pkg.type_strings.strings, vec!["string".to_owned()]);
    assert_eq!(pkg.key_strings.strings, vec!["app_name".to_owned()]);
    assert_eq!(table.entry_count(), 1, "exactly one resource entry");

    let resolved: String = table.resolve_id(0x7f01_0000).expect("0x7f010000 resolves");
    assert_eq!(
        resolved, "com.disrobe.fixture.string.app_name",
        "id 0x7f010000 maps to pkg.type.name"
    );

    let types: &disrobe_pass_jvm::ResTypeConfig = &pkg.types[0];
    assert_eq!(types.type_id, 1, "string type id is 1");
    assert_eq!(types.entries.len(), 1);
    let e: &disrobe_pass_jvm::ResEntry = &types.entries[0];
    assert_eq!(e.key, "app_name");
    match &e.value {
        disrobe_pass_jvm::ResEntryValue::Simple(v) => {
            assert_eq!(v.data_type, 0x03, "app_name is a STRING value");
            assert_eq!(
                v.formatted, "0",
                "string value points at global pool index 0"
            );
        }
        disrobe_pass_jvm::ResEntryValue::Bag { .. } => panic!("app_name is not a bag"),
    }
}

#[test]
fn certificate_fingerprint_matches_authored_cert() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let report: ApkResourceReport = analyze_apk_resources(&apk).expect("apk analyzes");
    assert!(
        !report.certificates.is_empty(),
        "at least one certificate parsed"
    );
    let cert: &CertificateInfo = report
        .certificates
        .iter()
        .find(|c: &&CertificateInfo| c.sha256_fingerprint == ORACLE_CERT_SHA256)
        .unwrap_or_else(|| {
            panic!(
                "no cert with the openssl fingerprint; got: {:?}",
                report
                    .certificates
                    .iter()
                    .map(|c: &CertificateInfo| c.sha256_fingerprint.clone())
                    .collect::<Vec<String>>()
            )
        });
    assert_eq!(
        cert.subject, ORACLE_SUBJECT,
        "subject matches openssl x509 -subject"
    );
    assert_eq!(
        cert.issuer, ORACLE_SUBJECT,
        "self-signed: issuer equals subject"
    );
    assert_eq!(
        cert.serial_hex, "05560D9A91BC1468",
        "serial matches openssl x509 -serial"
    );
}

#[test]
fn v1_only_apk_parses_cert_from_pkcs7() {
    let apk: Vec<u8> = read("fixture-v1-signed.apk");
    let report: ApkResourceReport = analyze_apk_resources(&apk).expect("v1 apk analyzes");
    let cert: &CertificateInfo = report
        .certificates
        .iter()
        .find(|c: &&CertificateInfo| c.sha256_fingerprint == ORACLE_CERT_SHA256)
        .expect("v1 .RSA pkcs7 cert parses to the same fixture cert");
    assert_eq!(cert.subject, ORACLE_SUBJECT);
}

#[test]
fn full_apk_report_surfaces_package_and_resources() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let report: ApkResourceReport = analyze_apk_resources(&apk).expect("apk analyzes");
    assert_eq!(report.package.as_deref(), Some("com.disrobe.fixture"));
    assert!(report.resource_table_present);
    assert_eq!(report.package_count, 1);
    assert_eq!(report.resource_entry_count, 1);
    assert!(
        report
            .resources
            .iter()
            .any(|r| r.id == 0x7f01_0000 && r.name == "com.disrobe.fixture.string.app_name"),
        "id map carries the app_name resource"
    );
    let xml: &str = report
        .manifest_xml
        .as_deref()
        .expect("manifest xml present");
    assert!(xml.contains("package=\"com.disrobe.fixture\""));
}

fn authored_axml_with_typed_values() -> Vec<u8> {
    const RES_XML_TYPE: u16 = 0x0003;
    const RES_STRING_POOL_TYPE: u16 = 0x0001;
    const RES_XML_START_NS: u16 = 0x0100;
    const RES_XML_END_NS: u16 = 0x0101;
    const RES_XML_START_ELEM: u16 = 0x0102;
    const RES_XML_END_ELEM: u16 = 0x0103;

    let strings: [&str; 6] = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "widget",
        "enabled",
        "theme",
        "size",
    ];
    let mut offsets: Vec<u32> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = s.encode_utf16().collect();
        let n: u16 = units.len() as u16;
        data.extend_from_slice(&n.to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let sp_header: u16 = 28;
    let index_size: u32 = offsets.len() as u32 * 4;
    let strings_start: u32 = u32::from(sp_header) + index_size;
    let sp_size: u32 = strings_start + data.len() as u32;
    let mut pool: Vec<u8> = Vec::new();
    pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    pool.extend_from_slice(&sp_header.to_le_bytes());
    pool.extend_from_slice(&sp_size.to_le_bytes());
    pool.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);

    let line: u32 = 1;
    let mut start_ns: Vec<u8> = Vec::new();
    start_ns.extend_from_slice(&RES_XML_START_NS.to_le_bytes());
    start_ns.extend_from_slice(&16u16.to_le_bytes());
    start_ns.extend_from_slice(&24u32.to_le_bytes());
    start_ns.extend_from_slice(&line.to_le_bytes());
    start_ns.extend_from_slice(&u32::MAX.to_le_bytes());
    start_ns.extend_from_slice(&0u32.to_le_bytes());
    start_ns.extend_from_slice(&1u32.to_le_bytes());

    let attrs: [(u32, u32, u8, u32); 3] = [
        (3, u32::MAX, 0x12, 1),
        (4, u32::MAX, 0x01, 0x7f01_0000),
        (5, u32::MAX, 0x05, (16u32 << 8) | (3u32 << 4) | 1u32),
    ];
    let mut start_elem: Vec<u8> = Vec::new();
    let elem_size: u32 = 16 + 20 + (attrs.len() as u32) * 20;
    start_elem.extend_from_slice(&RES_XML_START_ELEM.to_le_bytes());
    start_elem.extend_from_slice(&16u16.to_le_bytes());
    start_elem.extend_from_slice(&elem_size.to_le_bytes());
    start_elem.extend_from_slice(&line.to_le_bytes());
    start_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    start_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    start_elem.extend_from_slice(&2u32.to_le_bytes());
    start_elem.extend_from_slice(&0x0014u16.to_le_bytes());
    start_elem.extend_from_slice(&0x0014u16.to_le_bytes());
    start_elem.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    start_elem.extend_from_slice(&0u16.to_le_bytes());
    start_elem.extend_from_slice(&0u16.to_le_bytes());
    start_elem.extend_from_slice(&0u16.to_le_bytes());
    for (ns, raw, vtype, data) in attrs {
        start_elem.extend_from_slice(&1u32.to_le_bytes());
        start_elem.extend_from_slice(&ns.to_le_bytes());
        start_elem.extend_from_slice(&raw.to_le_bytes());
        start_elem.extend_from_slice(&0x0008u16.to_le_bytes());
        start_elem.push(0);
        start_elem.push(vtype);
        start_elem.extend_from_slice(&data.to_le_bytes());
    }
    let _ = strings;

    let mut end_elem: Vec<u8> = Vec::new();
    end_elem.extend_from_slice(&RES_XML_END_ELEM.to_le_bytes());
    end_elem.extend_from_slice(&16u16.to_le_bytes());
    end_elem.extend_from_slice(&24u32.to_le_bytes());
    end_elem.extend_from_slice(&line.to_le_bytes());
    end_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    end_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    end_elem.extend_from_slice(&2u32.to_le_bytes());

    let mut end_ns: Vec<u8> = Vec::new();
    end_ns.extend_from_slice(&RES_XML_END_NS.to_le_bytes());
    end_ns.extend_from_slice(&16u16.to_le_bytes());
    end_ns.extend_from_slice(&24u32.to_le_bytes());
    end_ns.extend_from_slice(&line.to_le_bytes());
    end_ns.extend_from_slice(&u32::MAX.to_le_bytes());
    end_ns.extend_from_slice(&0u32.to_le_bytes());
    end_ns.extend_from_slice(&1u32.to_le_bytes());

    let body_len: u32 =
        (pool.len() + start_ns.len() + start_elem.len() + end_elem.len() + end_ns.len()) as u32;
    let total: u32 = 8 + body_len;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&start_ns);
    out.extend_from_slice(&start_elem);
    out.extend_from_slice(&end_elem);
    out.extend_from_slice(&end_ns);
    out
}

#[test]
fn authored_axml_decodes_every_value_type() {
    let bytes: Vec<u8> = authored_axml_with_typed_values();
    let tree: AxmlTree = parse_axml(&bytes).expect("authored axml parses");
    let xml: String = tree.to_xml();

    assert!(
        xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
        "namespace emitted; got:\n{xml}"
    );
    assert!(
        xml.contains("android:enabled=\"true\""),
        "INT_BOOLEAN 1 -> true; got:\n{xml}"
    );
    assert!(
        xml.contains("android:theme=\"@0x7f010000\""),
        "REFERENCE with no resolver -> @0x...; got:\n{xml}"
    );
    assert!(
        xml.contains("android:size=\"16.0dip\""),
        "DIMENSION mantissa=16 radix=3 unit=dip -> 16.0dip; got:\n{xml}"
    );
    assert!(xml.contains("<widget") && xml.contains("</widget>"));
}
