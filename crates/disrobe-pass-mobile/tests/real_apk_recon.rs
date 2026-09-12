#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Write as _};
use std::path::PathBuf;

use disrobe_pass_mobile::apk_recon::{
    AppProtector, ProtectorArtifactKind, RouteTarget, SurfacedSecret, analyze,
};
use disrobe_pass_mobile::pass::extract_android_dex_children;
use zip::write::SimpleFileOptions;

fn read_fixture(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

#[test]
fn real_aapt2_apk_manifest_decodes_to_ground_truth() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let report = analyze(&apk).expect("analyze real apk");

    assert!(
        report.manifest_decoded,
        "binary AndroidManifest.xml decoded"
    );
    let manifest = report.manifest.expect("manifest summary present");

    assert_eq!(
        manifest.package.as_deref(),
        Some("com.disrobe.fixture"),
        "package recovered from real aapt2-built binary manifest"
    );
    assert_eq!(
        manifest.version_code.as_deref(),
        Some("1"),
        "android:versionCode typed-int recovered"
    );
    assert_eq!(
        manifest.version_name.as_deref(),
        Some("1.0"),
        "android:versionName string recovered"
    );
    assert_eq!(
        manifest.compile_sdk_version.as_deref(),
        Some("34"),
        "compileSdkVersion typed-int recovered"
    );
}

#[test]
fn real_apk_arsc_value_pool_contains_string_resource() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let report = analyze(&apk).expect("analyze real apk");
    let resources = report.resources.expect("resources.arsc decoded");

    assert!(
        resources.value_string_count >= 1,
        "arsc global value pool decoded: {resources:?}"
    );
    assert!(
        resources
            .package_names
            .iter()
            .any(|n: &String| n == "com.disrobe.fixture"),
        "arsc package name recovered: {resources:?}"
    );
}

#[test]
fn real_apk_routes_dex_to_dalvik() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let report = analyze(&apk).expect("analyze real apk");
    assert!(
        report
            .routed_children
            .iter()
            .any(|c| c.container_path == "classes.dex" && c.target == RouteTarget::DalvikDex),
        "real classes.dex routed to dalvik: {:?}",
        report.routed_children
    );
}

#[test]
fn clean_apk_with_no_secrets_yields_nothing() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let report = analyze(&apk).expect("analyze");
    assert!(
        report.secrets.is_empty(),
        "control fixture has no embedded secrets, must surface none: {:?}",
        report.secrets
    );
    assert!(
        report.endpoints.is_empty(),
        "control fixture has no http endpoints, must surface none: {:?}",
        report.endpoints
    );
    assert!(
        report.protector_walls.is_empty(),
        "unprotected control fixture must not wall: {:?}",
        report.protector_walls
    );
}

fn real_manifest_bytes() -> Vec<u8> {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let cur: Cursor<&[u8]> = Cursor::new(apk.as_slice());
    let mut z = zip::ZipArchive::new(cur).expect("open");
    let mut f = z.by_name("AndroidManifest.xml").expect("manifest");
    let mut b: Vec<u8> = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut b).expect("read");
    b
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        zw.start_file::<&str, ()>(name, opts).expect("start");
        zw.write_all(data).expect("write");
    }
    zw.finish().expect("finish").into_inner()
}

fn dex_blob(payload: &[u8]) -> Vec<u8> {
    let file_size: usize = 40 + payload.len();
    let mut out: Vec<u8> = vec![0; file_size];
    out[..8].copy_from_slice(b"dex\n035\0");
    out[32..36].copy_from_slice(&(file_size as u32).to_le_bytes());
    out[40..].copy_from_slice(payload);
    out
}

#[test]
fn embedded_secret_and_endpoint_are_surfaced() {
    let real_manifest: Vec<u8> = real_manifest_bytes();

    let config: &[u8] =
        b"{\"api\":\"https://api.evil.example.com/v1/track\",\"aws\":\"AKIA4ZXCV7QWPLMN2BGT\"}";
    let elf_so: &[u8] = &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0];
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", &real_manifest),
        ("classes.dex", b"dex\n035\0placeholder"),
        ("assets/config.json", config),
        ("lib/arm64-v8a/libnative.so", elf_so),
    ]);

    let report = analyze(&apk).expect("analyze");

    assert!(
        report
            .endpoints
            .iter()
            .any(|e| e.value == "https://api.evil.example.com/v1/track"),
        "embedded url endpoint surfaced: {:?}",
        report.endpoints
    );
    assert!(
        report.secrets.iter().any(|s| s.code.contains("AWS")),
        "embedded aws access key surfaced: {:?}",
        report.secrets
    );
    assert!(
        report.abis.iter().any(|a: &String| a == "arm64-v8a"),
        "native abi listed: {:?}",
        report.abis
    );
    assert!(
        report
            .routed_children
            .iter()
            .any(|c| c.container_path == "lib/arm64-v8a/libnative.so"
                && c.target == RouteTarget::NativeElf),
        "native .so routed: {:?}",
        report.routed_children
    );
}

#[test]
fn clean_control_apk_without_planted_data_yields_nothing() {
    let real_manifest: Vec<u8> = real_manifest_bytes();
    let benign: &[u8] = b"{\"theme\":\"dark\",\"count\":3,\"label\":\"hello world\"}";
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", &real_manifest),
        ("classes.dex", b"dex\n035\0"),
        ("assets/config.json", benign),
    ]);
    let report = analyze(&apk).expect("analyze");
    assert!(
        report.secrets.is_empty() && report.endpoints.is_empty(),
        "benign control must yield no secrets/endpoints: secrets={:?} endpoints={:?}",
        report.secrets,
        report.endpoints
    );
}

#[test]
fn commercial_shield_walls_honestly() {
    let real_manifest: Vec<u8> = real_manifest_bytes();
    let elf_so: &[u8] = &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    let embedded_dex: Vec<u8> = dex_blob(b"payload");
    let mut packed_payload: Vec<u8> = b"wrapped:".to_vec();
    packed_payload.extend_from_slice(&embedded_dex);
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", &real_manifest),
        ("classes.dex", b"dex\n035\0"),
        ("lib/arm64-v8a/libjiagu.so", elf_so),
        ("assets/o0oo00o0o.dat", &packed_payload),
    ]);
    let report = analyze(&apk).expect("analyze");
    assert!(
        report
            .protector_walls
            .iter()
            .any(|w| w.protector == AppProtector::CommercialShield && !w.recoverable),
        "libjiagu runtime shield must produce an honest non-recoverable wall: {:?}",
        report.protector_walls
    );
    assert!(
        report.protector_artifacts.iter().any(|a| {
            a.kind == ProtectorArtifactKind::NativeRuntime
                && a.container_path == "lib/arm64-v8a/libjiagu.so"
                && a.route == Some(RouteTarget::NativeElf)
        }),
        "libjiagu helper must be surfaced for native follow-up: {:?}",
        report.protector_artifacts
    );
    assert!(
        report.protector_artifacts.iter().any(|a| {
            a.kind == ProtectorArtifactKind::PackedPayload
                && a.container_path == "assets/o0oo00o0o.dat"
        }),
        "known packed payload entry must be surfaced: {:?}",
        report.protector_artifacts
    );
    assert!(
        report.protector_artifacts.iter().any(|a| {
            a.kind == ProtectorArtifactKind::EmbeddedDex
                && a.container_path == "assets/o0oo00o0o.dat@0x8"
                && a.route == Some(RouteTarget::DalvikDex)
        }),
        "embedded dex must be carved from packed payload: {:?}",
        report.protector_artifacts
    );
    assert!(
        report.routed_children.iter().any(|c| {
            c.container_path == "assets/o0oo00o0o.dat@0x8" && c.target == RouteTarget::DalvikDex
        }),
        "carved dex must be routed to dalvik analysis: {:?}",
        report.routed_children
    );
}

#[test]
fn commercial_shield_xor_payload_extracts_real_child_dex() {
    let real_manifest: Vec<u8> = real_manifest_bytes();
    let clean_dex: Vec<u8> = dex_blob(b"xor-payload");
    let encrypted_payload: Vec<u8> = clean_dex.iter().map(|b: &u8| *b ^ 0x5a).collect();
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", &real_manifest),
        ("classes.dex", b"dex\n035\0"),
        ("assets/o0oo00o0o.dat", &encrypted_payload),
    ]);
    let report = analyze(&apk).expect("analyze");
    assert!(
        report.protector_artifacts.iter().any(|a| {
            a.kind == ProtectorArtifactKind::EmbeddedDex
                && a.container_path == "assets/o0oo00o0o.dat@xor5a@0x0"
                && a.route == Some(RouteTarget::DalvikDex)
                && a.evidence.contains("single-byte xor")
        }),
        "xor-carved payload dex must be surfaced: {:?}",
        report.protector_artifacts
    );
    assert!(
        !report
            .protector_walls
            .iter()
            .any(|w| w.evidence == "obfuscated encrypted-payload asset present" && !w.recoverable),
        "recovered packed payload must not keep the asset-only wall: {:?}",
        report.protector_walls
    );
    let children: Vec<(String, Vec<u8>)> =
        extract_android_dex_children(&apk).expect("extract dex children");
    let child: &(String, Vec<u8>) = children
        .iter()
        .find(|child: &&(String, Vec<u8>)| child.0 == "assets/o0oo00o0o.dat@xor5a@0x0")
        .expect("xor-carved dex child");
    assert_eq!(
        child.1.as_slice(),
        clean_dex.as_slice(),
        "decoded child dex must be byte-exact"
    );
}

#[test]
fn two_distinct_keys_in_one_asset_survive_with_whole_values() {
    let first: String = format!("{}{}", "AKIA", "2QWERTYUIOPLKJHG");
    let second: String = format!("{}{}", "AKIA", "9ZXCVBNMASDFGHJK");
    let config: String = format!("{{\"primary\":\"{first}\",\"fallback\":\"{second}\"}}");
    let apk: Vec<u8> = zip_of(&[
        ("AndroidManifest.xml", &real_manifest_bytes()),
        ("classes.dex", b"dex\n035\0"),
        ("assets/config.json", config.as_bytes()),
    ]);

    let report = analyze(&apk).expect("analyze");
    let keys: Vec<&SurfacedSecret> = report
        .secrets
        .iter()
        .filter(|s: &&SurfacedSecret| {
            s.container_path == "assets/config.json" && s.kind == "AwsAccessKeyId"
        })
        .collect();

    assert_eq!(
        keys.len(),
        2,
        "two different access key ids in one file must stay two findings: {:?}",
        report.secrets
    );
    let previews: Vec<&str> = keys
        .iter()
        .map(|s: &&SurfacedSecret| s.preview.as_str())
        .collect();
    assert_eq!(
        previews[0], previews[1],
        "the fixture only detects a preview-keyed merge while both previews are indistinguishable: {previews:?}"
    );
    let values: Vec<&str> = keys
        .iter()
        .map(|s: &&SurfacedSecret| s.value.as_str())
        .collect();
    assert!(
        values.contains(&first.as_str()) && values.contains(&second.as_str()),
        "each finding must keep its own whole value: {values:?}"
    );
    for s in &keys {
        let offset: usize = s.offset.expect("byte offset into the scanned entry");
        let end: usize = offset + s.value.len();
        assert_eq!(
            config.as_bytes().get(offset..end),
            Some(s.value.as_bytes()),
            "offset must locate the value inside assets/config.json: {s:?}"
        );
    }

    let wire: String = serde_json::to_string(&report).expect("serialize report");
    assert!(
        wire.contains(first.as_str()) && wire.contains(second.as_str()),
        "the emitted report must carry both values in full, not a prefix: {wire}"
    );
}
