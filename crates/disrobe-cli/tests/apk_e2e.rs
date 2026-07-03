#![cfg(feature = "jvm")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;
use std::process::{Command, Output};

const FIXTURE: &str = "apk/fixture-v2v3-signed.apk";
const EXPECT_PACKAGE: &str = "com.disrobe.fixture";
const EXPECT_CERT_SHA256: &str = "F8:B7:66:4F:AD:A9:B0:F3:9D:7A:97:2A:BB:28:C1:37:09:5C:65:32:09:1E:98:DF:4F:11:3B:31:BF:23:D4:9C";

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

fn run_apk(extra: &[&str]) -> Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    let fixture: PathBuf = corpus_path(FIXTURE);
    let mut cmd: Command = Command::new(&bin);
    cmd.arg("apk").arg(&fixture);
    for a in extra {
        cmd.arg(a);
    }
    cmd.env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

#[test]
fn apk_text_surfaces_package_and_cert_fingerprint() {
    if !cargo_bin().exists() || !corpus_path(FIXTURE).exists() {
        eprintln!("SKIP: binary or fixture missing");
        return;
    }
    let out: Output = run_apk(&[]);
    assert!(
        out.status.success(),
        "apk text run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains(EXPECT_PACKAGE),
        "text output must surface the package name {EXPECT_PACKAGE}; got:\n{stdout}"
    );
    assert!(
        stdout.contains(EXPECT_CERT_SHA256),
        "text output must surface the signer cert sha256; got:\n{stdout}"
    );
    assert!(
        stdout.contains("com.disrobe.fixture.string.app_name"),
        "text output must surface the decoded resource id->name mapping; got:\n{stdout}"
    );
    assert!(
        stdout.contains("<manifest") && stdout.contains("package=\"com.disrobe.fixture\""),
        "text output must surface the decoded AndroidManifest.xml; got:\n{stdout}"
    );
}

#[test]
fn apk_out_writes_decoded_manifest_xml_and_resource_table() {
    if !cargo_bin().exists() || !corpus_path(FIXTURE).exists() {
        eprintln!("SKIP: binary or fixture missing");
        return;
    }
    let out_dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-apk-out-{}-{}",
        std::process::id(),
        FIXTURE.replace('/', "_")
    ));
    let _: std::io::Result<()> = std::fs::remove_dir_all(&out_dir);
    let out_arg: String = out_dir.to_string_lossy().into_owned();
    let out: Output = run_apk(&["--out", &out_arg]);
    assert!(
        out.status.success(),
        "apk --out run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let manifest_path: PathBuf = out_dir.join("AndroidManifest.xml");
    let resources_path: PathBuf = out_dir.join("resources.txt");
    assert!(
        manifest_path.exists(),
        "AndroidManifest.xml not written to {}",
        manifest_path.display()
    );
    assert!(
        resources_path.exists(),
        "resources.txt not written to {}",
        resources_path.display()
    );

    let manifest: String = std::fs::read_to_string(&manifest_path).expect("read manifest xml");
    assert!(
        manifest.contains("<manifest") && manifest.contains("package=\"com.disrobe.fixture\""),
        "written AndroidManifest.xml lacks decoded content; got:\n{manifest}"
    );
    let resources: String = std::fs::read_to_string(&resources_path).expect("read resources.txt");
    assert!(
        resources.contains("com.disrobe.fixture.string.app_name"),
        "written resources.txt lacks the decoded id->name table; got:\n{resources}"
    );
    assert!(
        resources
            .lines()
            .next()
            .is_some_and(|l: &str| l.starts_with("0x")),
        "resources.txt rows must lead with the hex resource id; got:\n{resources}"
    );

    let _: std::io::Result<()> = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn apk_json_emits_report_with_package_and_cert() {
    if !cargo_bin().exists() || !corpus_path(FIXTURE).exists() {
        eprintln!("SKIP: binary or fixture missing");
        return;
    }
    let out: Output = run_apk(&["--json"]);
    assert!(
        out.status.success(),
        "apk json run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e: serde_json::Error| {
            panic!("apk --json is not valid json: {e}\n{stdout}")
        });

    assert_eq!(
        doc.get("package").and_then(serde_json::Value::as_str),
        Some(EXPECT_PACKAGE),
        "json report package field"
    );
    assert_eq!(
        doc.get("resource_table_present")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "json report resource_table_present"
    );
    let certs: &Vec<serde_json::Value> = doc
        .get("certificates")
        .and_then(serde_json::Value::as_array)
        .expect("certificates array in json report");
    let has_cert: bool = certs.iter().any(|c: &serde_json::Value| {
        c.get("sha256_fingerprint")
            .and_then(serde_json::Value::as_str)
            == Some(EXPECT_CERT_SHA256)
    });
    assert!(
        has_cert,
        "json report must include the signer cert sha256 {EXPECT_CERT_SHA256}; got: {certs:?}"
    );
    let resources: &Vec<serde_json::Value> = doc
        .get("resources")
        .and_then(serde_json::Value::as_array)
        .expect("resources array in json report");
    let has_resource: bool = resources.iter().any(|r: &serde_json::Value| {
        r.get("name").and_then(serde_json::Value::as_str)
            == Some("com.disrobe.fixture.string.app_name")
    });
    assert!(
        has_resource,
        "json report must map resource ids to names; got: {resources:?}"
    );
}
