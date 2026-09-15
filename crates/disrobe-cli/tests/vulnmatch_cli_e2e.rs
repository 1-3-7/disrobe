#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::unreadable_literal
)]

mod common;

use std::path::PathBuf;

use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
};
use disrobe_ir::{Envelope, Rung};

fn fixture_path() -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    common::temp_path("vulnmatch", "dr")
}

fn write_fixture(path: &std::path::Path) {
    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0u8; 32],
        instructions: vec![
            DisasmInstruction {
                offset: 0x10,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "call".to_owned(),
                operands: vec!["gets".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x20),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x15,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: Vec::new(),
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0x10,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Export,
            },
            DisasmSymbol {
                address: 0x20,
                name: "gets".to_owned(),
                kind: DisasmSymbolKind::Import,
            },
        ],
    };
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode disassembly payload");
    let envelope: Envelope = Envelope::new(Rung::Disasm, hot, Vec::new());
    let bytes: Vec<u8> = envelope.encode().expect("encode envelope");
    common::write_bytes(path, &bytes);
}

#[test]
fn vulnmatch_reports_reachable_gets_deterministically() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) = fixture_path();
    write_fixture(&input);
    let input_arg: String = input.display().to_string();
    let first: common::Run = common::run_disrobe(&["vulnmatch", &input_arg]);
    let second: common::Run = common::run_disrobe(&["vulnmatch", &input_arg]);

    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    assert!(
        first.stdout.contains("cwe-242-gets"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("tier: reachable"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("analysis: incomplete"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("path: query:0000000000000010:main"),
        "stdout: {}",
        first.stdout
    );

    let _: std::io::Result<()> = std::fs::remove_file(input);
}

#[test]
fn vulnmatch_matches_installed_debian_package_against_local_osv() {
    let rootfs: disrobe_core::scratch::ScratchDir = common::temp_dir("vulnmatch-dpkg-rootfs");
    let status: PathBuf = rootfs.path().join("var/lib/dpkg/status");
    let os_release: PathBuf = rootfs.path().join("etc/os-release");
    common::write_bytes(
        &status,
        b"Package: nginx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.2.1-2.2+wheezy2\n\nPackage: nginx\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.4.4-1~bpo70+1\n",
    );
    common::write_bytes(
        &os_release,
        b"PRETTY_NAME=\"Debian GNU/Linux 7 (wheezy)\"\nID=debian\nVERSION_ID=\"7\"\n",
    );
    let (_database_scratch, database): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("vulnmatch-osv", "json");
    common::write_bytes(
        &database,
        br#"{
  "schema_version": "1.2.0",
  "id": "DSA-3029-1",
  "modified": "2022-05-13T01:12:21Z",
  "affected": [{
    "package": {"ecosystem": "Debian:7", "name": "nginx"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
      {"introduced": "0"},
      {"fixed": "1.2.1-2.2+wheezy3"}
    ]}]
  }]
}"#,
    );
    let root_arg: String = rootfs.path().display().to_string();
    let database_arg: String = database.display().to_string();
    let first: common::Run =
        common::run_disrobe(&["--json", "vulnmatch", &root_arg, "--osv-db", &database_arg]);
    let second: common::Run =
        common::run_disrobe(&["--json", "vulnmatch", &root_arg, "--osv-db", &database_arg]);

    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    let report: serde_json::Value = serde_json::from_str(&first.stdout).expect("JSON report");
    assert_eq!(report["database_schema_version"], "1.2.0");
    assert_eq!(report["database_modified"], "2022-05-13T01:12:21Z");
    assert_eq!(report["packages_scanned"], 2);
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["findings"][0]["vulnerability_id"], "DSA-3029-1");
    assert_eq!(report["findings"][0]["package"]["architecture"], "amd64");
    assert_eq!(
        report["findings"][0]["package"]["purl"],
        "pkg:deb/debian/nginx@1.2.1-2.2%2Bwheezy2?arch=amd64"
    );
}
