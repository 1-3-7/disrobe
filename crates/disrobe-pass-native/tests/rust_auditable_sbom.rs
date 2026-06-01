#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{AuditableSbom, parse_auditable_section};

#[test]
fn auditable_section_parses_minimal_json_payload() {
    let blob: &[u8] = br#"{"packages":[{"name":"tokio","version":"1.40.0","source":"crates.io"}]}"#;
    let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
    assert_eq!(sbom.crates.len(), 1);
    assert_eq!(sbom.crates[0].name, "tokio");
}

#[test]
#[ignore = "FIXTURE PENDING: real cargo-auditable-embedded Rust binary for .dep-v0 section"]
fn real_auditable_embedded_binary_round_trip() {}
