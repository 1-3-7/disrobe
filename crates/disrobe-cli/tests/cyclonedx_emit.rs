#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_native::{AuditableCrate, AuditableSbom, Error, parse_auditable_section};

const AUDITABLE_JSON: &[u8] = br#"{"packages":[
  {"name":"serde","version":"1.0.203","source":"registry+https://github.com/rust-lang/crates.io-index"},
  {"name":"anyhow","version":"1.0.86","source":"registry+https://github.com/rust-lang/crates.io-index"}
]}"#;

#[test]
fn parse_auditable_section_yields_expected_crates() {
    let sbom: AuditableSbom = parse_auditable_section(AUDITABLE_JSON).expect("parse auditable");
    assert_eq!(sbom.crates.len(), 2);

    let serde: &AuditableCrate = &sbom.crates[0];
    assert_eq!(serde.name, "serde");
    assert_eq!(serde.version, "1.0.203");
    assert_eq!(
        serde.source.as_deref(),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );

    let anyhow: &AuditableCrate = &sbom.crates[1];
    assert_eq!(anyhow.name, "anyhow");
    assert_eq!(anyhow.version, "1.0.86");
}

#[test]
fn missing_packages_array_is_rejected() {
    let result: disrobe_pass_native::Result<AuditableSbom> =
        parse_auditable_section(br#"{"not_packages":[]}"#);
    assert!(
        matches!(result, Err(Error::SignatureDb(ref msg)) if msg.contains("missing 'packages' array")),
        "expected SignatureDb(missing 'packages' array), got {result:?}"
    );
}
