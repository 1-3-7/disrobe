#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::{Finding, SecretKind, scan_bytes, scan_report};

fn has_kind(findings: &[Finding], kind: SecretKind) -> bool {
    findings.iter().any(|f: &Finding| f.kind == kind)
}

fn first_of(findings: &[Finding], kind: SecretKind) -> Option<&Finding> {
    findings.iter().find(|f: &&Finding| f.kind == kind)
}

fn joined(prefix: &[u8], body: &[u8]) -> Vec<u8> {
    [prefix, body].concat()
}

#[test]
fn aws_access_key_positive_and_negative() {
    let pos: Vec<Finding> = scan_bytes(b"key = AKIAIOSFODNN7EXAMPLE done", None);
    let f: &Finding = first_of(&pos, SecretKind::AwsAccessKeyId).expect("AWS access key id");
    assert_eq!(f.code, "DR-SEC-AWS-AKID");
    assert_eq!(f.level, "error");

    let neg: Vec<Finding> = scan_bytes(b"prefix AKIATOOSHORT lowercase akiaiosfodnn7example", None);
    assert!(!has_kind(&neg, SecretKind::AwsAccessKeyId));
}

#[test]
fn github_token_families() {
    let pat: Vec<Finding> =
        scan_bytes(b"token ghp_1234567890abcdefABCDEF1234567890abcd here", None);
    let f: &Finding = first_of(&pat, SecretKind::GithubPat).expect("github pat");
    assert_eq!(f.code, "DR-SEC-GH-PAT");
    assert_eq!(f.level, "error");

    let oauth: Vec<Finding> = scan_bytes(b"gho_1234567890abcdefABCDEF1234567890abcd", None);
    assert!(has_kind(&oauth, SecretKind::GithubOauth));

    let app: Vec<Finding> = scan_bytes(b"ghs_1234567890abcdefABCDEF1234567890abcd", None);
    assert!(has_kind(&app, SecretKind::GithubAppToken));

    let short: Vec<Finding> = scan_bytes(b"ghp_tooshort1234567890", None);
    assert!(!has_kind(&short, SecretKind::GithubPat));
}

#[test]
fn stripe_live_vs_test() {
    let live: Vec<Finding> =
        scan_bytes(&joined(b"sk_live_", b"4eC39HqLyjWDarjtT1zdp7dc more"), None);
    let f: &Finding = first_of(&live, SecretKind::StripeLiveSecret).expect("stripe live secret");
    assert_eq!(f.level, "error");

    let test: Vec<Finding> =
        scan_bytes(&joined(b"sk_test_", b"4eC39HqLyjWDarjtT1zdp7dc more"), None);
    assert!(!has_kind(&test, SecretKind::StripeLiveSecret));
}

#[test]
fn jwt_three_part_only() {
    let jwt: &[u8] =
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
    let pos: Vec<Finding> = scan_bytes(jwt, None);
    let f: &Finding = first_of(&pos, SecretKind::Jwt).expect("jwt");
    assert_eq!(f.code, "DR-SEC-JWT");
    assert_eq!(f.level, "warning");

    let one_part: Vec<Finding> = scan_bytes(b"eyJhbGciOiJIUzI1NiJ9 standalone", None);
    assert!(!has_kind(&one_part, SecretKind::Jwt));

    let two_part: Vec<Finding> = scan_bytes(b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ", None);
    assert!(!has_kind(&two_part, SecretKind::Jwt));
}

#[test]
fn pem_private_key_not_cert_or_public() {
    let priv_key: Vec<Finding> = scan_bytes(
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        None,
    );
    let f: &Finding = first_of(&priv_key, SecretKind::PemPrivateKey).expect("pem private key");
    assert_eq!(f.code, "DR-SEC-PEM-PRIV");
    assert_eq!(f.level, "error");

    let cert: Vec<Finding> = scan_bytes(
        b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
        None,
    );
    assert!(!has_kind(&cert, SecretKind::PemPrivateKey));

    let pubkey: Vec<Finding> = scan_bytes(
        b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
        None,
    );
    assert!(!has_kind(&pubkey, SecretKind::PemPrivateKey));
}

#[test]
fn ssh_public_key_requires_base64_body() {
    let key: Vec<Finding> = scan_bytes(
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef user@host",
        None,
    );
    let f: &Finding = first_of(&key, SecretKind::SshPublicKey).expect("ssh public key");
    assert_eq!(f.code, "DR-SEC-SSH-PUB");
    assert_eq!(f.level, "note");

    let bare: Vec<Finding> = scan_bytes(b"the ssh-rsa algorithm is common", None);
    assert!(!has_kind(&bare, SecretKind::SshPublicKey));
}

#[test]
fn gcp_slack_twilio() {
    let gcp: Vec<Finding> = scan_bytes(b"AIzaSyB1234567890abcdefghijklmnopqrstuv extra", None);
    assert!(has_kind(&gcp, SecretKind::GcpApiKey));

    let slack: Vec<Finding> = scan_bytes(b"xoxb-1234567890-abcdefABCDEF", None);
    assert!(has_kind(&slack, SecretKind::SlackToken));

    let twilio_sk: Vec<Finding> = scan_bytes(
        &joined(b"SK", b"0123456789abcdef0123456789abcdef body"),
        None,
    );
    assert!(has_kind(&twilio_sk, SecretKind::TwilioApiKey));

    let twilio_sid: Vec<Finding> = scan_bytes(
        &joined(b"AC", b"0123456789abcdef0123456789abcdef body"),
        None,
    );
    assert!(has_kind(&twilio_sid, SecretKind::TwilioAccountSid));
}

#[test]
fn gcp_service_account_blob() {
    let sa: &[u8] = br#"{"type":"service_account","project_id":"x"}"#;
    assert!(has_kind(
        &scan_bytes(sa, None),
        SecretKind::GcpServiceAccountKey
    ));

    let user: &[u8] = br#"{"type":"user","project_id":"x"}"#;
    assert!(!has_kind(
        &scan_bytes(user, None),
        SecretKind::GcpServiceAccountKey
    ));
}

#[test]
fn benign_text_and_config_yield_nothing() {
    let prose: &[u8] = b"The quick brown fox jumps over the lazy dog. Configuration is loaded from disk at startup, then validated against the declared schema before the service begins serving requests.";
    assert!(
        scan_bytes(prose, None).is_empty(),
        "prose flagged: {:?}",
        scan_bytes(prose, None)
    );

    let cfg: &[u8] = br#"{"name":"app","version":"1.0.0","port":8080,"debug":false}"#;
    assert!(
        scan_bytes(cfg, None).is_empty(),
        "config flagged: {:?}",
        scan_bytes(cfg, None)
    );
}

#[test]
fn high_entropy_generic_flags_random_run() {
    let pos: Vec<Finding> = scan_bytes(b"opaque=Zx9Kq2Lm7Pw4Rt8Nv3Bc6Hd1Fg5Jy0Ws blob", None);
    assert!(has_kind(&pos, SecretKind::HighEntropyGeneric));

    let repeated: Vec<Finding> = scan_bytes(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None);
    assert!(!has_kind(&repeated, SecretKind::HighEntropyGeneric));
}

#[test]
fn serialization_contract_matches_sarif_mapper() {
    let findings: Vec<Finding> = scan_bytes(b"AKIAIOSFODNN7EXAMPLE", Some("file:///t.txt"));
    let f: &Finding = findings.first().expect("one finding");
    let v: serde_json::Value = serde_json::to_value(f).expect("serialize finding");
    assert!(v.get("code").and_then(|x| x.as_str()).is_some());
    assert!(v.get("message").and_then(|x| x.as_str()).is_some());
    assert!(v.get("uri").and_then(|x| x.as_str()).is_some());
    let level: &str = v
        .get("level")
        .and_then(|x| x.as_str())
        .expect("level string");
    assert!(matches!(level, "error" | "warning" | "note"));
}

#[test]
fn redacted_preview_never_echoes_full_secret() {
    let findings: Vec<Finding> = scan_bytes(b"AKIAIOSFODNN7EXAMPLE", None);
    let f: &Finding = findings.first().expect("finding");
    assert!(!f.redacted_preview.contains("IOSFODNN7EXAMPLE"));
    assert!(f.redacted_preview.starts_with("AKIA"));
}

#[test]
fn report_wrapper_shape() {
    let report: disrobe_core::SecretScanReport =
        scan_report(b"ghp_1234567890abcdefABCDEF1234567890abcd", Some("u"));
    assert_eq!(report.schema, "disrobe.scan.secrets/v0");
    assert_eq!(report.uri.as_deref(), Some("u"));
    assert_eq!(report.byte_len, 40);
    assert!(!report.findings.is_empty());
    let v: serde_json::Value = serde_json::to_value(&report).expect("serialize report");
    assert!(v.get("findings").and_then(|x| x.as_array()).is_some());
}
