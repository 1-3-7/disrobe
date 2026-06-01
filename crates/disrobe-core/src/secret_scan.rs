use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AwsAccessKeyId,
    GcpApiKey,
    GcpServiceAccountKey,
    AzureStorageKey,
    GithubPat,
    GithubFineGrainedPat,
    GithubOauth,
    GithubAppToken,
    StripeLiveSecret,
    StripeLivePublishable,
    SlackToken,
    TwilioAccountSid,
    TwilioApiKey,
    Jwt,
    PemPrivateKey,
    SshPublicKey,
    HighEntropyGeneric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
}

impl Severity {
    #[inline]
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub level: String,
    pub kind: SecretKind,
    pub offset: usize,
    pub redacted_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub findings: Vec<Finding>,
}

pub const SCAN_SCHEMA: &str = "disrobe.scan.secrets/v0";

const ENTROPY_THRESHOLD: f64 = 4.5;
const ENTROPY_MIN_RUN: usize = 20;

struct RegexRule {
    kind: SecretKind,
    code: &'static str,
    severity: Severity,
    pattern: Regex,
}

struct PrefixRule {
    kind: SecretKind,
    code: &'static str,
    severity: Severity,
    needles: &'static [&'static [u8]],
}

#[allow(clippy::expect_used)]
static REGEX_RULES: LazyLock<Vec<RegexRule>> = LazyLock::new(|| {
    let specs: [(SecretKind, &'static str, Severity, &'static str); 14] = [
        (
            SecretKind::AwsAccessKeyId,
            "DR-SEC-AWS-AKID",
            Severity::Error,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        ),
        (
            SecretKind::GcpApiKey,
            "DR-SEC-GCP-APIKEY",
            Severity::Error,
            r"\bAIza[0-9A-Za-z_-]{35}\b",
        ),
        (
            SecretKind::AzureStorageKey,
            "DR-SEC-AZURE-STORAGE",
            Severity::Error,
            r"AccountKey=[A-Za-z0-9+/]{86}==",
        ),
        (
            SecretKind::GithubFineGrainedPat,
            "DR-SEC-GH-FINEPAT",
            Severity::Error,
            r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
        ),
        (
            SecretKind::GithubPat,
            "DR-SEC-GH-PAT",
            Severity::Error,
            r"\bghp_[0-9A-Za-z]{36}\b",
        ),
        (
            SecretKind::GithubOauth,
            "DR-SEC-GH-OAUTH",
            Severity::Error,
            r"\bgho_[0-9A-Za-z]{36}\b",
        ),
        (
            SecretKind::GithubAppToken,
            "DR-SEC-GH-APP",
            Severity::Error,
            r"\b(?:ghu|ghs|ghr)_[0-9A-Za-z]{36}\b",
        ),
        (
            SecretKind::StripeLiveSecret,
            "DR-SEC-STRIPE-SK",
            Severity::Error,
            r"\bsk_live_[0-9A-Za-z]{24,}\b",
        ),
        (
            SecretKind::StripeLivePublishable,
            "DR-SEC-STRIPE-PK",
            Severity::Warning,
            r"\bpk_live_[0-9A-Za-z]{24,}\b",
        ),
        (
            SecretKind::SlackToken,
            "DR-SEC-SLACK",
            Severity::Error,
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        ),
        (
            SecretKind::TwilioApiKey,
            "DR-SEC-TWILIO-SK",
            Severity::Error,
            r"\bSK[0-9a-fA-F]{32}\b",
        ),
        (
            SecretKind::TwilioAccountSid,
            "DR-SEC-TWILIO-SID",
            Severity::Warning,
            r"\bAC[0-9a-fA-F]{32}\b",
        ),
        (
            SecretKind::Jwt,
            "DR-SEC-JWT",
            Severity::Warning,
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        ),
        (
            SecretKind::GcpServiceAccountKey,
            "DR-SEC-GCP-SA",
            Severity::Error,
            r#""type"\s*:\s*"service_account""#,
        ),
    ];
    specs
        .into_iter()
        .map(
            |(kind, code, severity, pat): (SecretKind, &'static str, Severity, &'static str)| {
                RegexRule {
                    kind,
                    code,
                    severity,
                    pattern: Regex::new(pat)
                        .expect("DR-SEC-0001: static secret pattern must compile"),
                }
            },
        )
        .collect()
});

static PREFIX_RULES: LazyLock<Vec<PrefixRule>> = LazyLock::new(|| {
    vec![
        PrefixRule {
            kind: SecretKind::PemPrivateKey,
            code: "DR-SEC-PEM-PRIV",
            severity: Severity::Error,
            needles: &[
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN DSA PRIVATE KEY-----",
                b"-----BEGIN OPENSSH PRIVATE KEY-----",
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            ],
        },
        PrefixRule {
            kind: SecretKind::SshPublicKey,
            code: "DR-SEC-SSH-PUB",
            severity: Severity::Note,
            needles: &[
                b"ssh-rsa AAAA",
                b"ssh-ed25519 AAAA",
                b"ssh-dss AAAA",
                b"ecdsa-sha2-nistp256 AAAA",
                b"ecdsa-sha2-nistp384 AAAA",
                b"ecdsa-sha2-nistp521 AAAA",
            ],
        },
    ]
});

#[inline]
fn redact(matched: &str) -> String {
    let head: String = matched.chars().take(4).collect();
    format!("{head}\u{2026}{}", matched.len())
}

#[inline]
fn redact_bytes(matched: &[u8]) -> String {
    let head: String = String::from_utf8_lossy(&matched[..matched.len().min(4)]).into_owned();
    format!("{head}\u{2026}{}", matched.len())
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u32; 256] = [0; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len: f64 = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c: &&u32| c > 0)
        .map(|&c: &u32| {
            let p: f64 = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

#[inline]
const fn is_secretish_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn finding_for(
    kind: SecretKind,
    code: &'static str,
    severity: Severity,
    offset: usize,
    matched: &str,
    redacted_preview: String,
    uri: Option<&str>,
) -> Finding {
    Finding {
        code: code.to_owned(),
        message: format!("{} detected ({matched})", describe(kind)),
        uri: uri.map(str::to_owned),
        level: severity.sarif_level().to_owned(),
        kind,
        offset,
        redacted_preview,
    }
}

#[inline]
const fn describe(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::AwsAccessKeyId => "AWS access key id",
        SecretKind::GcpApiKey => "Google API key",
        SecretKind::GcpServiceAccountKey => "GCP service-account key blob",
        SecretKind::AzureStorageKey => "Azure storage account key",
        SecretKind::GithubPat => "GitHub personal access token",
        SecretKind::GithubFineGrainedPat => "GitHub fine-grained PAT",
        SecretKind::GithubOauth => "GitHub OAuth token",
        SecretKind::GithubAppToken => "GitHub app / refresh / server token",
        SecretKind::StripeLiveSecret => "Stripe live secret key",
        SecretKind::StripeLivePublishable => "Stripe live publishable key",
        SecretKind::SlackToken => "Slack token",
        SecretKind::TwilioAccountSid => "Twilio account SID",
        SecretKind::TwilioApiKey => "Twilio API key SID",
        SecretKind::Jwt => "JSON Web Token",
        SecretKind::PemPrivateKey => "PEM private key",
        SecretKind::SshPublicKey => "SSH public key",
        SecretKind::HighEntropyGeneric => "high-entropy secret-like string",
    }
}

#[must_use]
pub fn scan_bytes(bytes: &[u8], uri: Option<&str>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut claimed: Vec<(usize, usize)> = Vec::new();

    for rule in PREFIX_RULES.iter() {
        for needle in rule.needles {
            let mut start: usize = 0;
            while let Some(rel) = find_subslice(&bytes[start..], needle) {
                let at: usize = start + rel;
                let preview: String = redact_bytes(&bytes[at..at + needle.len()]);
                findings.push(finding_for(
                    rule.kind,
                    rule.code,
                    rule.severity,
                    at,
                    &String::from_utf8_lossy(needle),
                    preview,
                    uri,
                ));
                claimed.push((at, at + needle.len()));
                start = at + 1;
            }
        }
    }

    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
    let valid_utf8: bool = matches!(text, std::borrow::Cow::Borrowed(_));

    for rule in REGEX_RULES.iter() {
        for m in rule.pattern.find_iter(&text) {
            let matched: &str = m.as_str();
            let offset: usize = if valid_utf8 {
                m.start()
            } else {
                byte_offset_of(bytes, matched.as_bytes(), &claimed)
            };
            let preview: String = redact(matched);
            claimed.push((offset, offset + matched.len()));
            findings.push(finding_for(
                rule.kind,
                rule.code,
                rule.severity,
                offset,
                matched,
                preview,
                uri,
            ));
        }
    }

    scan_entropy(bytes, uri, &claimed, &mut findings);
    findings.sort_by_key(|f: &Finding| f.offset);
    findings
}

fn scan_entropy(
    bytes: &[u8],
    uri: Option<&str>,
    claimed: &[(usize, usize)],
    findings: &mut Vec<Finding>,
) {
    let mut i: usize = 0;
    let n: usize = bytes.len();
    while i < n {
        if !is_secretish_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let run_start: usize = i;
        while i < n && is_secretish_byte(bytes[i]) {
            i += 1;
        }
        let run: &[u8] = &bytes[run_start..i];
        if run.len() < ENTROPY_MIN_RUN {
            continue;
        }
        if claimed
            .iter()
            .any(|&(s, e): &(usize, usize)| run_start < e && s < i)
        {
            continue;
        }
        if shannon_entropy(run) < ENTROPY_THRESHOLD {
            continue;
        }
        let preview: String = redact_bytes(run);
        findings.push(finding_for(
            SecretKind::HighEntropyGeneric,
            "DR-SEC-ENTROPY",
            Severity::Note,
            run_start,
            &String::from_utf8_lossy(&run[..run.len().min(8)]),
            preview,
            uri,
        ));
    }
}

fn byte_offset_of(haystack: &[u8], needle: &[u8], claimed: &[(usize, usize)]) -> usize {
    let mut start: usize = 0;
    while let Some(rel) = find_subslice(&haystack[start..], needle) {
        let at: usize = start + rel;
        if !claimed.iter().any(|&(s, _e): &(usize, usize)| s == at) {
            return at;
        }
        start = at + 1;
    }
    0
}

#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[must_use]
pub fn scan_strings<'a, I: IntoIterator<Item = &'a str>>(
    strings: I,
    uri: Option<&str>,
) -> Vec<Finding> {
    strings
        .into_iter()
        .flat_map(|s: &str| scan_bytes(s.as_bytes(), uri))
        .collect()
}

#[must_use]
pub fn scan_report(bytes: &[u8], uri: Option<&str>) -> SecretScanReport {
    SecretScanReport {
        schema: SCAN_SCHEMA,
        uri: uri.map(str::to_owned),
        byte_len: bytes.len(),
        findings: scan_bytes(bytes, uri),
    }
}
