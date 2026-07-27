use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
pub mod git_history;
pub mod interop;
pub mod ioc;
pub mod malware_config;
#[cfg(feature = "redact")]
pub mod redact;
pub mod secret_scan;

use self::ioc::IocKind;
#[cfg(feature = "redact")]
pub use self::redact::Redactor;
use self::secret_scan::Severity;

pub const RECON_SCHEMA: &str = "disrobe.recon/v0";

const REGEX_SIZE_LIMIT: usize = 16 << 20;
const MAX_FILE_BYTES: u64 = 64 << 20;
const MAX_TREE_FILES: usize = 200_000;
const MAX_VALUE_LEN: usize = 512;
const ZIP_LOCAL_HEADER: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const ZIP_EMPTY_HEADER: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const MAX_ZIP_ENTRIES: usize = 50_000;
const MAX_ZIP_ENTRY_BYTES: u64 = 64 << 20;
const MAX_ZIP_TOTAL_BYTES: u64 = 1 << 30;
const ARCHIVE_MEMBER_PREALLOC_CAP: u64 = 1 << 20;

const MAX_BASE64_DEPTH: u8 = 4;
const MIN_BASE64_RUN: usize = 24;
const MAX_BASE64_RUNS: usize = 4096;
const MAX_BASE64_DECODED_TOTAL: usize = 16 << 20;

const MAX_CODEC_DEPTH: u8 = 3;
const MIN_CODEC_RUN: usize = 16;
const MAX_CODEC_RUN: usize = 1 << 20;
const MAX_CODEC_DECODED_TOTAL: usize = 16 << 20;
const CODEC_PRINTABLE_RATIO: f64 = 0.85;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconCategory {
    Secret,
    Endpoint,
    Manifest,
    Url,
    Domain,
    Ipv4,
    Ipv6,
    Email,
    Onion,
    Wallet,
    Pdb,
    Persistence,
    C2,
    Pii,
    MalwareConfig,
    Custom,
}

impl ReconCategory {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Endpoint => "endpoint",
            Self::Manifest => "manifest",
            Self::Url => "url",
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Email => "email",
            Self::Onion => "onion",
            Self::Wallet => "wallet",
            Self::Pdb => "pdb",
            Self::Persistence => "persistence",
            Self::C2 => "c2",
            Self::Pii => "pii",
            Self::MalwareConfig => "malware_config",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconFinding {
    pub category: ReconCategory,
    pub rule_id: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub line: usize,
    pub column: usize,
    pub offset: usize,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub non_utf8_files: usize,
    pub total: usize,
    pub findings: Vec<ReconFinding>,
}

#[derive(Debug, Clone)]
pub struct CustomPattern {
    pub name: String,
    pub regex: Regex,
}

impl CustomPattern {
    pub fn compile(name: &str, pattern: &str) -> Result<Self, ReconError> {
        let regex: Regex = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| ReconError::BadPattern {
                name: name.to_owned(),
                source: e.to_string(),
            })?;
        Ok(Self {
            name: name.to_owned(),
            regex,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReconConfig {
    pub custom: Vec<CustomPattern>,
    pub suppress_substrings: Vec<String>,
    pub include_high_entropy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconError {
    BadPattern { name: String, source: String },
    Io { path: String, source: String },
}

impl std::fmt::Display for ReconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPattern { name, source } => {
                write!(
                    f,
                    "DR-RECON-0001: custom pattern '{name}' failed to compile: {source}"
                )
            }
            Self::Io { path, source } => {
                write!(f, "DR-RECON-0002: cannot read '{path}': {source}")
            }
        }
    }
}

impl std::error::Error for ReconError {}

struct EndpointRule {
    rule_id: &'static str,
    category: ReconCategory,
    severity: Severity,
    pattern: Regex,
}

#[allow(clippy::expect_used)]
fn compile(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .expect("DR-RECON-0003: static recon pattern must compile")
}

type RuleSpec = (&'static str, ReconCategory, Severity, &'static str);

static ENDPOINT_RULES: LazyLock<Vec<EndpointRule>> = LazyLock::new(|| {
    let specs: [RuleSpec; 56] = [
        (
            "DR-RECON-FIREBASE",
            ReconCategory::Endpoint,
            Severity::Warning,
            r"(?i)\b[a-z0-9.-]+\.firebaseio\.com\b",
        ),
        (
            "DR-RECON-S3-BUCKET",
            ReconCategory::Endpoint,
            Severity::Warning,
            r"(?i)\b(?:[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9._-]{3,63})\b",
        ),
        (
            "DR-RECON-GCS-BUCKET",
            ReconCategory::Endpoint,
            Severity::Warning,
            r"(?i)\b(?:storage\.googleapis\.com/[a-z0-9._-]{3,63}|[a-z0-9._-]{3,63}\.storage\.googleapis\.com)\b",
        ),
        (
            "DR-RECON-AZURE-BLOB",
            ReconCategory::Endpoint,
            Severity::Warning,
            r"(?i)\b[a-z0-9]{3,24}\.blob\.core\.windows\.net\b",
        ),
        (
            "DR-RECON-GCP-OAUTH",
            ReconCategory::Endpoint,
            Severity::Warning,
            r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
        ),
        (
            "DR-RECON-GOOGLE-OAUTH-TOKEN",
            ReconCategory::Secret,
            Severity::Error,
            r"\bya29\.[0-9A-Za-z_-]{20,}",
        ),
        (
            "DR-RECON-SLACK-WEBHOOK",
            ReconCategory::Secret,
            Severity::Error,
            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{20,}",
        ),
        (
            "DR-RECON-DISCORD-WEBHOOK",
            ReconCategory::Secret,
            Severity::Error,
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,}",
        ),
        (
            "DR-RECON-TEAMS-WEBHOOK",
            ReconCategory::Secret,
            Severity::Warning,
            r"https://[a-z0-9.-]+\.webhook\.office\.com/webhookb2/[0-9A-Fa-f-]{36}@[0-9A-Fa-f-]{36}/IncomingWebhook/[0-9A-Fa-f]{32}/[0-9A-Fa-f-]{36}",
        ),
        (
            "DR-RECON-DISCORD-BOT",
            ReconCategory::Secret,
            Severity::Error,
            r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b",
        ),
        (
            "DR-RECON-TELEGRAM-BOT",
            ReconCategory::Secret,
            Severity::Error,
            r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{32,33}\b",
        ),
        (
            "DR-RECON-SENDGRID",
            ReconCategory::Secret,
            Severity::Error,
            r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b",
        ),
        (
            "DR-RECON-SHOPIFY-TOKEN",
            ReconCategory::Secret,
            Severity::Error,
            r"\bshp(?:at|ca|pa|ss)_[0-9A-Fa-f]{32}\b",
        ),
        (
            "DR-RECON-NPM-TOKEN",
            ReconCategory::Secret,
            Severity::Error,
            r"\bnpm_[0-9A-Za-z]{36}\b",
        ),
        (
            "DR-RECON-PYPI-TOKEN",
            ReconCategory::Secret,
            Severity::Error,
            r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}",
        ),
        (
            "DR-RECON-OPENAI-KEY",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}T3BlbkFJ[0-9A-Za-z_-]{20,}\b",
        ),
        (
            "DR-RECON-ANTHROPIC-KEY",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsk-ant-(?:api|admin)[0-9]{2}-[0-9A-Za-z_-]{80,}\b",
        ),
        (
            "DR-RECON-ALGOLIA-ADMIN",
            ReconCategory::Secret,
            Severity::Warning,
            r#"(?i)algolia[a-z_ ]{0,20}(?:admin|api)[_-]?key["']?\s*[:=]\s*["'][0-9a-f]{32}["']"#,
        ),
        (
            "DR-RECON-CLOUDINARY-URL",
            ReconCategory::Secret,
            Severity::Error,
            r"\bcloudinary://[0-9]{15}:[0-9A-Za-z_-]+@[0-9A-Za-z_-]+\b",
        ),
        (
            "DR-RECON-FACEBOOK-TOKEN",
            ReconCategory::Secret,
            Severity::Warning,
            r"\bEAACEdEose0cBA[0-9A-Za-z]+\b",
        ),
        (
            "DR-RECON-MAILGUN",
            ReconCategory::Secret,
            Severity::Error,
            r"\bkey-[0-9a-zA-Z]{32}\b",
        ),
        (
            "DR-RECON-MAILCHIMP",
            ReconCategory::Secret,
            Severity::Error,
            r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
        ),
        (
            "DR-RECON-SQUARE-ACCESS",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsq0atp-[0-9A-Za-z_-]{22}\b",
        ),
        (
            "DR-RECON-SQUARE-OAUTH",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsq0csp-[0-9A-Za-z_-]{43}\b",
        ),
        (
            "DR-RECON-PAYPAL-BRAINTREE",
            ReconCategory::Secret,
            Severity::Error,
            r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
        ),
        (
            "DR-RECON-HEROKU",
            ReconCategory::Secret,
            Severity::Warning,
            r"(?i)heroku[a-z0-9_ .\-,]{0,25}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        ),
        (
            "DR-RECON-AUTH-BEARER",
            ReconCategory::Secret,
            Severity::Warning,
            r"(?i)\bbearer\s+[a-zA-Z0-9_\-.=]{16,}",
        ),
        (
            "DR-RECON-PASSWORD-IN-URL",
            ReconCategory::Secret,
            Severity::Error,
            r"[a-zA-Z][a-zA-Z0-9+.\-]{2,9}://[^/\s:@]{2,64}:[^/\s:@]{2,64}@[^/\s:@]{1,128}",
        ),
        (
            "DR-RECON-API-ASSIGNMENT",
            ReconCategory::Secret,
            Severity::Warning,
            r#"(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][0-9A-Za-z_\-./+]{16,64}["']"#,
        ),
        (
            "DR-RECON-GITLAB-PAT",
            ReconCategory::Secret,
            Severity::Error,
            r"\bglpat-[0-9A-Za-z_-]{20}\b",
        ),
        (
            "DR-RECON-DIGITALOCEAN",
            ReconCategory::Secret,
            Severity::Error,
            r"\b(?:dop|doo|dor)_v1_[0-9a-f]{64}\b",
        ),
        (
            "DR-RECON-NEWRELIC",
            ReconCategory::Secret,
            Severity::Error,
            r"\bNRAK-[0-9A-Z]{27}\b",
        ),
        (
            "DR-RECON-HUGGINGFACE",
            ReconCategory::Secret,
            Severity::Error,
            r"\bhf_[0-9A-Za-z]{34}\b",
        ),
        (
            "DR-RECON-SUPABASE",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsb_(?:publishable|secret)_[0-9A-Za-z_-]{20,}\b",
        ),
        (
            "DR-RECON-VERCEL",
            ReconCategory::Secret,
            Severity::Error,
            r"\bvc[apo]_[0-9A-Za-z]{24,}\b",
        ),
        (
            "DR-RECON-LINEAR",
            ReconCategory::Secret,
            Severity::Error,
            r"\blin_api_[0-9A-Za-z]{40}\b",
        ),
        (
            "DR-RECON-NOTION",
            ReconCategory::Secret,
            Severity::Error,
            r"\b(?:secret_|ntn_)[0-9A-Za-z]{43,46}\b",
        ),
        (
            "DR-RECON-POSTMARK",
            ReconCategory::Secret,
            Severity::Warning,
            r#"(?i)x-postmark-(?:server|account)-token["':\s]{1,8}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        ),
        (
            "DR-RECON-DATADOG",
            ReconCategory::Secret,
            Severity::Warning,
            r#"(?i)(?:dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key)["':\s=]{1,8}[0-9a-f]{32}\b"#,
        ),
        (
            "DR-RECON-ASANA",
            ReconCategory::Secret,
            Severity::Error,
            r"\b[0-9]/[0-9]{16}:[0-9A-Za-z]{32}\b",
        ),
        (
            "DR-RECON-CLERK-SECRET",
            ReconCategory::Secret,
            Severity::Error,
            r"\bsk_(?:test|live)_[0-9A-Za-z]{40,}\b",
        ),
        (
            "DR-RECON-WEBSOCKET",
            ReconCategory::Endpoint,
            Severity::Note,
            r"(?i)\bwss?://[a-z0-9.\-]+(?::[0-9]{1,5})?(?:/[^\s'\x22<>()\[\]{}]{0,512})?",
        ),
        (
            "DR-RECON-MANIFEST-DEEPLINK",
            ReconCategory::Manifest,
            Severity::Note,
            r#"(?i)android:scheme\s*=\s*["'][a-z][a-z0-9+.\-]{1,40}["']"#,
        ),
        (
            "DR-RECON-MANIFEST-DEEPLINK-HOST",
            ReconCategory::Manifest,
            Severity::Note,
            r#"(?i)android:host\s*=\s*["'][a-z0-9*][a-z0-9.\-]{1,253}["']"#,
        ),
        (
            "DR-RECON-MANIFEST-EXPORTED",
            ReconCategory::Manifest,
            Severity::Warning,
            r#"(?i)<(?:activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*["']true["']"#,
        ),
        (
            "DR-RECON-MANIFEST-PROVIDER-AUTHORITY",
            ReconCategory::Manifest,
            Severity::Warning,
            r#"(?i)android:authorities\s*=\s*["'][a-z0-9][a-z0-9._\-;]{2,255}["']"#,
        ),
        (
            "DR-RECON-MANIFEST-PERMISSION",
            ReconCategory::Manifest,
            Severity::Note,
            r#"(?i)android:name\s*=\s*["']android\.permission\.[A-Z_]{3,48}["']"#,
        ),
        (
            "DR-RECON-C2-USER-AGENT",
            ReconCategory::C2,
            Severity::Note,
            r#"(?i)\b(?:Mozilla/[45]\.0|curl/[0-9]|python-requests/[0-9]|Go-http-client/[0-9]|axios/[0-9]|okhttp/[0-9])[^\r\n"']{0,120}"#,
        ),
        (
            "DR-RECON-C2-NAMED-PIPE",
            ReconCategory::C2,
            Severity::Warning,
            r"(?i)\\\\\.\\pipe\\[A-Za-z0-9_.\-{}]{2,64}",
        ),
        (
            "DR-RECON-C2-MUTEX",
            ReconCategory::C2,
            Severity::Warning,
            r"(?i)\b(?:Global|Local)\\[A-Za-z0-9_.\-{}]{2,64}",
        ),
        (
            "DR-RECON-C2-BEACON-PATH",
            ReconCategory::C2,
            Severity::Warning,
            r"(?i)/(?:gate|panel|api|cmd|c2|task|bot|admin|login|submit|upload)\.php\b",
        ),
        (
            "DR-RECON-C2-DEAD-DROP",
            ReconCategory::C2,
            Severity::Warning,
            r"(?i)\b(?:pastebin\.com/raw|raw\.githubusercontent\.com|cdn\.discordapp\.com/attachments|telegra\.ph|ghostbin\.[a-z]+|transfer\.sh)/[^\s'\x22<>()]{1,256}",
        ),
        (
            "DR-RECON-PERSIST-RUNKEY",
            ReconCategory::Persistence,
            Severity::Warning,
            r"(?i)(?:Software\\)?Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b",
        ),
        (
            "DR-RECON-PERSIST-WINLOGON",
            ReconCategory::Persistence,
            Severity::Warning,
            r"(?i)Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\(?:Shell|Userinit)\b",
        ),
        (
            "DR-RECON-PERSIST-IFEO",
            ReconCategory::Persistence,
            Severity::Warning,
            r"(?i)Image File Execution Options\\[A-Za-z0-9_.\-]{2,64}",
        ),
        (
            "DR-RECON-PERSIST-LAUNCHAGENT",
            ReconCategory::Persistence,
            Severity::Warning,
            r"(?i)(?:Library/Launch(?:Agents|Daemons)|/etc/(?:cron[a-z.]*|systemd/system|rc\.local))(?:/[^\s'\x22<>:]{1,128})?",
        ),
    ];
    specs
        .into_iter()
        .map(
            |(rule_id, category, severity, pat): RuleSpec| EndpointRule {
                rule_id,
                category,
                severity,
                pattern: compile(pat),
            },
        )
        .collect()
});

static ONION_RE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b"));

static ENDPOINT_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?x)
        ["'`](
            (?:\.{1,2}/|/)(?:[A-Za-z0-9_~%.\-]+/)*[A-Za-z0-9_~%.\-]+(?:\?[A-Za-z0-9_=&%.\-]*)?
            |
            [A-Za-z0-9_\-]{1,}/[A-Za-z0-9_./\-]{3,}(?:\?[A-Za-z0-9_=&%.\-]*)?
            |
            [A-Za-z0-9_\-]{1,}\.(?:php|aspx?|jsp|json|action|html?|js|xml|do)(?:\?[A-Za-z0-9_=&%.\-]*)?
        )["'`]"#,
    )
});

static FETCH_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?ix)
        (?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open|\$\.(?:get|post|ajax)|request)
        \s*\(\s*["'`]([^"'`\s]{2,512})["'`]"#,
    )
});

static GRAPHQL_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{2,64})\s*[({]")
});

#[inline]
fn line_col(bytes: &[u8], offset: usize) -> (usize, usize) {
    let capped: usize = offset.min(bytes.len());
    let mut line: usize = 1;
    let mut col: usize = 1;
    for &b in &bytes[..capped] {
        if b == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[inline]
fn truncate_value(value: &str) -> String {
    if value.len() <= MAX_VALUE_LEN {
        value.to_owned()
    } else {
        let mut end: usize = MAX_VALUE_LEN;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\u{2026}", &value[..end])
    }
}

fn endpoint_paths(text: &str, bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    for caps in ENDPOINT_PATH_RE.captures_iter(text) {
        let Some(g): Option<regex::Match<'_>> = caps.get(1) else {
            continue;
        };
        let value: &str = g.as_str();
        if value.len() < 4 || !value[1..].contains(|c: char| c.is_ascii_alphabetic()) {
            continue;
        }
        let offset: usize = g.start();
        let (line, column): (usize, usize) = line_col(bytes, offset);
        out.push(ReconFinding {
            category: ReconCategory::Endpoint,
            rule_id: "DR-RECON-URI-PATH".to_owned(),
            value: truncate_value(value),
            path: path.map(str::to_owned),
            line,
            column,
            offset,
            severity: Severity::Note.sarif_level().to_owned(),
        });
    }
}

fn push_capture(
    re: &Regex,
    rule_id: &str,
    text: &str,
    bytes: &[u8],
    path: Option<&str>,
    out: &mut Vec<ReconFinding>,
) {
    for caps in re.captures_iter(text) {
        let Some(g): Option<regex::Match<'_>> = caps.get(1) else {
            continue;
        };
        let offset: usize = g.start();
        let (line, column): (usize, usize) = line_col(bytes, offset);
        out.push(ReconFinding {
            category: ReconCategory::Endpoint,
            rule_id: rule_id.to_owned(),
            value: truncate_value(g.as_str()),
            path: path.map(str::to_owned),
            line,
            column,
            offset,
            severity: Severity::Note.sarif_level().to_owned(),
        });
    }
}

fn endpoint_calls(text: &str, bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    push_capture(&FETCH_CALL_RE, "DR-RECON-FETCH-URL", text, bytes, path, out);
    push_capture(&GRAPHQL_RE, "DR-RECON-GRAPHQL-OP", text, bytes, path, out);
}

fn endpoint_rules(text: &str, bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    for rule in ENDPOINT_RULES.iter() {
        for m in rule.pattern.find_iter(text) {
            let offset: usize = m.start();
            let (line, column): (usize, usize) = line_col(bytes, offset);
            out.push(ReconFinding {
                category: rule.category,
                rule_id: rule.rule_id.to_owned(),
                value: truncate_value(m.as_str()),
                path: path.map(str::to_owned),
                line,
                column,
                offset,
                severity: rule.severity.sarif_level().to_owned(),
            });
        }
    }
}

fn custom_rules(
    text: &str,
    bytes: &[u8],
    path: Option<&str>,
    config: &ReconConfig,
    out: &mut Vec<ReconFinding>,
) {
    for rule in &config.custom {
        for m in rule.regex.find_iter(text) {
            let offset: usize = m.start();
            let (line, column): (usize, usize) = line_col(bytes, offset);
            out.push(ReconFinding {
                category: ReconCategory::Custom,
                rule_id: format!("DR-RECON-CUSTOM-{}", rule.name.to_uppercase()),
                value: truncate_value(m.as_str()),
                path: path.map(str::to_owned),
                line,
                column,
                offset,
                severity: Severity::Warning.sarif_level().to_owned(),
            });
        }
    }
}

fn onion_findings(text: &str, bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    for m in ONION_RE.find_iter(text) {
        let offset: usize = m.start();
        let (line, column): (usize, usize) = line_col(bytes, offset);
        out.push(ReconFinding {
            category: ReconCategory::Onion,
            rule_id: "DR-RECON-ONION".to_owned(),
            value: truncate_value(m.as_str()),
            path: path.map(str::to_owned),
            line,
            column,
            offset,
            severity: Severity::Warning.sarif_level().to_owned(),
        });
    }
}

fn secret_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    for f in secret_scan::scan_bytes(bytes, path) {
        let (line, column): (usize, usize) = line_col(bytes, f.offset);
        out.push(ReconFinding {
            category: ReconCategory::Secret,
            rule_id: f.code,
            value: f.redacted_preview,
            path: path.map(str::to_owned),
            line,
            column,
            offset: f.offset,
            severity: f.level,
        });
    }
}

fn ioc_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    for ind in ioc::extract(bytes) {
        let category: ReconCategory = match ind.kind {
            IocKind::Url => ReconCategory::Url,
            IocKind::Domain => ReconCategory::Domain,
            IocKind::Ipv4 => ReconCategory::Ipv4,
            IocKind::Ipv6 => ReconCategory::Ipv6,
            IocKind::Email => ReconCategory::Email,
            IocKind::BitcoinAddress
            | IocKind::EthereumAddress
            | IocKind::MoneroAddress
            | IocKind::LitecoinAddress
            | IocKind::TronAddress => ReconCategory::Wallet,
            IocKind::PdbPath => ReconCategory::Pdb,
            IocKind::CreditCard | IocKind::MacAddress | IocKind::Uuid => ReconCategory::Pii,
            IocKind::RegistryKey | IocKind::WindowsPath | IocKind::UnixPath => {
                if is_persistence_indicator(&ind.value) {
                    ReconCategory::Persistence
                } else {
                    continue;
                }
            }
            IocKind::CryptoConstant => continue,
        };
        let severity: Severity = match category {
            ReconCategory::Wallet | ReconCategory::Persistence | ReconCategory::Pii => {
                Severity::Warning
            }
            _ => Severity::Note,
        };
        let (line, column): (usize, usize) = line_col(bytes, ind.offset);
        out.push(ReconFinding {
            category,
            rule_id: format!("DR-RECON-{}", ind.kind.label().to_uppercase()),
            value: truncate_value(&ind.value),
            path: path.map(str::to_owned),
            line,
            column,
            offset: ind.offset,
            severity: severity.sarif_level().to_owned(),
        });
    }
}

const PERSISTENCE_NEEDLES: &[&str] = &[
    "currentversion\\run",
    "currentversion\\runonce",
    "\\winlogon\\shell",
    "\\winlogon\\userinit",
    "appinit_dlls",
    "image file execution options",
    "\\start menu\\programs\\startup",
    "/etc/cron",
    "/etc/systemd/system",
    "/etc/rc.local",
    "/launchagents/",
    "/launchdaemons/",
    "schtasks",
    "\\tasks\\",
];

fn is_persistence_indicator(value: &str) -> bool {
    let lower: String = value.to_ascii_lowercase();
    PERSISTENCE_NEEDLES.iter().any(|n: &&str| lower.contains(n))
}

const COBALT_TLV_WINDOW: usize = 4096;

fn malware_config_findings(
    bytes: &[u8],
    text: &str,
    path: Option<&str>,
    out: &mut Vec<ReconFinding>,
) {
    cobalt_strike_findings(bytes, path, out);
    njrat_findings(text, path, out);
    remcos_findings(bytes, path, out);
    asyncrat_lineage_findings(bytes, path, out);
    quasar_findings(bytes, path, out);
    xworm_findings(bytes, path, out);
    agent_tesla_findings(bytes, path, out);
    darkcomet_findings(bytes, path, out);
}

fn push_malware_field(
    family: malware_config::MalwareFamily,
    key: &str,
    value: &str,
    bytes: &[u8],
    offset: usize,
    path: Option<&str>,
    out: &mut Vec<ReconFinding>,
) {
    let (line, column): (usize, usize) = line_col(bytes, offset);
    out.push(ReconFinding {
        category: ReconCategory::MalwareConfig,
        rule_id: format!("DR-RECON-MALCFG-{}-{}", family.label().to_uppercase(), key),
        value: truncate_value(value),
        path: path.map(str::to_owned),
        line,
        column,
        offset,
        severity: Severity::Error.sarif_level().to_owned(),
    });
}

const COBALT_SCAN_BUDGET: usize = 1 << 20;

fn cobalt_strike_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let scan_end: usize = bytes.len().min(COBALT_SCAN_BUDGET);
    for start in 0..scan_end.saturating_sub(8) {
        let end: usize = (start + COBALT_TLV_WINDOW).min(bytes.len());
        let window: &[u8] = &bytes[start..end];
        if let Some((key, _decoded)) = malware_config::cobalt_strike_decode(window) {
            let summary: String = format!("xor-key=0x{key:02x} tlv-table");
            push_malware_field(
                malware_config::MalwareFamily::CobaltStrike,
                "BEACON",
                &summary,
                bytes,
                start,
                path,
                out,
            );
            return;
        }
    }
}

fn njrat_findings(text: &str, path: Option<&str>, out: &mut Vec<ReconFinding>) {
    if !text.contains("|'|'|") {
        return;
    }
    for line in text.lines() {
        if !line.contains("|'|'|") {
            continue;
        }
        let fields: Vec<malware_config::ConfigField> = malware_config::njrat_split(line, 0);
        if fields.len() < 3 {
            continue;
        }
        for field in &fields {
            push_malware_field(
                malware_config::MalwareFamily::NjRat,
                &field.key.to_uppercase(),
                &field.value,
                text.as_bytes(),
                0,
                path,
                out,
            );
        }
        return;
    }
}

fn remcos_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let Some(at): Option<usize> = crate::byte_search::find(bytes, b"SETTINGS") else {
        return;
    };
    let search_start: usize = at + b"SETTINGS".len();
    let end: usize = (search_start + 8192).min(bytes.len());
    let region: &[u8] = bytes.get(search_start..end).unwrap_or(&[]);
    let Some(blob_start): Option<usize> = first_self_describing_rc4(region) else {
        return;
    };
    let blob: &[u8] = &region[blob_start..];
    let Some(plain): Option<Vec<u8>> = malware_config::remcos_settings_decode(blob) else {
        return;
    };
    let summary: String = String::from_utf8_lossy(&plain[..plain.len().min(MAX_VALUE_LEN)])
        .replace(|c: char| c.is_control(), " ");
    push_malware_field(
        malware_config::MalwareFamily::Remcos,
        "SETTINGS",
        &summary,
        bytes,
        search_start + blob_start,
        path,
        out,
    );
}

fn asyncrat_lineage_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    match malware_config::asyncrat_lineage_decode(bytes, 0) {
        Ok(fields) => {
            for field in &fields {
                push_malware_field(
                    field.family,
                    &field.key.to_uppercase(),
                    &field.value,
                    bytes,
                    field.offset,
                    path,
                    out,
                );
            }
        }
        Err(wall) => {
            let summary: String = format!("wall={} {}", wall.kind.label(), wall.evidence);
            push_malware_field(wall.family, "WALL", &summary, bytes, 0, path, out);
        }
    }
}

fn quasar_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let fields: Vec<malware_config::ConfigField> = malware_config::quasar_config_decode(bytes, 0);
    for field in &fields {
        push_malware_field(
            malware_config::MalwareFamily::QuasarRat,
            &field.key.to_uppercase(),
            &field.value,
            bytes,
            field.offset,
            path,
            out,
        );
    }
}

fn xworm_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let fields: Vec<malware_config::ConfigField> = malware_config::xworm_config_decode(bytes, 0);
    for field in &fields {
        push_malware_field(
            malware_config::MalwareFamily::XWorm,
            &field.key.to_uppercase(),
            &field.value,
            bytes,
            field.offset,
            path,
            out,
        );
    }
}

fn agent_tesla_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let fields: Vec<malware_config::ConfigField> =
        malware_config::agent_tesla_config_decode(bytes, 0);
    for field in &fields {
        push_malware_field(
            malware_config::MalwareFamily::AgentTesla,
            &field.key.to_uppercase(),
            &field.value,
            bytes,
            field.offset,
            path,
            out,
        );
    }
}

fn darkcomet_findings(bytes: &[u8], path: Option<&str>, out: &mut Vec<ReconFinding>) {
    let fields: Vec<malware_config::ConfigField> =
        malware_config::darkcomet_config_decode(bytes, 0);
    for field in &fields {
        push_malware_field(
            malware_config::MalwareFamily::DarkComet,
            &field.key.to_uppercase(),
            &field.value,
            bytes,
            field.offset,
            path,
            out,
        );
    }
}

fn first_self_describing_rc4(region: &[u8]) -> Option<usize> {
    for offset in 0..region.len().min(64) {
        let blob: &[u8] = &region[offset..];
        if malware_config::remcos_settings_decode(blob).is_some() {
            return Some(offset);
        }
    }
    None
}

fn extract_utf16le_ascii_strings(bytes: &[u8]) -> String {
    let mut out: String = String::new();
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        let lo: u8 = bytes[i];
        let hi: u8 = bytes[i + 1];
        if (0x20..=0x7E).contains(&lo) && hi == 0x00 {
            let mut chars: Vec<char> = Vec::new();
            while i + 1 < bytes.len() && (0x20..=0x7E).contains(&bytes[i]) && bytes[i + 1] == 0x00 {
                chars.push(bytes[i] as char);
                i += 2;
            }
            if chars.len() >= 4 {
                out.extend(chars);
                out.push('\n');
            }
        } else {
            i += 1;
        }
    }
    out
}

#[must_use]
pub fn scan_bytes(
    bytes: &[u8],
    path: Option<&str>,
    config: &ReconConfig,
) -> (Vec<ReconFinding>, bool) {
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
    let valid_utf8: bool = matches!(text, std::borrow::Cow::Borrowed(_));
    let wide_text: String = extract_utf16le_ascii_strings(bytes);

    let mut out: Vec<ReconFinding> = Vec::new();
    secret_findings(bytes, path, &mut out);
    ioc_findings(bytes, path, &mut out);
    endpoint_rules(&text, bytes, path, &mut out);
    endpoint_paths(&text, bytes, path, &mut out);
    endpoint_calls(&text, bytes, path, &mut out);
    onion_findings(&text, bytes, path, &mut out);
    if !wide_text.is_empty() {
        let wide_bytes: &[u8] = wide_text.as_bytes();
        endpoint_rules(&wide_text, wide_bytes, path, &mut out);
        onion_findings(&wide_text, wide_bytes, path, &mut out);
        ioc_findings(wide_bytes, path, &mut out);
    }
    malware_config_findings(bytes, &text, path, &mut out);
    custom_rules(&text, bytes, path, config, &mut out);

    if !config.include_high_entropy {
        out.retain(|f: &ReconFinding| f.rule_id != "DR-SEC-ENTROPY");
    }
    if !config.suppress_substrings.is_empty() {
        out.retain(|f: &ReconFinding| {
            !config
                .suppress_substrings
                .iter()
                .any(|s: &String| f.value.contains(s.as_str()))
        });
    }

    (out, valid_utf8)
}

const fn category_specificity(category: ReconCategory) -> u8 {
    match category {
        ReconCategory::Secret => 15,
        ReconCategory::MalwareConfig => 14,
        ReconCategory::C2 => 13,
        ReconCategory::Persistence => 12,
        ReconCategory::Wallet => 11,
        ReconCategory::Pdb => 10,
        ReconCategory::Pii => 9,
        ReconCategory::Onion => 8,
        ReconCategory::Email => 7,
        ReconCategory::Endpoint => 6,
        ReconCategory::Manifest => 5,
        ReconCategory::Url => 4,
        ReconCategory::Ipv6 => 3,
        ReconCategory::Ipv4 => 2,
        ReconCategory::Custom => 1,
        ReconCategory::Domain => 0,
    }
}

fn dedup(mut findings: Vec<ReconFinding>) -> Vec<ReconFinding> {
    findings.sort_by(|a: &ReconFinding, b: &ReconFinding| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.offset.cmp(&b.offset))
    });
    findings.dedup_by(|a: &mut ReconFinding, b: &mut ReconFinding| {
        a.path == b.path && a.category == b.category && a.rule_id == b.rule_id && a.value == b.value
    });
    findings.sort_by(|a: &ReconFinding, b: &ReconFinding| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.offset.cmp(&b.offset))
            .then_with(|| category_specificity(b.category).cmp(&category_specificity(a.category)))
    });
    findings.dedup_by(|a: &mut ReconFinding, b: &mut ReconFinding| {
        a.path == b.path && a.value == b.value && a.offset == b.offset
    });
    findings.sort_by(|a: &ReconFinding, b: &ReconFinding| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    findings
}

#[inline]
const fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn decode_base64_run(run: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let trimmed: &[u8] = run.strip_suffix(b"=").map_or(run, |_| {
        let mut end: usize = run.len();
        while end > 0 && run[end - 1] == b'=' {
            end -= 1;
        }
        &run[..end]
    });
    STANDARD
        .decode(run)
        .or_else(|_| URL_SAFE.decode(run))
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()
}

fn base64_decoded_upper_bound_len(encoded_len: usize) -> Option<usize> {
    encoded_len.checked_add(3)?.checked_div(4)?.checked_mul(3)
}

fn base64_decode_findings(
    bytes: &[u8],
    uri: Option<&str>,
    config: &ReconConfig,
    depth: u8,
) -> Vec<ReconFinding> {
    if depth >= MAX_BASE64_DEPTH {
        return Vec::new();
    }
    let mut out: Vec<ReconFinding> = Vec::new();
    let mut runs: usize = 0;
    let mut decoded_total: usize = 0;
    let mut i: usize = 0;
    let n: usize = bytes.len();
    while i < n {
        if !is_base64_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let run_start: usize = i;
        while i < n && is_base64_byte(bytes[i]) {
            i += 1;
        }
        let run: &[u8] = &bytes[run_start..i];
        if run.len() < MIN_BASE64_RUN {
            continue;
        }
        let Some(decoded_bound): Option<usize> = base64_decoded_upper_bound_len(run.len()) else {
            break;
        };
        if decoded_bound > MAX_BASE64_DECODED_TOTAL.saturating_sub(decoded_total) {
            continue;
        }
        let Some(decoded): Option<Vec<u8>> = decode_base64_run(run) else {
            continue;
        };
        let Ok(text): Result<&str, _> = std::str::from_utf8(&decoded) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        runs += 1;
        let Some(next_decoded_total): Option<usize> = decoded_total.checked_add(decoded.len())
        else {
            break;
        };
        decoded_total = next_decoded_total;
        if decoded_total > MAX_BASE64_DECODED_TOTAL {
            break;
        }
        let nested_uri: String = uri.map_or_else(
            || format!("#b64@{run_start}"),
            |u: &str| format!("{u}#b64@{run_start}"),
        );
        let (mut findings, _): (Vec<ReconFinding>, bool) =
            scan_bytes(&decoded, Some(&nested_uri), config);
        out.append(&mut findings);
        out.extend(base64_decode_findings(
            &decoded,
            Some(&nested_uri),
            config,
            depth + 1,
        ));
        if runs >= MAX_BASE64_RUNS {
            break;
        }
    }
    out
}

#[inline]
const fn is_codec_token_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x7e)
}

#[inline]
fn codec_output_advances(decoded: &[u8], original: &[u8]) -> bool {
    if decoded.is_empty() || decoded == original || decoded.len() > MAX_CODEC_RUN {
        return false;
    }
    if crate::codec::nested_container_magic(decoded) {
        return true;
    }
    let printable: usize = decoded
        .iter()
        .filter(|&&b: &&u8| matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r'))
        .count();
    (printable as f64 / decoded.len() as f64) >= CODEC_PRINTABLE_RATIO
}

fn codec_peel_token(
    token: &[u8],
    token_offset: usize,
    uri: Option<&str>,
    config: &ReconConfig,
    depth: u8,
    decoded_total: &mut usize,
    out: &mut Vec<ReconFinding>,
) {
    if token.len() < MIN_CODEC_RUN || token.len() > MAX_CODEC_RUN {
        return;
    }
    for &scheme in crate::codec::Scheme::all() {
        if *decoded_total >= MAX_CODEC_DECODED_TOTAL {
            return;
        }
        let Ok(decoded): Result<Vec<u8>, _> = crate::codec::decode(token, scheme) else {
            continue;
        };
        if !codec_output_advances(&decoded, token) {
            continue;
        }
        *decoded_total = decoded_total.saturating_add(decoded.len());
        let nested_uri: String = uri.map_or_else(
            || format!("#{}@{token_offset}", scheme.label()),
            |u: &str| format!("{u}#{}@{token_offset}", scheme.label()),
        );
        let (mut findings, _): (Vec<ReconFinding>, bool) =
            scan_bytes(&decoded, Some(&nested_uri), config);
        out.append(&mut findings);
        out.extend(scan_container(&decoded, Some(&nested_uri), config));
        out.extend(codec_cascade_findings(
            &decoded,
            Some(&nested_uri),
            config,
            depth + 1,
            decoded_total,
        ));
    }
}

fn codec_cascade_findings(
    bytes: &[u8],
    uri: Option<&str>,
    config: &ReconConfig,
    depth: u8,
    decoded_total: &mut usize,
) -> Vec<ReconFinding> {
    let mut out: Vec<ReconFinding> = Vec::new();
    if depth >= MAX_CODEC_DEPTH || bytes.len() < MIN_CODEC_RUN {
        return out;
    }
    codec_peel_token(bytes, 0, uri, config, depth, decoded_total, &mut out);
    let n: usize = bytes.len();
    let mut i: usize = 0;
    while i < n {
        if !is_codec_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start: usize = i;
        while i < n && is_codec_token_byte(bytes[i]) {
            i += 1;
        }
        if *decoded_total >= MAX_CODEC_DECODED_TOTAL {
            break;
        }
        let token: &[u8] = &bytes[start..i];
        if token.len() == n {
            continue;
        }
        codec_peel_token(token, start, uri, config, depth, decoded_total, &mut out);
    }
    out
}

fn scan_blob(bytes: &[u8], uri: Option<&str>, config: &ReconConfig) -> (Vec<ReconFinding>, bool) {
    let (mut findings, valid_utf8): (Vec<ReconFinding>, bool) = scan_bytes(bytes, uri, config);
    findings.extend(base64_decode_findings(bytes, uri, config, 0));
    let mut codec_total: usize = 0;
    findings.extend(codec_cascade_findings(
        bytes,
        uri,
        config,
        0,
        &mut codec_total,
    ));
    findings.extend(scan_container(bytes, uri, config));
    (findings, valid_utf8)
}

fn scan_container(bytes: &[u8], uri: Option<&str>, config: &ReconConfig) -> Vec<ReconFinding> {
    if is_zip_container(bytes) {
        return scan_zip_bytes(bytes, uri, config);
    }
    if is_gzip_magic(bytes) {
        return scan_gzip_bytes(bytes, uri, config);
    }
    if is_bzip2_magic(bytes) {
        return scan_bzip2_bytes(bytes, uri, config);
    }
    #[cfg(not(target_arch = "wasm32"))]
    if is_xz_magic(bytes) {
        return scan_xz_bytes(bytes, uri, config);
    }
    if is_tar_magic(bytes) {
        return scan_tar_bytes(bytes, uri, config);
    }
    Vec::new()
}

#[must_use]
pub fn report_bytes(bytes: &[u8], uri: Option<&str>, config: &ReconConfig) -> ReconReport {
    let (findings, valid_utf8): (Vec<ReconFinding>, bool) = scan_blob(bytes, uri, config);
    let deduped: Vec<ReconFinding> = dedup(findings);
    ReconReport {
        schema: RECON_SCHEMA,
        root: uri.map(str::to_owned),
        files_scanned: 1,
        bytes_scanned: bytes.len() as u64,
        non_utf8_files: usize::from(!valid_utf8),
        total: deduped.len(),
        findings: deduped,
    }
}

#[inline]
fn is_zip_container(bytes: &[u8]) -> bool {
    bytes.starts_with(&ZIP_LOCAL_HEADER) || bytes.starts_with(&ZIP_EMPTY_HEADER)
}

#[must_use]
pub fn scan_zip_bytes(
    bytes: &[u8],
    outer: Option<&str>,
    config: &ReconConfig,
) -> Vec<ReconFinding> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let Ok(mut archive): Result<zip::ZipArchive<_>, _> = zip::ZipArchive::new(cursor) else {
        return Vec::new();
    };
    let entry_count: usize = archive.len().min(MAX_ZIP_ENTRIES);
    let mut out: Vec<ReconFinding> = Vec::new();
    let mut total_read: u64 = 0;
    for index in 0..entry_count {
        let Ok(entry): Result<zip::read::ZipFile<'_>, _> = archive.by_index(index) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let inner_name: String = entry.name().to_owned();
        let declared: u64 = entry.size();
        if declared > MAX_ZIP_ENTRY_BYTES {
            continue;
        }
        if total_read >= MAX_ZIP_TOTAL_BYTES {
            break;
        }
        let cap: u64 = MAX_ZIP_ENTRY_BYTES.min(MAX_ZIP_TOTAL_BYTES - total_read);
        let Some(buf): Option<Vec<u8>> = read_archive_member(entry, declared, cap) else {
            break;
        };
        let Ok(read_len): Result<u64, _> = u64::try_from(buf.len()) else {
            break;
        };
        let Some(next_total): Option<u64> = total_read.checked_add(read_len) else {
            break;
        };
        total_read = next_total;
        let display: String = match outer {
            Some(o) => format!("{o}!{inner_name}"),
            None => inner_name,
        };
        let (mut findings, _): (Vec<ReconFinding>, bool) = scan_blob(&buf, Some(&display), config);
        out.append(&mut findings);
    }
    out
}

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const BZIP2_MAGIC: [u8; 3] = [0x42, 0x5a, 0x68];
#[cfg(not(target_arch = "wasm32"))]
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const TAR_USTAR_OFFSET: usize = 257;
const TAR_BLOCK: usize = 512;

#[inline]
fn is_gzip_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&GZIP_MAGIC)
}

#[inline]
fn is_bzip2_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&BZIP2_MAGIC) && bytes.get(3).is_some_and(|b: &u8| b.is_ascii_digit())
}

#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn is_xz_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&XZ_MAGIC)
}

#[inline]
fn is_tar_magic(bytes: &[u8]) -> bool {
    bytes.len() >= TAR_BLOCK
        && (bytes[TAR_USTAR_OFFSET..].starts_with(b"ustar\0")
            || bytes[TAR_USTAR_OFFSET..].starts_with(b"ustar  \0"))
}

#[inline]
fn archive_member_prealloc(declared: u64, cap: u64) -> usize {
    let bound: u64 = declared.min(cap).min(ARCHIVE_MEMBER_PREALLOC_CAP);
    usize::try_from(bound).map_or(usize::MAX, |value: usize| value)
}

fn read_archive_member<R: std::io::Read>(reader: R, declared: u64, cap: u64) -> Option<Vec<u8>> {
    if declared > cap {
        return None;
    }
    let read_limit: u64 = cap.checked_add(1)?;
    let mut limited: std::io::Take<R> = reader.take(read_limit);
    let mut out: Vec<u8> = Vec::with_capacity(archive_member_prealloc(declared, cap));
    let read: usize = std::io::Read::read_to_end(&mut limited, &mut out).ok()?;
    let read_u64: u64 = u64::try_from(read).ok()?;
    if read_u64 > cap { None } else { Some(out) }
}

fn decompress_bounded<R: std::io::Read>(reader: R) -> Option<Vec<u8>> {
    read_archive_member(reader, 0, MAX_ZIP_ENTRY_BYTES)
}

fn scan_decompressed(
    plain: Option<Vec<u8>>,
    outer: Option<&str>,
    suffix: &str,
    config: &ReconConfig,
) -> Vec<ReconFinding> {
    let Some(plain): Option<Vec<u8>> = plain else {
        return Vec::new();
    };
    let display: String =
        outer.map_or_else(|| suffix.to_owned(), |o: &str| format!("{o}!{suffix}"));
    let (findings, _): (Vec<ReconFinding>, bool) = scan_blob(&plain, Some(&display), config);
    findings
}

#[must_use]
pub fn scan_gzip_bytes(
    bytes: &[u8],
    outer: Option<&str>,
    config: &ReconConfig,
) -> Vec<ReconFinding> {
    let plain: Option<Vec<u8>> = decompress_bounded(flate2::read::GzDecoder::new(bytes));
    scan_decompressed(plain, outer, "gunzip", config)
}

#[must_use]
pub fn scan_bzip2_bytes(
    bytes: &[u8],
    outer: Option<&str>,
    config: &ReconConfig,
) -> Vec<ReconFinding> {
    let plain: Option<Vec<u8>> = decompress_bounded(bzip2_rs::DecoderReader::new(bytes));
    scan_decompressed(plain, outer, "bunzip2", config)
}

#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn scan_xz_bytes(bytes: &[u8], outer: Option<&str>, config: &ReconConfig) -> Vec<ReconFinding> {
    let plain: Option<Vec<u8>> = decompress_bounded(liblzma::read::XzDecoder::new(bytes));
    scan_decompressed(plain, outer, "unxz", config)
}

#[must_use]
pub fn scan_tar_bytes(
    bytes: &[u8],
    outer: Option<&str>,
    config: &ReconConfig,
) -> Vec<ReconFinding> {
    let mut archive: tar::Archive<&[u8]> = tar::Archive::new(bytes);
    let Ok(entries): Result<tar::Entries<'_, &[u8]>, _> = archive.entries() else {
        return Vec::new();
    };
    let mut out: Vec<ReconFinding> = Vec::new();
    let mut total_read: u64 = 0;
    let mut count: usize = 0;
    for entry in entries {
        if count >= MAX_ZIP_ENTRIES || total_read >= MAX_ZIP_TOTAL_BYTES {
            break;
        }
        let Ok(mut entry): Result<tar::Entry<'_, &[u8]>, _> = entry else {
            break;
        };
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let declared: u64 = entry.header().size().unwrap_or(0);
        if declared > MAX_ZIP_ENTRY_BYTES {
            continue;
        }
        count += 1;
        let inner_name: String = entry.path().map_or_else(
            |_| format!("entry{count}"),
            |p: std::borrow::Cow<'_, Path>| p.to_string_lossy().replace('\\', "/"),
        );
        let cap: u64 = MAX_ZIP_ENTRY_BYTES.min(MAX_ZIP_TOTAL_BYTES - total_read);
        let Some(buf): Option<Vec<u8>> = read_archive_member(&mut entry, declared, cap) else {
            break;
        };
        let Ok(read_len): Result<u64, _> = u64::try_from(buf.len()) else {
            break;
        };
        let Some(next_total): Option<u64> = total_read.checked_add(read_len) else {
            break;
        };
        total_read = next_total;
        let display: String = match outer {
            Some(o) => format!("{o}!{inner_name}"),
            None => inner_name,
        };
        let (mut findings, _): (Vec<ReconFinding>, bool) = scan_blob(&buf, Some(&display), config);
        out.append(&mut findings);
    }
    out
}

fn walk(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), ReconError> {
    walk_with_limit(root, files, MAX_TREE_FILES)
}

fn walk_with_limit(
    root: &Path,
    files: &mut Vec<PathBuf>,
    max_files: usize,
) -> Result<(), ReconError> {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    'dirs: while let Some(dir) = stack.pop() {
        if files.len() >= max_files {
            break;
        }
        let entries: std::fs::ReadDir = std::fs::read_dir(&dir).map_err(|e| ReconError::Io {
            path: dir.display().to_string(),
            source: e.to_string(),
        })?;
        for entry in entries {
            if files.len() >= max_files {
                break 'dirs;
            }
            let Ok(entry): Result<std::fs::DirEntry, _> = entry else {
                continue;
            };
            let kind: std::fs::FileType = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if kind.is_symlink() {
                continue;
            }
            let p: PathBuf = entry.path();
            if kind.is_dir() {
                stack.push(p);
            } else if kind.is_file() {
                files.push(p);
                if files.len() >= max_files {
                    break 'dirs;
                }
            }
        }
    }
    files.sort();
    Ok(())
}

fn read_scan_file(path: &Path) -> Option<Vec<u8>> {
    let file: std::fs::File = std::fs::File::open(path).ok()?;
    let len: u64 = file.metadata().ok()?.len();
    if len > MAX_FILE_BYTES {
        return None;
    }
    let capacity: usize = usize::try_from(len.min(MAX_FILE_BYTES)).unwrap_or_default();
    let mut limited: std::io::Take<std::fs::File> = file.take(MAX_FILE_BYTES.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    let _: usize = limited.read_to_end(&mut bytes).ok()?;
    let observed: u64 = u64::try_from(bytes.len()).ok()?;
    if observed > MAX_FILE_BYTES {
        return None;
    }
    Some(bytes)
}

pub fn report_tree(root: &Path, config: &ReconConfig) -> Result<ReconReport, ReconError> {
    let meta: std::fs::Metadata = std::fs::metadata(root).map_err(|e| ReconError::Io {
        path: root.display().to_string(),
        source: e.to_string(),
    })?;

    let files: Vec<PathBuf> = if meta.is_file() {
        vec![root.to_path_buf()]
    } else {
        let mut collected: Vec<PathBuf> = Vec::new();
        walk(root, &mut collected)?;
        collected
    };

    let mut all: Vec<ReconFinding> = Vec::new();
    let mut bytes_scanned: u64 = 0;
    let mut files_scanned: usize = 0;
    let mut non_utf8_files: usize = 0;

    for file in &files {
        let Some(bytes): Option<Vec<u8>> = read_scan_file(file) else {
            continue;
        };
        let rel: String = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let display: String = if rel.is_empty() {
            file.to_string_lossy().replace('\\', "/")
        } else {
            rel
        };
        let (findings, valid_utf8): (Vec<ReconFinding>, bool) =
            scan_blob(&bytes, Some(&display), config);
        if !valid_utf8 {
            non_utf8_files += 1;
        }
        all.extend(findings);
        bytes_scanned += bytes.len() as u64;
        files_scanned += 1;
    }

    let deduped: Vec<ReconFinding> = dedup(all);
    Ok(ReconReport {
        schema: RECON_SCHEMA,
        root: Some(root.to_string_lossy().replace('\\', "/")),
        files_scanned,
        bytes_scanned,
        non_utf8_files,
        total: deduped.len(),
        findings: deduped,
    })
}

#[must_use]
pub fn categories(report: &ReconReport) -> BTreeSet<ReconCategory> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.category)
        .collect()
}

#[must_use]
pub fn fingerprint(finding: &ReconFinding) -> String {
    format!(
        "{}|{}|{}|{}",
        finding.path.as_deref().unwrap_or(""),
        finding.category.label(),
        finding.rule_id,
        finding.value
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::codec;

    fn aws_akid() -> String {
        format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
    }

    fn values_in(report: &ReconReport, category: ReconCategory) -> Vec<String> {
        report
            .findings
            .iter()
            .filter(|f: &&ReconFinding| f.category == category)
            .map(|f: &ReconFinding| f.value.clone())
            .collect()
    }

    fn rule_ids(report: &ReconReport) -> BTreeSet<String> {
        report
            .findings
            .iter()
            .map(|f: &ReconFinding| f.rule_id.clone())
            .collect()
    }

    #[test]
    fn finds_firebase_and_gcp_oauth_endpoints() {
        let blob: &[u8] = b"db = https://myapp-1234.firebaseio.com\nclient 123456789-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        assert!(ids.contains("DR-RECON-FIREBASE"), "{ids:?}");
        assert!(ids.contains("DR-RECON-GCP-OAUTH"), "{ids:?}");
    }

    #[test]
    fn finds_high_value_saas_and_ai_tokens() {
        let discord: String = format!(
            "https://discord.com/api/webhooks/{}/{}",
            "123456789012345678",
            "a".repeat(64)
        );
        let telegram: String = format!("{}{}{}", "123456789", ":A", "A".repeat(34));
        let sendgrid: String = format!("{}.{}.{}", "SG", "A".repeat(22), "B".repeat(43));
        let npm: String = format!(
            "{}{}",
            "npm",
            concat!("_", "abcdefghijklmnopqrstuvwxyz0123456789")
        );
        let shopify: String = format!(
            "{}{}",
            "shp",
            concat!("at_", "0123456789abcdef0123456789abcdef")
        );
        let text: String =
            format!("discord {discord} tg {telegram} sg {sendgrid} npm {npm} shop {shopify}");
        let report: ReconReport = report_bytes(text.as_bytes(), None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        for required in [
            "DR-RECON-DISCORD-WEBHOOK",
            "DR-RECON-TELEGRAM-BOT",
            "DR-RECON-SENDGRID",
            "DR-RECON-NPM-TOKEN",
            "DR-RECON-SHOPIFY-TOKEN",
        ] {
            assert!(ids.contains(required), "missing {required}: {ids:?}");
        }
        assert!(
            report
                .findings
                .iter()
                .filter(|f: &&ReconFinding| f.rule_id == "DR-RECON-SENDGRID")
                .all(|f: &ReconFinding| f.category == ReconCategory::Secret),
            "saas tokens must be categorized as secrets"
        );
    }

    #[test]
    fn finds_android_manifest_recon() {
        let blob: &[u8] = b"<manifest>\n\
            <activity android:name=\".Main\" android:exported=\"true\"/>\n\
            <intent-filter><data android:scheme=\"myapp\" android:host=\"open.example.com\"/></intent-filter>\n\
            <provider android:authorities=\"com.example.app.fileprovider\"/>\n\
            <uses-permission android:name=\"android.permission.READ_CONTACTS\"/>\n\
            </manifest>";
        let report: ReconReport =
            report_bytes(blob, Some("AndroidManifest.xml"), &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        for required in [
            "DR-RECON-MANIFEST-EXPORTED",
            "DR-RECON-MANIFEST-DEEPLINK",
            "DR-RECON-MANIFEST-DEEPLINK-HOST",
            "DR-RECON-MANIFEST-PROVIDER-AUTHORITY",
            "DR-RECON-MANIFEST-PERMISSION",
        ] {
            assert!(ids.contains(required), "missing {required}: {ids:?}");
        }
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.category == ReconCategory::Manifest),
        );
    }

    #[test]
    fn fingerprint_is_path_category_rule_value() {
        let report: ReconReport = report_bytes(
            format!("k {}", aws_akid()).as_bytes(),
            Some("a.smali"),
            &ReconConfig::default(),
        );
        let aws: &ReconFinding = report
            .findings
            .iter()
            .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
            .expect("aws finding");
        assert_eq!(
            fingerprint(aws),
            "a.smali|secret|DR-SEC-AWS-AKID|AKIA\u{2026}20"
        );
    }

    #[test]
    fn finds_onion_address() {
        let blob: &[u8] =
            b"c2 at expyuzz4wqqyqhjn.onion and v3 vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let onions: Vec<String> = values_in(&report, ReconCategory::Onion);
        assert!(
            onions.iter().any(|o: &String| o.contains(".onion")),
            "{onions:?}"
        );
        assert!(onions.len() >= 2, "both v2 and v3 onion: {onions:?}");
    }

    #[test]
    fn finds_modern_provider_secrets() {
        let gitlab: String = format!("{}{}", "glpat", concat!("-", "abcdefghij0123456789"));
        let digitalocean: String = format!("{}{}", "dop_v1_", "0".repeat(64));
        let huggingface: String = format!(
            "{}{}",
            "hf",
            concat!("_", "abcdefghijklmnopqrstuvwxyz01234567")
        );
        let newrelic: String = format!("{}{}", "NRAK", concat!("-", "ABCDEFGHIJKLMNOPQRSTUVWXY12"));
        let supabase: String = format!(
            "{}{}",
            "sb",
            concat!("_secret_", "abcdefghijklmnopqrstuvwx")
        );
        let vercel: String = format!(
            "{}{}",
            "vca",
            concat!("_", "abcdefghijklmnopqrstuvwxyz0123")
        );
        let linear: String = format!(
            "{}{}",
            "lin",
            concat!("_api_", "0123456789abcdef0123456789abcdef01234567")
        );
        let blob: String = format!(
            "gl={gitlab}\ndo={digitalocean}\nhf={huggingface}\nnr={newrelic}\nsb={supabase}\nvc={vercel}\nlin={linear}\n"
        );
        let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        for required in [
            "DR-RECON-GITLAB-PAT",
            "DR-RECON-DIGITALOCEAN",
            "DR-RECON-HUGGINGFACE",
            "DR-RECON-NEWRELIC",
            "DR-RECON-SUPABASE",
            "DR-RECON-VERCEL",
            "DR-RECON-LINEAR",
        ] {
            assert!(ids.contains(required), "missing {required}: {ids:?}");
        }
    }

    #[test]
    fn finds_fetch_axios_graphql_and_websocket_endpoints() {
        let blob: &[u8] = b"fetch(\"/api/v3/orders\")\n\
            axios.post('https://api.x.example.com/charge')\n\
            const ws = new WebSocket(\"wss://live.example.com/socket\")\n\
            query GetUserProfile { user { id } }\n";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        assert!(ids.contains("DR-RECON-FETCH-URL"), "{ids:?}");
        assert!(ids.contains("DR-RECON-WEBSOCKET"), "{ids:?}");
        assert!(ids.contains("DR-RECON-GRAPHQL-OP"), "{ids:?}");
        let ops: Vec<String> = report
            .findings
            .iter()
            .filter(|f: &&ReconFinding| f.rule_id == "DR-RECON-GRAPHQL-OP")
            .map(|f: &ReconFinding| f.value.clone())
            .collect();
        assert!(ops.contains(&"GetUserProfile".to_owned()), "{ops:?}");
    }

    #[test]
    fn relative_and_extensionless_paths_are_extracted() {
        let blob: &[u8] = b"load(\"../config/settings.json\"); go(\"./assets/main.js\"); call(\"v2/admin/users\")";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let endpoints: Vec<String> = values_in(&report, ReconCategory::Endpoint);
        assert!(
            endpoints
                .iter()
                .any(|e: &String| e.contains("../config/settings.json")),
            "relative ../ path: {endpoints:?}"
        );
        assert!(
            endpoints
                .iter()
                .any(|e: &String| e.contains("./assets/main.js")),
            "relative ./ path: {endpoints:?}"
        );
        assert!(
            endpoints
                .iter()
                .any(|e: &String| e.contains("v2/admin/users")),
            "rest path without leading slash: {endpoints:?}"
        );
    }

    #[test]
    fn finds_cloud_storage_buckets() {
        let blob: &[u8] = b"a https://my-app-uploads.s3.amazonaws.com/avatar.png \
                            b https://storage.googleapis.com/leaky-bucket/key \
                            c https://prodaccount.blob.core.windows.net/data";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        assert!(ids.contains("DR-RECON-S3-BUCKET"), "{ids:?}");
        assert!(ids.contains("DR-RECON-GCS-BUCKET"), "{ids:?}");
        assert!(ids.contains("DR-RECON-AZURE-BLOB"), "{ids:?}");
    }

    #[test]
    fn finds_slack_webhook_and_google_token() {
        let webhook: String = format!(
            "https://hooks.slack.com/services/{}/{}/{}",
            "T00000000", "B11111111", "abcdefghijklmnopqrstuvwx"
        );
        let google: String = format!("{}{}", "ya29", ".AbCdEf0123456789ghijkl");
        let text: String = format!("hook {webhook} token {google}");
        let blob: &[u8] = text.as_bytes();
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        assert!(ids.contains("DR-RECON-SLACK-WEBHOOK"), "{ids:?}");
        assert!(ids.contains("DR-RECON-GOOGLE-OAUTH-TOKEN"), "{ids:?}");
    }

    #[test]
    fn reuses_secret_scan_for_aws_and_github() {
        let github: String = format!(
            "{}{}",
            "ghp",
            concat!("_", "0123456789abcdefghijklmnopqrstuvwxyz")
        );
        let text: String = format!("aws {} gh {github}", aws_akid());
        let report: ReconReport = report_bytes(text.as_bytes(), None, &ReconConfig::default());
        let ids: BTreeSet<String> = rule_ids(&report);
        assert!(ids.contains("DR-SEC-AWS-AKID"), "{ids:?}");
        assert!(ids.contains("DR-SEC-GH-PAT"), "{ids:?}");
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.category == ReconCategory::Secret),
        );
    }

    #[test]
    fn extracts_uri_paths_as_endpoints() {
        let blob: &[u8] = b"const base = \"/api/v2/users/login\"; fetch(\"/internal/admin/keys\")";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        let endpoints: Vec<String> = values_in(&report, ReconCategory::Endpoint);
        assert!(
            endpoints.contains(&"/api/v2/users/login".to_owned()),
            "{endpoints:?}"
        );
        assert!(
            endpoints.contains(&"/internal/admin/keys".to_owned()),
            "{endpoints:?}"
        );
    }

    #[test]
    fn extracts_url_and_email_via_ioc() {
        let blob: &[u8] = b"see https://api.example.com/v1 and mail dev@corp.example.org";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        assert!(
            values_in(&report, ReconCategory::Url)
                .iter()
                .any(|u: &String| u.contains("api.example.com"))
        );
        assert!(
            values_in(&report, ReconCategory::Email).contains(&"dev@corp.example.org".to_owned())
        );
    }

    #[test]
    fn custom_pattern_matches_and_is_categorized() {
        let pat: CustomPattern = CustomPattern::compile("acme", r"ACME-[0-9]{6}").expect("compile");
        let config: ReconConfig = ReconConfig {
            custom: vec![pat],
            ..ReconConfig::default()
        };
        let report: ReconReport = report_bytes(b"token ACME-424242 here", None, &config);
        let custom: Vec<String> = values_in(&report, ReconCategory::Custom);
        assert_eq!(
            custom,
            vec!["ACME-424242".to_owned()],
            "{:?}",
            report.findings
        );
        assert!(rule_ids(&report).contains("DR-RECON-CUSTOM-ACME"));
    }

    #[test]
    fn bad_custom_pattern_errors_not_panics() {
        let err: ReconError = CustomPattern::compile("broken", r"(unclosed").unwrap_err();
        assert!(matches!(err, ReconError::BadPattern { .. }));
    }

    #[test]
    fn non_utf8_input_is_scanned_not_crashed() {
        let mut blob: Vec<u8> = vec![0x80, 0x81, 0xff, 0xfe];
        blob.extend_from_slice(format!(" {} ", aws_akid()).as_bytes());
        blob.extend_from_slice(&[0x90, 0xc0, 0xc1]);
        blob.extend_from_slice(b" https://evil.example.com/c2");
        let report: ReconReport = report_bytes(&blob, Some("classes.dex"), &ReconConfig::default());
        assert_eq!(report.non_utf8_files, 1, "non-utf8 must be flagged");
        assert!(
            rule_ids(&report).contains("DR-SEC-AWS-AKID"),
            "{:?}",
            report.findings
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.category == ReconCategory::Url),
            "url after invalid bytes must still be found: {:?}",
            report.findings
        );
    }

    #[test]
    fn findings_carry_one_based_line_and_column() {
        let blob: String = format!("line one\nline two {} tail", aws_akid());
        let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
        let aws: &ReconFinding = report
            .findings
            .iter()
            .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
            .expect("aws finding");
        assert_eq!(aws.line, 2, "{aws:?}");
        assert_eq!(aws.column, 10, "{aws:?}");
    }

    #[test]
    fn dedup_collapses_repeats_within_file() {
        let key: String = aws_akid();
        let blob: String = format!("{key} {key} {key}");
        let report: ReconReport =
            report_bytes(blob.as_bytes(), Some("a.txt"), &ReconConfig::default());
        let aws: usize = report
            .findings
            .iter()
            .filter(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
            .count();
        assert_eq!(aws, 1, "{:?}", report.findings);
    }

    #[test]
    fn suppress_substring_drops_false_positive() {
        let blob: &[u8] =
            b"db https://example.firebaseio.com other https://real-secret.firebaseio.com";
        let config: ReconConfig = ReconConfig {
            suppress_substrings: vec!["example.firebaseio.com".to_owned()],
            ..ReconConfig::default()
        };
        let report: ReconReport = report_bytes(blob, None, &config);
        let fb: Vec<String> = report
            .findings
            .iter()
            .filter(|f: &&ReconFinding| f.rule_id == "DR-RECON-FIREBASE")
            .map(|f: &ReconFinding| f.value.clone())
            .collect();
        assert!(
            fb.iter()
                .all(|v: &String| !v.contains("example.firebaseio.com")),
            "{fb:?}"
        );
        assert!(
            fb.iter().any(|v: &String| v.contains("real-secret")),
            "{fb:?}"
        );
    }

    #[test]
    fn entropy_findings_off_by_default_on_by_request() {
        let blob: &[u8] = b"k = dGhpc2lzYXZlcnlsb25nc2VjcmV0a2V5d2l0aGhpZ2hlbnRyb3B5MTIzNDU2Nzg5";
        let off: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        assert!(
            off.findings
                .iter()
                .all(|f: &ReconFinding| f.rule_id != "DR-SEC-ENTROPY")
        );
        let config: ReconConfig = ReconConfig {
            include_high_entropy: true,
            ..ReconConfig::default()
        };
        let on: ReconReport = report_bytes(blob, None, &config);
        assert!(
            on.findings
                .iter()
                .any(|f: &ReconFinding| f.rule_id == "DR-SEC-ENTROPY"),
            "{:?}",
            on.findings
        );
    }

    #[test]
    fn report_round_trips_json() {
        let report: ReconReport = report_bytes(
            format!("key {} url https://x.example.com/a", aws_akid()).as_bytes(),
            Some("a.bin"),
            &ReconConfig::default(),
        );
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(RECON_SCHEMA));
        let back: Vec<ReconFinding> =
            serde_json::from_value(value["findings"].clone()).expect("round trip");
        assert_eq!(back, report.findings);
    }

    #[test]
    fn password_in_url_detected() {
        let blob: &[u8] = b"conn = mysql://admin:hunter2pass@db.internal.example.com/app";
        let report: ReconReport = report_bytes(blob, None, &ReconConfig::default());
        assert!(
            rule_ids(&report).contains("DR-RECON-PASSWORD-IN-URL"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn clean_text_yields_no_findings() {
        let report: ReconReport = report_bytes(
            b"the quick brown fox jumps over thirteen lazy dogs",
            None,
            &ReconConfig::default(),
        );
        assert_eq!(report.total, 0, "false positives: {:?}", report.findings);
    }

    #[test]
    fn report_tree_skips_oversized_file() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-recon-oversized").expect("mkdir");
        let root: PathBuf = scratch.path().to_path_buf();
        let path: PathBuf = root.join("huge.bin");
        let file: std::fs::File = std::fs::File::create(&path).expect("create");
        file.set_len(MAX_FILE_BYTES + 1).expect("set len");
        let report: ReconReport = report_tree(&root, &ReconConfig::default()).expect("scan");
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.bytes_scanned, 0);
    }

    #[test]
    fn read_scan_file_oversized_file_is_policy_skip() {
        let (scratch, file): (crate::scratch::ScratchFile, std::fs::File) =
            crate::scratch::ScratchFile::create("disrobe-recon-oversized-direct", "")
                .expect("create");
        let path: PathBuf = scratch.path().to_path_buf();
        file.set_len(MAX_FILE_BYTES + 1).expect("set len");
        drop(file);
        let bytes: Option<Vec<u8>> = read_scan_file(&path);
        assert!(bytes.is_none());
    }

    #[test]
    fn walk_with_limit_stops_inside_large_directory() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-recon-walk-limit").expect("mkdir");
        let root: PathBuf = scratch.path().to_path_buf();
        for i in 0..3usize {
            std::fs::write(root.join(format!("{i}.txt")), b"x").expect("write");
        }
        let mut files: Vec<PathBuf> = Vec::new();
        walk_with_limit(&root, &mut files, 2).expect("walk");
        assert_eq!(files.len(), 2);
    }

    fn b64_standard(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn build_tar_gz(inner_name: &str, inner: &[u8]) -> Vec<u8> {
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut builder: tar::Builder<&mut Vec<u8>> = tar::Builder::new(&mut tar_bytes);
            let mut header: tar::Header = tar::Header::new_gnu();
            header.set_size(inner.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, inner_name, inner)
                .expect("append tar entry");
            builder.finish().expect("finish tar");
        }
        let mut gz: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar_bytes).expect("gz write");
        gz.finish().expect("gz finish")
    }

    fn build_zip(inner_name: &str, inner: &[u8]) -> Vec<u8> {
        let mut cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        {
            let mut writer: zip::ZipWriter<&mut std::io::Cursor<Vec<u8>>> =
                zip::ZipWriter::new(&mut cursor);
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file(inner_name, options).expect("start_file");
            std::io::Write::write_all(&mut writer, inner).expect("zip write");
            writer.finish().expect("zip finish");
        }
        cursor.into_inner()
    }

    #[test]
    fn tar_gz_archive_secret_is_detected() {
        let key: String = aws_akid();
        let inner: String = format!("AWS_ACCESS_KEY_ID={key}\n");
        let archive: Vec<u8> = build_tar_gz("config/secret.env", inner.as_bytes());
        assert!(is_gzip_magic(&archive), "fixture must be a gzip stream");
        let report: ReconReport =
            report_bytes(&archive, Some("bundle.tgz"), &ReconConfig::default());
        let aws: Option<&ReconFinding> = report
            .findings
            .iter()
            .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID");
        let _aws: &ReconFinding = aws
            .unwrap_or_else(|| panic!("tar.gz inner secret must be found: {:?}", report.findings));
        assert!(
            report.findings.iter().any(|f: &ReconFinding| {
                f.rule_id == "DR-SEC-AWS-AKID"
                    && f.path
                        .as_deref()
                        .is_some_and(|p: &str| p.contains("secret.env"))
            }),
            "tar extraction must attribute a finding to the inner path: {:?}",
            report.findings
        );
    }

    #[test]
    fn zip_detected_by_magic_despite_wrong_extension() {
        let key: String = aws_akid();
        let inner: String = format!("key {key}\n");
        let archive: Vec<u8> = build_zip("inner.txt", inner.as_bytes());
        assert!(is_zip_container(&archive), "fixture must be a zip");
        let report: ReconReport =
            report_bytes(&archive, Some("payload.dat"), &ReconConfig::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.rule_id == "DR-SEC-AWS-AKID"
                    && f.path.as_deref() == Some("payload.dat!inner.txt")),
            "magic-sniffed zip with a non-zip extension must still be opened: {:?}",
            report.findings
        );
    }

    #[test]
    fn bounded_archive_reader_rejects_over_cap() {
        let data: &[u8] = b"abcd";
        assert!(read_archive_member(std::io::Cursor::new(data), 4, 3).is_none());
    }

    #[test]
    fn base64_embedded_secret_is_decoded_and_detected() {
        let key: String = aws_akid();
        let plaintext: String = format!("AWS_ACCESS_KEY_ID={key}");
        let encoded: String = b64_standard(plaintext.as_bytes());
        let blob: String = format!("payload = \"{encoded}\"");
        let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.rule_id == "DR-SEC-AWS-AKID"),
            "base64-wrapped secret must be decoded and found: {:?}",
            report.findings
        );
    }

    #[test]
    fn base64_decoded_bound_is_conservative() {
        assert_eq!(base64_decoded_upper_bound_len(0), Some(0));
        assert_eq!(base64_decoded_upper_bound_len(1), Some(3));
        assert_eq!(base64_decoded_upper_bound_len(4), Some(3));
        assert_eq!(base64_decoded_upper_bound_len(5), Some(6));
        assert_eq!(base64_decoded_upper_bound_len(usize::MAX), None);
    }

    #[test]
    fn base64_decode_skips_runs_over_decode_budget() {
        let encoded_len: usize = ((MAX_BASE64_DECODED_TOTAL / 3) + 1) * 4;
        let encoded: String = "A".repeat(encoded_len);
        let found: Vec<ReconFinding> =
            base64_decode_findings(encoded.as_bytes(), None, &ReconConfig::default(), 0);
        assert!(found.is_empty());
    }

    #[test]
    fn base64_decode_depth_is_capped() {
        let key: String = aws_akid();
        let mut layered: String = format!("AWS_ACCESS_KEY_ID={key}");
        for _ in 0..(MAX_BASE64_DEPTH + 3) {
            layered = b64_standard(layered.as_bytes());
        }
        let extra: Vec<ReconFinding> =
            base64_decode_findings(layered.as_bytes(), None, &ReconConfig::default(), 0);
        assert!(
            extra
                .iter()
                .all(|f: &ReconFinding| f.rule_id != "DR-SEC-AWS-AKID"),
            "a key buried below the depth cap must not be reached: {extra:?}"
        );
        let mut shallow: String = format!("AWS_ACCESS_KEY_ID={key}");
        for _ in 0..2 {
            shallow = b64_standard(shallow.as_bytes());
        }
        let found: Vec<ReconFinding> =
            base64_decode_findings(shallow.as_bytes(), None, &ReconConfig::default(), 0);
        assert!(
            found
                .iter()
                .any(|f: &ReconFinding| f.rule_id == "DR-SEC-AWS-AKID"),
            "a key within the depth cap must be reached: {found:?}"
        );
    }

    #[test]
    fn pem_full_body_captured_and_validated() {
        let body: String = b64_standard(&[0x30, 0x82, 0x01, 0x22, 0x02, 0x01, 0x00].repeat(40));
        let wrapped: String = body
            .as_bytes()
            .chunks(64)
            .map(|c: &[u8]| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<String>>()
            .join("\n");
        let pem: String =
            format!("-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----\n");
        let findings: Vec<secret_scan::Finding> = secret_scan::scan_bytes(pem.as_bytes(), None);
        let pem_hit: Option<&secret_scan::Finding> = findings
            .iter()
            .find(|f: &&secret_scan::Finding| f.code == "DR-SEC-PEM-PRIV");
        let pem_hit: &secret_scan::Finding =
            pem_hit.unwrap_or_else(|| panic!("PEM private key must be found: {findings:?}"));
        assert_eq!(
            pem_hit.validation,
            Some(secret_scan::Confidence::Confirmed),
            "valid base64 body must validate as confirmed: {pem_hit:?}"
        );
        let block_len: usize = pem.trim_end().len();
        assert!(
            pem_hit.redacted_preview.ends_with(&block_len.to_string()),
            "preview must report the full block length {block_len}: {pem_hit:?}"
        );
        assert!(
            block_len > 256,
            "full multi-line body must be captured, not just the prefix: {block_len}"
        );
    }

    #[test]
    fn pem_invalid_base64_body_is_speculative() {
        let pem: &[u8] =
            b"-----BEGIN PRIVATE KEY-----\nnot valid base64 @@@@\n-----END PRIVATE KEY-----\n";
        let findings: Vec<secret_scan::Finding> = secret_scan::scan_bytes(pem, None);
        let pem_hit: &secret_scan::Finding = findings
            .iter()
            .find(|f: &&secret_scan::Finding| f.code == "DR-SEC-PEM-PRIV")
            .unwrap_or_else(|| panic!("private-key block still reported: {findings:?}"));
        assert_eq!(
            pem_hit.validation,
            Some(secret_scan::Confidence::Speculative)
        );
    }

    fn encode_codec(scheme: codec::Scheme, plain: &[u8]) -> String {
        use codec::alphabets::{
            Base58Variant, base45_encode, base58_encode, base62_encode, base91_encode,
            base92_encode,
        };
        use codec::framed::{ascii85_encode, uuencode, xxencode};
        use codec::web_escape::percent_encode;
        match scheme {
            codec::Scheme::Base58Bitcoin => base58_encode(plain, Base58Variant::Bitcoin),
            codec::Scheme::Base58Ripple => base58_encode(plain, Base58Variant::Ripple),
            codec::Scheme::Base62 => base62_encode(plain),
            codec::Scheme::Base45 => base45_encode(plain),
            codec::Scheme::Base91 => base91_encode(plain),
            codec::Scheme::Base92 => base92_encode(plain),
            codec::Scheme::Ascii85 => ascii85_encode(plain),
            codec::Scheme::UuEncode => uuencode(plain, "p.bin"),
            codec::Scheme::XxEncode => xxencode(plain, "p.bin"),
            codec::Scheme::PercentUrl => percent_encode(plain),
            other => panic!("no encoder fixture for {other:?}"),
        }
    }

    const FIXTURE_SCHEMES: &[codec::Scheme] = &[
        codec::Scheme::Base58Bitcoin,
        codec::Scheme::Base58Ripple,
        codec::Scheme::Base62,
        codec::Scheme::Base91,
        codec::Scheme::Base92,
        codec::Scheme::Ascii85,
        codec::Scheme::UuEncode,
        codec::Scheme::XxEncode,
        codec::Scheme::PercentUrl,
    ];

    #[test]
    fn every_codec_single_layer_recovers_url_ioc() {
        let plain: &[u8] = b"reach http://c2.codec-layer.example.com/gate.php now";
        for &scheme in FIXTURE_SCHEMES {
            let encoded: String = encode_codec(scheme, plain);
            let blob: String = format!("payload\n{encoded}\n");
            let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
            assert!(
                values_in(&report, ReconCategory::Url)
                    .iter()
                    .any(|u: &String| u.contains("c2.codec-layer.example.com")),
                "{:?} layer did not recover the URL: {:?}",
                scheme,
                report.findings
            );
        }
    }

    #[test]
    fn codec_layer_recovers_ipv4_and_aws_key() {
        let aws: String = aws_akid();
        let plain: String = format!("ip 203.0.113.77 key {aws} done");
        for &scheme in &[
            codec::Scheme::Base91,
            codec::Scheme::Ascii85,
            codec::Scheme::Base62,
            codec::Scheme::PercentUrl,
        ] {
            let encoded: String = encode_codec(scheme, plain.as_bytes());
            let blob: String = format!("blob {encoded}");
            let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
            assert!(
                values_in(&report, ReconCategory::Ipv4).contains(&"203.0.113.77".to_owned()),
                "{scheme:?} layer did not recover the IP: {:?}",
                report.findings
            );
            assert!(
                rule_ids(&report).contains("DR-SEC-AWS-AKID"),
                "{scheme:?} layer did not recover the AWS key: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn nested_two_layer_codec_stack_is_peeled() {
        let plain: &[u8] = b"call https://deep.nest.example.org/beacon now";
        let inner: String = encode_codec(codec::Scheme::Base91, plain);
        let outer: String = encode_codec(codec::Scheme::Ascii85, inner.as_bytes());
        let blob: String = format!("data {outer}");
        let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
        assert!(
            values_in(&report, ReconCategory::Url)
                .iter()
                .any(|u: &String| u.contains("deep.nest.example.org")),
            "two-layer ascii85(base91(url)) not peeled: {:?}",
            report.findings
        );
    }

    #[test]
    fn nested_three_layer_codec_stack_is_peeled() {
        let plain: &[u8] = b"c2 http://triple.layer.example.net/x within depth bound";
        let l1: String = encode_codec(codec::Scheme::Base62, plain);
        let l2: String = encode_codec(codec::Scheme::Base91, l1.as_bytes());
        let l3: String = encode_codec(codec::Scheme::Ascii85, l2.as_bytes());
        let blob: String = format!("p {l3}");
        let report: ReconReport = report_bytes(blob.as_bytes(), None, &ReconConfig::default());
        assert!(
            values_in(&report, ReconCategory::Url)
                .iter()
                .any(|u: &String| u.contains("triple.layer.example.net")),
            "three-layer codec stack not peeled: {:?}",
            report.findings
        );
    }

    #[test]
    fn codec_recursion_depth_is_bounded() {
        let plain: &[u8] = b"http://buried.below.depth.example.com/deep";
        let mut layered: String = encode_codec(codec::Scheme::Base91, plain);
        for _ in 0..(MAX_CODEC_DEPTH + 3) {
            layered = encode_codec(codec::Scheme::Base91, layered.as_bytes());
        }
        let mut total: usize = 0;
        let extra: Vec<ReconFinding> = codec_cascade_findings(
            layered.as_bytes(),
            None,
            &ReconConfig::default(),
            0,
            &mut total,
        );
        assert!(
            extra
                .iter()
                .all(|f: &ReconFinding| !f.value.contains("buried.below.depth.example.com")),
            "a url buried below the codec depth cap must not be reached: {extra:?}"
        );
    }

    #[test]
    fn random_bytes_do_not_falsely_decode_into_findings() {
        let noise: Vec<u8> = (0u32..4096)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .filter(u8::is_ascii_graphic)
            .collect();
        let mut total: usize = 0;
        let findings: Vec<ReconFinding> =
            codec_cascade_findings(&noise, None, &ReconConfig::default(), 0, &mut total);
        assert!(
            findings
                .iter()
                .all(|f: &ReconFinding| f.category != ReconCategory::Url
                    && f.category != ReconCategory::Email
                    && f.category != ReconCategory::Secret),
            "random bytes produced spurious decoded IOCs: {findings:?}"
        );
    }

    #[test]
    fn codec_decoded_indicators_are_tagged_in_ioc_layer() {
        let plain: &[u8] = b"visit http://tagged.codec.example.com/p";
        let encoded: String = encode_codec(codec::Scheme::Base91, plain);
        let indicators: Vec<ioc::Indicator> = ioc::extract(encoded.as_bytes());
        assert!(
            indicators.iter().any(|i: &ioc::Indicator| {
                i.kind == IocKind::Url
                    && i.encoding == ioc::Encoding::Codec
                    && i.value.contains("tagged.codec.example.com")
            }),
            "codec-decoded url must carry the codec encoding tag: {indicators:?}"
        );
    }
}
