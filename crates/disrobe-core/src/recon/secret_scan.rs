use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AwsAccessKeyId,
    AwsSecretAccessKey,
    BasicAuthHeader,
    GcpApiKey,
    GcpServiceAccountKey,
    AzureStorageKey,
    GithubPat,
    GithubFineGrainedPat,
    GithubOauth,
    GithubAppToken,
    StripeLiveSecret,
    StripeLivePublishable,
    StripeRestricted,
    StripeTest,
    SlackToken,
    TwilioAccountSid,
    TwilioApiKey,
    Jwt,
    PemPrivateKey,
    SshPublicKey,
    AwsBedrock,
    AzureAdClientSecret,
    AlibabaAccessKey,
    AtlassianToken,
    OnePasswordServiceAccount,
    AgeSecretKey,
    AirtableToken,
    CloudflareOriginCa,
    DatabricksToken,
    DynatraceToken,
    DopplerToken,
    DropboxToken,
    FlyIoToken,
    PostmanKey,
    GrafanaToken,
    RubyGemsKey,
    PlanetScaleToken,
    TailscaleKey,
    SentryDsn,
    SnykToken,
    TwitterBearer,
    MongoDbUri,
    PostgresUri,
    RedisUri,
    AmqpUri,
    AnthropicOauth,
    GroqApiKey,
    XaiApiKey,
    PineconeKey,
    LangSmithKey,
    ZhipuApiKey,
    WandbApiKey,
    TavilyKey,
    CastAiKey,
    NewRelicLicenseKey,
    NewRelicBrowserKey,
    TencentCloudSecretId,
    DuoIntegrationKey,
    PersonaKey,
    DockerSwarmJoinToken,
    AzureSasToken,
    AzureAppConfigConnection,
    SolanaKeypair,
    GiteaPat,
    RailsMasterKey,
    VaultServiceToken,
    VaultBatchToken,
    GitLabRunnerToken,
    FrameIoToken,
    ClojarsToken,
    ConfluentToken,
    ContentfulToken,
    FastlyToken,
    JfrogToken,
    MessageBirdToken,
    OktaToken,
    PlaidToken,
    PrefectToken,
    ScalingoToken,
    SumoLogicToken,
    TwitterApiKey,
    ZendeskToken,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Probable,
    Speculative,
}

impl Confidence {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Probable => "probable",
            Self::Speculative => "speculative",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<Confidence>,
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

fn keyword_context_pattern(keyword: &str, body: &str) -> String {
    format!(
        r#"(?i)[\w.-]{{0,50}}?(?:{keyword})(?:[ \t\w.-]{{0,20}})[\s'"]{{0,3}}(?:=|>|:{{1,3}}=|\|\||:|=>|\?=|,)[\x60'"\s=]{{0,5}}({body})(?:[\x60'"\s;]|\\[nr]|$)"#
    )
}

struct ContextSpec {
    kind: SecretKind,
    code: &'static str,
    severity: Severity,
    keyword: &'static str,
    body: &'static str,
}

const CONTEXT_SPECS: &[ContextSpec] = &[
    ContextSpec {
        kind: SecretKind::ConfluentToken,
        code: "DR-SEC-CONFLUENT",
        severity: Severity::Error,
        keyword: "confluent",
        body: "[a-z0-9]{16}",
    },
    ContextSpec {
        kind: SecretKind::ContentfulToken,
        code: "DR-SEC-CONTENTFUL",
        severity: Severity::Error,
        keyword: "contentful",
        body: r"[a-z0-9=_\-]{43}",
    },
    ContextSpec {
        kind: SecretKind::FastlyToken,
        code: "DR-SEC-FASTLY",
        severity: Severity::Error,
        keyword: "fastly",
        body: r"[a-z0-9=_\-]{32}",
    },
    ContextSpec {
        kind: SecretKind::JfrogToken,
        code: "DR-SEC-JFROG",
        severity: Severity::Error,
        keyword: "jfrog|artifactory|bintray|xray",
        body: "(?:[a-z0-9]{73}|[a-z0-9]{64})",
    },
    ContextSpec {
        kind: SecretKind::MessageBirdToken,
        code: "DR-SEC-MESSAGEBIRD",
        severity: Severity::Error,
        keyword: "message[_-]?bird",
        body: "[a-z0-9]{25}",
    },
    ContextSpec {
        kind: SecretKind::OktaToken,
        code: "DR-SEC-OKTA",
        severity: Severity::Error,
        keyword: "okta",
        body: r"00[\w=\-]{40}",
    },
    ContextSpec {
        kind: SecretKind::PlaidToken,
        code: "DR-SEC-PLAID",
        severity: Severity::Error,
        keyword: "plaid",
        body: "access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    },
    ContextSpec {
        kind: SecretKind::SumoLogicToken,
        code: "DR-SEC-SUMOLOGIC",
        severity: Severity::Error,
        keyword: "sumo",
        body: "[a-z0-9]{64}",
    },
    ContextSpec {
        kind: SecretKind::TwitterApiKey,
        code: "DR-SEC-TWITTER-APIKEY",
        severity: Severity::Warning,
        keyword: "twitter",
        body: "[a-z0-9]{25}",
    },
    ContextSpec {
        kind: SecretKind::ZendeskToken,
        code: "DR-SEC-ZENDESK",
        severity: Severity::Error,
        keyword: "zendesk",
        body: "[a-z0-9]{40}",
    },
];

#[allow(clippy::expect_used)]
static REGEX_RULES: LazyLock<Vec<RegexRule>> = LazyLock::new(|| {
    let specs: [(SecretKind, &'static str, Severity, &'static str); 69] = [
        (
            SecretKind::AwsAccessKeyId,
            "DR-SEC-AWS-AKID",
            Severity::Error,
            r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|A3T[0-9A-Z])[0-9A-Z]{16}\b",
        ),
        (
            SecretKind::AwsSecretAccessKey,
            "DR-SEC-AWS-SECRET",
            Severity::Error,
            r#"(?i)aws[_.-]?(?:secret|sak)[_.-]?(?:access[_.-]?)?key["' :=]{1,8}([0-9A-Za-z/+]{40})\b"#,
        ),
        (
            SecretKind::BasicAuthHeader,
            "DR-SEC-BASIC-AUTH",
            Severity::Warning,
            r"(?i)\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}",
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
        (
            SecretKind::StripeRestricted,
            "DR-SEC-STRIPE-RK",
            Severity::Error,
            r"\brk_live_[0-9A-Za-z]{24,}\b",
        ),
        (
            SecretKind::StripeTest,
            "DR-SEC-STRIPE-TEST",
            Severity::Note,
            r"\b(?:sk|pk|rk)_test_[0-9A-Za-z]{24,}\b",
        ),
        (
            SecretKind::AwsBedrock,
            "DR-SEC-AWS-BEDROCK",
            Severity::Error,
            r"\bABSK[0-9A-Za-z+/]{40,}\b",
        ),
        (
            SecretKind::AzureAdClientSecret,
            "DR-SEC-AZURE-AD",
            Severity::Error,
            r"\b[A-Za-z0-9_~.]{3}(?:8Q~|7Q~|dQ~)[A-Za-z0-9_~.]{31,34}\b",
        ),
        (
            SecretKind::AlibabaAccessKey,
            "DR-SEC-ALIBABA",
            Severity::Error,
            r"\bLTAI[A-Za-z0-9]{20}\b",
        ),
        (
            SecretKind::AtlassianToken,
            "DR-SEC-ATLASSIAN",
            Severity::Error,
            r"\b(?:ATATT3|ATCTT3)[A-Za-z0-9_=.\-]{186}\b",
        ),
        (
            SecretKind::OnePasswordServiceAccount,
            "DR-SEC-1PASSWORD-SA",
            Severity::Error,
            r"\bops_eyJ[A-Za-z0-9+/=]{250,}",
        ),
        (
            SecretKind::AgeSecretKey,
            "DR-SEC-AGE",
            Severity::Error,
            r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b",
        ),
        (
            SecretKind::AirtableToken,
            "DR-SEC-AIRTABLE",
            Severity::Error,
            r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b",
        ),
        (
            SecretKind::CloudflareOriginCa,
            "DR-SEC-CLOUDFLARE-CA",
            Severity::Error,
            r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b",
        ),
        (
            SecretKind::DatabricksToken,
            "DR-SEC-DATABRICKS",
            Severity::Error,
            r"\bdapi[a-f0-9]{32}\b",
        ),
        (
            SecretKind::DynatraceToken,
            "DR-SEC-DYNATRACE",
            Severity::Error,
            r"\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b",
        ),
        (
            SecretKind::DopplerToken,
            "DR-SEC-DOPPLER",
            Severity::Error,
            r"\bdp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,44}\b",
        ),
        (
            SecretKind::DropboxToken,
            "DR-SEC-DROPBOX",
            Severity::Error,
            r"\bsl\.[A-Za-z0-9_-]{130,}",
        ),
        (
            SecretKind::FlyIoToken,
            "DR-SEC-FLYIO",
            Severity::Error,
            r"\b(?:fm1|fm2|fo1)[_.][A-Za-z0-9]{30,}",
        ),
        (
            SecretKind::PostmanKey,
            "DR-SEC-POSTMAN",
            Severity::Error,
            r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
        ),
        (
            SecretKind::GrafanaToken,
            "DR-SEC-GRAFANA",
            Severity::Error,
            r"\bgl(?:c|sa)_[A-Za-z0-9]{32,}\b",
        ),
        (
            SecretKind::RubyGemsKey,
            "DR-SEC-RUBYGEMS",
            Severity::Error,
            r"\brubygems_[a-f0-9]{48}\b",
        ),
        (
            SecretKind::PlanetScaleToken,
            "DR-SEC-PLANETSCALE",
            Severity::Error,
            r"\bpscale_tkn_[A-Za-z0-9_]{32,}",
        ),
        (
            SecretKind::TailscaleKey,
            "DR-SEC-TAILSCALE",
            Severity::Error,
            r"\btskey-(?:auth|api)-[A-Za-z0-9]{40,}",
        ),
        (
            SecretKind::SentryDsn,
            "DR-SEC-SENTRY-DSN",
            Severity::Warning,
            r"\bhttps://[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/[0-9]+\b",
        ),
        (
            SecretKind::SnykToken,
            "DR-SEC-SNYK",
            Severity::Error,
            r"\bsnyk_[a-z0-9-]{36}\b",
        ),
        (
            SecretKind::TwitterBearer,
            "DR-SEC-TWITTER-BEARER",
            Severity::Warning,
            r"\bAAAAAAAAAA[A-Za-z0-9%]{60,}",
        ),
        (
            SecretKind::MongoDbUri,
            "DR-SEC-MONGODB-URI",
            Severity::Error,
            r"\bmongodb(?:\+srv)?://[^\s:@/]{1,128}:[^\s:@/]{1,128}@[^\s/]{1,256}",
        ),
        (
            SecretKind::PostgresUri,
            "DR-SEC-POSTGRES-URI",
            Severity::Error,
            r"\bpostgres(?:ql)?://[^\s:@/]{1,128}:[^\s:@/]{1,128}@[^\s/]{1,256}",
        ),
        (
            SecretKind::RedisUri,
            "DR-SEC-REDIS-URI",
            Severity::Error,
            r"\bredis(?:s)?://[^\s:@/]{0,128}:[^\s:@/]{1,128}@[^\s/]{1,256}",
        ),
        (
            SecretKind::AmqpUri,
            "DR-SEC-AMQP-URI",
            Severity::Error,
            r"\bamqps?://[^\s:@/]{1,128}:[^\s:@/]{1,128}@[^\s/]{1,256}",
        ),
        (
            SecretKind::AnthropicOauth,
            "DR-SEC-ANTHROPIC-OAUTH",
            Severity::Error,
            r"\bsk-ant-o(?:at|rt)01-[A-Za-z0-9_-]{80,}\b",
        ),
        (
            SecretKind::GroqApiKey,
            "DR-SEC-GROQ",
            Severity::Error,
            r"\bgsk_[A-Za-z0-9]{52}\b",
        ),
        (
            SecretKind::XaiApiKey,
            "DR-SEC-XAI",
            Severity::Error,
            r"\bxai-[A-Za-z0-9]{80}\b",
        ),
        (
            SecretKind::PineconeKey,
            "DR-SEC-PINECONE",
            Severity::Error,
            r"\bpcsk_[A-Za-z0-9]{7,}_[A-Za-z0-9]{30,}\b",
        ),
        (
            SecretKind::LangSmithKey,
            "DR-SEC-LANGSMITH",
            Severity::Error,
            r"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b",
        ),
        (
            SecretKind::ZhipuApiKey,
            "DR-SEC-ZHIPU",
            Severity::Error,
            r"\b[0-9a-f]{32}\.[A-Za-z0-9]{16}\b",
        ),
        (
            SecretKind::WandbApiKey,
            "DR-SEC-WANDB",
            Severity::Error,
            r#"(?i)wandb[_.-]?(?:api[_.-]?)?key["' :=]{1,8}([0-9a-f]{40})\b"#,
        ),
        (
            SecretKind::TavilyKey,
            "DR-SEC-TAVILY",
            Severity::Error,
            r"\btvly-(?:dev-|prod-)?[A-Za-z0-9]{32}\b",
        ),
        (
            SecretKind::CastAiKey,
            "DR-SEC-CASTAI",
            Severity::Error,
            r#"(?i)cast[_.-]?ai[_.-]?(?:api[_.-]?)?key["' :=]{1,8}([0-9a-f]{64})\b"#,
        ),
        (
            SecretKind::NewRelicLicenseKey,
            "DR-SEC-NEWRELIC-LIC",
            Severity::Error,
            r"\b[a-f0-9]{36}(?:NRAL|FFFFNRAL)\b",
        ),
        (
            SecretKind::NewRelicBrowserKey,
            "DR-SEC-NEWRELIC-BROWSER",
            Severity::Warning,
            r"\bNRJS-[a-f0-9]{19}\b",
        ),
        (
            SecretKind::TencentCloudSecretId,
            "DR-SEC-TENCENT-AKID",
            Severity::Error,
            r"\bAKID[A-Za-z0-9]{32,40}\b",
        ),
        (
            SecretKind::DuoIntegrationKey,
            "DR-SEC-DUO-IKEY",
            Severity::Warning,
            r"\bDI[A-Z0-9]{18}\b",
        ),
        (
            SecretKind::PersonaKey,
            "DR-SEC-PERSONA",
            Severity::Error,
            r"\bpersona_(?:production|sandbox)_[A-Za-z0-9]{32,}\b",
        ),
        (
            SecretKind::DockerSwarmJoinToken,
            "DR-SEC-DOCKER-SWMTKN",
            Severity::Error,
            r"\bSWMTKN-1-[a-z0-9]{40,}-[a-z0-9]{25}\b",
        ),
        (
            SecretKind::AzureSasToken,
            "DR-SEC-AZURE-SAS",
            Severity::Error,
            r"\bsv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&[^\s]*\bsig=[A-Za-z0-9%]{44,}",
        ),
        (
            SecretKind::AzureAppConfigConnection,
            "DR-SEC-AZURE-APPCONFIG",
            Severity::Error,
            r"Endpoint=https://[a-z0-9-]+\.azconfig\.io;Id=[A-Za-z0-9+/=:-]+;Secret=[A-Za-z0-9+/]{40,}={0,2}",
        ),
        (
            SecretKind::GiteaPat,
            "DR-SEC-GITEA-PAT",
            Severity::Error,
            r#"(?i)(?:gitea|codeberg|forgejo)[_.-]?(?:api[_.-]?)?(?:token|pat|key)["' :=]{1,8}([a-f0-9]{40})\b"#,
        ),
        (
            SecretKind::RailsMasterKey,
            "DR-SEC-RAILS-MASTER",
            Severity::Error,
            r#"(?i)(?:RAILS_MASTER_KEY|master[_.-]?key)["' :=]{1,8}([a-f0-9]{32})\b"#,
        ),
        (
            SecretKind::VaultServiceToken,
            "DR-SEC-VAULT-SVC",
            Severity::Error,
            r"\bhvs\.[A-Za-z0-9_-]{90,120}\b",
        ),
        (
            SecretKind::VaultBatchToken,
            "DR-SEC-VAULT-BATCH",
            Severity::Error,
            r"\bhvb\.[A-Za-z0-9_-]{138,212}\b",
        ),
        (
            SecretKind::GitLabRunnerToken,
            "DR-SEC-GITLAB-RUNNER",
            Severity::Error,
            r"\bGR1348941[0-9A-Za-z_-]{20}\b",
        ),
        (
            SecretKind::FrameIoToken,
            "DR-SEC-FRAMEIO",
            Severity::Error,
            r"\bfio-u-[A-Za-z0-9_=-]{64}\b",
        ),
        (
            SecretKind::ClojarsToken,
            "DR-SEC-CLOJARS",
            Severity::Error,
            r"\bCLOJARS_[a-zA-Z0-9]{60}\b",
        ),
        (
            SecretKind::PrefectToken,
            "DR-SEC-PREFECT",
            Severity::Error,
            r"\bpnu_[a-zA-Z0-9]{36}\b",
        ),
        (
            SecretKind::ScalingoToken,
            "DR-SEC-SCALINGO",
            Severity::Error,
            r"\btk-us-[a-zA-Z0-9_-]{48}\b",
        ),
    ];
    let mut rules: Vec<RegexRule> = specs
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
        .collect();
    for spec in CONTEXT_SPECS {
        rules.push(RegexRule {
            kind: spec.kind,
            code: spec.code,
            severity: spec.severity,
            pattern: Regex::new(&keyword_context_pattern(spec.keyword, spec.body))
                .expect("DR-SEC-0002: static keyword-context pattern must compile"),
        });
    }
    rules
});

static PREFIX_RULES: LazyLock<Vec<PrefixRule>> = LazyLock::new(|| {
    vec![PrefixRule {
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
    }]
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

#[must_use]
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
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
        validation: None,
    }
}

const ALLOWLIST_EXACT: &[&str] = &["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"];

const ALLOWLIST_SUBSTRINGS: &[&str] = &[
    "your-key-here",
    "your_api_key",
    "yourapikey",
    "xxxxxxxxxxxx",
    "0000000000000000",
    "111111111111",
    "placeholder",
    "deadbeefdeadbeef",
    "examplekey",
    "example_key",
    "dummytoken",
    "dummy_token",
    "changeme",
    "notarealkey",
];

#[inline]
fn is_allowlisted(matched: &str) -> bool {
    if ALLOWLIST_EXACT.contains(&matched) {
        return true;
    }
    let lower: String = matched.to_ascii_lowercase();
    ALLOWLIST_SUBSTRINGS
        .iter()
        .any(|s: &&str| lower.contains(s))
}

#[inline]
fn base32_decode_rfc4648(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 5 / 8 + 1);
    for ch in s.bytes() {
        if ch == b'=' {
            break;
        }
        let val: u32 = ALPHABET.iter().position(|&a: &u8| a == ch)? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Offline structural verification of a candidate secret.
///
/// No network is used: the check decodes the token's own embedded structure (AWS
/// account-id base32 payload, JWT base64url header) or applies a format
/// constraint, returning the confidence that the value is a real credential.
#[must_use]
pub fn validate(kind: SecretKind, value: &str) -> Confidence {
    if is_allowlisted(value) {
        return Confidence::Speculative;
    }
    match kind {
        SecretKind::AwsAccessKeyId => validate_aws_akid(value),
        SecretKind::Jwt => validate_jwt(value),
        SecretKind::StripeTest => Confidence::Speculative,
        SecretKind::GroqApiKey => validate_fixed_alnum(value, "gsk_", 52),
        SecretKind::XaiApiKey => validate_fixed_alnum(value, "xai-", 80),
        SecretKind::NewRelicLicenseKey => validate_newrelic_license(value),
        SecretKind::AnthropicOauth => validate_anthropic_oauth(value),
        SecretKind::SolanaKeypair => Confidence::Confirmed,
        _ => Confidence::Probable,
    }
}

fn validate_fixed_alnum(value: &str, prefix: &str, body_len: usize) -> Confidence {
    let Some(body): Option<&str> = value.strip_prefix(prefix) else {
        return Confidence::Speculative;
    };
    if body.len() == body_len && body.bytes().all(|b: u8| b.is_ascii_alphanumeric()) {
        Confidence::Confirmed
    } else {
        Confidence::Speculative
    }
}

fn validate_newrelic_license(value: &str) -> Confidence {
    let Some(prefix): Option<&str> = value.strip_suffix("NRAL") else {
        return Confidence::Speculative;
    };
    if prefix.len() == 36 && prefix.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        Confidence::Confirmed
    } else {
        Confidence::Speculative
    }
}

fn validate_anthropic_oauth(value: &str) -> Confidence {
    let stripped: Option<&str> = value
        .strip_prefix("sk-ant-oat01-")
        .or_else(|| value.strip_prefix("sk-ant-ort01-"));
    let Some(body): Option<&str> = stripped else {
        return Confidence::Speculative;
    };
    if body.len() >= 80
        && body
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Confidence::Confirmed
    } else {
        Confidence::Speculative
    }
}

fn validate_aws_akid(value: &str) -> Confidence {
    let body: &str = value.get(4..).unwrap_or("");
    match base32_decode_rfc4648(body) {
        Some(bytes) if bytes.len() >= 6 => Confidence::Confirmed,
        _ => Confidence::Speculative,
    }
}

fn validate_jwt(value: &str) -> Confidence {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let Some(header_b64): Option<&str> = value.split('.').next() else {
        return Confidence::Speculative;
    };
    let Ok(header): Result<Vec<u8>, _> = B64URL.decode(header_b64) else {
        return Confidence::Speculative;
    };
    let Ok(text): Result<&str, _> = core::str::from_utf8(&header) else {
        return Confidence::Speculative;
    };
    if text.contains("\"alg\"") && text.contains('{') {
        Confidence::Confirmed
    } else {
        Confidence::Speculative
    }
}

#[inline]
const fn describe(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::AwsAccessKeyId => "AWS access key id",
        SecretKind::AwsSecretAccessKey => "AWS secret access key",
        SecretKind::BasicAuthHeader => "HTTP Basic authorization credentials",
        SecretKind::GcpApiKey => "Google API key",
        SecretKind::GcpServiceAccountKey => "GCP service-account key blob",
        SecretKind::AzureStorageKey => "Azure storage account key",
        SecretKind::GithubPat => "GitHub personal access token",
        SecretKind::GithubFineGrainedPat => "GitHub fine-grained PAT",
        SecretKind::GithubOauth => "GitHub OAuth token",
        SecretKind::GithubAppToken => "GitHub app / refresh / server token",
        SecretKind::StripeLiveSecret => "Stripe live secret key",
        SecretKind::StripeLivePublishable => "Stripe live publishable key",
        SecretKind::StripeRestricted => "Stripe restricted key",
        SecretKind::StripeTest => "Stripe test key",
        SecretKind::SlackToken => "Slack token",
        SecretKind::TwilioAccountSid => "Twilio account SID",
        SecretKind::TwilioApiKey => "Twilio API key SID",
        SecretKind::Jwt => "JSON Web Token",
        SecretKind::PemPrivateKey => "PEM private key",
        SecretKind::SshPublicKey => "SSH public key",
        SecretKind::AwsBedrock => "AWS Bedrock API key",
        SecretKind::AzureAdClientSecret => "Azure AD client secret",
        SecretKind::AlibabaAccessKey => "Alibaba Cloud access key id",
        SecretKind::AtlassianToken => "Atlassian API token",
        SecretKind::OnePasswordServiceAccount => "1Password service-account token",
        SecretKind::AgeSecretKey => "age encryption secret key",
        SecretKind::AirtableToken => "Airtable personal access token",
        SecretKind::CloudflareOriginCa => "Cloudflare Origin CA key",
        SecretKind::DatabricksToken => "Databricks personal access token",
        SecretKind::DynatraceToken => "Dynatrace API token",
        SecretKind::DopplerToken => "Doppler token",
        SecretKind::DropboxToken => "Dropbox access token",
        SecretKind::FlyIoToken => "Fly.io API token",
        SecretKind::PostmanKey => "Postman API key",
        SecretKind::GrafanaToken => "Grafana service-account token",
        SecretKind::RubyGemsKey => "RubyGems API key",
        SecretKind::PlanetScaleToken => "PlanetScale token",
        SecretKind::TailscaleKey => "Tailscale auth key",
        SecretKind::SentryDsn => "Sentry DSN",
        SecretKind::SnykToken => "Snyk API token",
        SecretKind::TwitterBearer => "Twitter bearer token",
        SecretKind::MongoDbUri => "MongoDB connection URI with credentials",
        SecretKind::PostgresUri => "PostgreSQL connection URI with credentials",
        SecretKind::RedisUri => "Redis connection URI with credentials",
        SecretKind::AmqpUri => "AMQP connection URI with credentials",
        SecretKind::AnthropicOauth => "Anthropic OAuth access / refresh token",
        SecretKind::GroqApiKey => "Groq API key",
        SecretKind::XaiApiKey => "xAI API key",
        SecretKind::PineconeKey => "Pinecone API key",
        SecretKind::LangSmithKey => "LangSmith API key",
        SecretKind::ZhipuApiKey => "Zhipu / Z.ai API key",
        SecretKind::WandbApiKey => "Weights & Biases API key",
        SecretKind::TavilyKey => "Tavily API key",
        SecretKind::CastAiKey => "CAST AI API key",
        SecretKind::NewRelicLicenseKey => "New Relic license key",
        SecretKind::NewRelicBrowserKey => "New Relic browser key",
        SecretKind::TencentCloudSecretId => "Tencent Cloud secret id",
        SecretKind::DuoIntegrationKey => "Duo integration key",
        SecretKind::PersonaKey => "Persona API key",
        SecretKind::DockerSwarmJoinToken => "Docker Swarm join token",
        SecretKind::AzureSasToken => "Azure storage SAS token",
        SecretKind::AzureAppConfigConnection => "Azure App Configuration connection string",
        SecretKind::SolanaKeypair => "Solana ed25519 keypair byte array",
        SecretKind::GiteaPat => "Gitea / Codeberg personal access token",
        SecretKind::RailsMasterKey => "Rails master key",
        SecretKind::VaultServiceToken => "HashiCorp Vault service token",
        SecretKind::VaultBatchToken => "HashiCorp Vault batch token",
        SecretKind::GitLabRunnerToken => "GitLab runner registration token",
        SecretKind::FrameIoToken => "Frame.io API token",
        SecretKind::ClojarsToken => "Clojars API token",
        SecretKind::ConfluentToken => "Confluent Cloud access token",
        SecretKind::ContentfulToken => "Contentful delivery API token",
        SecretKind::FastlyToken => "Fastly API token",
        SecretKind::JfrogToken => "JFrog / Artifactory API token",
        SecretKind::MessageBirdToken => "MessageBird API token",
        SecretKind::OktaToken => "Okta API token",
        SecretKind::PlaidToken => "Plaid API access token",
        SecretKind::PrefectToken => "Prefect Cloud API token",
        SecretKind::ScalingoToken => "Scalingo API token",
        SecretKind::SumoLogicToken => "Sumo Logic access token",
        SecretKind::TwitterApiKey => "Twitter API key",
        SecretKind::ZendeskToken => "Zendesk secret key",
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
            while let Some(rel) = crate::byte_search::find(&bytes[start..], needle) {
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
            if is_allowlisted(matched) {
                continue;
            }
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

    scan_pem_blocks(bytes, uri, &mut claimed, &mut findings);
    scan_solana_keypair(&text, uri, &mut claimed, &mut findings);

    scan_entropy(bytes, uri, &claimed, &mut findings);
    findings.sort_by_key(|f: &Finding| f.offset);
    findings
}

const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_DASHES: &[u8] = b"-----";
const PEM_MAX_BLOCK_BYTES: usize = 1 << 20;

const PEM_PRIVATE_LABELS: &[&str] = &[
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
];

fn pem_body_is_valid_base64(body: &str) -> bool {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    let mut compact: String = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.contains(": ") || trimmed.ends_with(':') {
            continue;
        }
        compact.push_str(trimmed);
    }
    if compact.is_empty() {
        return false;
    }
    B64.decode(compact.as_bytes()).is_ok()
}

fn scan_pem_blocks(
    bytes: &[u8],
    uri: Option<&str>,
    claimed: &mut Vec<(usize, usize)>,
    findings: &mut Vec<Finding>,
) {
    let mut start: usize = 0;
    while let Some(rel) = crate::byte_search::find(&bytes[start..], PEM_BEGIN) {
        let begin_at: usize = start + rel;
        let label_start: usize = begin_at + PEM_BEGIN.len();
        let Some(label_rel): Option<usize> =
            crate::byte_search::find(&bytes[label_start..], PEM_DASHES)
        else {
            break;
        };
        let label_end: usize = label_start + label_rel;
        let label: String = String::from_utf8_lossy(&bytes[label_start..label_end]).into_owned();
        let header_end: usize = label_end + PEM_DASHES.len();

        let mut end_marker: Vec<u8> = Vec::with_capacity(label.len() + 16);
        end_marker.extend_from_slice(b"-----END ");
        end_marker.extend_from_slice(label.as_bytes());
        end_marker.extend_from_slice(PEM_DASHES);

        let search_cap: usize = (header_end + PEM_MAX_BLOCK_BYTES).min(bytes.len());
        let region: &[u8] = &bytes[header_end..search_cap];
        let Some(end_rel): Option<usize> = crate::byte_search::find(region, &end_marker) else {
            start = header_end;
            continue;
        };
        let body_end: usize = header_end + end_rel;
        let block_end: usize = body_end + end_marker.len();

        let body: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bytes[header_end..body_end]);
        let valid: bool = pem_body_is_valid_base64(&body);
        let is_private: bool = PEM_PRIVATE_LABELS
            .iter()
            .any(|known: &&str| known.eq_ignore_ascii_case(label.trim()));

        let (kind, code, severity): (SecretKind, &'static str, Severity) = if is_private {
            (
                SecretKind::PemPrivateKey,
                "DR-SEC-PEM-PRIV",
                Severity::Error,
            )
        } else {
            (
                SecretKind::PemPrivateKey,
                "DR-SEC-PEM-BLOCK",
                Severity::Note,
            )
        };

        let block_len: usize = block_end - begin_at;
        let preview: String = format!("-----BEGIN {label}\u{2026}{block_len}");
        let mut finding: Finding = finding_for(
            kind,
            code,
            severity,
            begin_at,
            &format!("-----BEGIN {label}-----"),
            preview,
            uri,
        );
        finding.validation = Some(if valid {
            Confidence::Confirmed
        } else {
            Confidence::Speculative
        });
        if is_private || valid {
            findings.push(finding);
            claimed.push((begin_at, block_end));
        }
        start = block_end;
    }
}

fn scan_solana_keypair(
    text: &str,
    uri: Option<&str>,
    claimed: &mut Vec<(usize, usize)>,
    findings: &mut Vec<Finding>,
) {
    let raw: &[u8] = text.as_bytes();
    let len: usize = raw.len();
    let mut cursor: usize = 0;
    while cursor < len {
        if raw[cursor] != b'[' {
            cursor += 1;
            continue;
        }
        let start: usize = cursor;
        let mut pos: usize = cursor + 1;
        let mut ints: u32 = 0;
        let mut all_byte_range: bool = true;
        let mut malformed: bool = false;
        while pos < len && raw[pos] != b']' {
            let byte: u8 = raw[pos];
            if byte.is_ascii_whitespace() || byte == b',' {
                pos += 1;
                continue;
            }
            if !byte.is_ascii_digit() {
                malformed = true;
                break;
            }
            let num_start: usize = pos;
            while pos < len && raw[pos].is_ascii_digit() {
                pos += 1;
            }
            let parsed: Result<u16, _> = text[num_start..pos].parse::<u16>();
            match parsed {
                Ok(value) if value <= 255 => ints += 1,
                Ok(_) => {
                    all_byte_range = false;
                    ints += 1;
                }
                Err(_) => {
                    malformed = true;
                    break;
                }
            }
            if ints > 64 {
                break;
            }
        }
        if !malformed && pos < len && raw[pos] == b']' && ints == 64 && all_byte_range {
            let end: usize = pos + 1;
            if !claimed
                .iter()
                .any(|&(claim_start, claim_end): &(usize, usize)| {
                    start < claim_end && claim_start < end
                })
            {
                let preview: String = format!("[\u{2026}{}", end - start);
                findings.push(finding_for(
                    SecretKind::SolanaKeypair,
                    "DR-SEC-SOLANA-KEYPAIR",
                    Severity::Error,
                    start,
                    "[64-byte ed25519 keypair]",
                    preview,
                    uri,
                ));
                claimed.push((start, end));
            }
            cursor = end;
        } else {
            cursor = start + 1;
        }
    }
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
    while let Some(rel) = crate::byte_search::find(&haystack[start..], needle) {
        let at: usize = start + rel;
        if !claimed.iter().any(|&(s, _e): &(usize, usize)| s == at) {
            return at;
        }
        start = at + 1;
    }
    0
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
