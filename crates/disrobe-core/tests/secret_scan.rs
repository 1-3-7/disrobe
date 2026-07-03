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

fn aws_akid() -> String {
    format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
}

#[test]
fn aws_access_key_positive_and_negative() {
    let pos: Vec<Finding> = scan_bytes(format!("key = {} done", aws_akid()).as_bytes(), None);
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
fn aws_expanded_key_prefixes() {
    for prefix in ["ASIA", "AGPA", "AIDA", "AROA", "ANPA"] {
        let body: &str = "3KFTG2KQ4WXYZ7AB";
        let text: String = format!("k = {prefix}{body} done");
        let found: Vec<Finding> = scan_bytes(text.as_bytes(), None);
        assert!(
            has_kind(&found, SecretKind::AwsAccessKeyId),
            "prefix {prefix} should match as an AWS key id"
        );
    }
}

#[test]
fn aws_secret_access_key_contextual() {
    let secret: String = format!("{}{}", "wJalrXUtnFEMIK7MDENG", "bPxRfiCYz9Qd2RtBvHnP");
    let text: String = format!("aws_secret_access_key = {secret}");
    let found: Vec<Finding> = scan_bytes(text.as_bytes(), None);
    let f: &Finding = first_of(&found, SecretKind::AwsSecretAccessKey).expect("aws secret");
    assert_eq!(f.code, "DR-SEC-AWS-SECRET");
    assert_eq!(f.level, "error");

    let bare: Vec<Finding> = scan_bytes(secret.as_bytes(), None);
    assert!(
        !has_kind(&bare, SecretKind::AwsSecretAccessKey),
        "a bare 40-char string without aws context must not match"
    );
}

#[test]
fn basic_authorization_credentials() {
    let creds: String = format!("Authorization: Basic {}", "YWRtaW46czNjcjN0UEBzc3cwcmQ=");
    let found: Vec<Finding> = scan_bytes(creds.as_bytes(), None);
    let f: &Finding = first_of(&found, SecretKind::BasicAuthHeader).expect("basic auth");
    assert_eq!(f.code, "DR-SEC-BASIC-AUTH");

    let plain: Vec<Finding> = scan_bytes(b"basic understanding of the system here", None);
    assert!(!has_kind(&plain, SecretKind::BasicAuthHeader));
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
    let findings: Vec<Finding> = scan_bytes(aws_akid().as_bytes(), Some("file:///t.txt"));
    let f: &Finding = findings.first().expect("one finding");
    let v: serde_json::Value = serde_json::to_value(f).expect("serialize finding");
    let code: &str = v
        .get("code")
        .and_then(serde_json::Value::as_str)
        .expect("code string");
    assert_eq!(
        code, "DR-SEC-AWS-AKID",
        "the serialized code must be the AWS access-key-id rule id, not some other rule"
    );
    assert!(
        code.starts_with("DR-SEC-"),
        "every secret rule id follows the DR-SEC-* shape, got {code}"
    );
    let message: &str = v
        .get("message")
        .and_then(serde_json::Value::as_str)
        .expect("message string");
    assert!(!message.is_empty(), "the finding must carry a message");
    assert_eq!(
        v.get("uri").and_then(serde_json::Value::as_str),
        Some("file:///t.txt"),
        "the serialized uri must round-trip the scan uri"
    );
    let level: &str = v
        .get("level")
        .and_then(serde_json::Value::as_str)
        .expect("level string");
    assert_eq!(
        level, "error",
        "an AWS access key id is an error-level secret"
    );
}

#[test]
fn redacted_preview_never_echoes_full_secret() {
    let key: String = aws_akid();
    let findings: Vec<Finding> = scan_bytes(key.as_bytes(), None);
    let f: &Finding = findings.first().expect("finding");
    assert!(!f.redacted_preview.contains(&key[4..]));
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

#[test]
fn extended_provider_prefixes_are_detected() {
    let cases: [(SecretKind, String); 12] = [
        (
            SecretKind::AlibabaAccessKey,
            format!("{}{}", "LTAI", "5tABCDEFGHIJKLMNOPQR"),
        ),
        (
            SecretKind::DatabricksToken,
            format!("{}{}", "dapi", "0123456789abcdef0123456789abcdef"),
        ),
        (
            SecretKind::PostmanKey,
            format!(
                "{}{}{}{}",
                "PMAK-", "0123456789abcdef01234567", "-", "0123456789abcdef0123456789abcdef01"
            ),
        ),
        (
            SecretKind::AgeSecretKey,
            format!(
                "{}{}",
                "AGE-SECRET-KEY-1", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            ),
        ),
        (
            SecretKind::SnykToken,
            format!("{}{}", "snyk_", "0123456789abcdef0123456789abcdef0123"),
        ),
        (
            SecretKind::TailscaleKey,
            format!(
                "{}{}",
                "tskey-auth-", "0123456789abcdefABCDEF0123456789abcdefAB"
            ),
        ),
        (
            SecretKind::DopplerToken,
            format!("{}{}", "dp.pt.", "0123456789abcdefABCDEF0123456789abcdefAB"),
        ),
        (
            SecretKind::GrafanaToken,
            format!("{}{}", "glsa_", "0123456789abcdefABCDEFghijklmnopqrstuv"),
        ),
        (
            SecretKind::RubyGemsKey,
            format!(
                "{}{}",
                "rubygems_", "0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        ),
        (
            SecretKind::PlanetScaleToken,
            format!("{}{}", "pscale_tkn_", "0123456789abcdef0123456789abcdef"),
        ),
        (
            SecretKind::StripeRestricted,
            format!("{}{}", "rk_live_", "0123456789abcdefABCDEFgh"),
        ),
        (
            SecretKind::MongoDbUri,
            format!(
                "{}{}{}",
                "mongodb://", "admin:s3cretP", "ass@cluster.mongodb.net/db"
            ),
        ),
    ];
    for (kind, value) in &cases {
        let findings: Vec<Finding> = scan_bytes(format!("x {value} y").as_bytes(), None);
        assert!(
            has_kind(&findings, *kind),
            "missing {kind:?} for {value:?}: {:?}",
            findings
                .iter()
                .map(|f: &Finding| &f.code)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn placeholder_secrets_are_allowlisted_away() {
    let placeholder_aws: Vec<Finding> = scan_bytes(b"key = AKIAIOSFODNN7EXAMPLE done", None);
    assert!(!has_kind(&placeholder_aws, SecretKind::AwsAccessKeyId));
    let your_key: Vec<Finding> = scan_bytes(b"snyk_your-key-here-0000000000000000xx", None);
    assert!(!has_kind(&your_key, SecretKind::SnykToken));
}

#[test]
fn offline_validate_confirms_real_aws_key() {
    use disrobe_core::{Confidence, secret_validate};
    let real: String = format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB");
    assert_eq!(
        secret_validate(SecretKind::AwsAccessKeyId, &real),
        Confidence::Confirmed
    );
    let placeholder: &str = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(
        secret_validate(SecretKind::AwsAccessKeyId, placeholder),
        Confidence::Speculative
    );
}

fn alnum(seed: u8, len: usize) -> String {
    const POOL: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|i: usize| {
            POOL[(usize::from(seed).wrapping_add(i).wrapping_mul(7)) % POOL.len()] as char
        })
        .collect()
}

fn hexstr(seed: u8, len: usize) -> String {
    const POOL: &[u8; 16] = b"0123456789abcdef";
    (0..len)
        .map(|i: usize| {
            POOL[(usize::from(seed).wrapping_add(i).wrapping_mul(5)) % POOL.len()] as char
        })
        .collect()
}

#[test]
fn new_provider_rules_detect_real_format_fixtures() {
    let groq: String = format!("{}{}", "gsk_", alnum(3, 52));
    let xai: String = format!("{}{}", "xai-", alnum(9, 80));
    let anthropic: String = format!("{}{}", "sk-ant-oat01-", alnum(1, 96));
    let anthropic_rt: String = format!("{}{}", "sk-ant-ort01-", alnum(4, 96));
    let pinecone: String = format!("{}{}{}{}", "pcsk_", alnum(2, 10), "_", alnum(5, 40));
    let langsmith: String = format!("{}{}{}{}", "lsv2_pt_", hexstr(6, 32), "_", hexstr(2, 10));
    let zhipu: String = format!("{}{}{}", hexstr(7, 32), ".", alnum(8, 16));
    let wandb: String = format!("{}{}", "WANDB_API_KEY=", hexstr(1, 40));
    let tavily: String = format!("{}{}", "tvly-dev-", alnum(6, 32));
    let castai: String = format!("{}{}", "CASTAI_API_KEY: ", hexstr(3, 64));
    let nr_lic: String = format!("{}{}", hexstr(4, 36), "NRAL");
    let nr_browser: String = format!("{}{}", "NRJS-", hexstr(5, 19));
    let tencent: String = format!("{}{}", "AKID", alnum(2, 34));
    let duo: String = format!("{}{}", "DI", "ABCDEF0123456789GH");
    let persona: String = format!("{}{}", "persona_production_", alnum(7, 40));
    let docker: String = format!("{}{}{}{}", "SWMTKN-1-", hexstr(1, 50), "-", hexstr(9, 25));
    let azure_sas: String = format!(
        "{}{}{}",
        "https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b&srt=o&sp=r&sig=",
        alnum(3, 43),
        "%3D"
    );
    let appcfg_secret: String = format!("{}=", alnum(4, 43));
    let azure_appcfg: String = format!(
        "{}{}{}{}{}",
        "Endpoint=https://mystore.azconfig.io;Id=",
        "abcd-l0-s0:",
        alnum(2, 12),
        ";Secret=",
        appcfg_secret
    );
    let gitea: String = format!("{}{}", "gitea_token = ", hexstr(8, 40));
    let rails: String = format!("{}{}", "RAILS_MASTER_KEY=", hexstr(5, 32));

    let cases: [(SecretKind, &str); 22] = [
        (SecretKind::GroqApiKey, &groq),
        (SecretKind::XaiApiKey, &xai),
        (SecretKind::AnthropicOauth, &anthropic),
        (SecretKind::AnthropicOauth, &anthropic_rt),
        (SecretKind::PineconeKey, &pinecone),
        (SecretKind::LangSmithKey, &langsmith),
        (SecretKind::ZhipuApiKey, &zhipu),
        (SecretKind::WandbApiKey, &wandb),
        (SecretKind::TavilyKey, &tavily),
        (SecretKind::CastAiKey, &castai),
        (SecretKind::NewRelicLicenseKey, &nr_lic),
        (SecretKind::NewRelicBrowserKey, &nr_browser),
        (SecretKind::TencentCloudSecretId, &tencent),
        (SecretKind::DuoIntegrationKey, &duo),
        (SecretKind::PersonaKey, &persona),
        (SecretKind::DockerSwarmJoinToken, &docker),
        (SecretKind::AzureSasToken, &azure_sas),
        (SecretKind::AzureAppConfigConnection, &azure_appcfg),
        (SecretKind::GiteaPat, &gitea),
        (SecretKind::RailsMasterKey, &rails),
        (SecretKind::AnthropicOauth, &anthropic),
        (SecretKind::GroqApiKey, &groq),
    ];
    for (kind, value) in &cases {
        let findings: Vec<Finding> = scan_bytes(format!("x {value} y").as_bytes(), None);
        assert!(
            has_kind(&findings, *kind),
            "missing {kind:?} for {value:?}: {:?}",
            findings
                .iter()
                .map(|f: &Finding| &f.code)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn solana_keypair_parser_positive_and_negative() {
    let mut arr: String = String::from("{\"key\":[");
    for i in 0..64 {
        if i > 0 {
            arr.push(',');
        }
        arr.push_str(&((i * 3 + 1) % 256).to_string());
    }
    arr.push_str("]}");
    let found: Vec<Finding> = scan_bytes(arr.as_bytes(), None);
    let f: &Finding = first_of(&found, SecretKind::SolanaKeypair).expect("solana keypair");
    assert_eq!(f.code, "DR-SEC-SOLANA-KEYPAIR");
    assert_eq!(f.level, "error");

    let too_short: String = format!("[{}]", vec!["1"; 32].join(","));
    assert!(!has_kind(
        &scan_bytes(too_short.as_bytes(), None),
        SecretKind::SolanaKeypair
    ));

    let out_of_range: String = format!("[{},256]", vec!["1"; 63].join(","));
    assert!(!has_kind(
        &scan_bytes(out_of_range.as_bytes(), None),
        SecretKind::SolanaKeypair
    ));

    let too_long: String = format!("[{}]", vec!["1"; 65].join(","));
    assert!(!has_kind(
        &scan_bytes(too_long.as_bytes(), None),
        SecretKind::SolanaKeypair
    ));
}

#[test]
fn new_provider_rules_reject_placeholders() {
    let groq_ph: String = format!("{}{}", "gsk_", "0".repeat(52));
    assert!(!has_kind(
        &scan_bytes(format!("k={groq_ph}").as_bytes(), None),
        SecretKind::GroqApiKey
    ));

    let anthropic_ph: String = format!("{}{}", "sk-ant-oat01-", "EXAMPLE".repeat(12));
    let ph_findings: Vec<Finding> = scan_bytes(format!("k={anthropic_ph}").as_bytes(), None);
    if let Some(f) = first_of(&ph_findings, SecretKind::AnthropicOauth) {
        use disrobe_core::{Confidence, secret_validate};
        let _ = f;
        assert_eq!(
            secret_validate(SecretKind::AnthropicOauth, "sk-ant-oat01-EXAMPLE"),
            Confidence::Speculative
        );
    }

    let nr_ph: String = format!("{}{}", "0".repeat(36), "NRAL");
    assert!(!has_kind(
        &scan_bytes(format!("k={nr_ph}").as_bytes(), None),
        SecretKind::NewRelicLicenseKey
    ));
}

#[test]
fn offline_validate_confirms_new_clean_prefix_kinds() {
    use disrobe_core::{Confidence, secret_validate};
    let groq: String = format!("{}{}", "gsk_", alnum(11, 52));
    assert_eq!(
        secret_validate(SecretKind::GroqApiKey, &groq),
        Confidence::Confirmed
    );

    let xai: String = format!("{}{}", "xai-", alnum(13, 80));
    assert_eq!(
        secret_validate(SecretKind::XaiApiKey, &xai),
        Confidence::Confirmed
    );

    let nr: String = format!("{}{}", hexstr(2, 36), "NRAL");
    assert_eq!(
        secret_validate(SecretKind::NewRelicLicenseKey, &nr),
        Confidence::Confirmed
    );

    let oauth: String = format!("{}{}", "sk-ant-oat01-", alnum(3, 96));
    assert_eq!(
        secret_validate(SecretKind::AnthropicOauth, &oauth),
        Confidence::Confirmed
    );

    assert_eq!(
        secret_validate(SecretKind::GroqApiKey, "gsk_short"),
        Confidence::Speculative
    );
}

#[test]
fn offline_validate_decodes_jwt_header() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use disrobe_core::{Confidence, secret_validate};
    let header: String = B64URL.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload: String = B64URL.encode(br#"{"sub":"1","iss":"acme"}"#);
    let jwt: String = format!("{header}.{payload}.{}", "c".repeat(43));
    assert_eq!(
        secret_validate(SecretKind::Jwt, &jwt),
        Confidence::Confirmed
    );
}

#[test]
fn gitleaks_class_standalone_prefix_tokens_are_detected() {
    let vault_svc: String = format!("{}{}", "hvs.", alnum(3, 96));
    let vault_batch: String = format!("{}{}", "hvb.", alnum(7, 150));
    let gitlab_runner: String = format!("{}{}", "GR1348941", alnum(2, 20));
    let frameio: String = format!("{}{}", "fio-u-", alnum(5, 64));
    let clojars: String = format!("{}{}", "CLOJARS_", alnum(9, 60));

    let cases: [(SecretKind, &str); 5] = [
        (SecretKind::VaultServiceToken, &vault_svc),
        (SecretKind::VaultBatchToken, &vault_batch),
        (SecretKind::GitLabRunnerToken, &gitlab_runner),
        (SecretKind::FrameIoToken, &frameio),
        (SecretKind::ClojarsToken, &clojars),
    ];
    for (kind, value) in &cases {
        let findings: Vec<Finding> = scan_bytes(format!("token = {value}\n").as_bytes(), None);
        assert!(
            has_kind(&findings, *kind),
            "missing {kind:?} for {value:?}: {:?}",
            findings
                .iter()
                .map(|f: &Finding| &f.code)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn gitleaks_class_tokens_reject_wrong_length() {
    let vault_short: String = format!("{}{}", "hvs.", alnum(3, 40));
    assert!(!has_kind(
        &scan_bytes(format!("t={vault_short}").as_bytes(), None),
        SecretKind::VaultServiceToken
    ));

    let gitlab_wrong_prefix: String = format!("{}{}", "GR9999999", alnum(2, 20));
    assert!(!has_kind(
        &scan_bytes(format!("t={gitlab_wrong_prefix}").as_bytes(), None),
        SecretKind::GitLabRunnerToken
    ));

    let frameio_short: String = format!("{}{}", "fio-u-", alnum(5, 20));
    assert!(!has_kind(
        &scan_bytes(format!("t={frameio_short}").as_bytes(), None),
        SecretKind::FrameIoToken
    ));

    let clojars_short: String = format!("{}{}", "CLOJARS_", alnum(9, 30));
    assert!(!has_kind(
        &scan_bytes(format!("t={clojars_short}").as_bytes(), None),
        SecretKind::ClojarsToken
    ));
}

fn lc(seed: u8, len: usize) -> String {
    const POOL: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|i: usize| {
            POOL[(usize::from(seed).wrapping_add(i).wrapping_mul(7)) % POOL.len()] as char
        })
        .collect()
}

fn uuid(seed: u8) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hexstr(seed, 8),
        hexstr(seed.wrapping_add(1), 4),
        hexstr(seed.wrapping_add(2), 4),
        hexstr(seed.wrapping_add(3), 4),
        hexstr(seed.wrapping_add(4), 12)
    )
}

#[test]
fn gitleaks_keyword_context_providers_are_detected() {
    let confluent: String = format!("confluent_access_token = \"{}\"", lc(1, 16));
    let contentful: String = format!("contentful_delivery_token = \"{}\"", lc(3, 43));
    let fastly: String = format!("fastly_api_token = \"{}\"", lc(4, 32));
    let jfrog: String = format!("jfrog_api_key = \"{}\"", lc(5, 73));
    let jfrog_alias: String = format!("artifactory_identity_token = \"{}\"", lc(6, 64));
    let messagebird: String = format!("messagebird_api_token = \"{}\"", lc(7, 25));
    let messagebird_alias: String = format!("message-bird-token = \"{}\"", lc(7, 25));
    let okta: String = format!("okta_api_token = \"00{}\"", lc(9, 40));
    let plaid: String = format!("plaid_api_token = \"access-production-{}\"", uuid(10));
    let sumologic: String = format!("sumologic_access_token = \"{}\"", lc(16, 64));
    let twitter: String = format!("twitter_api_key = \"{}\"", lc(17, 25));
    let zendesk: String = format!("zendesk_secret_key = \"{}\"", lc(22, 40));
    let prefect: String = format!("prefect_token = \"pnu_{}\"", lc(13, 36));
    let scalingo: String = format!("scalingo_token = \"tk-us-{}\"", lc(14, 48));

    let cases: [(SecretKind, &str); 14] = [
        (SecretKind::ConfluentToken, &confluent),
        (SecretKind::ContentfulToken, &contentful),
        (SecretKind::FastlyToken, &fastly),
        (SecretKind::JfrogToken, &jfrog),
        (SecretKind::JfrogToken, &jfrog_alias),
        (SecretKind::MessageBirdToken, &messagebird),
        (SecretKind::MessageBirdToken, &messagebird_alias),
        (SecretKind::OktaToken, &okta),
        (SecretKind::PlaidToken, &plaid),
        (SecretKind::SumoLogicToken, &sumologic),
        (SecretKind::TwitterApiKey, &twitter),
        (SecretKind::ZendeskToken, &zendesk),
        (SecretKind::PrefectToken, &prefect),
        (SecretKind::ScalingoToken, &scalingo),
    ];
    for (kind, value) in &cases {
        let findings: Vec<Finding> = scan_bytes(value.as_bytes(), None);
        assert!(
            has_kind(&findings, *kind),
            "missing {kind:?} for {value:?}: {:?}",
            findings
                .iter()
                .map(|f: &Finding| &f.code)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn gitleaks_keyword_context_requires_the_provider_keyword() {
    let bare_16: String = lc(1, 16);
    assert!(
        !has_kind(
            &scan_bytes(format!("token = \"{bare_16}\"").as_bytes(), None),
            SecretKind::ConfluentToken
        ),
        "a bare 16-char alnum without the confluent keyword must not match"
    );

    let bare_25: String = lc(17, 25);
    assert!(
        !has_kind(
            &scan_bytes(format!("api_key = \"{bare_25}\"").as_bytes(), None),
            SecretKind::TwitterApiKey
        ),
        "a bare 25-char alnum without the twitter keyword must not match"
    );

    let bare_40: String = lc(22, 40);
    assert!(
        !has_kind(
            &scan_bytes(format!("secret = \"{bare_40}\"").as_bytes(), None),
            SecretKind::ZendeskToken
        ),
        "a bare 40-char alnum without the zendesk keyword must not match"
    );

    let no_assign: String = format!("the fastly cdn serves {} bytes", lc(4, 32));
    assert!(
        !has_kind(
            &scan_bytes(no_assign.as_bytes(), None),
            SecretKind::FastlyToken
        ),
        "prose mentioning fastly without an assignment must not match"
    );
}

#[test]
fn gitleaks_keyword_context_rejects_wrong_length_body() {
    let confluent_short: String = format!("confluent_token = \"{}\"", lc(1, 12));
    assert!(!has_kind(
        &scan_bytes(confluent_short.as_bytes(), None),
        SecretKind::ConfluentToken
    ));

    let okta_no_prefix: String = format!("okta_token = \"{}\"", lc(9, 42));
    assert!(!has_kind(
        &scan_bytes(okta_no_prefix.as_bytes(), None),
        SecretKind::OktaToken
    ));

    let prefect_wrong_prefix: String = format!("prefect = \"pat_{}\"", lc(13, 36));
    assert!(!has_kind(
        &scan_bytes(prefect_wrong_prefix.as_bytes(), None),
        SecretKind::PrefectToken
    ));

    let scalingo_wrong_region: String = format!("scalingo = \"tk-eu-{}\"", lc(14, 48));
    assert!(!has_kind(
        &scan_bytes(scalingo_wrong_region.as_bytes(), None),
        SecretKind::ScalingoToken
    ));
}

#[test]
fn keyword_context_providers_are_fp_clean_on_disrobe_source() {
    let src: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let kinds: [SecretKind; 13] = [
        SecretKind::ConfluentToken,
        SecretKind::ContentfulToken,
        SecretKind::FastlyToken,
        SecretKind::JfrogToken,
        SecretKind::MessageBirdToken,
        SecretKind::OktaToken,
        SecretKind::PlaidToken,
        SecretKind::PrefectToken,
        SecretKind::ScalingoToken,
        SecretKind::SumoLogicToken,
        SecretKind::TwitterApiKey,
        SecretKind::ZendeskToken,
        SecretKind::HighEntropyGeneric,
    ];
    let mut offenders: Vec<String> = Vec::new();
    walk_rs(&src, &mut |path: &std::path::Path| {
        let bytes: Vec<u8> = std::fs::read(path).expect("read src file");
        for f in scan_bytes(&bytes, None) {
            if kinds.contains(&f.kind) && f.kind != SecretKind::HighEntropyGeneric {
                offenders.push(format!("{} {:?} @{}", path.display(), f.kind, f.offset));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "keyword-context rules must be FP-clean on disrobe-core/src: {offenders:?}"
    );
}

fn walk_rs(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path)) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let entry: std::fs::DirEntry = entry.expect("dir entry");
        let kind: std::fs::FileType = entry.file_type().expect("file type");
        let path: std::path::PathBuf = entry.path();
        if kind.is_dir() {
            walk_rs(&path, f);
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            f(&path);
        }
    }
}
