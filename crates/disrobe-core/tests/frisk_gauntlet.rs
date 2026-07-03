#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_core::recon::{ReconCategory, ReconConfig, ReconFinding, ReconReport, report_tree};

const PLANTED: &str = "../../corpus/recon/planted";

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

struct Staged {
    root: PathBuf,
}

impl Staged {
    fn new() -> Self {
        let seq: u64 = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
        let root: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-frisk-gauntlet-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        copy_tree(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PLANTED),
            &root,
        );
        Self { root }
    }

    fn write(&self, rel: &str, contents: &str) {
        let path: PathBuf = self.root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, contents).expect("write staged file");
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create dst");
    for entry in std::fs::read_dir(src).expect("read planted corpus") {
        let entry: std::fs::DirEntry = entry.expect("dir entry");
        let kind: std::fs::FileType = entry.file_type().expect("file type");
        let target: PathBuf = dst.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

/// Assembles each secret at runtime from split prefix + body so no contiguous
/// real-format secret literal is ever committed (push-protection safe).
fn planted_secrets() -> String {
    let aws: String = format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB");
    let github: String = format!(
        "{}{}",
        "ghp",
        concat!("_", "0123456789abcdefghijklmnopqrstuvwxyz")
    );
    let slack: String = format!(
        "https://hooks.slack.com/services/{}/{}/{}",
        "T00000000", "B11111111", "abcdefghijklmnopqrstuvwx"
    );
    let stripe: String = format!("{}{}", "sk", concat!("_live_", "0123456789abcdefghijABCD"));
    let gcp: String = format!("{}{}", "AIza", "SyA0123456789abcdefghijklmnopqrstuv");
    let openai: String = format!(
        "{}{}{}",
        "sk-",
        "a".repeat(20),
        concat!("T3BlbkFJ", "bbbbbbbbbbbbbbbbbbbb")
    );
    let google_tok: String = format!("{}{}", "ya29", ".AbCdEf0123456789ghijkl");
    let gitlab: String = format!("{}{}", "glpat", concat!("-", "abcdefghij0123456789"));
    let huggingface: String = format!(
        "{}{}",
        "hf",
        concat!("_", "abcdefghijklmnopqrstuvwxyz01234567")
    );
    let supabase: String = format!(
        "{}{}",
        "sb",
        concat!("_secret_", "abcdefghijklmnopqrstuvwx")
    );
    let vault: String = format!(
        "{}{}",
        "hvs",
        concat!(
            ".",
            "aB3",
            "cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eF8gH9iJ0kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1gH2"
        )
    );
    let gitlab_runner: String = format!("{}{}", "GR1348941", "aB3cD4eF5gH6iJ7kL8mN");
    let okta: String = format!(
        "okta_api_token = \"{}{}\"",
        "00", "abcdefghij0123456789abcdefghij0123456789"
    );
    let twitter: String = format!("twitter_api_key = \"{}\"", "abcdefghij0123456789abcde");
    let prefect: String = format!(
        "prefect_token = \"{}{}\"",
        "pnu_", "abcdefghij0123456789abcdefghij012345"
    );
    let scalingo: String = format!(
        "scalingo_token = \"{}{}\"",
        "tk-us-", "abcdefghij0123456789abcdefghij0123456789abcdefgh"
    );
    format!(
        "aws = \"{aws}\"\n\
         github = \"{github}\"\n\
         slack = \"{slack}\"\n\
         stripe = \"{stripe}\"\n\
         gcp = \"{gcp}\"\n\
         openai = \"{openai}\"\n\
         google = \"{google_tok}\"\n\
         gitlab = \"{gitlab}\"\n\
         huggingface = \"{huggingface}\"\n\
         supabase = \"{supabase}\"\n\
         vault = \"{vault}\"\n\
         runner = \"{gitlab_runner}\"\n\
         {okta}\n\
         {twitter}\n\
         {prefect}\n\
         {scalingo}\n"
    )
}

fn scan() -> ReconReport {
    let staged: Staged = Staged::new();
    staged.write("res/raw/credentials.properties", &planted_secrets());
    report_tree(&staged.root, &ReconConfig::default()).expect("scan planted tree")
}

fn rule_ids(report: &ReconReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.rule_id.clone())
        .collect()
}

fn categories(report: &ReconReport) -> BTreeSet<ReconCategory> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.category)
        .collect()
}

fn finding<'a>(report: &'a ReconReport, rule_id: &str) -> &'a ReconFinding {
    report
        .findings
        .iter()
        .find(|f: &&ReconFinding| f.rule_id == rule_id)
        .unwrap_or_else(|| panic!("no finding for {rule_id}: {:?}", rule_ids(report)))
}

#[test]
fn every_category_is_detected() {
    let report: ReconReport = scan();
    let cats: BTreeSet<ReconCategory> = categories(&report);
    for required in [
        ReconCategory::Secret,
        ReconCategory::Endpoint,
        ReconCategory::Manifest,
        ReconCategory::Url,
        ReconCategory::Ipv4,
        ReconCategory::Email,
        ReconCategory::Onion,
    ] {
        assert!(
            cats.contains(&required),
            "missing category {required:?}: {cats:?}"
        );
    }
}

#[test]
fn every_secret_provider_is_detected() {
    let report: ReconReport = scan();
    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-SEC-AWS-AKID",
        "DR-SEC-GH-PAT",
        "DR-RECON-SLACK-WEBHOOK",
        "DR-SEC-STRIPE-SK",
        "DR-SEC-GCP-APIKEY",
        "DR-RECON-OPENAI-KEY",
        "DR-RECON-GOOGLE-OAUTH-TOKEN",
        "DR-RECON-GITLAB-PAT",
        "DR-RECON-HUGGINGFACE",
        "DR-RECON-SUPABASE",
        "DR-SEC-VAULT-SVC",
        "DR-SEC-GITLAB-RUNNER",
        "DR-SEC-OKTA",
        "DR-SEC-TWITTER-APIKEY",
        "DR-SEC-PREFECT",
        "DR-SEC-SCALINGO",
    ] {
        assert!(
            ids.contains(required),
            "missing secret rule {required}: {ids:?}"
        );
    }
}

#[test]
fn manifest_recon_is_detected_with_paths() {
    let report: ReconReport = scan();
    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-RECON-MANIFEST-DEEPLINK",
        "DR-RECON-MANIFEST-DEEPLINK-HOST",
        "DR-RECON-MANIFEST-EXPORTED",
        "DR-RECON-MANIFEST-PROVIDER-AUTHORITY",
        "DR-RECON-MANIFEST-PERMISSION",
    ] {
        assert!(
            ids.contains(required),
            "missing manifest rule {required}: {ids:?}"
        );
    }
    let exported: &ReconFinding = finding(&report, "DR-RECON-MANIFEST-EXPORTED");
    assert_eq!(
        exported.path.as_deref(),
        Some("AndroidManifest.xml"),
        "manifest finding must carry its file path: {exported:?}"
    );
    assert!(
        exported.line >= 1,
        "manifest finding carries a line: {exported:?}"
    );
}

#[test]
fn endpoints_and_iocs_carry_file_and_line() {
    let report: ReconReport = scan();
    let ids: BTreeSet<String> = rule_ids(&report);
    assert!(ids.contains("DR-RECON-URI-PATH"), "endpoint paths: {ids:?}");
    assert!(ids.contains("DR-RECON-ONION"), "onion ioc: {ids:?}");

    let route: &ReconFinding = report
        .findings
        .iter()
        .find(|f: &&ReconFinding| {
            f.rule_id == "DR-RECON-URI-PATH" && f.value.contains("/admin/keys")
        })
        .expect("the planted /api/v2/admin/keys endpoint must be found");
    assert_eq!(
        route.path.as_deref(),
        Some("smali/com/planted/recon/Api.smali.txt"),
        "endpoint must carry its smali file path: {route:?}"
    );
    assert!(route.line >= 1);

    let onion: &ReconFinding = finding(&report, "DR-RECON-ONION");
    assert_eq!(onion.path.as_deref(), Some("assets/config.json"));
    assert!(onion.value.contains(".onion"), "{onion:?}");
}

#[test]
fn js_bundle_yields_fetch_websocket_and_graphql_endpoints() {
    let report: ReconReport = scan();
    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-RECON-FETCH-URL",
        "DR-RECON-WEBSOCKET",
        "DR-RECON-GRAPHQL-OP",
    ] {
        assert!(ids.contains(required), "missing {required}: {ids:?}");
    }
    let ws: &ReconFinding = finding(&report, "DR-RECON-WEBSOCKET");
    assert_eq!(ws.path.as_deref(), Some("assets/app.bundle.js"));
    assert!(ws.value.starts_with("wss://"), "{ws:?}");
    let op: &ReconFinding = finding(&report, "DR-RECON-GRAPHQL-OP");
    assert_eq!(op.value, "GetPlantedProfile", "{op:?}");
}

#[test]
fn secret_value_is_redacted_not_raw() {
    let report: ReconReport = scan();
    let aws: &ReconFinding = finding(&report, "DR-SEC-AWS-AKID");
    assert!(
        aws.value.contains('\u{2026}'),
        "secret preview must be redacted, not the raw key: {aws:?}"
    );
    assert_eq!(aws.path.as_deref(), Some("res/raw/credentials.properties"));
}

#[test]
fn committed_corpus_has_no_contiguous_secret_literal() {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PLANTED);
    let mut checked: usize = 0;
    walk_files(&dir, &mut |path: &Path| {
        let bytes: Vec<u8> = std::fs::read(path).expect("read corpus file");
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        for marker in [
            "AKIA",
            "ghp_",
            "sk_live_",
            "AIzaSy",
            "hooks.slack.com/services/T",
            "glpat-",
            "hf_",
            "dop_v1_",
            "sb_secret_",
        ] {
            assert!(
                !text.contains(marker),
                "committed corpus file {} contains secret marker {marker:?}; build it at runtime instead",
                path.display()
            );
        }
        checked += 1;
    });
    assert!(
        checked >= 3,
        "expected to scan the planted corpus files, scanned {checked}"
    );
}

fn walk_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    for entry in std::fs::read_dir(dir).expect("read corpus dir") {
        let entry: std::fs::DirEntry = entry.expect("dir entry");
        let kind: std::fs::FileType = entry.file_type().expect("file type");
        if kind.is_dir() {
            walk_files(&entry.path(), f);
        } else if kind.is_file() {
            f(&entry.path());
        }
    }
}
