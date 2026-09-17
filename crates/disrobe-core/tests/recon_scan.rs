#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_core::recon::{
    CustomPattern, ReconCategory, ReconConfig, ReconFinding, ReconReport, report_tree,
};
use disrobe_core::scratch::ScratchDir;

struct Fixture {
    _scratch: ScratchDir,
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let purpose: String = format!("disrobe-recon-{tag}");
        let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create fixture root");
        let root: PathBuf = scratch.path().to_path_buf();
        Self {
            _scratch: scratch,
            root,
        }
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let path: PathBuf = self.root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(&path, bytes).expect("write fixture file");
    }
}

fn rule_ids(report: &ReconReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.rule_id.clone())
        .collect()
}

fn aws_akid() -> String {
    format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
}

fn paths_for(report: &ReconReport, rule_id: &str) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .filter(|f: &&ReconFinding| f.rule_id == rule_id)
        .filter_map(|f: &ReconFinding| f.path.clone())
        .collect()
}

fn rule_breakdown(report: &ReconReport) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for finding in &report.findings {
        *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }
    counts
}

#[test]
fn scans_decompiled_tree_for_every_category_with_file_and_line() {
    let fx: Fixture = Fixture::new("tree");
    fx.write(
        "smali/com/app/Api.smali",
        format!(
            "const-string v0, \"{}\"\n\
             const-string v1, \"https://api.backend.example.com/v1/login\"\n\
             const-string v2, \"/internal/admin/keys\"\n",
            aws_akid()
        )
        .as_bytes(),
    );
    let github_pat: String = format!(
        "{}{}",
        "ghp",
        concat!("_", "0123456789abcdefghijklmnopqrstuvwxyz")
    );
    fx.write(
        "res/values/strings.xml",
        format!(
            "<resources>\n\
             <string name=\"fb\">https://prod-app.firebaseio.com</string>\n\
             <string name=\"gh\">{github_pat}</string>\n\
             <string name=\"mail\">support@vendor.example.org</string>\n\
             </resources>\n"
        )
        .as_bytes(),
    );
    let slack_webhook: String = format!(
        "https://hooks.slack.com/services/{}/{}/{}",
        "T00000000", "B11111111", "abcdefghijklmnopqrstuvwx"
    );
    fx.write(
        "assets/config.json",
        format!("{{\"slack\":\"{slack_webhook}\"}}").as_bytes(),
    );

    let report: ReconReport =
        report_tree(&fx.root, &ReconConfig::default()).expect("scan tree succeeds");

    assert_eq!(report.files_scanned, 3);
    let breakdown: BTreeMap<String, usize> = rule_breakdown(&report);
    let expected_breakdown: BTreeMap<String, usize> = BTreeMap::from([
        ("DR-RECON-EMAIL".to_owned(), 1),
        ("DR-RECON-FIREBASE".to_owned(), 1),
        ("DR-RECON-SLACK-WEBHOOK".to_owned(), 1),
        ("DR-RECON-URI-PATH".to_owned(), 1),
        ("DR-RECON-URL".to_owned(), 2),
        ("DR-SEC-AWS-AKID".to_owned(), 1),
        ("DR-SEC-GH-PAT".to_owned(), 1),
    ]);
    assert_eq!(report.total, 8, "unexpected findings: {breakdown:#?}");
    assert_eq!(breakdown, expected_breakdown);
    let cats: BTreeSet<ReconCategory> = disrobe_core::recon::categories(&report);
    for required in [
        ReconCategory::Secret,
        ReconCategory::Endpoint,
        ReconCategory::Url,
        ReconCategory::Email,
    ] {
        assert!(
            cats.contains(&required),
            "missing category {required:?}: {cats:?}"
        );
    }

    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-SEC-AWS-AKID",
        "DR-SEC-GH-PAT",
        "DR-RECON-FIREBASE",
        "DR-RECON-SLACK-WEBHOOK",
        "DR-RECON-URI-PATH",
    ] {
        assert!(ids.contains(required), "missing rule {required}: {ids:?}");
    }

    let aws_paths: BTreeSet<String> = paths_for(&report, "DR-SEC-AWS-AKID");
    assert!(
        aws_paths.contains("smali/com/app/Api.smali"),
        "aws finding must carry its relative file path: {aws_paths:?}"
    );

    let aws: &ReconFinding = report
        .findings
        .iter()
        .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
        .expect("aws finding present");
    assert_eq!(aws.line, 1, "aws is on line 1 of Api.smali: {aws:?}");
}

#[test]
fn non_utf8_resource_file_is_scanned_not_crashed() {
    let fx: Fixture = Fixture::new("cp1252");
    let mut bytes: Vec<u8> = vec![0x53, 0x6d, 0x61, 0x6c, 0x69, 0x20, 0xe9, 0xe8, 0xff, 0x0a];
    bytes.extend_from_slice(format!("key={}\n", aws_akid()).as_bytes());
    bytes.extend_from_slice(&[0x80, 0x9d, 0x91]);
    bytes.extend_from_slice(b"\nurl=https://c2.evil.example.com/gate\n");
    fx.write("res/raw/blob.bin", &bytes);
    fx.write("clean.txt", b"nothing to see here\n");

    let report: ReconReport =
        report_tree(&fx.root, &ReconConfig::default()).expect("non-utf8 tree must not crash");

    assert_eq!(
        report.non_utf8_files, 1,
        "the cp1252-ish file must be flagged non-utf8"
    );
    let ids: BTreeSet<String> = rule_ids(&report);
    assert!(
        ids.contains("DR-SEC-AWS-AKID"),
        "secret after invalid bytes: {ids:?}"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f: &ReconFinding| f.category == ReconCategory::Url),
        "url after invalid bytes must still be recovered: {:?}",
        report.findings
    );
}

#[test]
fn custom_pattern_file_categories_findings_in_tree() {
    let fx: Fixture = Fixture::new("custom");
    fx.write(
        "lib/keys.txt",
        b"internal token COMPANY-SECRET-9182 deployed",
    );

    let pattern: CustomPattern =
        CustomPattern::compile("company", r"COMPANY-SECRET-[0-9]{4}").expect("compile custom");
    let config: ReconConfig = ReconConfig {
        custom: vec![pattern],
        ..ReconConfig::default()
    };

    let report: ReconReport = report_tree(&fx.root, &config).expect("scan with custom pattern");
    let custom: Vec<&ReconFinding> = report
        .findings
        .iter()
        .filter(|f: &&ReconFinding| f.category == ReconCategory::Custom)
        .collect();
    assert_eq!(custom.len(), 1, "{:?}", report.findings);
    assert_eq!(custom[0].value, "COMPANY-SECRET-9182");
    assert_eq!(custom[0].path.as_deref(), Some("lib/keys.txt"));
}

#[test]
fn symlink_cycles_do_not_hang_and_single_file_works() {
    let fx: Fixture = Fixture::new("single");
    fx.write(
        "only.txt",
        format!("url https://single.example.com/x aws {}", aws_akid()).as_bytes(),
    );
    let single: PathBuf = fx.root.join("only.txt");
    let report: ReconReport =
        report_tree(&single, &ReconConfig::default()).expect("single file scan");
    assert_eq!(report.files_scanned, 1);
    assert!(
        rule_ids(&report).contains("DR-SEC-AWS-AKID"),
        "{:?}",
        report.findings
    );
}

fn categories_present(report: &ReconReport) -> BTreeSet<ReconCategory> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.category)
        .collect()
}

#[test]
fn c2_indicators_are_surfaced() {
    let blob: &[u8] = b"ua Mozilla/5.0 (Windows NT 10.0)\n\
        pipe \\\\.\\pipe\\msagent_42\n\
        mutex Global\\xZ7Q-singleton\n\
        beacon https://cdn.example.net/gate.php\n\
        drop https://cdn.discordapp.com/attachments/1/2/payload.bin\n";
    let report: ReconReport =
        disrobe_core::recon::report_bytes(blob, Some("sample.bin"), &ReconConfig::default());
    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-RECON-C2-USER-AGENT",
        "DR-RECON-C2-NAMED-PIPE",
        "DR-RECON-C2-MUTEX",
        "DR-RECON-C2-BEACON-PATH",
        "DR-RECON-C2-DEAD-DROP",
    ] {
        assert!(ids.contains(required), "missing {required}: {ids:?}");
    }
    assert!(categories_present(&report).contains(&ReconCategory::C2));
}

#[test]
fn persistence_artifacts_are_surfaced() {
    let blob: &[u8] = b"reg Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n\
        ifeo Image File Execution Options\\sethc.exe\n\
        mac /Users/victim/Library/LaunchAgents/com.evil.plist\n\
        cron /etc/cron.d/backdoor\n";
    let report: ReconReport =
        disrobe_core::recon::report_bytes(blob, None, &ReconConfig::default());
    let ids: BTreeSet<String> = rule_ids(&report);
    assert!(ids.contains("DR-RECON-PERSIST-RUNKEY"), "{ids:?}");
    assert!(ids.contains("DR-RECON-PERSIST-IFEO"), "{ids:?}");
    assert!(ids.contains("DR-RECON-PERSIST-LAUNCHAGENT"), "{ids:?}");
    assert!(categories_present(&report).contains(&ReconCategory::Persistence));
}

#[test]
fn wallets_and_pii_pass_through_to_recon() {
    let eth: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    let btc: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let card: &str = "4111111111111111";
    let blob: String = format!("eth {eth} btc {btc} card {card}");
    let report: ReconReport =
        disrobe_core::recon::report_bytes(blob.as_bytes(), None, &ReconConfig::default());
    let cats: BTreeSet<ReconCategory> = categories_present(&report);
    assert!(
        cats.contains(&ReconCategory::Wallet),
        "{:?}",
        report.findings
    );
    assert!(cats.contains(&ReconCategory::Pii), "{:?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f: &ReconFinding| f.value == eth && f.category == ReconCategory::Wallet)
    );
}

#[test]
fn malware_config_njrat_round_trip_is_recovered() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    let host: String = B64.encode("c2.example.net");
    let port: String = B64.encode("5552");
    let mutex: String = B64.encode("njRAT-mtx-xyz");
    let blob: String = format!("{host}|'|'|{port}|'|'|{mutex}");
    let report: ReconReport = disrobe_core::recon::report_bytes(
        format!("config {blob}\n").as_bytes(),
        Some("stub.exe"),
        &ReconConfig::default(),
    );
    let malcfg: Vec<&ReconFinding> = report
        .findings
        .iter()
        .filter(|f: &&ReconFinding| f.category == ReconCategory::MalwareConfig)
        .collect();
    assert!(
        malcfg
            .iter()
            .any(|f: &&ReconFinding| f.value == "c2.example.net"),
        "njrat host not recovered: {:?}",
        report.findings
    );
    assert!(malcfg.iter().any(|f: &&ReconFinding| f.value == "5552"));
}

#[test]
fn malware_config_cobalt_strike_xor_tlv_is_recovered() {
    fn tlv(index: u16, ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&index.to_be_bytes());
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }
    let mut plain: Vec<u8> = Vec::new();
    plain.extend_from_slice(&tlv(1, 1, &[0x00, 0x01]));
    plain.extend_from_slice(&tlv(2, 2, &[0x00, 0x00, 0x01, 0xbb]));
    plain.extend_from_slice(&tlv(8, 3, b"/submit.php"));
    let key: u8 = 0x2e;
    let mut blob: Vec<u8> = b"MZ junk header padding bytes here....".to_vec();
    blob.extend(plain.iter().map(|&b: &u8| b ^ key));
    let report: ReconReport =
        disrobe_core::recon::report_bytes(&blob, Some("beacon.bin"), &ReconConfig::default());
    assert!(
        report.findings.iter().any(
            |f: &ReconFinding| f.category == ReconCategory::MalwareConfig
                && f.value.contains("xor-key=0x2e")
        ),
        "cobalt strike beacon not detected: {:?}",
        report.findings
    );
}

#[test]
fn malware_config_remote_wall_kind_is_reported() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"DcRatByqwqdanchun");
    blob.extend_from_slice(b"\nstage=https://pastebin.com/raw/abcdef\n");
    let report: ReconReport =
        disrobe_core::recon::report_bytes(&blob, Some("dcrat.bin"), &ReconConfig::default());
    assert!(
        report.findings.iter().any(
            |f: &ReconFinding| f.category == ReconCategory::MalwareConfig
                && f.value.contains("wall=remote-config")
        ),
        "remote config wall kind not surfaced: {:?}",
        report.findings
    );
}

#[test]
fn clean_source_yields_no_recon_false_positives() {
    let clean: &[u8] = b"fn main() {\n\
        let total = items.iter().map(|i| i.price).sum::<u64>();\n\
        println!(\"total is {}\", total);\n\
    }\n";
    let report: ReconReport =
        disrobe_core::recon::report_bytes(clean, Some("main.rs"), &ReconConfig::default());
    assert_eq!(
        report.total, 0,
        "clean source produced findings: {:?}",
        report.findings
    );
}
