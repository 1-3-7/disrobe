#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use disrobe_prowl::http::{FetchError, FetchResponse, Fetcher};
use disrobe_prowl::provider::{Request, Yield};
use disrobe_prowl::providers;
use disrobe_prowl::{
    EngineConfig, Filter, HttpConfig, Ioc, IocKind, KeySet, ProwlReport, ReqwestFetcher, Source,
    parse_target_lines, targets_from_disrobe_report,
};

fn fixture(name: &str) -> String {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn parse(source: Source, body: &str) -> Yield {
    providers::build(source).parse(body)
}

#[test]
fn wayback_fixture_extracts_known_urls_and_statuses() {
    let y: Yield = parse(Source::Wayback, &fixture("wayback.json"));
    assert_eq!(y.urls.len(), 5);
    assert_eq!(y.urls[0].url, "https://planted.example.com/");
    assert_eq!(y.urls[0].status, Some(200));
    assert_eq!(y.urls[0].timestamp.as_deref(), Some("20230101120000"));
    assert_eq!(y.urls[3].status, Some(404));
    assert_eq!(y.urls[2].mime.as_deref(), Some("image/png"));
}

#[test]
fn commoncrawl_fixture_extracts_known_urls() {
    let y: Yield = parse(Source::CommonCrawl, &fixture("commoncrawl.ndjson"));
    assert_eq!(y.urls.len(), 4);
    assert_eq!(y.urls[0].url, "https://planted.example.com/index.html");
    assert_eq!(y.urls[2].status, Some(301));
    assert_eq!(y.urls[1].mime.as_deref(), Some("application/json"));
}

#[test]
fn otx_fixture_extracts_known_urls() {
    let y: Yield = parse(Source::Otx, &fixture("otx.json"));
    assert_eq!(y.urls.len(), 2);
    assert_eq!(y.urls[0].url, "https://planted.example.com/api/v2/admin");
    assert_eq!(y.urls[0].status, Some(200));
    assert_eq!(y.urls[1].status, Some(403));
}

#[test]
fn urlscan_fixture_extracts_known_urls() {
    let y: Yield = parse(Source::Urlscan, &fixture("urlscan.json"));
    assert_eq!(y.urls.len(), 2);
    assert_eq!(y.urls[0].url, "https://planted.example.com/dashboard");
    assert_eq!(
        y.urls[0].timestamp.as_deref(),
        Some("2023-06-01T00:00:00.000Z")
    );
}

#[test]
fn crtsh_fixture_extracts_subdomains() {
    let y: Yield = parse(Source::Crtsh, &fixture("crtsh.json"));
    let values: Vec<&str> = y.iocs.iter().map(|i: &Ioc| i.value.as_str()).collect();
    assert!(values.contains(&"planted.example.com"), "{values:?}");
    assert!(values.contains(&"www.planted.example.com"), "{values:?}");
    assert!(values.contains(&"api.planted.example.com"), "{values:?}");
    assert!(
        y.iocs
            .iter()
            .all(|i: &Ioc| matches!(i.kind, IocKind::Subdomain | IocKind::Domain)),
        "crt.sh yields name IoCs only"
    );
}

#[test]
fn urlhaus_fixture_extracts_malware_urls_and_tags() {
    let y: Yield = parse(Source::Urlhaus, &fixture("urlhaus.json"));
    assert_eq!(y.urls.len(), 2);
    assert_eq!(
        y.urls[0].url,
        "http://planted.example.com/payload/5016223.exe"
    );
    assert_eq!(y.urls[0].threat.as_deref(), Some("malware_download"));
    assert!(y.urls[0].tags.contains(&"AZORult".to_owned()));
}

#[test]
fn threatfox_fixture_splits_urls_and_iocs() {
    let y: Yield = parse(Source::Threatfox, &fixture("threatfox.json"));
    assert_eq!(y.urls.len(), 1);
    assert_eq!(y.urls[0].url, "http://planted.example.com/c2/gate.php");
    assert!(
        y.iocs
            .iter()
            .any(|i: &Ioc| i.kind == IocKind::Ipv4 && i.value == "203.0.113.55"),
        "ip:port stripped to ip: {:?}",
        y.iocs
    );
    assert!(
        y.iocs
            .iter()
            .any(|i: &Ioc| i.kind == IocKind::Subdomain && i.value == "mal.planted.example.com"),
        "{:?}",
        y.iocs
    );
}

#[derive(Debug)]
struct FixtureFetcher;

#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
        let body: Option<&str> = if request.url.contains("web.archive.org") {
            Some("wayback.json")
        } else if request.url.contains("index.commoncrawl.org") && request.url.contains("collinfo")
        {
            None
        } else if request.url.contains("index.commoncrawl.org") {
            Some("commoncrawl.ndjson")
        } else if request.url.contains("otx.alienvault.com") {
            Some("otx.json")
        } else if request.url.contains("urlscan.io") {
            Some("urlscan.json")
        } else if request.url.contains("crt.sh") {
            Some("crtsh.json")
        } else if request.url.contains("urlhaus") {
            Some("urlhaus.json")
        } else if request.url.contains("threatfox") {
            Some("threatfox.json")
        } else if request.url.contains("virustotal.com") {
            Some("virustotal.json")
        } else {
            None
        };
        body.map_or(Err(FetchError::Status(404)), |name: &str| {
            Ok(FetchResponse {
                body: fixture(name),
                retry_after_secs: None,
                truncated: false,
            })
        })
    }
}

fn fast_cfg() -> EngineConfig {
    EngineConfig {
        base_backoff: Duration::from_millis(0),
        max_backoff: Duration::from_millis(0),
        per_host_rps: 0.0,
        per_host_burst: 1.0,
        ..EngineConfig::default()
    }
}

fn all_keys() -> KeySet {
    let mut keys: KeySet = KeySet::new();
    keys.insert(Source::Urlhaus, "uh-fixture-key-aaaaaaaaaa".to_owned());
    keys.insert(Source::Threatfox, "tf-fixture-key-bbbbbbbbbb".to_owned());
    keys.insert(Source::Virustotal, "vt-fixture-key-cccccccccc".to_owned());
    keys
}

#[tokio::test]
async fn full_harvest_merges_all_sources_dedups_and_extracts_iocs() {
    let fetcher: Arc<FixtureFetcher> = Arc::new(FixtureFetcher);
    let report: ProwlReport = disrobe_prowl::harvest_with_keys(
        fetcher,
        &["planted.example.com".to_owned()],
        &Source::all(),
        &Filter {
            subs: true,
            blacklist_extensions: vec!["png".to_owned()],
            ..Filter::default()
        },
        &fast_cfg(),
        &all_keys(),
    )
    .await;

    assert!(
        report
            .urls
            .iter()
            .all(|u| !u.url.to_ascii_lowercase().ends_with(".png")),
        "png blacklisted"
    );
    assert!(
        report
            .urls
            .iter()
            .any(|u| u.url == "https://planted.example.com/dashboard")
    );
    assert!(
        report
            .urls
            .iter()
            .any(|u| u.url == "http://planted.example.com/c2/gate.php")
    );
    assert!(
        report
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Subdomain && i.value == "api.planted.example.com"),
        "crt.sh subdomain folded in"
    );
    assert!(
        report
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Ipv4 && i.value == "203.0.113.55"),
        "threatfox ip folded in"
    );
    let dup_urls: usize = {
        let mut all: Vec<&str> = report.urls.iter().map(|u| u.url.as_str()).collect();
        let before: usize = all.len();
        all.sort_unstable();
        all.dedup();
        before - all.len()
    };
    assert_eq!(dup_urls, 0, "report URLs are de-duplicated");
}

#[tokio::test]
async fn host_scoping_drops_offtarget_for_url_archives() {
    let fetcher: Arc<FixtureFetcher> = Arc::new(FixtureFetcher);
    let report: ProwlReport = disrobe_prowl::harvest(
        fetcher,
        &["planted.example.com".to_owned()],
        &[Source::Wayback],
        &Filter::default(),
        &fast_cfg(),
    )
    .await;
    assert!(
        report
            .urls
            .iter()
            .all(|u| !u.url.contains("shop.planted.example.com")),
        "subdomain dropped without subs"
    );
}

#[test]
fn proxy_config_constructs_fetcher() {
    let cfg: HttpConfig = HttpConfig {
        proxy: Some("http://127.0.0.1:8080".to_owned()),
        ..HttpConfig::default()
    };
    let built: Result<ReqwestFetcher, FetchError> = ReqwestFetcher::new(&cfg);
    assert!(built.is_ok(), "proxy-configured fetcher builds");
    let bad: HttpConfig = HttpConfig {
        proxy: Some("not a url".to_owned()),
        ..HttpConfig::default()
    };
    assert!(ReqwestFetcher::new(&bad).is_err(), "invalid proxy rejected");
}

#[test]
fn batch_and_recon_interop_inputs() {
    let lines: Vec<String> =
        parse_target_lines("a.example\n# skip\nhttps://b.example/x\na.example\n");
    assert_eq!(lines, vec!["a.example", "b.example"]);

    let recon: &str = r#"{"schema":"disrobe.recon/v0","findings":[
        {"category":"url","value":"https://c2.example/beacon","line":1,"column":1,"offset":0,"severity":"high","rule_id":"r"},
        {"category":"ipv4","value":"198.51.100.7","line":1,"column":1,"offset":0,"severity":"high","rule_id":"r"}]}"#;
    let targets: Vec<String> = targets_from_disrobe_report(recon);
    assert_eq!(targets, vec!["c2.example", "198.51.100.7"]);
}
