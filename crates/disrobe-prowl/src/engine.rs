use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt as _};

use crate::extract::extract_iocs;
use crate::filter::{Filter, apply_ioc_filters, apply_url_filters};
use crate::http::{FetchError, FetchResponse, Fetcher};
use crate::keys::{AuthPolicy, auth_policy, prowl_env};
use crate::model::{
    HarvestedUrl, Ioc, PROWL_SCHEMA, ProviderOutcome, ProviderStatus, ProwlReport, Source,
};
use crate::provider::{Provider, Request, Yield};
use crate::providers;
use crate::ratelimit::{HostRateLimiter, RateConfig};

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub provider_concurrency: usize,
    pub max_pages_per_provider: u32,
    pub max_urls: usize,
    pub max_iocs: usize,
    pub max_retries: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub per_host_rps: f64,
    pub per_host_burst: f64,
    pub extract_iocs: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            provider_concurrency: 12,
            max_pages_per_provider: 50,
            max_urls: 1_000_000,
            max_iocs: 1_000_000,
            max_retries: 3,
            base_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            per_host_rps: 4.0,
            per_host_burst: 4.0,
            extract_iocs: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeySet {
    keys: BTreeMap<Source, String>,
}

impl KeySet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, source: Source, key: String) {
        self.keys.insert(source, key);
    }

    #[must_use]
    pub fn get(&self, source: Source) -> Option<&str> {
        self.keys.get(&source).map(String::as_str)
    }
}

/// Computes the exponential backoff for `attempt` (0-based), honoring a server `Retry-After` hint when present, clamped to `max`.
#[must_use]
pub fn backoff_for(
    attempt: u32,
    base: Duration,
    max: Duration,
    retry_after: Option<u64>,
) -> Duration {
    if let Some(secs) = retry_after {
        return Duration::from_secs(secs).min(max);
    }
    let factor: u32 = 1u32
        .checked_shl(attempt)
        .map_or(u32::MAX, |value: u32| value);
    base.saturating_mul(factor).min(max)
}

async fn fetch_with_retry(
    fetcher: &dyn Fetcher,
    request: &Request,
    config: &EngineConfig,
) -> Result<FetchResponse, FetchError> {
    let mut attempt: u32 = 0;
    loop {
        match fetcher.fetch(request).await {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                if !err.is_retryable() || attempt >= config.max_retries {
                    return Err(err);
                }
                let wait: Duration =
                    backoff_for(attempt, config.base_backoff, config.max_backoff, None);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                attempt += 1;
            }
        }
    }
}

#[derive(Debug)]
struct HarvestOutcome {
    yields: Yield,
    outcome: ProviderOutcome,
    note: Option<String>,
}

async fn harvest_one(
    provider: &dyn Provider,
    fetcher: &dyn Fetcher,
    limiter: &HostRateLimiter,
    target: &str,
    filter: &Filter,
    config: &EngineConfig,
) -> HarvestOutcome {
    let mut merged: Yield = Yield::default();
    let mut queue: Vec<Request> = provider.seed_requests(target, filter);
    let mut pages: u32 = 0;
    let mut outcome: ProviderOutcome = ProviderOutcome::Ok;
    let mut note: Option<String> = None;
    while let Some(request) = queue.pop() {
        if pages >= config.max_pages_per_provider {
            break;
        }
        pages += 1;
        limiter
            .acquire(&HostRateLimiter::host_of(&request.url))
            .await;
        match fetch_with_retry(fetcher, &request, config).await {
            Ok(resp) => {
                if resp.truncated && note.is_none() {
                    note = Some("response capped by fetcher limit".to_owned());
                }
                let page_yield: Yield = provider.parse(&resp.body);
                if let Some(next) = provider.next_request(target, filter, &request, &page_yield) {
                    queue.push(next);
                }
                merged.urls.extend(page_yield.urls);
                merged.iocs.extend(page_yield.iocs);
                if merged.iocs.len() > config.max_iocs {
                    merged.iocs.truncate(config.max_iocs);
                }
                if merged.urls.len() >= config.max_urls {
                    merged.urls.truncate(config.max_urls);
                    break;
                }
            }
            Err(err) if err.is_auth_error() => {
                outcome = ProviderOutcome::Unauthorized;
                let source: Source = provider.source();
                note = Some(format!(
                    "API key missing/unauthorized/expired - set {}",
                    prowl_env(source)
                ));
                break;
            }
            Err(err) => {
                outcome = ProviderOutcome::Failed;
                note = Some(err.to_string());
                break;
            }
        }
    }
    HarvestOutcome {
        yields: merged,
        outcome,
        note,
    }
}

/// Resolves the latest Common Crawl index id so harvests do not pin a stale collection.
async fn resolve_commoncrawl_index(fetcher: &dyn Fetcher) -> Option<String> {
    let request: Request =
        Request::get(providers::url_archive::CommonCrawl::collinfo_url().to_owned());
    let resp: FetchResponse = fetcher.fetch(&request).await.ok()?;
    providers::url_archive::CommonCrawl::latest_index_from_collinfo(&resp.body)
}

/// Harvests every requested source for each target with no API keys (anonymous access only).
pub async fn harvest(
    fetcher: Arc<dyn Fetcher>,
    targets: &[String],
    sources: &[Source],
    filter: &Filter,
    config: &EngineConfig,
) -> ProwlReport {
    harvest_with_keys(fetcher, targets, sources, filter, config, &KeySet::new()).await
}

#[derive(Debug, Default)]
struct ProviderAccumulator {
    urls: usize,
    iocs: usize,
    outcomes: Vec<ProviderOutcome>,
    note: Option<String>,
}

/// Harvests every requested source for each target, authenticating with `keys` where a service supports or requires an API key.
pub async fn harvest_with_keys(
    fetcher: Arc<dyn Fetcher>,
    targets: &[String],
    sources: &[Source],
    filter: &Filter,
    config: &EngineConfig,
    keys: &KeySet,
) -> ProwlReport {
    let cc_index: Option<String> = if sources.contains(&Source::CommonCrawl) {
        resolve_commoncrawl_index(fetcher.as_ref()).await
    } else {
        None
    };

    let limiter: HostRateLimiter = HostRateLimiter::new(RateConfig {
        per_host_rps: config.per_host_rps,
        burst: config.per_host_burst.max(1.0),
    });

    let mut status: BTreeMap<Source, ProviderAccumulator> = BTreeMap::new();
    for source in sources {
        status.entry(*source).or_default();
    }

    let mut jobs: Vec<(Source, String)> = Vec::new();
    for source in sources {
        if matches!(auth_policy(*source), AuthPolicy::Required) && keys.get(*source).is_none() {
            if let Some(acc) = status.get_mut(source) {
                acc.outcomes.push(ProviderOutcome::Skipped);
                acc.note = Some(format!(
                    "requires an API key - set {} (skipped)",
                    prowl_env(*source)
                ));
            }
            continue;
        }
        for target in targets {
            jobs.push((*source, target.clone()));
        }
    }

    let results: Vec<(Source, HarvestOutcome)> = stream::iter(jobs)
        .map(|(source, target): (Source, String)| {
            let fetcher: Arc<dyn Fetcher> = Arc::clone(&fetcher);
            let filter: Filter = filter.clone();
            let config: EngineConfig = config.clone();
            let cc_index: Option<String> = cc_index.clone();
            let limiter: HostRateLimiter = limiter.clone();
            let key: Option<String> = keys.get(source).map(str::to_owned);
            async move {
                let provider: Box<dyn Provider> = match (source, cc_index) {
                    (Source::CommonCrawl, Some(index)) => {
                        Box::new(providers::url_archive::CommonCrawl { index })
                    }
                    _ => providers::build_with_key(source, key),
                };
                let outcome: HarvestOutcome = harvest_one(
                    provider.as_ref(),
                    fetcher.as_ref(),
                    &limiter,
                    &target,
                    &filter,
                    &config,
                )
                .await;
                (source, outcome)
            }
        })
        .buffer_unordered(config.provider_concurrency.max(1))
        .collect()
        .await;

    let mut raw_urls: Vec<HarvestedUrl> = Vec::new();
    let mut raw_iocs: Vec<Ioc> = Vec::new();
    for (source, outcome) in results {
        let acc: &mut ProviderAccumulator = status.entry(source).or_default();
        acc.urls += outcome.yields.urls.len();
        acc.iocs += outcome.yields.iocs.len();
        acc.outcomes.push(outcome.outcome);
        if acc.note.is_none() {
            acc.note = outcome.note;
        }
        raw_urls.extend(outcome.yields.urls);
        if raw_urls.len() > config.max_urls {
            raw_urls.truncate(config.max_urls);
        }
        raw_iocs.extend(outcome.yields.iocs);
        if raw_iocs.len() > config.max_iocs {
            raw_iocs.truncate(config.max_iocs);
        }
    }

    let url_scope: Vec<String> = targets.to_vec();
    let mut urls: Vec<HarvestedUrl> = apply_url_filters(raw_urls, &url_scope, filter);
    if urls.len() > config.max_urls {
        urls.truncate(config.max_urls);
    }

    if config.extract_iocs {
        raw_iocs.extend(extract_iocs(&urls, &[]));
        if raw_iocs.len() > config.max_iocs {
            raw_iocs.truncate(config.max_iocs);
        }
    }
    let mut iocs: Vec<Ioc> = apply_ioc_filters(raw_iocs, filter);
    if iocs.len() > config.max_iocs {
        iocs.truncate(config.max_iocs);
    }

    let providers: Vec<ProviderStatus> = sources
        .iter()
        .filter_map(|source: &Source| {
            status
                .get(source)
                .map(|acc: &ProviderAccumulator| ProviderStatus {
                    source: *source,
                    outcome: fold_outcome(&acc.outcomes),
                    urls: acc.urls,
                    iocs: acc.iocs,
                    note: acc.note.clone(),
                })
        })
        .collect();

    ProwlReport {
        schema: PROWL_SCHEMA,
        targets: targets.to_vec(),
        sources: sources.to_vec(),
        url_total: urls.len(),
        ioc_total: iocs.len(),
        urls,
        iocs,
        providers,
    }
}

#[must_use]
fn fold_outcome(outcomes: &[ProviderOutcome]) -> ProviderOutcome {
    if outcomes.is_empty() {
        return ProviderOutcome::Failed;
    }
    if outcomes.contains(&ProviderOutcome::Ok) {
        return ProviderOutcome::Ok;
    }
    if outcomes.contains(&ProviderOutcome::Unauthorized) {
        return ProviderOutcome::Unauthorized;
    }
    if outcomes
        .iter()
        .all(|o: &ProviderOutcome| *o == ProviderOutcome::Skipped)
    {
        return ProviderOutcome::Skipped;
    }
    ProviderOutcome::Failed
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::FetchResponse;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct MockFetcher {
        responses: BTreeMap<String, Result<FetchResponse, FetchError>>,
        calls: Mutex<Vec<String>>,
        fail_then: Mutex<BTreeMap<String, u32>>,
    }

    impl MockFetcher {
        fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
                calls: Mutex::new(Vec::new()),
                fail_then: Mutex::new(BTreeMap::new()),
            }
        }

        fn with(mut self, key: &str, body: &str) -> Self {
            self.responses.insert(
                key.to_owned(),
                Ok(FetchResponse {
                    body: body.to_owned(),
                    retry_after_secs: None,
                    truncated: false,
                }),
            );
            self
        }

        fn match_key(&self, url: &str) -> Option<String> {
            self.responses
                .keys()
                .find(|k: &&String| url.contains(k.as_str()))
                .cloned()
        }
    }

    #[async_trait]
    impl Fetcher for MockFetcher {
        async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
            self.calls.lock().unwrap().push(request.url.clone());
            let Some(key): Option<String> = self.match_key(&request.url) else {
                return Err(FetchError::Status(404));
            };
            let should_fail: bool = {
                let mut ft: std::sync::MutexGuard<'_, BTreeMap<String, u32>> =
                    self.fail_then.lock().unwrap();
                match ft.get_mut(&key) {
                    Some(remaining) if *remaining > 0 => {
                        *remaining -= 1;
                        true
                    }
                    _ => false,
                }
            };
            if should_fail {
                return Err(FetchError::Status(429));
            }
            self.responses.get(&key).cloned().unwrap()
        }
    }

    fn cfg() -> EngineConfig {
        EngineConfig {
            base_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            per_host_rps: 0.0,
            per_host_burst: 1.0,
            ..EngineConfig::default()
        }
    }

    #[tokio::test]
    async fn wayback_and_threatfox_merge_into_report() {
        let wayback: &str = r#"[["original","timestamp","statuscode","mimetype"],
            ["https://t.example/a","20230101","200","text/html"]]"#;
        let tfox: &str = r#"{"query_status":"ok","data":[
            {"ioc":"5.6.7.8:443","ioc_type":"ip:port","malware":"x"},
            {"ioc":"http://t.example/mal","ioc_type":"url","malware":"y"}]}"#;
        let fetcher: Arc<MockFetcher> = Arc::new(
            MockFetcher::new()
                .with("web.archive.org", wayback)
                .with("threatfox", tfox),
        );
        let mut keys: KeySet = KeySet::new();
        keys.insert(Source::Threatfox, "tfox-test-key-aaaaaaaaaa".to_owned());
        let report: ProwlReport = harvest_with_keys(
            fetcher,
            &["t.example".to_owned()],
            &[Source::Wayback, Source::Threatfox],
            &Filter::default(),
            &cfg(),
            &keys,
        )
        .await;
        assert!(
            report
                .urls
                .iter()
                .any(|u: &HarvestedUrl| u.url == "https://t.example/a")
        );
        assert!(
            report
                .urls
                .iter()
                .any(|u: &HarvestedUrl| u.url == "http://t.example/mal")
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|i: &Ioc| i.value == "5.6.7.8" && i.kind == crate::model::IocKind::Ipv4)
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|i: &Ioc| i.value == "t.example" && i.kind == crate::model::IocKind::Domain)
        );
    }

    #[tokio::test]
    async fn retries_on_429_then_succeeds() {
        let wayback: &str = r#"[["original","timestamp","statuscode","mimetype"],["https://r.example/x","20230101","200","text/html"]]"#;
        let mock: MockFetcher = MockFetcher::new().with("web.archive.org", wayback);
        mock.fail_then
            .lock()
            .unwrap()
            .insert("web.archive.org".to_owned(), 2);
        let fetcher: Arc<MockFetcher> = Arc::new(mock);
        let report: ProwlReport = harvest(
            Arc::clone(&fetcher) as Arc<dyn Fetcher>,
            &["r.example".to_owned()],
            &[Source::Wayback],
            &Filter::default(),
            &cfg(),
        )
        .await;
        assert_eq!(report.url_total, 1);
        assert_eq!(fetcher.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn final_url_and_ioc_caps_are_enforced_after_merge() {
        let wayback: &str = r#"[["original","timestamp","statuscode","mimetype"],
            ["https://cap.example/a","20230101","200","text/html"],
            ["https://cap.example/b","20230102","200","text/html"]]"#;
        let tfox: &str = r#"{"query_status":"ok","data":[
            {"ioc":"5.6.7.8:443","ioc_type":"ip:port","malware":"x"},
            {"ioc":"9.10.11.12","ioc_type":"ip","malware":"y"}]}"#;
        let fetcher: Arc<MockFetcher> = Arc::new(
            MockFetcher::new()
                .with("web.archive.org", wayback)
                .with("threatfox", tfox),
        );
        let mut keys: KeySet = KeySet::new();
        keys.insert(Source::Threatfox, "tfox-cap-key-0000000000".to_owned());
        let config: EngineConfig = EngineConfig {
            max_urls: 1,
            max_iocs: 1,
            extract_iocs: false,
            ..cfg()
        };
        let report: ProwlReport = harvest_with_keys(
            fetcher,
            &["cap.example".to_owned()],
            &[Source::Wayback, Source::Threatfox],
            &Filter::default(),
            &config,
            &keys,
        )
        .await;
        assert_eq!(report.urls.len(), 1);
        assert_eq!(report.iocs.len(), 1);
        assert_eq!(report.url_total, 1);
        assert_eq!(report.ioc_total, 1);
    }

    #[tokio::test]
    async fn gives_up_after_max_retries() {
        let mock: MockFetcher = MockFetcher::new().with("web.archive.org", "[[\"original\"]]");
        mock.fail_then
            .lock()
            .unwrap()
            .insert("web.archive.org".to_owned(), 99);
        let fetcher: Arc<MockFetcher> = Arc::new(mock);
        let report: ProwlReport = harvest(
            Arc::clone(&fetcher) as Arc<dyn Fetcher>,
            &["g.example".to_owned()],
            &[Source::Wayback],
            &Filter::default(),
            &cfg(),
        )
        .await;
        assert_eq!(report.url_total, 0);
        assert_eq!(
            fetcher.calls.lock().unwrap().len(),
            (cfg().max_retries + 1) as usize
        );
    }

    #[derive(Debug)]
    struct OtxMock {
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl Fetcher for OtxMock {
        async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
            {
                let mut c: std::sync::MutexGuard<'_, u32> = self.calls.lock().unwrap();
                *c += 1;
            }
            let body: &str = if request.url.contains("page=1") {
                r#"{"url_list":[{"url":"https://p.example/1"}]}"#
            } else {
                r#"{"url_list":[]}"#
            };
            Ok(FetchResponse {
                body: body.to_owned(),
                retry_after_secs: None,
                truncated: false,
            })
        }
    }

    #[tokio::test]
    async fn otx_paginates_until_empty() {
        let fetcher: Arc<OtxMock> = Arc::new(OtxMock {
            calls: Mutex::new(0),
        });
        let report: ProwlReport = harvest(
            Arc::clone(&fetcher) as Arc<dyn Fetcher>,
            &["p.example".to_owned()],
            &[Source::Otx],
            &Filter::default(),
            &cfg(),
        )
        .await;
        assert_eq!(report.url_total, 1);
        assert_eq!(*fetcher.calls.lock().unwrap(), 2);
    }

    #[test]
    fn backoff_is_exponential_and_clamped() {
        let base: Duration = Duration::from_millis(100);
        let max: Duration = Duration::from_secs(10);
        assert_eq!(backoff_for(0, base, max, None), Duration::from_millis(100));
        assert_eq!(backoff_for(1, base, max, None), Duration::from_millis(200));
        assert_eq!(backoff_for(2, base, max, None), Duration::from_millis(400));
        assert_eq!(backoff_for(20, base, max, None), max);
        assert_eq!(backoff_for(0, base, max, Some(5)), Duration::from_secs(5));
        assert_eq!(backoff_for(0, base, max, Some(999)), max);
    }

    #[tokio::test]
    async fn key_required_provider_without_key_is_skipped_and_reported() {
        let fetcher: Arc<MockFetcher> = Arc::new(MockFetcher::new());
        let report: ProwlReport = harvest(
            fetcher,
            &["s.example".to_owned()],
            &[Source::Virustotal],
            &Filter::default(),
            &cfg(),
        )
        .await;
        let vt: &ProviderStatus = report
            .providers
            .iter()
            .find(|p: &&ProviderStatus| p.source == Source::Virustotal)
            .expect("vt status present");
        assert_eq!(vt.outcome, ProviderOutcome::Skipped);
        assert!(
            vt.note
                .as_deref()
                .map_or("", |value: &str| value)
                .contains("API key")
        );
    }

    #[derive(Debug)]
    struct AuthMock {
        seen_headers: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl Fetcher for AuthMock {
        async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
            for (name, value) in &request.headers {
                self.seen_headers
                    .lock()
                    .unwrap()
                    .push((name.clone(), value.clone()));
            }
            if request.url.contains("virustotal.com") {
                let key_ok: bool = request.headers.iter().any(|(n, v): &(String, String)| {
                    n == "x-apikey" && v == "vt-good-key-0000000000"
                });
                if !key_ok {
                    return Err(FetchError::Status(401));
                }
                return Ok(FetchResponse {
                    body: r#"{"data":[{"attributes":{"url":"https://s.example/vt","last_http_response_code":200}}]}"#
                        .to_owned(),
                    retry_after_secs: None,
                    truncated: false,
                });
            }
            Err(FetchError::Status(404))
        }
    }

    #[tokio::test]
    async fn virustotal_sends_x_apikey_header() {
        let fetcher: Arc<AuthMock> = Arc::new(AuthMock {
            seen_headers: Mutex::new(Vec::new()),
        });
        let mut keys: KeySet = KeySet::new();
        keys.insert(Source::Virustotal, "vt-good-key-0000000000".to_owned());
        let report: ProwlReport = harvest_with_keys(
            Arc::clone(&fetcher) as Arc<dyn Fetcher>,
            &["s.example".to_owned()],
            &[Source::Virustotal],
            &Filter::default(),
            &cfg(),
            &keys,
        )
        .await;
        assert_eq!(report.url_total, 1);
        assert!(
            fetcher
                .seen_headers
                .lock()
                .unwrap()
                .iter()
                .any(|(n, v): &(String, String)| n == "x-apikey" && v == "vt-good-key-0000000000"),
            "x-apikey header present"
        );
    }

    #[tokio::test]
    async fn unauthorized_provider_is_skipped_and_others_continue() {
        let fetcher: Arc<AuthMock> = Arc::new(AuthMock {
            seen_headers: Mutex::new(Vec::new()),
        });
        let mut keys: KeySet = KeySet::new();
        keys.insert(Source::Virustotal, "wrong-key-1111111111".to_owned());
        let report: ProwlReport = harvest_with_keys(
            Arc::clone(&fetcher) as Arc<dyn Fetcher>,
            &["s.example".to_owned()],
            &[Source::Virustotal],
            &Filter::default(),
            &cfg(),
            &keys,
        )
        .await;
        let vt: &ProviderStatus = report
            .providers
            .iter()
            .find(|p: &&ProviderStatus| p.source == Source::Virustotal)
            .expect("vt status present");
        assert_eq!(vt.outcome, ProviderOutcome::Unauthorized);
        assert!(
            vt.note
                .as_deref()
                .map_or("", |value: &str| value)
                .contains("unauthorized"),
            "{:?}",
            vt.note
        );
        let header_hits: usize = fetcher.seen_headers.lock().unwrap().len();
        assert_eq!(header_hits, 1, "401 is not retried");
    }
}
