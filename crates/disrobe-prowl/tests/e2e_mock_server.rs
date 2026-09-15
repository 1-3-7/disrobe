#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use disrobe_prowl::http::{FetchError, FetchResponse, Fetcher};
use disrobe_prowl::provider::Request;
use disrobe_prowl::{
    EngineConfig, Filter, HttpConfig, IocKind, KeySet, ProviderOutcome, ProwlReport,
    ReqwestFetcher, Source,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

fn fixture(name: &str) -> String {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

#[derive(Debug, Default)]
struct CapturedRequest {
    path: String,
    headers: BTreeMap<String, String>,
    #[allow(dead_code)]
    body: String,
}

#[derive(Debug)]
struct MockServer {
    addr: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

fn route_fixture(path: &str) -> Option<(u16, String)> {
    if path.contains("/cdx/") {
        Some((200, fixture("wayback.json")))
    } else if path.contains("/collinfo") {
        Some((200, "[{\"id\":\"CC-MAIN-2099-99\"}]".to_owned()))
    } else if path.contains("-index") {
        Some((200, fixture("commoncrawl.ndjson")))
    } else if path.contains("/url_list") {
        Some((200, fixture("otx.json")))
    } else if path.contains("/search/") {
        Some((200, fixture("urlscan.json")))
    } else if path.contains("crt.sh") || path.starts_with("/?q=") {
        Some((200, fixture("crtsh.json")))
    } else if path.contains("/host/") {
        Some((200, fixture("urlhaus.json")))
    } else if path.contains("/api/v1/") {
        Some((200, fixture("threatfox.json")))
    } else if path.contains("/api/v3/domains/") {
        Some((200, fixture("virustotal.json")))
    } else {
        None
    }
}

async fn read_http_request(stream: &mut TcpStream) -> (String, BTreeMap<String, String>, String) {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp: [u8; 2048] = [0u8; 2048];
    let mut header_end: Option<usize> = None;
    while header_end.is_none() {
        let n: usize = stream
            .read(&mut tmp)
            .await
            .map_or(0usize, |value: usize| value);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        header_end = buf
            .windows(4)
            .position(|w: &[u8]| w == b"\r\n\r\n")
            .map(|p: usize| p + 4);
    }
    let head_len: usize = header_end.map_or(buf.len(), |value: usize| value);
    let head: String = String::from_utf8_lossy(&buf[..head_len]).into_owned();
    let mut lines: std::str::Lines<'_> = head.lines();
    let request_line: &str = lines.next().map_or("", |value: &str| value);
    let path: String = request_line
        .split_whitespace()
        .nth(1)
        .map_or("/", |value: &str| value)
        .to_owned();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name: String = name.trim().to_ascii_lowercase();
            let value: String = value.trim().to_owned();
            if name == "content-length" {
                content_length = value.parse().map_or(0usize, |parsed: usize| parsed);
            }
            headers.insert(name, value);
        }
    }
    let mut body: Vec<u8> = buf[head_len..].to_vec();
    while body.len() < content_length {
        let n: usize = stream
            .read(&mut tmp)
            .await
            .map_or(0usize, |value: usize| value);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    (path, headers, String::from_utf8_lossy(&body).into_owned())
}

impl MockServer {
    async fn start() -> Self {
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: String = listener.local_addr().unwrap().to_string();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_loop: Arc<Mutex<Vec<CapturedRequest>>> = Arc::clone(&captured);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)): Result<(TcpStream, _), _> = listener.accept().await else {
                    break;
                };
                let captured_conn: Arc<Mutex<Vec<CapturedRequest>>> = Arc::clone(&captured_loop);
                tokio::spawn(async move {
                    let (path, headers, body): (String, BTreeMap<String, String>, String) =
                        read_http_request(&mut stream).await;
                    captured_conn.lock().unwrap().push(CapturedRequest {
                        path: path.clone(),
                        headers: headers.clone(),
                        body,
                    });
                    let (status, payload): (u16, String) =
                        route_fixture(&path).unwrap_or_else(|| (404, "{}".to_owned()));
                    let reason: &str = if status == 200 { "OK" } else { "Not Found" };
                    let response: String = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self { addr, captured }
    }
}

#[derive(Debug)]
struct RewritingFetcher {
    inner: ReqwestFetcher,
    base: String,
    auth_fail_for: Mutex<BTreeMap<String, u32>>,
    rate_fail_for: Mutex<BTreeMap<String, u32>>,
}

impl RewritingFetcher {
    fn new(base: String) -> Self {
        Self {
            inner: ReqwestFetcher::new(&HttpConfig {
                timeout: Duration::from_secs(5),
                ..HttpConfig::default()
            })
            .unwrap(),
            base,
            auth_fail_for: Mutex::new(BTreeMap::new()),
            rate_fail_for: Mutex::new(BTreeMap::new()),
        }
    }

    fn fail_auth(self, marker: &str, times: u32) -> Self {
        self.auth_fail_for
            .lock()
            .unwrap()
            .insert(marker.to_owned(), times);
        self
    }

    fn fail_rate(self, marker: &str, times: u32) -> Self {
        self.rate_fail_for
            .lock()
            .unwrap()
            .insert(marker.to_owned(), times);
        self
    }

    fn rewrite(&self, url: &str) -> String {
        let after: &str = url.split_once("://").map_or(url, |(_, r): (&str, &str)| r);
        let path_and_query: &str = after.split_once('/').map_or("/", |(_, r): (&str, &str)| r);
        format!("{}/{path_and_query}", self.base)
    }
}

#[async_trait]
impl Fetcher for RewritingFetcher {
    async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
        {
            let mut guard: std::sync::MutexGuard<'_, BTreeMap<String, u32>> =
                self.auth_fail_for.lock().unwrap();
            for (marker, remaining) in guard.iter_mut() {
                if request.url.contains(marker.as_str()) && *remaining > 0 {
                    *remaining -= 1;
                    return Err(FetchError::Status(401));
                }
            }
        }
        {
            let mut guard: std::sync::MutexGuard<'_, BTreeMap<String, u32>> =
                self.rate_fail_for.lock().unwrap();
            for (marker, remaining) in guard.iter_mut() {
                if request.url.contains(marker.as_str()) && *remaining > 0 {
                    *remaining -= 1;
                    return Err(FetchError::Status(429));
                }
            }
        }
        let rewritten: String = self.rewrite(&request.url);
        let local: Request = Request {
            method: request.method,
            url: rewritten,
            body: request.body.clone(),
            content_type: request.content_type,
            headers: request.headers.clone(),
            page: request.page,
        };
        self.inner.fetch(&local).await
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
    keys.insert(Source::Urlhaus, "uh-e2e-key-0000000000".to_owned());
    keys.insert(Source::Threatfox, "tf-e2e-key-1111111111".to_owned());
    keys.insert(Source::Virustotal, "vt-e2e-key-2222222222".to_owned());
    keys.insert(Source::Urlscan, "us-e2e-key-3333333333".to_owned());
    keys.insert(Source::Otx, "otx-e2e-key-4444444444".to_owned());
    keys
}

fn captured_header(captured: &[CapturedRequest], needle: &str, name: &str) -> Option<String> {
    captured
        .iter()
        .find(|c: &&CapturedRequest| c.path.contains(needle))
        .and_then(|c: &CapturedRequest| c.headers.get(name).cloned())
}

#[tokio::test]
async fn e2e_harvest_against_local_mock_server_emits_known_urls_and_iocs() {
    let server: MockServer = MockServer::start().await;
    let fetcher: Arc<RewritingFetcher> =
        Arc::new(RewritingFetcher::new(format!("http://{}", server.addr)));
    let report: ProwlReport = disrobe_prowl::harvest_with_keys(
        Arc::clone(&fetcher) as Arc<dyn Fetcher>,
        &["planted.example.com".to_owned()],
        &Source::all(),
        &Filter {
            subs: true,
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
            .any(|u| u.url == "https://planted.example.com/dashboard"),
        "urlscan url surfaced over real localhost HTTP"
    );
    assert!(
        report
            .urls
            .iter()
            .any(|u| u.url == "http://planted.example.com/c2/gate.php"),
        "threatfox malware url surfaced"
    );
    assert!(
        report
            .urls
            .iter()
            .any(|u| u.url == "https://planted.example.com/vt/observed"),
        "virustotal url surfaced"
    );
    assert!(
        report
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Ipv4 && i.value == "203.0.113.55"),
        "threatfox ip ioc folded in"
    );
    assert!(
        report
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Subdomain && i.value == "api.planted.example.com"),
        "crt.sh subdomain folded in"
    );

    let captured: Vec<CapturedRequest> = {
        let guard: std::sync::MutexGuard<'_, Vec<CapturedRequest>> =
            server.captured.lock().unwrap();
        guard
            .iter()
            .map(|c: &CapturedRequest| CapturedRequest {
                path: c.path.clone(),
                headers: c.headers.clone(),
                body: c.body.clone(),
            })
            .collect()
    };
    assert_eq!(
        captured_header(&captured, "/api/v3/domains/", "x-apikey").as_deref(),
        Some("vt-e2e-key-2222222222"),
        "VirusTotal x-apikey header sent verbatim"
    );
    assert_eq!(
        captured_header(&captured, "/api/v1/search/", "api-key").as_deref(),
        Some("us-e2e-key-3333333333"),
        "urlscan API-Key header sent"
    );
    assert_eq!(
        captured_header(&captured, "/url_list", "x-otx-api-key").as_deref(),
        Some("otx-e2e-key-4444444444"),
        "OTX X-OTX-API-KEY header sent"
    );
    assert_eq!(
        captured_header(&captured, "/host/", "auth-key").as_deref(),
        Some("uh-e2e-key-0000000000"),
        "URLhaus Auth-Key header sent"
    );

    assert!(
        report
            .providers
            .iter()
            .all(|p| p.outcome == ProviderOutcome::Ok),
        "every provider OK against the mock: {:?}",
        report.providers
    );
}

#[tokio::test]
async fn e2e_unauthorized_provider_skipped_while_others_complete() {
    let server: MockServer = MockServer::start().await;
    let fetcher: Arc<RewritingFetcher> = Arc::new(
        RewritingFetcher::new(format!("http://{}", server.addr)).fail_auth("virustotal.com", 99),
    );
    let report: ProwlReport = disrobe_prowl::harvest_with_keys(
        Arc::clone(&fetcher) as Arc<dyn Fetcher>,
        &["planted.example.com".to_owned()],
        &[Source::Wayback, Source::Virustotal],
        &Filter::default(),
        &fast_cfg(),
        &all_keys(),
    )
    .await;

    let vt_outcome: ProviderOutcome = report
        .providers
        .iter()
        .find(|p| p.source == Source::Virustotal)
        .map(|p| p.outcome)
        .expect("vt status");
    assert_eq!(vt_outcome, ProviderOutcome::Unauthorized);
    assert!(
        report
            .urls
            .iter()
            .any(|u| u.url == "https://planted.example.com/"),
        "wayback still harvested despite VT 401"
    );
    assert!(
        report
            .providers
            .iter()
            .any(|p| p.source == Source::Wayback && p.outcome == ProviderOutcome::Ok),
        "wayback reported OK"
    );
}

#[tokio::test]
async fn e2e_429_retries_then_succeeds() {
    let server: MockServer = MockServer::start().await;
    let fetcher: Arc<RewritingFetcher> =
        Arc::new(RewritingFetcher::new(format!("http://{}", server.addr)).fail_rate("/cdx/", 2));
    let cfg: EngineConfig = EngineConfig {
        base_backoff: Duration::from_millis(0),
        max_backoff: Duration::from_millis(0),
        per_host_rps: 0.0,
        per_host_burst: 1.0,
        max_retries: 3,
        ..EngineConfig::default()
    };
    let report: ProwlReport = disrobe_prowl::harvest_with_keys(
        Arc::clone(&fetcher) as Arc<dyn Fetcher>,
        &["planted.example.com".to_owned()],
        &[Source::Wayback],
        &Filter::default(),
        &cfg,
        &all_keys(),
    )
    .await;
    assert!(
        report.url_total > 0,
        "wayback harvested over localhost after two 429s"
    );
    assert!(
        report
            .providers
            .iter()
            .any(|p| p.source == Source::Wayback && p.outcome == ProviderOutcome::Ok)
    );
}
