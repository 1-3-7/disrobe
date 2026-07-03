use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Proxy;

use crate::provider::{Method, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    Status(u16),
    Transport(String),
}

impl FetchError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Status(429 | 500 | 502 | 503 | 504))
    }

    #[must_use]
    pub const fn is_auth_error(&self) -> bool {
        matches!(self, Self::Status(401 | 403))
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(code) => write!(f, "HTTP {code}"),
            Self::Transport(msg) => write!(f, "{msg}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub body: String,
    pub retry_after_secs: Option<u64>,
    pub truncated: bool,
}

#[async_trait]
pub trait Fetcher: Send + Sync + std::fmt::Debug {
    async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError>;
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub user_agent: String,
    pub timeout: Duration,
    pub proxy: Option<String>,
    pub max_response_bytes: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            user_agent: format!("disrobe-prowl/{}", env!("CARGO_PKG_VERSION")),
            timeout: Duration::from_secs(45),
            proxy: None,
            max_response_bytes: 64 << 20,
        }
    }
}

#[derive(Debug)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
    max_response_bytes: usize,
}

impl ReqwestFetcher {
    /// Builds a reqwest async client honoring the configured timeout, user-agent and proxy.
    /// An explicit `proxy` wins; otherwise reqwest reads `HTTP_PROXY`/`HTTPS_PROXY` from the
    /// environment automatically.
    pub fn new(config: &HttpConfig) -> Result<Self, FetchError> {
        let mut builder: reqwest::ClientBuilder = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .timeout(config.timeout)
            .gzip(true);
        if let Some(proxy_url) = &config.proxy {
            let proxy: Proxy =
                Proxy::all(proxy_url).map_err(|e| FetchError::Transport(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
        let client: reqwest::Client = builder
            .build()
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            max_response_bytes: config.max_response_bytes,
        })
    }
}

#[must_use]
fn parse_retry_after(value: Option<&str>) -> Option<u64> {
    value?.trim().parse::<u64>().ok()
}

#[async_trait]
impl Fetcher for ReqwestFetcher {
    async fn fetch(&self, request: &Request) -> Result<FetchResponse, FetchError> {
        let mut builder: reqwest::RequestBuilder = match request.method {
            Method::Get => self.client.get(&request.url),
            Method::Post => self.client.post(&request.url),
        };
        if let Some(ct) = request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, ct);
        }
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        let mut resp: reqwest::Response = builder
            .send()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        let status: u16 = resp.status().as_u16();
        let retry_after: Option<u64> = parse_retry_after(
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
        );
        if !resp.status().is_success() {
            return Err(FetchError::Status(status));
        }
        let mut raw: Vec<u8> = Vec::new();
        let mut truncated: bool = false;
        while raw.len() < self.max_response_bytes {
            let Some(chunk): Option<Bytes> = resp
                .chunk()
                .await
                .map_err(|e| FetchError::Transport(e.to_string()))?
            else {
                break;
            };
            let remaining: usize = self.max_response_bytes - raw.len();
            let take: usize = chunk.len().min(remaining);
            raw.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                truncated = true;
                break;
            }
        }
        if !truncated && raw.len() == self.max_response_bytes {
            let next_chunk: Option<Bytes> = resp
                .chunk()
                .await
                .map_err(|e| FetchError::Transport(e.to_string()))?;
            if next_chunk.is_some() {
                truncated = true;
            }
        }
        let body: String = String::from_utf8_lossy(&raw).into_owned();
        Ok(FetchResponse {
            body,
            retry_after_secs: retry_after,
            truncated,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn fetch_caps_response_body_while_reading() {
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: std::net::SocketAddr = listener.local_addr().unwrap();
        let server: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            let (mut stream, _): (tokio::net::TcpStream, std::net::SocketAddr) =
                listener.accept().await.unwrap();
            let mut request: [u8; 1024] = [0u8; 1024];
            let _read: usize = stream.read(&mut request).await.unwrap();
            let body: &str = "abcdef";
            let response: String = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let config: HttpConfig = HttpConfig {
            user_agent: "prowl-test".to_owned(),
            timeout: Duration::from_secs(5),
            proxy: None,
            max_response_bytes: 3,
        };
        let fetcher: ReqwestFetcher = ReqwestFetcher::new(&config).unwrap();
        let request: Request = Request::get(format!("http://{addr}/"));
        let response: FetchResponse = fetcher.fetch(&request).await.unwrap();

        assert_eq!(response.body, "abc");
        assert!(response.truncated);
        server.await.unwrap();
    }
}
