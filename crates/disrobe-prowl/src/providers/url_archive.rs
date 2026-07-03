use async_trait::async_trait;
use serde_json::Value;

use crate::filter::Filter;
use crate::model::{HarvestedUrl, Source};
use crate::provider::{Provider, Request, Yield};

pub const OTX_MAX_PAGES: u32 = 50;
const OTX_PAGE_SIZE: u32 = 500;
const HEX_UPPER: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

#[must_use]
pub fn urlencode(raw: &str) -> String {
    let mut out: String = String::with_capacity(urlencode_prealloc(raw.len()));
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                push_percent_encoded(&mut out, byte);
            }
        }
    }
    out
}

fn push_percent_encoded(out: &mut String, byte: u8) {
    let high: usize = usize::from(byte >> 4);
    let low: usize = usize::from(byte & 0x0f);
    out.push('%');
    out.push(HEX_UPPER[high]);
    out.push(HEX_UPPER[low]);
}

const fn urlencode_prealloc(raw_len: usize) -> usize {
    raw_len.saturating_mul(3)
}

#[must_use]
fn host_pattern(target: &str, subs: bool) -> String {
    let host: String = target.trim().trim_end_matches('/').to_owned();
    if subs {
        format!("*.{host}/*")
    } else {
        format!("{host}/*")
    }
}

#[must_use]
fn status_from_str(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok()
}

#[derive(Debug, Default)]
pub struct Wayback;

#[async_trait]
impl Provider for Wayback {
    fn source(&self) -> Source {
        Source::Wayback
    }

    fn seed_requests(&self, target: &str, filter: &Filter) -> Vec<Request> {
        let pattern: String = host_pattern(target, filter.subs);
        let mut url: String = format!(
            "https://web.archive.org/cdx/search/cdx?url={}&output=json&collapse=urlkey&fl=original,timestamp,statuscode,mimetype",
            urlencode(&pattern)
        );
        if let Some(from) = &filter.from {
            url.push_str("&from=");
            url.push_str(from);
        }
        if let Some(to) = &filter.to {
            url.push_str("&to=");
            url.push_str(to);
        }
        vec![Request::get(url)]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(Value::Array(rows)): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for row in rows.iter().skip(1) {
            let Value::Array(cols) = row else {
                continue;
            };
            let Some(url): Option<&str> = cols.first().and_then(Value::as_str) else {
                continue;
            };
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: cols.get(1).and_then(Value::as_str).map(str::to_owned),
                status: cols
                    .get(2)
                    .and_then(Value::as_str)
                    .and_then(status_from_str),
                mime: cols.get(3).and_then(Value::as_str).map(str::to_owned),
                threat: None,
                tags: Vec::new(),
                source: Source::Wayback,
            });
        }
        Yield {
            urls,
            iocs: Vec::new(),
            next_cursor: None,
        }
    }
}

#[derive(Debug)]
pub struct CommonCrawl {
    pub index: String,
}

impl Default for CommonCrawl {
    fn default() -> Self {
        Self {
            index: "CC-MAIN-2024-10".to_owned(),
        }
    }
}

impl CommonCrawl {
    #[must_use]
    pub const fn collinfo_url() -> &'static str {
        "https://index.commoncrawl.org/collinfo.json"
    }

    #[must_use]
    pub fn latest_index_from_collinfo(body: &str) -> Option<String> {
        let cols: Value = serde_json::from_str(body).ok()?;
        cols.as_array()?
            .first()?
            .get("id")?
            .as_str()
            .map(str::to_owned)
    }
}

#[async_trait]
impl Provider for CommonCrawl {
    fn source(&self) -> Source {
        Source::CommonCrawl
    }

    fn seed_requests(&self, target: &str, filter: &Filter) -> Vec<Request> {
        let pattern: String = host_pattern(target, filter.subs);
        vec![Request::get(format!(
            "https://index.commoncrawl.org/{}-index?url={}&output=json",
            self.index,
            urlencode(&pattern)
        ))]
    }

    fn parse(&self, body: &str) -> Yield {
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for line in body.lines() {
            let trimmed: &str = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(obj): Result<Value, _> = serde_json::from_str(trimmed) else {
                continue;
            };
            let Some(url): Option<&str> = obj.get("url").and_then(Value::as_str) else {
                continue;
            };
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: obj
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status: obj
                    .get("status")
                    .and_then(Value::as_str)
                    .and_then(status_from_str),
                mime: obj
                    .get("mime-detected")
                    .or_else(|| obj.get("mime"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                threat: None,
                tags: Vec::new(),
                source: Source::CommonCrawl,
            });
        }
        Yield {
            urls,
            iocs: Vec::new(),
            next_cursor: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Otx {
    pub api_key: Option<String>,
}

impl Otx {
    #[must_use]
    pub const fn with_key(api_key: Option<String>) -> Self {
        Self { api_key }
    }

    #[must_use]
    fn page_url(target: &str, subs: bool, page: u32) -> String {
        let host: String = target.trim().trim_end_matches('/').to_owned();
        let kind: &str = if subs { "domain" } else { "hostname" };
        format!(
            "https://otx.alienvault.com/api/v1/indicators/{kind}/{host}/url_list?limit={OTX_PAGE_SIZE}&page={page}"
        )
    }

    fn authed(&self, request: Request) -> Request {
        match &self.api_key {
            Some(key) => request.with_header("X-OTX-API-KEY", key),
            None => request,
        }
    }
}

#[async_trait]
impl Provider for Otx {
    fn source(&self) -> Source {
        Source::Otx
    }

    fn seed_requests(&self, target: &str, filter: &Filter) -> Vec<Request> {
        vec![self.authed(Request::get(Self::page_url(target, filter.subs, 1)).at_page(1))]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(obj): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        let Some(Value::Array(list)): Option<&Value> = obj.get("url_list") else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for entry in list {
            let Some(url): Option<&str> = entry.get("url").and_then(Value::as_str) else {
                continue;
            };
            let status: Option<u16> = entry
                .get("httpcode")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n: u64| u16::try_from(n).ok());
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: entry.get("date").and_then(Value::as_str).map(str::to_owned),
                status,
                mime: None,
                threat: None,
                tags: Vec::new(),
                source: Source::Otx,
            });
        }
        Yield {
            urls,
            iocs: Vec::new(),
            next_cursor: None,
        }
    }

    fn next_request(
        &self,
        target: &str,
        filter: &Filter,
        previous: &Request,
        last_yield: &Yield,
    ) -> Option<Request> {
        if last_yield.urls.is_empty() || previous.page >= OTX_MAX_PAGES {
            return None;
        }
        let next: u32 = previous.page + 1;
        Some(self.authed(Request::get(Self::page_url(target, filter.subs, next)).at_page(next)))
    }
}

#[derive(Debug, Default)]
pub struct Urlscan {
    pub api_key: Option<String>,
}

impl Urlscan {
    #[must_use]
    pub const fn with_key(api_key: Option<String>) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl Provider for Urlscan {
    fn source(&self) -> Source {
        Source::Urlscan
    }

    fn seed_requests(&self, target: &str, filter: &Filter) -> Vec<Request> {
        let host: String = target.trim().trim_end_matches('/').to_owned();
        let q: String = if filter.subs {
            format!("domain:{host}")
        } else {
            format!("page.domain:{host}")
        };
        let request: Request = Request::get(format!(
            "https://urlscan.io/api/v1/search/?q={}&size=10000",
            urlencode(&q)
        ));
        let request: Request = match &self.api_key {
            Some(key) => request.with_header("API-Key", key),
            None => request,
        };
        vec![request]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(obj): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        let Some(Value::Array(results)): Option<&Value> = obj.get("results") else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for entry in results {
            let Some(url): Option<&str> = entry
                .get("page")
                .and_then(|p: &Value| p.get("url"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: entry
                    .get("task")
                    .and_then(|t: &Value| t.get("time"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status: None,
                mime: None,
                threat: None,
                tags: Vec::new(),
                source: Source::Urlscan,
            });
        }
        Yield {
            urls,
            iocs: Vec::new(),
            next_cursor: None,
        }
    }
}

pub const VT_PAGE_SIZE: u32 = 40;
pub const VT_MAX_PAGES: u32 = 50;

#[derive(Debug, Default)]
pub struct Virustotal {
    pub api_key: Option<String>,
}

impl Virustotal {
    #[must_use]
    pub const fn with_key(api_key: Option<String>) -> Self {
        Self { api_key }
    }

    #[must_use]
    fn relationship_url(target: &str, cursor: Option<&str>) -> String {
        let host: String = target.trim().trim_end_matches('/').to_owned();
        let mut url: String = format!(
            "https://www.virustotal.com/api/v3/domains/{}/urls?limit={VT_PAGE_SIZE}",
            urlencode(&host)
        );
        if let Some(cursor) = cursor {
            let encoded: String = urlencode(cursor);
            url.push_str("&cursor=");
            url.push_str(&encoded);
        }
        url
    }

    fn authed(&self, request: Request) -> Request {
        match &self.api_key {
            Some(key) => request.with_header("x-apikey", key),
            None => request,
        }
    }
}

#[async_trait]
impl Provider for Virustotal {
    fn source(&self) -> Source {
        Source::Virustotal
    }

    fn seed_requests(&self, target: &str, _filter: &Filter) -> Vec<Request> {
        vec![self.authed(Request::get(Self::relationship_url(target, None)).at_page(1))]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(obj): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        let Some(Value::Array(data)): Option<&Value> = obj.get("data") else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for entry in data {
            let attrs: Option<&Value> = entry.get("attributes");
            let Some(url): Option<&str> = attrs
                .and_then(|a: &Value| a.get("url"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let status: Option<u16> = attrs
                .and_then(|a: &Value| a.get("last_http_response_code"))
                .and_then(Value::as_u64)
                .and_then(|n: u64| u16::try_from(n).ok());
            let threat: Option<String> = attrs
                .and_then(|a: &Value| a.get("last_analysis_stats"))
                .and_then(|s: &Value| s.get("malicious"))
                .and_then(Value::as_u64)
                .filter(|n: &u64| *n > 0)
                .map(|n: u64| format!("malicious:{n}"));
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: attrs
                    .and_then(|a: &Value| a.get("last_submission_date"))
                    .and_then(Value::as_u64)
                    .map(|n: u64| n.to_string()),
                status,
                mime: None,
                threat,
                tags: Vec::new(),
                source: Source::Virustotal,
            });
        }
        let next_cursor: Option<String> = obj
            .get("meta")
            .and_then(|m: &Value| m.get("cursor"))
            .and_then(Value::as_str)
            .filter(|c: &&str| !c.is_empty())
            .map(str::to_owned);
        Yield {
            urls,
            iocs: Vec::new(),
            next_cursor,
        }
    }

    fn next_request(
        &self,
        target: &str,
        _filter: &Filter,
        previous: &Request,
        last_yield: &Yield,
    ) -> Option<Request> {
        if previous.page >= VT_MAX_PAGES {
            return None;
        }
        let cursor: &String = last_yield.next_cursor.as_ref()?;
        let next: u32 = previous.page + 1;
        Some(self.authed(Request::get(Self::relationship_url(target, Some(cursor))).at_page(next)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_escapes_reserved_bytes() {
        let encoded: String = urlencode("a b/?#%");
        assert_eq!(encoded, "a%20b%2F%3F%23%25");
    }

    #[test]
    fn urlencode_prealloc_saturates() {
        let capped: usize = urlencode_prealloc(usize::MAX);
        assert_eq!(capped, usize::MAX);
    }
}
