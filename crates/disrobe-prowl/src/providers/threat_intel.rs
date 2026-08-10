use async_trait::async_trait;
use disrobe_core::codec::web_escape::{PercentEncodeSet, percent_encode_str};
use serde_json::Value;

use crate::filter::Filter;
use crate::model::{HarvestedUrl, Ioc, IocKind, Source};
use crate::provider::{Provider, Request, Yield};

const JSON_CONTENT_TYPE: &str = "application/json";

#[must_use]
fn classify_host(host: &str) -> (IocKind, String) {
    let host: String = host.trim_matches('.').to_ascii_lowercase();
    let labels: usize = host.split('.').filter(|l: &&str| !l.is_empty()).count();
    if labels >= 3 {
        (IocKind::Subdomain, host)
    } else {
        (IocKind::Domain, host)
    }
}

#[derive(Debug, Default)]
pub struct Crtsh;

#[async_trait]
impl Provider for Crtsh {
    fn source(&self) -> Source {
        Source::Crtsh
    }

    fn seed_requests(&self, target: &str, _filter: &Filter) -> Vec<Request> {
        let host: String = target.trim().trim_end_matches('/').to_owned();
        vec![Request::get(format!(
            "https://crt.sh/?q={}&output=json",
            percent_encode_str(&format!("%.{host}"), PercentEncodeSet::RFC3986)
        ))]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(Value::Array(rows)): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        let mut iocs: Vec<Ioc> = Vec::new();
        for row in &rows {
            let mut names: Vec<&str> = Vec::new();
            if let Some(nv) = row.get("name_value").and_then(Value::as_str) {
                names.extend(nv.lines());
            }
            if let Some(cn) = row.get("common_name").and_then(Value::as_str) {
                names.push(cn);
            }
            for raw in names {
                let name: &str = raw.trim().trim_start_matches("*.");
                if name.is_empty() || !name.contains('.') {
                    continue;
                }
                let (kind, value): (IocKind, String) = classify_host(name);
                iocs.push(Ioc {
                    kind,
                    value,
                    source: Source::Crtsh,
                });
            }
        }
        Yield {
            urls: Vec::new(),
            iocs,
            next_cursor: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Urlhaus {
    pub api_key: Option<String>,
}

impl Urlhaus {
    #[must_use]
    pub const fn with_key(api_key: Option<String>) -> Self {
        Self { api_key }
    }
}

#[must_use]
fn host_of_target(target: &str) -> String {
    let stripped: &str = target
        .split_once("://")
        .map_or(target, |(_, rest): (&str, &str)| rest);
    let authority: &str = stripped
        .split(['/', '?', '#'])
        .next()
        .map_or(stripped, |value: &str| value);
    authority
        .rsplit('@')
        .next()
        .map_or(authority, |value: &str| value)
        .split(':')
        .next()
        .map_or(authority, |value: &str| value)
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

#[async_trait]
impl Provider for Urlhaus {
    fn source(&self) -> Source {
        Source::Urlhaus
    }

    fn seed_requests(&self, target: &str, _filter: &Filter) -> Vec<Request> {
        let host: String = host_of_target(target);
        let request: Request = Request::post(
            "https://urlhaus-api.abuse.ch/v1/host/".to_owned(),
            format!(
                "host={}",
                percent_encode_str(&host, PercentEncodeSet::RFC3986)
            ),
            "application/x-www-form-urlencoded",
        );
        let request: Request = match &self.api_key {
            Some(key) => request.with_header("Auth-Key", key),
            None => request,
        };
        vec![request]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(obj): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        if obj.get("query_status").and_then(Value::as_str) != Some("ok") {
            return Yield::default();
        }
        let Some(Value::Array(list)): Option<&Value> = obj.get("urls") else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        for entry in list {
            let Some(url): Option<&str> = entry.get("url").and_then(Value::as_str) else {
                continue;
            };
            let tags: Vec<String> = entry.get("tags").and_then(Value::as_array).map_or_else(
                Vec::new,
                |a: &Vec<Value>| {
                    a.iter()
                        .filter_map(|t: &Value| t.as_str().map(str::to_owned))
                        .collect()
                },
            );
            urls.push(HarvestedUrl {
                url: url.to_owned(),
                timestamp: entry
                    .get("date_added")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status: None,
                mime: None,
                threat: entry
                    .get("threat")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                tags,
                source: Source::Urlhaus,
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
pub struct Threatfox {
    pub api_key: Option<String>,
}

impl Threatfox {
    #[must_use]
    pub const fn with_key(api_key: Option<String>) -> Self {
        Self { api_key }
    }
}

#[must_use]
fn ioc_kind_for(raw: &str, ioc_type: Option<&str>) -> Option<IocKind> {
    let bare: &str = raw.split(':').next().map_or(raw, |value: &str| value);
    match ioc_type {
        Some("ip:port") => Some(IocKind::Ipv4),
        Some("domain") => Some(classify_host(bare).0),
        Some("md5_hash") => Some(IocKind::Md5),
        Some("sha1_hash") => Some(IocKind::Sha1),
        Some("sha256_hash") => Some(IocKind::Sha256),
        _ => None,
    }
}

#[async_trait]
impl Provider for Threatfox {
    fn source(&self) -> Source {
        Source::Threatfox
    }

    fn seed_requests(&self, target: &str, _filter: &Filter) -> Vec<Request> {
        let host: String = host_of_target(target);
        let body: String = format!(
            r#"{{"query":"search_ioc","search_term":"{}"}}"#,
            host.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let request: Request = Request::post(
            "https://threatfox-api.abuse.ch/api/v1/".to_owned(),
            body,
            JSON_CONTENT_TYPE,
        );
        let request: Request = match &self.api_key {
            Some(key) => request.with_header("Auth-Key", key),
            None => request,
        };
        vec![request]
    }

    fn parse(&self, body: &str) -> Yield {
        let Ok(obj): Result<Value, _> = serde_json::from_str(body) else {
            return Yield::default();
        };
        if obj.get("query_status").and_then(Value::as_str) != Some("ok") {
            return Yield::default();
        }
        let Some(Value::Array(list)): Option<&Value> = obj.get("data") else {
            return Yield::default();
        };
        let mut urls: Vec<HarvestedUrl> = Vec::new();
        let mut iocs: Vec<Ioc> = Vec::new();
        for entry in list {
            let Some(raw): Option<&str> = entry.get("ioc").and_then(Value::as_str) else {
                continue;
            };
            let ioc_type: Option<&str> = entry.get("ioc_type").and_then(Value::as_str);
            let tags: Vec<String> = entry.get("tags").and_then(Value::as_array).map_or_else(
                Vec::new,
                |a: &Vec<Value>| {
                    a.iter()
                        .filter_map(|t: &Value| t.as_str().map(str::to_owned))
                        .collect()
                },
            );
            if ioc_type == Some("url") {
                urls.push(HarvestedUrl {
                    url: raw.to_owned(),
                    timestamp: entry
                        .get("first_seen")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    status: None,
                    mime: None,
                    threat: entry
                        .get("malware")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    tags,
                    source: Source::Threatfox,
                });
            } else if let Some(kind) = ioc_kind_for(raw, ioc_type) {
                let value: String = if kind == IocKind::Ipv4 {
                    raw.split(':')
                        .next()
                        .map_or(raw, |value: &str| value)
                        .to_owned()
                } else {
                    raw.to_ascii_lowercase()
                };
                iocs.push(Ioc {
                    kind,
                    value,
                    source: Source::Threatfox,
                });
            }
        }
        Yield {
            urls,
            iocs,
            next_cursor: None,
        }
    }
}
