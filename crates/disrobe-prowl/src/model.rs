use serde::{Deserialize, Serialize};

pub const PROWL_SCHEMA: &str = "disrobe.prowl/v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Wayback,
    CommonCrawl,
    Otx,
    Urlscan,
    Crtsh,
    Urlhaus,
    Threatfox,
    Virustotal,
}

impl Source {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wayback => "wayback",
            Self::CommonCrawl => "commoncrawl",
            Self::Otx => "otx",
            Self::Urlscan => "urlscan",
            Self::Crtsh => "crtsh",
            Self::Urlhaus => "urlhaus",
            Self::Threatfox => "threatfox",
            Self::Virustotal => "virustotal",
        }
    }

    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "wayback" => Some(Self::Wayback),
            "commoncrawl" => Some(Self::CommonCrawl),
            "otx" => Some(Self::Otx),
            "urlscan" => Some(Self::Urlscan),
            "crtsh" => Some(Self::Crtsh),
            "urlhaus" => Some(Self::Urlhaus),
            "threatfox" => Some(Self::Threatfox),
            "virustotal" | "vt" => Some(Self::Virustotal),
            _ => None,
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Wayback,
            Self::CommonCrawl,
            Self::Otx,
            Self::Urlscan,
            Self::Crtsh,
            Self::Urlhaus,
            Self::Threatfox,
            Self::Virustotal,
        ]
    }

    #[inline]
    #[must_use]
    pub const fn yields_urls(self) -> bool {
        matches!(
            self,
            Self::Wayback
                | Self::CommonCrawl
                | Self::Otx
                | Self::Urlscan
                | Self::Urlhaus
                | Self::Virustotal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvestedUrl {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub source: Source,
}

impl HarvestedUrl {
    #[must_use]
    pub const fn plain(url: String, source: Source) -> Self {
        Self {
            url,
            timestamp: None,
            status: None,
            mime: None,
            threat: None,
            tags: Vec::new(),
            source,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Subdomain,
    Domain,
    Ipv4,
    Ipv6,
    Email,
    Md5,
    Sha1,
    Sha256,
    Asn,
}

impl IocKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Subdomain => "subdomain",
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Email => "email",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Asn => "asn",
        }
    }

    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "subdomain" => Some(Self::Subdomain),
            "domain" => Some(Self::Domain),
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "email" => Some(Self::Email),
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "asn" => Some(Self::Asn),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcome {
    Ok,
    Unauthorized,
    Skipped,
    Failed,
}

impl ProviderOutcome {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unauthorized => "unauthorized",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub source: Source,
    pub outcome: ProviderOutcome,
    pub urls: usize,
    pub iocs: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProwlReport {
    pub schema: &'static str,
    pub targets: Vec<String>,
    pub sources: Vec<Source>,
    pub url_total: usize,
    pub ioc_total: usize,
    pub urls: Vec<HarvestedUrl>,
    pub iocs: Vec<Ioc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderStatus>,
}
