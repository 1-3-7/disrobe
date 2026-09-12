use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::RECON_SCHEMA;
use super::ioc::IOC_SCHEMA;

pub const INDICATORS_SCHEMA: &str = "disrobe.indicators/v0";
pub const PROWL_SCHEMA: &str = "disrobe.prowl/v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorClass {
    Url,
    Domain,
    Ipv4,
    Ipv6,
    Email,
    Hash,
    Asn,
    Wallet,
    Path,
    Registry,
    Secret,
    Other,
}

impl IndicatorClass {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Email => "email",
            Self::Hash => "hash",
            Self::Asn => "asn",
            Self::Wallet => "wallet",
            Self::Path => "path",
            Self::Registry => "registry",
            Self::Secret => "secret",
            Self::Other => "other",
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_network(self) -> bool {
        matches!(
            self,
            Self::Url | Self::Domain | Self::Ipv4 | Self::Ipv6 | Self::Email
        )
    }

    #[must_use]
    fn from_recon_category(category: &str) -> Self {
        match category {
            "url" => Self::Url,
            "domain" => Self::Domain,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "email" => Self::Email,
            "wallet" => Self::Wallet,
            "secret" => Self::Secret,
            "persistence" => Self::Registry,
            _ => Self::Other,
        }
    }

    #[must_use]
    fn from_ioc_kind(kind: &str) -> Self {
        match kind {
            "url" => Self::Url,
            "domain" => Self::Domain,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "email" => Self::Email,
            "bitcoin_address" | "ethereum_address" | "monero_address" | "litecoin_address"
            | "tron_address" => Self::Wallet,
            "windows_path" | "unix_path" | "pdb_path" => Self::Path,
            "registry_key" => Self::Registry,
            _ => Self::Other,
        }
    }

    #[must_use]
    fn from_prowl_kind(kind: &str) -> Self {
        match kind {
            "subdomain" | "domain" => Self::Domain,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "email" => Self::Email,
            "md5" | "sha1" | "sha256" => Self::Hash,
            "asn" => Self::Asn,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedIndicator {
    pub class: IndicatorClass,
    pub value: String,
    pub kinds: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorBundle {
    pub schema: &'static str,
    pub total: usize,
    pub ingested: Vec<String>,
    pub indicators: Vec<UnifiedIndicator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSchema {
    Recon,
    Ioc,
    Prowl,
}

impl ArtifactSchema {
    #[must_use]
    const fn provenance(self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Ioc => "ioc",
            Self::Prowl => "prowl",
        }
    }
}

#[must_use]
pub fn identify_schema(value: &Value) -> Option<ArtifactSchema> {
    if let Some(schema) = value.get("schema").and_then(Value::as_str) {
        if schema == RECON_SCHEMA {
            return Some(ArtifactSchema::Recon);
        }
        if schema == IOC_SCHEMA {
            return Some(ArtifactSchema::Ioc);
        }
        if schema == PROWL_SCHEMA {
            return Some(ArtifactSchema::Prowl);
        }
    }
    if value.get("urls").is_some() || value.get("iocs").is_some() {
        return Some(ArtifactSchema::Prowl);
    }
    if value.get("findings").is_some() {
        return Some(ArtifactSchema::Recon);
    }
    if value.get("indicators").is_some() {
        return Some(ArtifactSchema::Ioc);
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct IndicatorAggregator {
    table: BTreeMap<(IndicatorClass, String), Entry>,
    ingested: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    kinds: std::collections::BTreeSet<String>,
    sources: std::collections::BTreeSet<String>,
}

impl IndicatorAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, class: IndicatorClass, value: &str, kind: &str, source: &str) {
        let trimmed: &str = value.trim();
        if trimmed.is_empty() {
            return;
        }
        let entry: &mut Entry = self.table.entry((class, trimmed.to_owned())).or_default();
        entry.kinds.insert(kind.to_owned());
        entry.sources.insert(source.to_owned());
    }

    pub fn ingest_json(&mut self, json: &str) -> Option<ArtifactSchema> {
        let value: Value = serde_json::from_str(json).ok()?;
        let schema: ArtifactSchema = identify_schema(&value)?;
        match schema {
            ArtifactSchema::Recon => self.ingest_recon(&value),
            ArtifactSchema::Ioc => self.ingest_ioc(&value),
            ArtifactSchema::Prowl => self.ingest_prowl(&value),
        }
        self.ingested.push(schema.provenance().to_owned());
        Some(schema)
    }

    fn ingest_recon(&mut self, value: &Value) {
        let Some(findings) = value.get("findings").and_then(Value::as_array) else {
            return;
        };
        for f in findings {
            let Some(category) = f.get("category").and_then(Value::as_str) else {
                continue;
            };
            let Some(v) = f.get("value").and_then(Value::as_str) else {
                continue;
            };
            let class: IndicatorClass = IndicatorClass::from_recon_category(category);
            self.insert(class, v, category, "recon");
        }
    }

    fn ingest_ioc(&mut self, value: &Value) {
        let Some(indicators) = value.get("indicators").and_then(Value::as_array) else {
            return;
        };
        for ind in indicators {
            let Some(kind) = ind.get("kind").and_then(Value::as_str) else {
                continue;
            };
            let Some(v) = ind.get("value").and_then(Value::as_str) else {
                continue;
            };
            let class: IndicatorClass = IndicatorClass::from_ioc_kind(kind);
            self.insert(class, v, kind, "ioc");
        }
    }

    fn ingest_prowl(&mut self, value: &Value) {
        if let Some(urls) = value.get("urls").and_then(Value::as_array) {
            for u in urls {
                if let Some(v) = u.get("url").and_then(Value::as_str) {
                    self.insert(IndicatorClass::Url, v, "url", "prowl");
                }
            }
        }
        if let Some(iocs) = value.get("iocs").and_then(Value::as_array) {
            for ioc in iocs {
                let Some(kind) = ioc.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let Some(v) = ioc.get("value").and_then(Value::as_str) else {
                    continue;
                };
                let class: IndicatorClass = IndicatorClass::from_prowl_kind(kind);
                self.insert(class, v, kind, "prowl");
            }
        }
    }

    #[must_use]
    pub fn finish(self) -> IndicatorBundle {
        let mut indicators: Vec<UnifiedIndicator> = self
            .table
            .into_iter()
            .map(
                |((class, value), entry): ((IndicatorClass, String), Entry)| UnifiedIndicator {
                    class,
                    value,
                    kinds: entry.kinds.into_iter().collect(),
                    sources: entry.sources.into_iter().collect(),
                },
            )
            .collect();
        indicators.sort_by(|a: &UnifiedIndicator, b: &UnifiedIndicator| {
            a.class.cmp(&b.class).then_with(|| a.value.cmp(&b.value))
        });
        let mut ingested: Vec<String> = self.ingested;
        ingested.sort_unstable();
        ingested.dedup();
        IndicatorBundle {
            schema: INDICATORS_SCHEMA,
            total: indicators.len(),
            ingested,
            indicators,
        }
    }

    #[must_use]
    pub fn network_values(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .table
            .keys()
            .filter(|(class, _): &&(IndicatorClass, String)| class.is_network())
            .map(|(_, value): &(IndicatorClass, String)| value.clone())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[must_use]
pub fn aggregate(documents: &[&str]) -> IndicatorBundle {
    let mut agg: IndicatorAggregator = IndicatorAggregator::new();
    for doc in documents {
        let _ = agg.ingest_json(doc);
    }
    agg.finish()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const RECON_DOC: &str = r#"{
        "schema":"disrobe.recon/v0",
        "files_scanned":1,"bytes_scanned":10,"non_utf8_files":0,"total":3,
        "findings":[
            {"category":"url","rule_id":"r1","value":"https://recon.example/a","line":1,"column":1,"offset":0,"severity":"note"},
            {"category":"ipv4","rule_id":"r2","value":"198.51.100.9","line":1,"column":1,"offset":0,"severity":"note"},
            {"category":"secret","rule_id":"DR-SEC-X","value":"AKIASECRET","line":1,"column":1,"offset":0,"severity":"error"}
        ]
    }"#;

    const IOC_DOC: &str = r#"{
        "schema":"disrobe.ioc/v0","byte_len":10,"total":2,
        "indicators":[
            {"kind":"domain","value":"c2.example","offset":0,"encoding":"plain"},
            {"kind":"ipv4","value":"198.51.100.9","offset":0,"encoding":"plain"}
        ]
    }"#;

    const PROWL_DOC: &str = r#"{
        "schema":"disrobe.prowl/v0","targets":["example.com"],"sources":["wayback"],
        "url_total":1,"ioc_total":1,
        "urls":[{"url":"https://example.com/login","source":"wayback"}],
        "iocs":[{"kind":"sha256","value":"abc123","source":"otx"}]
    }"#;

    #[test]
    fn identifies_each_schema_by_tag() {
        assert_eq!(
            identify_schema(&serde_json::from_str(RECON_DOC).unwrap()),
            Some(ArtifactSchema::Recon)
        );
        assert_eq!(
            identify_schema(&serde_json::from_str(IOC_DOC).unwrap()),
            Some(ArtifactSchema::Ioc)
        );
        assert_eq!(
            identify_schema(&serde_json::from_str(PROWL_DOC).unwrap()),
            Some(ArtifactSchema::Prowl)
        );
    }

    #[test]
    fn aggregates_three_artifacts_with_provenance() {
        let bundle: IndicatorBundle = aggregate(&[RECON_DOC, IOC_DOC, PROWL_DOC]);
        assert_eq!(bundle.schema, INDICATORS_SCHEMA);
        assert_eq!(bundle.ingested, vec!["ioc", "prowl", "recon"]);

        let ip: &UnifiedIndicator = bundle
            .indicators
            .iter()
            .find(|i: &&UnifiedIndicator| i.value == "198.51.100.9")
            .expect("shared ip present");
        assert_eq!(ip.class, IndicatorClass::Ipv4);
        assert_eq!(ip.sources, vec!["ioc", "recon"]);

        assert!(
            bundle
                .indicators
                .iter()
                .any(|i: &UnifiedIndicator| i.class == IndicatorClass::Hash
                    && i.value == "abc123"
                    && i.sources == vec!["prowl"]),
            "prowl hash ioc missing: {:?}",
            bundle.indicators
        );
        assert!(
            bundle.indicators.iter().any(|i: &UnifiedIndicator| {
                i.class == IndicatorClass::Secret && i.value == "AKIASECRET"
            }),
            "recon secret missing"
        );
    }

    #[test]
    fn merges_duplicate_value_sources() {
        let mut agg: IndicatorAggregator = IndicatorAggregator::new();
        agg.ingest_json(RECON_DOC).expect("recon");
        agg.ingest_json(IOC_DOC).expect("ioc");
        let networks: Vec<String> = agg.network_values();
        assert!(networks.contains(&"198.51.100.9".to_owned()));
        assert!(networks.contains(&"c2.example".to_owned()));
        assert!(networks.contains(&"https://recon.example/a".to_owned()));
        assert!(!networks.contains(&"AKIASECRET".to_owned()));
    }

    #[test]
    fn unrecognized_document_is_skipped() {
        let mut agg: IndicatorAggregator = IndicatorAggregator::new();
        assert_eq!(agg.ingest_json(r#"{"hello":"world"}"#), None);
        assert_eq!(agg.ingest_json("not json"), None);
        assert!(agg.finish().indicators.is_empty());
    }

    #[test]
    fn bundle_round_trips_json() {
        let bundle: IndicatorBundle = aggregate(&[RECON_DOC, PROWL_DOC]);
        let value: Value = serde_json::to_value(&bundle).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(INDICATORS_SCHEMA));
        let back: Vec<UnifiedIndicator> =
            serde_json::from_value(value["indicators"].clone()).expect("round-trip");
        assert_eq!(back, bundle.indicators);
    }
}
