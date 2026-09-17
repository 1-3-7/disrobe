use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProvenanceStage {
    HeaderParse,
    BccPeel,
    OuterCtrDecrypt,
    PlaintextHeader,
    XorKeyVm,
    MarshalLoad,
    InnerDescriptorCtr,
    InnerXorProcedure,
    InnerCopyPrologue,
    MixStringCtr,
    WrapHeaderStrip,
    WrapFooterStrip,
    PycHeader,
    MarshalEmit,
}

impl ProvenanceStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HeaderParse => "header-parse",
            Self::BccPeel => "bcc-peel",
            Self::OuterCtrDecrypt => "outer-ctr-decrypt",
            Self::PlaintextHeader => "plaintext-header",
            Self::XorKeyVm => "xor-key-vm",
            Self::MarshalLoad => "marshal-load",
            Self::InnerDescriptorCtr => "inner-descriptor-ctr",
            Self::InnerXorProcedure => "inner-xor-procedure",
            Self::InnerCopyPrologue => "inner-copy-prologue",
            Self::MixStringCtr => "mix-string-ctr",
            Self::WrapHeaderStrip => "wrap-header-strip",
            Self::WrapFooterStrip => "wrap-footer-strip",
            Self::PycHeader => "pyc-header",
            Self::MarshalEmit => "marshal-emit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceRegion {
    pub start: usize,
    pub end: usize,
    pub stage: ProvenanceStage,
    pub note: Option<String>,
}

impl ProvenanceRegion {
    #[must_use]
    pub const fn length(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PyarmorProvenance {
    regions: BTreeMap<usize, ProvenanceRegion>,
    stage_totals: BTreeMap<ProvenanceStage, u64>,
}

impl PyarmorProvenance {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, region: ProvenanceRegion) {
        let length: u64 = region.length() as u64;
        let key: usize = region.start;
        *self.stage_totals.entry(region.stage).or_insert(0) += length;
        self.regions.insert(key, region);
    }

    pub fn record_range(
        &mut self,
        start: usize,
        end: usize,
        stage: ProvenanceStage,
        note: Option<String>,
    ) {
        if end < start {
            return;
        }
        self.record(ProvenanceRegion {
            start,
            end,
            stage,
            note,
        });
    }

    pub fn regions(&self) -> impl Iterator<Item = &ProvenanceRegion> {
        self.regions.values()
    }

    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    #[must_use]
    pub fn stage_bytes(&self, stage: ProvenanceStage) -> u64 {
        self.stage_totals.get(&stage).copied().unwrap_or(0)
    }

    pub fn stages(&self) -> impl Iterator<Item = (ProvenanceStage, u64)> + '_ {
        self.stage_totals
            .iter()
            .map(|(stage, bytes)| (*stage, *bytes))
    }

    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let regions: Vec<serde_json::Value> = self
            .regions
            .values()
            .map(|r| {
                serde_json::json!({
                    "start": r.start,
                    "end": r.end,
                    "length": r.length(),
                    "stage": r.stage.label(),
                    "note": r.note,
                })
            })
            .collect();
        let stages: Vec<serde_json::Value> = self
            .stage_totals
            .iter()
            .map(|(stage, bytes)| {
                serde_json::json!({
                    "stage": stage.label(),
                    "bytes": bytes,
                })
            })
            .collect();
        serde_json::json!({
            "schema": "disrobe.pyarmor.provenance/v1",
            "regions": regions,
            "stage_totals": stages,
        })
    }

    pub fn merge(&mut self, other: Self) {
        for region in other.regions.into_values() {
            self.record(region);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn record_accumulates_stage_totals() {
        let mut p: PyarmorProvenance = PyarmorProvenance::new();
        p.record_range(0, 16, ProvenanceStage::HeaderParse, None);
        p.record_range(16, 32, ProvenanceStage::HeaderParse, None);
        p.record_range(
            32,
            64,
            ProvenanceStage::OuterCtrDecrypt,
            Some("aes-ctr".into()),
        );
        assert_eq!(p.region_count(), 3);
        assert_eq!(p.stage_bytes(ProvenanceStage::HeaderParse), 32);
        assert_eq!(p.stage_bytes(ProvenanceStage::OuterCtrDecrypt), 32);
    }

    #[test]
    fn json_round_trips_label_and_length() {
        let mut p: PyarmorProvenance = PyarmorProvenance::new();
        p.record_range(0, 10, ProvenanceStage::PycHeader, None);
        let v: serde_json::Value = p.to_json();
        let regions: Vec<serde_json::Value> = v
            .get("regions")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0].get("length").and_then(serde_json::Value::as_u64),
            Some(10)
        );
        assert_eq!(
            regions[0].get("stage").and_then(|x| x.as_str()),
            Some("pyc-header")
        );
    }

    #[test]
    fn merge_combines_two_provenances() {
        let mut a: PyarmorProvenance = PyarmorProvenance::new();
        a.record_range(0, 8, ProvenanceStage::BccPeel, None);
        let mut b: PyarmorProvenance = PyarmorProvenance::new();
        b.record_range(8, 24, ProvenanceStage::MixStringCtr, None);
        a.merge(b);
        assert_eq!(a.region_count(), 2);
        assert_eq!(a.stage_bytes(ProvenanceStage::MixStringCtr), 16);
    }

    #[test]
    fn empty_range_is_ignored_by_record_range() {
        let mut p: PyarmorProvenance = PyarmorProvenance::new();
        p.record_range(64, 0, ProvenanceStage::WrapHeaderStrip, None);
        assert_eq!(p.region_count(), 0);
    }

    #[test]
    fn stage_labels_are_stable() {
        assert_eq!(
            ProvenanceStage::OuterCtrDecrypt.label(),
            "outer-ctr-decrypt"
        );
        assert_eq!(
            ProvenanceStage::InnerDescriptorCtr.label(),
            "inner-descriptor-ctr"
        );
        assert_eq!(
            ProvenanceStage::WrapHeaderStrip.label(),
            "wrap-header-strip"
        );
    }
}
