use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::pass::PassId;
use crate::provenance::Language;

#[derive(Debug, Clone, Copy)]
pub struct DetectContext<'a> {
    pub bytes: &'a [u8],
    pub path_hint: Option<&'a str>,
    pub parent_hint: Option<&'a str>,
    pub depth: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct ArtifactRef<'a> {
    pub bytes: &'a [u8],
    pub path_hint: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
}

impl ConfidenceBand {
    #[inline]
    #[must_use]
    pub fn from_confidence(c: f32) -> Self {
        if c >= 0.90 {
            Self::High
        } else if c >= 0.70 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectVerdict {
    pub pass_id: PassId,
    pub format_tag: &'static str,
    pub family: &'static str,
    pub confidence: f32,
    pub band: ConfidenceBand,
    pub specificity: u16,
    pub markers: Vec<&'static str>,
    pub explain: String,
}

impl DetectVerdict {
    #[inline]
    #[must_use]
    pub fn new(
        pass_id: PassId,
        format_tag: &'static str,
        family: &'static str,
        confidence: f32,
        specificity: u16,
        markers: Vec<&'static str>,
        explain: String,
    ) -> Self {
        Self {
            pass_id,
            format_tag,
            family,
            confidence,
            band: ConfidenceBand::from_confidence(confidence),
            specificity,
            markers,
            explain,
        }
    }
}

pub type Detection = DetectVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildHandle {
    pub artifact_index: u32,
    pub relative_path: String,
    pub hint: Option<String>,
}

/// Hint sentinel marking a child the pass has fully handled.
pub const TERMINAL_HINT: &str = "disrobe.terminal";

impl ChildHandle {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.hint.as_deref() == Some(TERMINAL_HINT)
    }
}

#[derive(Debug, Clone)]
pub struct ChildArtifact {
    pub handle: ChildHandle,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum OutputKind {
    Source {
        language: Language,
        formatted: bool,
    },
    Bytes {
        format_tag: &'static str,
        family: &'static str,
    },
    Mixed {
        children: Vec<ChildHandle>,
    },
}

impl OutputKind {
    #[must_use]
    pub fn mixed_from_children(extracted: Vec<ChildArtifact>) -> (Self, Vec<Vec<u8>>) {
        let mut handles: Vec<ChildHandle> = Vec::with_capacity(extracted.len());
        let mut bytes: Vec<Vec<u8>> = Vec::with_capacity(extracted.len());
        for (index, child) in extracted.into_iter().enumerate() {
            let mut handle: ChildHandle = child.handle;
            handle.artifact_index = u32::try_from(index).unwrap_or(u32::MAX);
            handles.push(handle);
            bytes.push(child.bytes);
        }
        (Self::Mixed { children: handles }, bytes)
    }

    #[inline]
    #[must_use]
    pub const fn is_source(&self) -> bool {
        matches!(self, Self::Source { .. })
    }

    #[inline]
    #[must_use]
    pub const fn is_mixed(&self) -> bool {
        matches!(self, Self::Mixed { .. })
    }

    #[inline]
    #[must_use]
    pub const fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes { .. })
    }
}

#[derive(Debug, Clone)]
pub struct PassRunOutcome {
    pub output_bytes: Vec<u8>,
    pub kind: OutputKind,
    pub duration: Duration,
    pub metadata: BTreeMap<String, String>,
    pub children: Vec<Vec<u8>>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn band_threshold_high() {
        assert_eq!(ConfidenceBand::from_confidence(0.90), ConfidenceBand::High);
        assert_eq!(ConfidenceBand::from_confidence(1.0), ConfidenceBand::High);
    }

    #[test]
    fn band_threshold_medium() {
        assert_eq!(
            ConfidenceBand::from_confidence(0.70),
            ConfidenceBand::Medium
        );
        assert_eq!(
            ConfidenceBand::from_confidence(0.899),
            ConfidenceBand::Medium
        );
    }

    #[test]
    fn band_threshold_low() {
        assert_eq!(ConfidenceBand::from_confidence(0.0), ConfidenceBand::Low);
        assert_eq!(ConfidenceBand::from_confidence(0.699), ConfidenceBand::Low);
    }

    #[test]
    fn band_ordering_low_lt_medium_lt_high() {
        assert!(ConfidenceBand::Low < ConfidenceBand::Medium);
        assert!(ConfidenceBand::Medium < ConfidenceBand::High);
    }

    #[test]
    fn detect_verdict_derives_band() {
        let v: DetectVerdict = DetectVerdict::new(
            "test.pass",
            "tag-1",
            "obfuscator-wrapper",
            0.95,
            10,
            vec!["m1"],
            "explain".to_string(),
        );
        assert_eq!(v.band, ConfidenceBand::High);
        assert_eq!(v.confidence, 0.95);
    }

    #[test]
    fn output_kind_variants() {
        let s: OutputKind = OutputKind::Source {
            language: Language::Python,
            formatted: true,
        };
        let b: OutputKind = OutputKind::Bytes {
            format_tag: "pyc-3.11",
            family: "interpreter-bytecode",
        };
        let m: OutputKind = OutputKind::Mixed { children: vec![] };
        assert!(s.is_source());
        assert!(b.is_bytes());
        assert!(m.is_mixed());
    }
}
