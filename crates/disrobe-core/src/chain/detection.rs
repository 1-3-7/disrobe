//! Detection contract types.
//!
//! Every pass crate exposes a [`Detector`](super::detector::Detector) that
//! returns a [`DetectVerdict`] (renamed [`Detection`] in module-level export
//! for ergonomics). The driver collects verdicts from all detectors at each
//! layer and ranks them with [`super::precedence::compare`].

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::pass::PassId;
use crate::provenance::Language;

/// Borrowed view of the bytes being inspected, plus optional filesystem
/// path and a parent hint surfaced by an upstream pass.
///
/// Detectors are pure functions of this context and must not mutate it.
///
/// ```
/// # #[cfg(feature = "chain")] {
/// use disrobe_core::chain::DetectContext;
/// let bytes: &[u8] = b"PYZ\0";
/// let ctx: DetectContext<'_> = DetectContext {
///     bytes,
///     path_hint: None,
///     parent_hint: None,
///     depth: 0,
/// };
/// assert_eq!(ctx.bytes.len(), 4);
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DetectContext<'a> {
    pub bytes: &'a [u8],
    pub path_hint: Option<&'a str>,
    pub parent_hint: Option<&'a str>,
    pub depth: u8,
}

/// Borrowed reference to the artifact a pass will operate on.
/// Driver-internal; passes never construct this directly.
#[derive(Debug, Clone, Copy)]
pub struct ArtifactRef<'a> {
    pub bytes: &'a [u8],
    pub path_hint: Option<&'a str>,
}

/// Categorical confidence band. Used as the primary sort key in
/// [`super::precedence::compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
}

impl ConfidenceBand {
    /// Derive a band from a normalized `[0.0, 1.0]` numeric confidence.
    ///
    /// ```
    /// # #[cfg(feature = "chain")] {
    /// use disrobe_core::chain::ConfidenceBand;
    /// assert_eq!(ConfidenceBand::from_confidence(0.95), ConfidenceBand::High);
    /// assert_eq!(ConfidenceBand::from_confidence(0.75), ConfidenceBand::Medium);
    /// assert_eq!(ConfidenceBand::from_confidence(0.4), ConfidenceBand::Low);
    /// # }
    /// ```
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

/// A single detector verdict; the driver picks the highest-precedence
/// verdict per layer (see [`super::precedence::compare`]).
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
    /// Construct a verdict and derive the band automatically.
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

/// Alias for parity with the spec, which sometimes refers to the verdict
/// as `Detection`.
pub type Detection = DetectVerdict;

/// Provenance handle for a single child surfaced by a fan-out pass.
///
/// `artifact_index` keys into [`super::state_machine::Node::artifacts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildHandle {
    pub artifact_index: u32,
    pub relative_path: String,
    pub hint: Option<String>,
}

/// What a pass produced. Drives the next dispatch decision in the
/// state machine.
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

/// Result of a single [`crate::Pass::run`] invocation, augmented with the
/// classification the driver needs to make the next routing decision.
#[derive(Debug, Clone)]
pub struct PassRunOutcome {
    pub output_bytes: Vec<u8>,
    pub kind: OutputKind,
    pub duration: Duration,
    pub metadata: BTreeMap<String, String>,
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
