use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OracleKind {
    RecompileEquiv,
    ByteIdenticalUnpack,
    DifferentialVsSource,
    DetectionDeterministic,
}

impl OracleKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecompileEquiv => "recompile-equiv",
            Self::ByteIdenticalUnpack => "byte-identical-unpack",
            Self::DifferentialVsSource => "differential-vs-source",
            Self::DetectionDeterministic => "detection-deterministic",
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::RecompileEquiv,
            Self::ByteIdenticalUnpack,
            Self::DifferentialVsSource,
            Self::DetectionDeterministic,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum OracleVerdict {
    Recovered,
    ByteIdentical,
    DetectCorrect,
    DetectWrong { got: String, expected: String },
    Lossy { residual_bp: u32, note: String },
    NoRecovery { note: String },
    ToolMissing { tool: String },
    FixtureAbsent { rel: String },
    PassError { error: String },
    Ungraded { reason: String },
}

impl OracleVerdict {
    #[must_use]
    pub const fn counts_in_denominator(&self) -> bool {
        !matches!(
            self,
            Self::ToolMissing { .. } | Self::FixtureAbsent { .. } | Self::Ungraded { .. }
        )
    }

    #[must_use]
    pub const fn is_full_recovery(&self) -> bool {
        matches!(
            self,
            Self::Recovered | Self::ByteIdentical | Self::DetectCorrect
        )
    }

    #[must_use]
    pub const fn is_byte_identical(&self) -> bool {
        matches!(self, Self::ByteIdentical)
    }

    #[must_use]
    pub const fn is_detect_correct(&self) -> bool {
        matches!(self, Self::DetectCorrect)
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Recovered => "recovered",
            Self::ByteIdentical => "byte-identical",
            Self::DetectCorrect => "detect-correct",
            Self::DetectWrong { .. } => "detect-wrong",
            Self::Lossy { .. } => "lossy",
            Self::NoRecovery { .. } => "no-recovery",
            Self::ToolMissing { .. } => "tool-missing",
            Self::FixtureAbsent { .. } => "fixture-absent",
            Self::PassError { .. } => "pass-error",
            Self::Ungraded { .. } => "ungraded",
        }
    }
}

#[must_use]
pub fn ungraded_differential_reason(fixture_id: &str) -> String {
    format!(
        "{fixture_id} is a differential fixture with no clean-source baseline in its manifest, so \
         the recovered text was compared against nothing. Reporting it as recovered would credit a \
         non-empty token stream as a graded result"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleResult {
    pub oracle: OracleKind,
    pub pass_under_test: String,
    pub fixture_id: String,
    pub input_rel: String,
    pub baseline_rel: Option<String>,
    pub verdict: OracleVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedFixture {
    pub oracle: OracleKind,
    pub pass_under_test: String,
    pub fixture_id: String,
    pub input_path: PathBuf,
    pub input_rel: String,
    pub baseline_path: Option<PathBuf>,
    pub baseline_rel: Option<String>,
    pub baseline_sha256: Option<String>,
    pub expected_detection: Option<String>,
    pub byte_identical_floor_bp: Option<u32>,
}
