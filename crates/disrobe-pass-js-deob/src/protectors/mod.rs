#![allow(clippy::module_name_repetitions)]
pub mod arxan;
pub mod jsdefender;
pub mod pace;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[allow(clippy::enum_variant_names)]
pub enum LegalStance {
    AmberLeaningGreen,
    AmberDetectOnly,
}

impl LegalStance {
    #[must_use]
    pub const fn allows_bypass_with_authorization(self) -> bool {
        matches!(self, Self::AmberLeaningGreen | Self::AmberDetectOnly)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ProtectorFamily {
    JsDefender,
    Arxan,
    Pace,
}

impl ProtectorFamily {
    #[must_use]
    pub const fn legal_stance(self) -> LegalStance {
        match self {
            Self::JsDefender => LegalStance::AmberLeaningGreen,
            Self::Arxan | Self::Pace => LegalStance::AmberDetectOnly,
        }
    }

    #[must_use]
    pub const fn stance_doc(self) -> &'static str {
        match self {
            Self::JsDefender => "docs/legal/jsdefender-stance.md",
            Self::Arxan => "docs/legal/digital-ai-arxan-stance.md",
            Self::Pace => "docs/legal/pace-js-stance.md",
        }
    }

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::JsDefender => "PreEmptive JSDefender",
            Self::Arxan => "Digital.ai Arxan",
            Self::Pace => "PACE JS / Fusion",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectorDetection {
    pub family: ProtectorFamily,
    pub legal_stance: LegalStance,
    pub stance_doc: &'static str,
    pub confidence: f32,
    pub markers: Vec<String>,
}

impl ProtectorDetection {
    pub(crate) const fn new(
        family: ProtectorFamily,
        confidence: f32,
        markers: Vec<String>,
    ) -> Self {
        Self {
            family,
            legal_stance: family.legal_stance(),
            stance_doc: family.stance_doc(),
            confidence,
            markers,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtectorOptions {
    pub i_have_authorization: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProtectorStats {
    pub matched: usize,
    pub reversed: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectorOutput {
    pub source: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub family: ProtectorFamily,
    pub legal_stance: LegalStance,
    pub stance_doc: &'static str,
    pub detection: Option<ProtectorDetection>,
    pub stats: ProtectorStats,
}
