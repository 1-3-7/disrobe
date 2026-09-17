use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::LlmMetadataError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Ast,
    Disasm,
    Cfg,
    Dfg,
    Symbols,
    Strings,
    Types,
    Imports,
    Constants,
    Signatures,
    Provenance,
    RoundtripVerdict,
    SourceMap,
    Manifest,
    DecryptionKeys,
    Confidence,
    OpcodeCoverage,
    PiiMap,
}

impl Category {
    pub const ALL: [Self; 18] = [
        Self::Ast,
        Self::Disasm,
        Self::Cfg,
        Self::Dfg,
        Self::Symbols,
        Self::Strings,
        Self::Types,
        Self::Imports,
        Self::Constants,
        Self::Signatures,
        Self::Provenance,
        Self::RoundtripVerdict,
        Self::SourceMap,
        Self::Manifest,
        Self::DecryptionKeys,
        Self::Confidence,
        Self::OpcodeCoverage,
        Self::PiiMap,
    ];

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ast => "ast",
            Self::Disasm => "disasm",
            Self::Cfg => "cfg",
            Self::Dfg => "dfg",
            Self::Symbols => "symbols",
            Self::Strings => "strings",
            Self::Types => "types",
            Self::Imports => "imports",
            Self::Constants => "constants",
            Self::Signatures => "signatures",
            Self::Provenance => "provenance",
            Self::RoundtripVerdict => "roundtrip_verdict",
            Self::SourceMap => "source_map",
            Self::Manifest => "manifest",
            Self::DecryptionKeys => "decryption_keys",
            Self::Confidence => "confidence",
            Self::OpcodeCoverage => "opcode_coverage",
            Self::PiiMap => "pii_map",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, LlmMetadataError> {
        let trimmed: &str = raw.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|c: &Self| c.label().eq_ignore_ascii_case(trimmed))
            .ok_or_else(|| LlmMetadataError::UnknownCategory(raw.to_owned()))
    }
}

impl Display for Category {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Category {
    type Err = LlmMetadataError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}
