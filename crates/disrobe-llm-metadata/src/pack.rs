use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::category::Category;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Pack {
    #[serde(rename = "pack-1")]
    Pack1,
    #[serde(rename = "pack-2")]
    Pack2,
    #[serde(rename = "pack-3")]
    Pack3,
    #[serde(rename = "pack-4")]
    Pack4,
}

impl Pack {
    pub const ALL: [Self; 4] = [Self::Pack1, Self::Pack2, Self::Pack3, Self::Pack4];

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pack1 => "pack-1",
            Self::Pack2 => "pack-2",
            Self::Pack3 => "pack-3",
            Self::Pack4 => "pack-4",
        }
    }

    #[must_use]
    pub fn expand(self) -> BTreeSet<Category> {
        let slice: &'static [Category] = match self {
            Self::Pack1 => &PACK1,
            Self::Pack2 => &PACK2,
            Self::Pack3 => &PACK3,
            Self::Pack4 => &PACK4,
        };
        slice.iter().copied().collect()
    }
}

const PACK1: [Category; 4] = [
    Category::Ast,
    Category::Disasm,
    Category::Symbols,
    Category::Strings,
];

const PACK2: [Category; 8] = [
    Category::Ast,
    Category::Disasm,
    Category::Symbols,
    Category::Strings,
    Category::Cfg,
    Category::Types,
    Category::Imports,
    Category::Provenance,
];

const PACK3: [Category; 14] = [
    Category::Ast,
    Category::Disasm,
    Category::Symbols,
    Category::Strings,
    Category::Cfg,
    Category::Types,
    Category::Imports,
    Category::Provenance,
    Category::Dfg,
    Category::Signatures,
    Category::Constants,
    Category::RoundtripVerdict,
    Category::SourceMap,
    Category::Manifest,
];

const PACK4: [Category; 18] = [
    Category::Ast,
    Category::Disasm,
    Category::Symbols,
    Category::Strings,
    Category::Cfg,
    Category::Types,
    Category::Imports,
    Category::Provenance,
    Category::Dfg,
    Category::Signatures,
    Category::Constants,
    Category::RoundtripVerdict,
    Category::SourceMap,
    Category::Manifest,
    Category::Confidence,
    Category::OpcodeCoverage,
    Category::PiiMap,
    Category::DecryptionKeys,
];
