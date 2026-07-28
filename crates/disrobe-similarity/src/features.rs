use std::collections::BTreeSet;

use crate::constant::is_discriminating_constant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FunctionId(pub u64);

impl From<u64> for FunctionId {
    #[inline]
    fn from(address: u64) -> Self {
        Self(address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataReference {
    StringLiteral(String),
    UnusualConstant(u64),
    ImportedCall(String),
}

impl DataReference {
    pub fn string_literal(value: impl Into<String>) -> Self {
        Self::StringLiteral(value.into())
    }

    pub fn imported_call(name: impl Into<String>) -> Self {
        Self::ImportedCall(name.into())
    }

    #[must_use]
    pub const fn constant(value: u64) -> Option<Self> {
        if is_discriminating_constant(value) {
            Some(Self::UnusualConstant(value))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn is_admissible(&self) -> bool {
        match self {
            Self::StringLiteral(_) => true,
            Self::UnusualConstant(value) => is_discriminating_constant(*value),
            Self::ImportedCall(name) => !name.is_empty(),
        }
    }

    #[must_use]
    pub const fn anchors_alone(&self) -> bool {
        match self {
            Self::StringLiteral(_) | Self::UnusualConstant(_) => true,
            Self::ImportedCall(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionFeatures {
    id: FunctionId,
    references: BTreeSet<DataReference>,
}

impl FunctionFeatures {
    pub fn new(id: FunctionId, references: impl IntoIterator<Item = DataReference>) -> Self {
        Self {
            id,
            references: references
                .into_iter()
                .filter(DataReference::is_admissible)
                .collect(),
        }
    }

    #[must_use]
    pub const fn id(&self) -> FunctionId {
        self.id
    }

    #[must_use]
    pub const fn references(&self) -> &BTreeSet<DataReference> {
        &self.references
    }

    #[must_use]
    pub fn has_anchor(&self) -> bool {
        !self.references.is_empty()
    }

    #[must_use]
    pub fn anchor_strength(&self) -> AnchorStrength {
        anchor_strength(&self.references)
    }
}

#[must_use]
pub fn anchor_strength(references: &BTreeSet<DataReference>) -> AnchorStrength {
    let only_reference: Option<&DataReference> = match references.len() {
        1 => references.iter().next(),
        _ => None,
    };
    match only_reference {
        Some(reference) if !reference.anchors_alone() => AnchorStrength::SingleImportedCall,
        _ => AnchorStrength::Distinctive,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnchorStrength {
    Distinctive,
    SingleImportedCall,
}
