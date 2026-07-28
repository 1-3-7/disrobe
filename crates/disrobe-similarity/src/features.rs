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
}
