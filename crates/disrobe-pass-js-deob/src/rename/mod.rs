mod hex_idents;
mod scope_aware;

use serde::Serialize;

pub use scope_aware::ScopeAwareStats;

use crate::error::Result;

#[derive(Debug, Default, Clone, Serialize)]
pub struct RenameStats {
    pub idents_renamed: usize,
    pub references_rewritten: usize,
}

#[must_use]
pub fn rename_hex_idents(source: &str) -> (String, RenameStats) {
    hex_idents::rename(source)
}

pub fn rename_scope_aware(source: &str) -> Result<(String, ScopeAwareStats)> {
    scope_aware::rename(source)
}
