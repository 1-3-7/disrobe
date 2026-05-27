#![allow(
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::manual_is_multiple_of,
    clippy::manual_range_contains,
    clippy::map_unwrap_or,
    clippy::unreadable_literal,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls
)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod allatori;
pub mod dasho;
pub mod dexguard;
pub mod stringer;
pub mod zelix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectorFamily {
    ZelixKlassMaster,
    Allatori,
    Stringer,
    DashO,
    DexGuard,
}

impl ProtectorFamily {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZelixKlassMaster => "Zelix KlassMaster",
            Self::Allatori => "Allatori",
            Self::Stringer => "Stringer",
            Self::DashO => "DashO",
            Self::DexGuard => "DexGuard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectorPeelReport {
    pub family: ProtectorFamily,
    pub strings_recovered: BTreeMap<u16, String>,
    pub strings_residual: usize,
    pub cff_methods_unflattened: u32,
    pub cff_branches_recovered: u32,
    pub watermarks_stripped: Vec<String>,
    pub notes: Vec<String>,
}

impl ProtectorPeelReport {
    #[inline]
    #[must_use]
    pub const fn new(family: ProtectorFamily) -> Self {
        Self {
            family,
            strings_recovered: BTreeMap::new(),
            strings_residual: 0,
            cff_methods_unflattened: 0,
            cff_branches_recovered: 0,
            watermarks_stripped: Vec::new(),
            notes: Vec::new(),
        }
    }
}
