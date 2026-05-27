#![allow(
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::manual_is_multiple_of,
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

use serde::{Deserialize, Serialize};

pub mod ioncube;
pub mod sourceguardian;
pub mod zend_guard;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectorFamily {
    IonCube,
    SourceGuardian,
    ZendGuard,
}

impl ProtectorFamily {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::IonCube => "ionCube",
            Self::SourceGuardian => "SourceGuardian",
            Self::ZendGuard => "ZendGuard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeelResult {
    pub family: ProtectorFamily,
    pub version_label: String,
    pub layers_peeled: u32,
    pub recovered_strings: Vec<String>,
    pub recovered_php: Option<String>,
    pub residual_bytes: usize,
}

impl PeelResult {
    #[inline]
    #[must_use]
    pub const fn new(family: ProtectorFamily, version_label: String) -> Self {
        Self {
            family,
            version_label,
            layers_peeled: 0,
            recovered_strings: Vec::new(),
            recovered_php: None,
            residual_bytes: 0,
        }
    }
}
