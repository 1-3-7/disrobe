//! Spices.Net (9rays.Net) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["9rays.Net", "Spices.Net"];

pub fn peel_spices_net(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::SpicesNet,
        bytes,
        WATERMARKS,
        vec![
            "Spices.Net uses Cyrillic-homoglyph renames + per-method ROT-N string scrambles; \
             code-flow is goto-shuffling only (no opaque predicates)."
                .to_string(),
        ],
    )
}
