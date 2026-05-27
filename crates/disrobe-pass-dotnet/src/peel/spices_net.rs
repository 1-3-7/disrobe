//! Spices.Net (9rays.Net) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Spices_Net/):
//! * Watermark — `9rays.Net` / `Spices.Net` in the manifest module name and decorator types.
//! * String decrypter — per-method Caesar-style ROT against a per-string key + base64 unwrap.
//! * Renamer — replaces identifiers with Unicode lookalikes (Cyrillic 'а' for 'a', etc.).
//! * Code-flow — `Spices_Net/CflowReader` simple goto-shuffling, no opaque predicates.
//!
//! Real-fixture availability — Spices.Net is sold by 9rays.net; community samples appear on
//! GitHub. Renamer-only peel is achievable without a paid sample by reversing Cyrillic homoglyphs.

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
