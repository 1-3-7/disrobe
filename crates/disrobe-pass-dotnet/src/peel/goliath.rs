//! Goliath.NET peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Goliath_NET/):
//! * Watermark — `Goliath.NET` / `Goliath` namespace.
//! * String decrypter — XOR with the SHA1 of the string-index integer.
//! * Resource encryption — per-resource Rijndael-CBC.
//! * Renamer — generic-method-parameter shadowing tricks (T->U->V) to confuse decompilers.
//!
//! Real-fixture availability — Goliath.NET is archived/discontinued; samples only on scene
//! archives.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Goliath.NET", "Goliath"];

pub fn peel_goliath(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::Goliath,
        bytes,
        WATERMARKS,
        vec![
            "Goliath.NET strings: XOR with SHA1(index). Resources: Rijndael-CBC per-resource. \
             Generic-shadowing renamer. Discontinued."
                .to_string(),
        ],
    )
}
