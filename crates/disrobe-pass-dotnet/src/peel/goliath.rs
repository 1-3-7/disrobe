//! Goliath.NET peel.

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
