//! DeepSea peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["DeepSea", "DeepSeaObfuscator"];

pub fn peel_deepsea(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::DeepSea,
        bytes,
        WATERMARKS,
        vec![
            "DeepSea strings: XOR-32bit-key (v1.x) or Rijndael-CBC (v3+). Resources: LZMA. \
             Discontinued protector, fixtures sourced from scene archives only."
                .to_string(),
        ],
    )
}
