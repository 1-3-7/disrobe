//! ArmDot peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["ArmDot", "_ArmDotMutator"];

pub fn peel_armdot(bytes: &[u8]) -> Result<PeelReport> {
    detect_only_native(
        Protector::ArmDot,
        bytes,
        WATERMARKS,
        "ArmDot devirtualizes into a custom per-method VM with LCG-encrypted opcodes; static \
         peeling is not feasible without a per-build dispatch-table extraction step. \
         PROTECTOR-UNOBTAINABLE for round-trip testing.",
    )
}
