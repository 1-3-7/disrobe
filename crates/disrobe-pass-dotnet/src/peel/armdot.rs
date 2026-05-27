//! ArmDot peel.
//!
//! Algorithm summary (clean-room from de4dot has no first-class ArmDot deobfuscator — we
//! document the algorithm from public reverse-engineering write-ups + the upstream `Unknown`
//! handler in de4dot):
//! * Watermark — `ArmDot` / `_ArmDotMutator` types.
//! * Methods are converted into a custom VM bytecode interpreted by an `Execute(byte[])` method
//!   in `_ArmDotMutator`. The VM dispatches on opcode bytes encrypted with a per-method LCG.
//! * String decrypter — uses the same VM; strings are emitted as VM-bytecode literals.
//! * Anti-tamper — checksum of the manifest module's CIL.
//!
//! Real-fixture availability — ArmDot is paid; the VM-tier algorithm is intentionally outside
//! static deobfuscation scope.

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
