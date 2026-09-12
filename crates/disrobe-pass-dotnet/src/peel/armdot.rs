#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::eazvm::{self, EazVmDetection};
use crate::peel::{PeelReport, apply_eazvm_tier, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["ArmDot", "_ArmDotMutator"];

pub fn peel_armdot(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = detect_only_native(
        Protector::ArmDot,
        bytes,
        WATERMARKS,
        "ArmDot managed VM: selected methods become interpreter stubs over an embedded operand \
         stream. Static recovery is attempted when the image carries the dispatch table, handler \
         bodies, and encrypted stream; otherwise the VM tier remains detect-only for that image.",
    )?;
    let detection: EazVmDetection = eazvm::detect(bytes);
    let recovered_before: usize = report.recovered_methods.len();
    apply_eazvm_tier(bytes, &mut report, "ArmDot");
    if report.recovered_methods.len() == recovered_before {
        report.notes.push(armdot_vm_gap_note(detection));
    }
    Ok(report)
}

fn armdot_vm_gap_note(detection: EazVmDetection) -> String {
    if detection.embedded_resource_present
        || detection.dispatch_table_present
        || detection.identified_opcodes > 0
        || detection.stub_count > 0
    {
        return format!(
            "ArmDot VM-tier: EazVM-shape probe found resource={}, dispatch_table={}, handlers={}, \
             stubs={}, but no stub decoded; ArmDot-specific table names or runtime keys need a \
             vendor fixture before static recovery can be graded",
            detection.embedded_resource_present,
            detection.dispatch_table_present,
            detection.identified_opcodes,
            detection.stub_count,
        );
    }
    "ArmDot VM-tier: no EazVM-shaped embedded stream, dispatch table, or VM stubs found in this \
     image; shared managed-VM recovery is proven by the EazVM corpus, but ArmDot-specific table \
     names need a vendor fixture before static recovery can be graded"
        .to_owned()
}
