#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::format_push_string,
    clippy::similar_names,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::use_self
)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod decompile;
pub mod disasm;
pub mod error;
pub mod ml;
pub mod opcode;
pub mod polyglot;
pub mod safety;
pub mod vm;

pub use decompile::{to_python, to_python_assignment};
pub use disasm::{DecodedArg, Disassembly, Insn, disassemble, render as render_disasm};
pub use error::{Error, Result};
pub use ml::{
    EmbeddedPickle, MlReport, ModelFormat, detect as detect_model, extract as extract_ml,
};
pub use opcode::{ArgKind, Effect, OPCODES, OpInfo, lookup as lookup_opcode, max_proto};
pub use polyglot::{ContainerKind, PolyglotReport, analyze as analyze_polyglot, looks_like_pickle};
pub use safety::{
    Finding, Policy, SafetyReport, Severity, analyze as analyze_safety, analyze_with_policy,
};
pub use vm::{GlobalRef, PickleValue, Session, VmTrace, execute};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// One-shot convenience: disassemble, run the symbolic VM, & analyze safety.
///
/// Returns the disassembly, the symbolic object graph trace, & the static
/// safety report in a single pass over the stream.
pub fn analyze_all(bytes: &[u8]) -> Result<(Disassembly, VmTrace, SafetyReport)> {
    let dis: Disassembly = disassemble(bytes)?;
    let trace: VmTrace = execute(&dis)?;
    let report: SafetyReport = analyze_safety(&trace);
    Ok((dis, trace, report))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn analyze_all_roundtrip() {
        let (dis, trace, report): (Disassembly, VmTrace, SafetyReport) =
            analyze_all(b"\x80\x02K\x07.").expect("analyze");
        assert_eq!(dis.protocol, 2);
        assert_eq!(trace.result, PickleValue::Int(7));
        assert_eq!(report.severity, Severity::Benign);
    }

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}
