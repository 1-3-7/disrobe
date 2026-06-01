use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn cil_disasm_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Disassembled, duration, Language::Cil, version)
}

#[must_use]
pub fn csharp_decompiled_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::CSharp, version)
}

#[must_use]
pub fn vbnet_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::VbNet, version)
}

#[must_use]
pub fn fsharp_decompiled_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::FSharp, version)
}

#[must_use]
pub fn render_cil_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    cil_disasm_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_csharp_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    csharp_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cil_header_uses_double_slash() {
        let s: String = render_cil_with_header(".method\n", Duration::from_millis(20), "ECMA-335");
        assert!(s.starts_with("// Disassembled in 20ms"));
        assert!(s.contains("\n// CIL ECMA-335\n"));
    }

    #[test]
    fn csharp_header_uses_double_slash() {
        let s: String = render_csharp_with_header("class C{}\n", Duration::from_millis(45), "12");
        assert!(s.starts_with("// Decompiled in 45ms"));
        assert!(s.contains("\n// C# 12\n"));
    }
}
