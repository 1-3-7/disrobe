use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn wat_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Wat, version)
}

#[must_use]
pub fn rust_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::Rust, version)
}

#[must_use]
pub fn ts_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::TypeScript, version)
}

#[must_use]
pub fn c_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::C, version)
}

#[must_use]
pub fn render_wat_decompiled_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    wat_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_rust_lifted_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    rust_lifted_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_ts_lifted_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    ts_lifted_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_c_lifted_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    c_lifted_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wat_decompiled_header_uses_semisemi() {
        let s: String =
            render_wat_decompiled_with_header("(module)\n", Duration::from_millis(5100), "1.0");
        assert!(s.starts_with(";; Decompiled in 5.1s"));
        assert!(s.contains("\n;; WebAssembly 1.0\n"));
    }

    #[test]
    fn rust_lifted_header_uses_double_slash() {
        let s: String = render_rust_lifted_with_header(
            "fn lifted() {}\n",
            Duration::from_millis(120),
            "edition 2024",
        );
        assert!(s.starts_with("// Lifted in 120ms"));
        assert!(s.contains("\n// Rust edition 2024\n"));
    }

    #[test]
    fn c_lifted_header_uses_double_slash() {
        let s: String =
            render_c_lifted_with_header("int main(){}\n", Duration::from_millis(2), "C11");
        assert!(s.starts_with("// Lifted in 2ms"));
        assert!(s.contains("\n// C C11\n"));
    }
}
