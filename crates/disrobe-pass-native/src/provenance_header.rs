use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn rust_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::Rust, version)
}

#[must_use]
pub fn c_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::C, version)
}

#[must_use]
pub fn cpp_lifted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::Cpp, version)
}

#[must_use]
pub fn render_rust_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    rust_lifted_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_c_with_header(body: &str, duration: Duration, version: impl Into<String>) -> String {
    c_lifted_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_cpp_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    cpp_lifted_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_lifted_header_uses_double_slash() {
        let s: String =
            render_rust_with_header("fn x(){}\n", Duration::from_millis(10), "edition 2024");
        assert!(s.starts_with("// Lifted in 10ms"));
        assert!(s.contains("\n// Rust edition 2024\n"));
    }
}
