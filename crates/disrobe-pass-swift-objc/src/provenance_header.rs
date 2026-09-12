use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn swift_class_dump_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::Swift, version)
}

#[must_use]
pub fn objc_class_dump_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::ObjectiveC, version)
}

#[must_use]
pub fn render_swift_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    swift_class_dump_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_objc_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    objc_class_dump_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_header_uses_double_slash() {
        let s: String = render_swift_with_header("class C{}\n", Duration::from_millis(50), "5.10");
        assert!(s.starts_with("// Extracted in 50ms"));
        assert!(s.contains("\n// Swift 5.10\n"));
    }

    #[test]
    fn objc_header_uses_double_slash() {
        let s: String =
            render_objc_with_header("@interface X\n@end\n", Duration::from_millis(60), "2.0");
        assert!(s.starts_with("// Extracted in 60ms"));
        assert!(s.contains("\n// Objective-C 2.0\n"));
    }
}
