use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

use crate::lang::ScriptLang;

#[must_use]
pub fn language_for(lang: ScriptLang) -> Language {
    match lang {
        ScriptLang::Perl => Language::Perl,
        ScriptLang::R => Language::R,
        ScriptLang::Tcl => Language::Tcl,
        ScriptLang::Haxe => Language::Haxe,
    }
}

#[must_use]
pub fn scriptlang_header(
    lang: ScriptLang,
    protocol: Protocol,
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(protocol, duration, language_for(lang), version)
}

#[must_use]
pub fn render_with_header(
    body: &str,
    lang: ScriptLang,
    protocol: Protocol,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    scriptlang_header(lang, protocol, duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perl_header_uses_hash_style() {
        let s: String = render_with_header(
            "sub greet {}\n",
            ScriptLang::Perl,
            Protocol::Extracted,
            Duration::from_millis(12),
            "5.42",
        );
        assert!(s.starts_with("# Extracted in 12ms"));
        assert!(s.contains("\n# Perl 5.42\n"));
    }

    #[test]
    fn tcl_header_uses_hash_style() {
        let s: String = render_with_header(
            "puts hi\n",
            ScriptLang::Tcl,
            Protocol::Extracted,
            Duration::from_millis(5),
            "8.6",
        );
        assert!(s.contains("\n# Tcl 8.6\n"));
    }

    #[test]
    fn haxe_header_uses_double_slash() {
        let s: String = render_with_header(
            "class Main {}\n",
            ScriptLang::Haxe,
            Protocol::Decompiled,
            Duration::from_millis(7),
            "4.3.6",
        );
        assert!(s.starts_with("// Decompiled in 7ms"));
        assert!(s.contains("\n// Haxe 4.3.6\n"));
    }
}
