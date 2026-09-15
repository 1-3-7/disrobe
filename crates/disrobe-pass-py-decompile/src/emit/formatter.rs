use std::time::Duration;

use disrobe_core::format::{FormatterLanguage, format_or_passthrough};
use disrobe_core::provenance::{CommentStyle, Language, Protocol, ProvenanceHeader};

use crate::bytecode::version::PyVersion;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PyEmitFormatterLanguage {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Go,
    C,
    Dart,
    Lua,
    Php,
    Ruby,
}

impl From<PyEmitFormatterLanguage> for FormatterLanguage {
    #[inline]
    fn from(value: PyEmitFormatterLanguage) -> Self {
        match value {
            PyEmitFormatterLanguage::Python => Self::Python,
            PyEmitFormatterLanguage::JavaScript => Self::JavaScript,
            PyEmitFormatterLanguage::TypeScript => Self::TypeScript,
            PyEmitFormatterLanguage::Rust => Self::Rust,
            PyEmitFormatterLanguage::Go => Self::Go,
            PyEmitFormatterLanguage::C => Self::C,
            PyEmitFormatterLanguage::Dart => Self::Dart,
            PyEmitFormatterLanguage::Lua => Self::Lua,
            PyEmitFormatterLanguage::Php => Self::Php,
            PyEmitFormatterLanguage::Ruby => Self::Ruby,
        }
    }
}

pub trait SourceFormatter: std::fmt::Debug + Send + Sync {
    fn format(&self, src: &str, lang: PyEmitFormatterLanguage) -> Result<String>;
}

#[derive(Debug, Default)]
pub struct CoreFormatter;

impl CoreFormatter {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SourceFormatter for CoreFormatter {
    #[inline]
    fn format(&self, src: &str, lang: PyEmitFormatterLanguage) -> Result<String> {
        Ok(format_or_passthrough(src, lang.into()))
    }
}

#[derive(Debug, Default)]
pub struct IdentityFormatter;

impl IdentityFormatter {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SourceFormatter for IdentityFormatter {
    #[inline]
    fn format(&self, src: &str, _lang: PyEmitFormatterLanguage) -> Result<String> {
        Ok(src.to_owned())
    }
}

#[inline]
#[must_use]
pub fn format_python(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Python)
}

#[inline]
#[must_use]
pub fn format_identity(src: &str) -> String {
    src.to_owned()
}

#[inline]
#[must_use]
pub fn pyversion_label(version: &PyVersion) -> String {
    format!("{}.{}", version.major(), version.minor())
}

#[must_use]
pub fn provenance_header(version: &PyVersion, elapsed: Duration) -> ProvenanceHeader {
    ProvenanceHeader::new(
        Protocol::Decompiled,
        elapsed,
        Language::Python.label(),
        pyversion_label(version),
        CommentStyle::Hash,
    )
}

#[must_use]
pub fn format_python_with_header(body: &str, version: &PyVersion, elapsed: Duration) -> String {
    let formatted: String = format_python(body);
    let header: ProvenanceHeader = provenance_header(version, elapsed);
    let with_sep: String = ensure_trailing_newline(&formatted);
    header.prepend_to(&with_sep)
}

#[must_use]
pub fn format_python_no_format_with_header(
    body: &str,
    version: &PyVersion,
    elapsed: Duration,
) -> String {
    let header: ProvenanceHeader = provenance_header(version, elapsed);
    let with_sep: String = ensure_trailing_newline(body);
    header.prepend_to(&with_sep)
}

#[inline]
#[must_use]
fn ensure_trailing_newline(s: &str) -> String {
    if s.is_empty() || s.ends_with('\n') {
        s.to_owned()
    } else {
        let mut out: String = String::with_capacity(s.len() + 1);
        out.push_str(s);
        out.push('\n');
        out
    }
}
