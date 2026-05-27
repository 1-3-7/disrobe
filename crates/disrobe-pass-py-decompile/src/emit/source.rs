use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

use crate::ast::node::AstModule;
use crate::bytecode::version::PyVersion;
use crate::codegen::{CodeEmitter, DefaultEmitter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceOpts {
    pub auto_format: bool,
    pub preserve_blank_lines: bool,
    pub indent_width: u32,
    pub use_double_quotes: bool,
}

impl SourceOpts {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            auto_format: true,
            preserve_blank_lines: true,
            indent_width: 4,
            use_double_quotes: true,
        }
    }

    #[inline]
    #[must_use]
    pub const fn without_formatter(mut self) -> Self {
        self.auto_format = false;
        self
    }
}

impl Default for SourceOpts {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn render_source(module: &AstModule, version: &PyVersion, opts: &SourceOpts) -> String {
    let emitter: DefaultEmitter = DefaultEmitter {
        indent_width: opts.indent_width,
        use_double_quotes: opts.use_double_quotes,
        preserve_blank_lines: opts.preserve_blank_lines,
    };
    let raw: String = emitter.emit_module(module, version);
    let with_trailing: String = ensure_trailing_newline(&raw);
    if opts.auto_format {
        format_or_passthrough(&with_trailing, FormatterLanguage::Python)
    } else {
        with_trailing
    }
}

#[must_use]
pub fn render_source_with(
    emitter: &dyn CodeEmitter,
    module: &AstModule,
    version: &PyVersion,
    auto_format: bool,
) -> String {
    let raw: String = emitter.emit_module(module, version);
    let with_trailing: String = ensure_trailing_newline(&raw);
    if auto_format {
        format_or_passthrough(&with_trailing, FormatterLanguage::Python)
    } else {
        with_trailing
    }
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
