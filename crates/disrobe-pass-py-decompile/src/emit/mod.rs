pub mod marker_guard;

use crate::ast::node::AstModule;
use crate::bytecode::version::PyVersion;
use crate::codegen::{CodeEmitter, DefaultEmitter, module_has_unicode_literals};
use crate::error::{DecompileError, Result};

pub use marker_guard::{
    LeakedMarker, authentic_literal_markers, carries_a_marker, find_leaked_marker,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitPipeline {
    pub preserve_blank_lines: bool,
}

impl Default for EmitPipeline {
    #[inline]
    fn default() -> Self {
        Self {
            preserve_blank_lines: true,
        }
    }
}

impl EmitPipeline {
    pub fn run(&self, module: &AstModule, version: &PyVersion) -> Result<EmitOutput> {
        let emitter: DefaultEmitter = DefaultEmitter {
            indent_width: 4,
            use_double_quotes: true,
            preserve_blank_lines: self.preserve_blank_lines,
            unicode_literals: module_has_unicode_literals(module),
        };
        let source: String = ensure_trailing_newline(&emitter.emit_module(module, version));
        let module_is_empty: bool = module.docstring.is_none() && module.body.is_empty();
        if !module_is_empty && source.trim().is_empty() {
            return Err(DecompileError::Emit {
                reason: "emit pipeline produced empty source".to_owned(),
            });
        }
        Ok(EmitOutput { source })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitOutput {
    pub source: String,
}

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
