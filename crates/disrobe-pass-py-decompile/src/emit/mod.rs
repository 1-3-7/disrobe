pub mod formatter;
pub mod llm_json;
pub mod marker_guard;
pub mod source;

use std::time::Instant;

use serde_json::Value;

use crate::ast::node::AstModule;
use crate::bytecode::version::PyVersion;
use crate::codegen::{CodeEmitter, DefaultEmitter, module_has_unicode_literals};
use crate::error::{DecompileError, Result};

pub use formatter::{
    CoreFormatter, IdentityFormatter, PyEmitFormatterLanguage, SourceFormatter, format_identity,
    format_python, format_python_no_format_with_header, format_python_with_header,
    provenance_header, pyversion_label,
};
pub use llm_json::{LlmJsonBundle, SCHEMA_ID as LLM_JSON_SCHEMA_ID, build_llm_sidecar};
pub use marker_guard::{
    LeakedMarker, authentic_literal_markers, carries_a_marker, find_leaked_marker,
};
pub use source::{SourceOpts, render_source, render_source_with};

pub struct EmitPipeline {
    pub emitter: Box<dyn CodeEmitter>,
    pub formatter_enabled: bool,
    pub include_provenance: bool,
    pub include_llm_json: bool,
    pub preserve_blank_lines: bool,
}

impl std::fmt::Debug for EmitPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmitPipeline")
            .field("emitter", &"<dyn CodeEmitter>")
            .field("formatter_enabled", &self.formatter_enabled)
            .field("include_provenance", &self.include_provenance)
            .field("include_llm_json", &self.include_llm_json)
            .field("preserve_blank_lines", &self.preserve_blank_lines)
            .finish()
    }
}

impl Default for EmitPipeline {
    #[inline]
    fn default() -> Self {
        Self {
            emitter: Box::new(DefaultEmitter::new()),
            formatter_enabled: true,
            include_provenance: true,
            include_llm_json: false,
            preserve_blank_lines: true,
        }
    }
}

impl EmitPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_emitter(emitter: Box<dyn CodeEmitter>) -> Self {
        Self {
            emitter,
            formatter_enabled: true,
            include_provenance: true,
            include_llm_json: false,
            preserve_blank_lines: true,
        }
    }

    pub fn run(
        &self,
        module: &AstModule,
        version: &PyVersion,
        started_at: Option<Instant>,
    ) -> Result<EmitOutput> {
        let unicode_literals: bool = module_has_unicode_literals(module);
        let raw: String = if self.preserve_blank_lines {
            let emitter: DefaultEmitter = DefaultEmitter {
                indent_width: 4,
                use_double_quotes: true,
                preserve_blank_lines: true,
                unicode_literals,
            };
            emitter.emit_module(module, version)
        } else {
            let emitter: DefaultEmitter = DefaultEmitter {
                indent_width: 4,
                use_double_quotes: true,
                preserve_blank_lines: false,
                unicode_literals,
            };
            emitter.emit_module(module, version)
        };
        let with_newline: String = ensure_trailing_newline(&raw);
        let formatted: String = if self.formatter_enabled {
            format_python(&with_newline)
        } else {
            with_newline
        };

        let module_is_empty: bool = module.docstring.is_none() && module.body.is_empty();
        if !is_python_acceptable(&formatted, module_is_empty) {
            return Err(DecompileError::Emit {
                reason: "emit pipeline produced non-utf8 / empty source".to_owned(),
            });
        }

        let final_source: String = if self.include_provenance {
            let elapsed: std::time::Duration =
                started_at.map_or(std::time::Duration::ZERO, |at: Instant| at.elapsed());
            provenance_header(version, elapsed).prepend_to(&formatted)
        } else {
            formatted
        };

        let llm_json: Option<Value> = if self.include_llm_json {
            Some(build_llm_sidecar(module, version, &final_source))
        } else {
            None
        };

        Ok(EmitOutput {
            source: final_source,
            llm_json,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EmitOutput {
    pub source: String,
    pub llm_json: Option<Value>,
}

impl EmitOutput {
    #[inline]
    #[must_use]
    pub fn has_llm_json(&self) -> bool {
        self.llm_json.is_some()
    }

    #[inline]
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

#[inline]
#[must_use]
fn is_python_acceptable(s: &str, module_is_empty: bool) -> bool {
    module_is_empty || !s.is_empty()
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

#[derive(Debug)]
pub struct PythonSourceEmitter;

impl PythonSourceEmitter {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn emit(
        &self,
        module: &AstModule,
        version: &PyVersion,
        formatter_enabled: bool,
    ) -> Result<String> {
        let opts: SourceOpts = SourceOpts {
            auto_format: formatter_enabled,
            preserve_blank_lines: true,
            indent_width: 4,
            use_double_quotes: true,
        };
        Ok(render_source(module, version, &opts))
    }
}

impl Default for PythonSourceEmitter {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
