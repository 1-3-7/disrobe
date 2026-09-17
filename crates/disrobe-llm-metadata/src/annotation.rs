use disrobe_core::recovery::ConfidenceTier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ANNOTATION_SCHEMA: &str = "disrobe.annotations/v1";

const MAX_NOTE_LINES: usize = 2;
pub const MAX_FILE_BYTES: usize = 4096;
pub const MAX_SYMBOL_BYTES: usize = 1024;
pub const MAX_KIND_BYTES: usize = 128;
pub const MAX_NOTE_BYTES: usize = 4096;
pub const MAX_ANNOTATIONS: usize = 4096;

#[inline]
const fn annotation_schema() -> &'static str {
    ANNOTATION_SCHEMA
}

#[inline]
#[must_use]
fn note_line_count(note: &str) -> usize {
    note.matches('\n').count() + 1
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnnotationError {
    #[error("annotation note for symbol `{symbol}` spans {found} lines (max {MAX_NOTE_LINES})")]
    NoteTooLong { symbol: String, found: usize },
    #[error("annotation `{field}` has {found} bytes (max {max})")]
    FieldTooLong {
        field: &'static str,
        found: usize,
        max: usize,
    },
    #[error("annotation file has {found} annotations (max {max})")]
    TooManyAnnotations { found: usize, max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolAnnotation {
    pub symbol: String,
    pub kind: String,
    pub note: String,
    pub confidence: ConfidenceTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotationFile {
    #[serde(default = "annotation_schema", skip_deserializing)]
    pub schema: &'static str,
    pub file: String,
    pub annotations: Vec<SymbolAnnotation>,
}

impl SymbolAnnotation {
    #[must_use]
    pub fn new(
        symbol: impl Into<String>,
        kind: impl Into<String>,
        note: impl Into<String>,
        confidence: ConfidenceTier,
    ) -> Self {
        Self {
            symbol: symbol.into(),
            kind: kind.into(),
            note: note.into(),
            confidence,
        }
    }

    pub fn validate(&self) -> Result<(), AnnotationError> {
        check_bytes("symbol", &self.symbol, MAX_SYMBOL_BYTES)?;
        check_bytes("kind", &self.kind, MAX_KIND_BYTES)?;
        check_bytes("note", &self.note, MAX_NOTE_BYTES)?;
        let found: usize = note_line_count(&self.note);
        if found > MAX_NOTE_LINES {
            return Err(AnnotationError::NoteTooLong {
                symbol: self.symbol.clone(),
                found,
            });
        }
        Ok(())
    }
}

impl AnnotationFile {
    #[must_use]
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            schema: ANNOTATION_SCHEMA,
            file: file.into(),
            annotations: Vec::new(),
        }
    }

    pub fn push(&mut self, annotation: SymbolAnnotation) -> Result<(), AnnotationError> {
        check_bytes("file", &self.file, MAX_FILE_BYTES)?;
        if self.annotations.len() >= MAX_ANNOTATIONS {
            return Err(AnnotationError::TooManyAnnotations {
                found: self.annotations.len().saturating_add(1),
                max: MAX_ANNOTATIONS,
            });
        }
        annotation.validate()?;
        self.annotations.push(annotation);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AnnotationError> {
        check_bytes("file", &self.file, MAX_FILE_BYTES)?;
        if self.annotations.len() > MAX_ANNOTATIONS {
            return Err(AnnotationError::TooManyAnnotations {
                found: self.annotations.len(),
                max: MAX_ANNOTATIONS,
            });
        }
        for annotation in &self.annotations {
            annotation.validate()?;
        }
        Ok(())
    }
}

const fn check_bytes(field: &'static str, value: &str, max: usize) -> Result<(), AnnotationError> {
    let found: usize = value.len();
    if found > max {
        return Err(AnnotationError::FieldTooLong { field, found, max });
    }
    Ok(())
}
