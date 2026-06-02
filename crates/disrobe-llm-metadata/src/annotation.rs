use disrobe_core::recovery::ConfidenceTier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ANNOTATION_SCHEMA: &str = "disrobe.annotations/v1";

const MAX_NOTE_LINES: usize = 2;

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
        annotation.validate()?;
        self.annotations.push(annotation);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AnnotationError> {
        for annotation in &self.annotations {
            annotation.validate()?;
        }
        Ok(())
    }
}
