use serde::{Deserialize, Serialize};

use crate::recovery::ConfidenceTier;

pub const PROVENANCE_MAP_SCHEMA: &str = "disrobe.provenance-map/v1";

pub const MAX_NOTE_LINES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceMapError {
    #[error(
        "DR-CORE-PMAP-0001: provenance note for line {line} has {found} lines; cap is {MAX_NOTE_LINES}"
    )]
    NoteTooManyLines { line: u32, found: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineProvenance {
    pub line: u32,
    pub pass: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode_range: Option<[u64; 2]>,
    pub confidence: ConfidenceTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[inline]
fn normalize_note(note: String) -> Option<String> {
    let trimmed: &str = note.trim();
    if trimmed.is_empty() { None } else { Some(note) }
}

#[inline]
fn note_line_count(note: &str) -> usize {
    note.lines().count()
}

#[inline]
fn check_note_cap(line: u32, note: Option<&str>) -> Result<(), ProvenanceMapError> {
    if let Some(text) = note {
        let found: usize = note_line_count(text);
        if found > MAX_NOTE_LINES {
            return Err(ProvenanceMapError::NoteTooManyLines { line, found });
        }
    }
    Ok(())
}

impl LineProvenance {
    #[must_use]
    pub fn new(line: u32, pass: impl Into<String>, confidence: ConfidenceTier) -> Self {
        Self {
            line,
            pass: pass.into(),
            source_offset: None,
            opcode_range: None,
            confidence,
            note: None,
        }
    }

    #[must_use]
    pub const fn with_source_offset(mut self, offset: u64) -> Self {
        self.source_offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_opcode_range(mut self, start: u64, end: u64) -> Self {
        self.opcode_range = Some([start, end]);
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Result<Self, ProvenanceMapError> {
        let normalized: Option<String> = normalize_note(note.into());
        check_note_cap(self.line, normalized.as_deref())?;
        self.note = normalized;
        Ok(self)
    }
}

#[inline]
const fn provenance_map_schema() -> &'static str {
    PROVENANCE_MAP_SCHEMA
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMap {
    #[serde(default = "provenance_map_schema", skip_deserializing)]
    pub schema: &'static str,
    pub tool_version: String,
    pub file: String,
    pub lines: Vec<LineProvenance>,
}

#[derive(Debug, Clone)]
pub struct ProvenanceMapBuilder {
    tool_version: String,
    file: String,
    lines: Vec<LineProvenance>,
}

impl ProvenanceMapBuilder {
    #[must_use]
    pub fn new(file: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_version: tool_version.into(),
            file: file.into(),
            lines: Vec::new(),
        }
    }

    pub fn push_line(&mut self, entry: LineProvenance) -> Result<&mut Self, ProvenanceMapError> {
        check_note_cap(entry.line, entry.note.as_deref())?;
        self.lines.push(entry);
        Ok(self)
    }

    #[must_use]
    pub fn build(self) -> ProvenanceMap {
        ProvenanceMap {
            schema: PROVENANCE_MAP_SCHEMA,
            tool_version: self.tool_version,
            file: self.file,
            lines: self.lines,
        }
    }
}
