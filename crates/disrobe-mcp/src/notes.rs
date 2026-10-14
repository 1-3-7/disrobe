use std::path::{Path, PathBuf};

use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};

use super::{DisrobeMcp, disrobe_dir, ensure_text_bytes, read_bounded_file};

const NOTES_SCHEMA: &str = "disrobe.target-notes/v1";
const MAX_NOTE_TEXT_BYTES: usize = 8192;
const MAX_NOTE_RECORDS: usize = 16_384;
const MAX_NOTES_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ADDRESS_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[schemars(crate = "rmcp::schemars")]
pub(super) enum NoteKind {
    Rename,
    Comment,
    Bookmark,
    Unknown,
    Resolution,
}

#[derive(Debug, Clone, Serialize, Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NoteRecord {
    pub seq: u32,
    pub kind: NoteKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NotesFile {
    schema: String,
    target_id: String,
    records: Vec<NoteRecord>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct AddNoteParams {
    pub target_id: String,
    pub kind: NoteKind,
    #[serde(default)]
    pub address: Option<String>,
    pub text: String,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub resolves: Option<u32>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ListNotesParams {
    pub target_id: String,
    #[serde(default)]
    pub kind: Option<NoteKind>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NotesOut {
    pub target_id: String,
    pub file: String,
    pub records: Vec<NoteRecord>,
    pub open_unknowns: Vec<u32>,
}

#[rmcp::tool_router(router = notes_tool_router, vis = "pub(super)")]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "add_note",
        description = "Record a finding about an opened target in .disrobe/notes/targets/<target_id>.json: a rename, comment or bookmark at an address, an open unknown (a question the investigation has not answered), or a resolution that closes an unknown by its seq with the evidence that settles it. Records are append-only."
    )]
    fn add_note(
        &self,
        Parameters(p): Parameters<AddNoteParams>,
    ) -> Result<Json<NotesOut>, ErrorData> {
        self.known_target(&p.target_id)?;
        ensure_text_bytes("text", &p.text, MAX_NOTE_TEXT_BYTES, "DR-MCP-0730")?;
        if p.text.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "DR-MCP-0730: `text` must not be empty",
                None,
            ));
        }
        if let Some(evidence) = &p.evidence {
            ensure_text_bytes("evidence", evidence, MAX_NOTE_TEXT_BYTES, "DR-MCP-0730")?;
        }
        if let Some(address) = &p.address {
            ensure_text_bytes("address", address, MAX_ADDRESS_BYTES, "DR-MCP-0730")?;
        }
        let path: PathBuf = notes_path(&p.target_id)?;
        let mut file: NotesFile = load_notes(&path, &p.target_id)?;
        match (p.kind, p.resolves) {
            (NoteKind::Resolution, Some(seq)) => {
                let resolvable: bool = file.records.iter().any(|record: &NoteRecord| {
                    record.seq == seq && record.kind == NoteKind::Unknown
                });
                if !resolvable {
                    return Err(ErrorData::invalid_params(
                        format!("DR-MCP-0731: no unknown with seq {seq} exists to resolve"),
                        None,
                    ));
                }
                if p.evidence
                    .as_deref()
                    .is_none_or(|text: &str| text.trim().is_empty())
                {
                    return Err(ErrorData::invalid_params(
                        "DR-MCP-0731: a resolution must carry the evidence that settles the unknown",
                        None,
                    ));
                }
            }
            (NoteKind::Resolution, None) => {
                return Err(ErrorData::invalid_params(
                    "DR-MCP-0731: a resolution names the unknown it closes in `resolves`",
                    None,
                ));
            }
            (_, Some(_)) => {
                return Err(ErrorData::invalid_params(
                    "DR-MCP-0731: only a resolution carries `resolves`",
                    None,
                ));
            }
            (_, None) => {}
        }
        if file.records.len() >= MAX_NOTE_RECORDS {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0732: the notes file already holds {MAX_NOTE_RECORDS} records"),
                None,
            ));
        }
        let seq: u32 = file
            .records
            .iter()
            .map(|record: &NoteRecord| record.seq)
            .max()
            .map_or(1, |last: u32| last.saturating_add(1));
        file.records.push(NoteRecord {
            seq,
            kind: p.kind,
            address: p.address,
            text: p.text,
            evidence: p.evidence,
            resolves: p.resolves,
        });
        store_notes(&path, &file)?;
        Ok(Json(notes_out(&path, file, None)))
    }

    #[rmcp::tool(
        name = "list_notes",
        description = "Every note recorded for an opened target, optionally of one kind, plus the seqs of unknowns no resolution has closed."
    )]
    fn list_notes(
        &self,
        Parameters(p): Parameters<ListNotesParams>,
    ) -> Result<Json<NotesOut>, ErrorData> {
        self.known_target(&p.target_id)?;
        let path: PathBuf = notes_path(&p.target_id)?;
        let file: NotesFile = load_notes(&path, &p.target_id)?;
        Ok(Json(notes_out(&path, file, p.kind)))
    }
}

fn notes_out(path: &Path, file: NotesFile, kind: Option<NoteKind>) -> NotesOut {
    let open_unknowns: Vec<u32> = file
        .records
        .iter()
        .filter(|record: &&NoteRecord| record.kind == NoteKind::Unknown)
        .map(|record: &NoteRecord| record.seq)
        .filter(|seq: &u32| {
            !file
                .records
                .iter()
                .any(|record: &NoteRecord| record.resolves == Some(*seq))
        })
        .collect();
    NotesOut {
        target_id: file.target_id,
        file: path.display().to_string(),
        records: file
            .records
            .into_iter()
            .filter(|record: &NoteRecord| kind.is_none_or(|wanted: NoteKind| record.kind == wanted))
            .collect(),
        open_unknowns,
    }
}

fn notes_path(target_id: &str) -> Result<PathBuf, ErrorData> {
    Ok(disrobe_dir()?
        .join("notes")
        .join("targets")
        .join(format!("{target_id}.json")))
}

fn load_notes(path: &Path, target_id: &str) -> Result<NotesFile, ErrorData> {
    if !path.exists() {
        return Ok(NotesFile {
            schema: NOTES_SCHEMA.to_owned(),
            target_id: target_id.to_owned(),
            records: Vec::new(),
        });
    }
    let bytes: Vec<u8> = read_bounded_file(path, MAX_NOTES_FILE_BYTES, "DR-MCP-0733")?;
    let file: NotesFile = serde_json::from_slice(&bytes).map_err(|error: serde_json::Error| {
        ErrorData::invalid_params(
            format!(
                "DR-MCP-0733: {} is not a notes file: {error}",
                path.display()
            ),
            None,
        )
    })?;
    if file.schema != NOTES_SCHEMA
        || file.target_id != target_id
        || file.records.len() > MAX_NOTE_RECORDS
    {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0733: {} does not hold {NOTES_SCHEMA} notes for {target_id} within {MAX_NOTE_RECORDS} records",
                path.display()
            ),
            None,
        ));
    }
    Ok(file)
}

fn store_notes(path: &Path, file: &NotesFile) -> Result<(), ErrorData> {
    let parent: &Path = path.parent().ok_or_else(|| {
        ErrorData::internal_error("DR-MCP-0734: notes path has no parent directory", None)
    })?;
    std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
        ErrorData::internal_error(
            format!("DR-MCP-0734: cannot create {}: {error}", parent.display()),
            None,
        )
    })?;
    let text: Vec<u8> = serde_json::to_vec_pretty(file).map_err(|error: serde_json::Error| {
        ErrorData::internal_error(format!("DR-MCP-0734: notes serialize: {error}"), None)
    })?;
    let staging: PathBuf = path.with_extension("json.partial");
    std::fs::write(&staging, &text).map_err(|error: std::io::Error| {
        ErrorData::internal_error(
            format!("DR-MCP-0734: cannot write {}: {error}", staging.display()),
            None,
        )
    })?;
    std::fs::rename(&staging, path).map_err(|error: std::io::Error| {
        ErrorData::internal_error(
            format!("DR-MCP-0734: cannot replace {}: {error}", path.display()),
            None,
        )
    })
}
