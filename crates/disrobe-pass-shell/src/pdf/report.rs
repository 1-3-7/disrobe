use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::limits;
use super::names;
use super::object::PdfDocument;
use super::{actions, xref};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsFinding {
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    pub script: String,
    pub bytes: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub deobfuscation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionFinding {
    pub kind: String,
    pub origin: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedFileFinding {
    pub name: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subtype: Option<String>,
    pub bytes: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameObfuscation {
    pub raw: String,
    pub decoded: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub handler: String,
    pub decrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfReport {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pdf_version: Option<String>,
    pub object_count: usize,
    pub xref_table: bool,
    pub xref_stream: bool,
    pub recovered_by_scan: bool,
    pub open_action: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encryption: Option<EncryptionInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub javascript: Vec<JsFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub actions: Vec<ActionFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub embedded_files: Vec<EmbeddedFileFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub name_obfuscation: Vec<NameObfuscation>,
}

impl PdfReport {
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        !self.javascript.is_empty()
            || !self.embedded_files.is_empty()
            || self.open_action
            || self
                .actions
                .iter()
                .any(|action: &ActionFinding| action.kind == "Launch")
    }
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[must_use]
pub fn is_pdf(data: &[u8]) -> bool {
    let head: &[u8] = &data[..data.len().min(1024)];
    super::parse::find_subsequence(head, b"%PDF-", 0).is_some()
}

#[must_use]
pub fn pdf_version(data: &[u8]) -> Option<String> {
    let head: &[u8] = &data[..data.len().min(1024)];
    let position: usize = super::parse::find_subsequence(head, b"%PDF-", 0)?;
    let start: usize = position + 5;
    let end: usize = head[start..]
        .iter()
        .position(|byte: &u8| !matches!(byte, b'0'..=b'9' | b'.'))
        .map_or(head.len(), |offset: usize| start + offset);
    let version: String = String::from_utf8_lossy(&head[start..end]).into_owned();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

#[must_use]
pub fn analyze(data: &[u8]) -> Option<PdfReport> {
    if !is_pdf(data) {
        return None;
    }
    let bounded: &[u8] = &data[..data.len().min(limits::MAX_DOCUMENT_BYTES)];
    let doc: PdfDocument = xref::load(bounded);
    let found: actions::Findings = actions::collect(&doc);
    let name_obfuscation: Vec<NameObfuscation> = names::scan_hex_obfuscated_names(bounded)
        .into_iter()
        .map(|(raw, decoded): (String, String)| NameObfuscation { raw, decoded })
        .collect();
    let encryption: Option<EncryptionInfo> = doc.encryption.as_ref().map(|status| EncryptionInfo {
        handler: status.handler.clone(),
        decrypted: status.decrypted,
    });
    Some(PdfReport {
        pdf_version: pdf_version(data),
        object_count: doc.objects.len(),
        xref_table: doc.xref_table_seen,
        xref_stream: doc.xref_stream_seen,
        recovered_by_scan: doc.recovered_by_scan,
        open_action: found.open_action,
        encryption,
        javascript: found.javascript,
        actions: found.actions,
        embedded_files: found.embedded_files,
        name_obfuscation,
    })
}
