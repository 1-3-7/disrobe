use disrobe_binfmt::{ContainerKind, chain_detector::CONTAINER_PASS, detect_container};
use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::llm::null_bundled_value;
use crate::typed::{ContainerDetection, ContainerMembers};

const MAX_CONTAINER_INPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct ContainerDetectReport {
    detected: bool,
    kind: Option<String>,
    is_zip_family: bool,
}

#[pyfunction]
#[pyo3(text_signature = "(container_bytes)")]
fn container_detect(container_bytes: &[u8]) -> PyResult<ContainerDetection> {
    let kind: Option<ContainerKind> = detect_container(container_bytes);
    let report: ContainerDetectReport = ContainerDetectReport {
        detected: kind.is_some(),
        kind: kind.map(|k: ContainerKind| k.label().to_owned()),
        is_zip_family: kind.is_some_and(ContainerKind::is_zip_family),
    };
    Ok(ContainerDetection::from_value(null_bundled_value(&report)?))
}

#[derive(Debug, Clone, Serialize)]
struct ContainerMembersReport {
    format: String,
    size: u64,
    listing: MemberListing,
    entries: Vec<MemberEntry>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MemberListing {
    Enumerated,
    RequiresExtraction,
    Unreadable,
}

#[derive(Debug, Clone, Serialize)]
struct MemberEntry {
    name: String,
    size: u64,
}

#[pyfunction]
#[pyo3(text_signature = "(container_bytes)")]
fn container_members(container_bytes: &[u8]) -> PyResult<ContainerMembers> {
    ensure_container_input_within_cap(container_bytes.len(), MAX_CONTAINER_INPUT_BYTES)?;
    if detect_container(container_bytes).is_none() {
        return Err(DisrobeError::new_err(
            "input is not a recognised container".to_owned(),
        ));
    }
    let root_hash: [u8; 32] = *blake3::hash(container_bytes).as_bytes();
    let artifact: Artifact = Artifact::new(Rung::Raw, container_bytes.to_vec(), root_hash);
    let manifest_artifact: Artifact = CONTAINER_PASS
        .run(&artifact)
        .map_err(map("container members"))?;
    let manifest: &str = std::str::from_utf8(&manifest_artifact.envelope)
        .map_err(|e: std::str::Utf8Error| DisrobeError::new_err(format!("manifest utf8: {e}")))?;
    let report: ContainerMembersReport = parse_manifest(manifest, container_bytes.len() as u64);
    Ok(ContainerMembers::from_value(null_bundled_value(&report)?))
}

fn ensure_container_input_within_cap(input_len: usize, max_input_bytes: usize) -> PyResult<()> {
    if input_len > max_input_bytes {
        return Err(DisrobeError::new_err(format!(
            "container input {input_len} bytes exceeds {max_input_bytes} byte cap"
        )));
    }
    Ok(())
}

fn parse_manifest(manifest: &str, fallback_size: u64) -> ContainerMembersReport {
    let mut format: String = "unknown".to_owned();
    let mut size: u64 = fallback_size;
    let mut listing: MemberListing = MemberListing::RequiresExtraction;
    let mut entries: Vec<MemberEntry> = Vec::new();
    for line in manifest.lines() {
        if let Some(rest) = line.strip_prefix("format=") {
            let (fmt, sz): (String, u64) = parse_format_line(rest, fallback_size);
            format = fmt;
            size = sz;
        } else if let Some(rest) = line.strip_prefix("entries=") {
            listing = classify_listing(rest);
        } else if let Some((name, size_field)) = line.split_once('\t')
            && let Some(byte_str) = size_field.strip_prefix("bytes=")
            && let Ok(entry_size) = byte_str.trim().parse::<u64>()
        {
            entries.push(MemberEntry {
                name: name.to_owned(),
                size: entry_size,
            });
        }
    }
    ContainerMembersReport {
        format,
        size,
        listing,
        entries,
    }
}

fn parse_format_line(rest: &str, fallback_size: u64) -> (String, u64) {
    let mut format: String = "unknown".to_owned();
    let mut size: u64 = fallback_size;
    for field in rest.split_whitespace() {
        if let Some(value) = field.strip_prefix("size=") {
            size = value
                .parse::<u64>()
                .map_or(fallback_size, |parsed: u64| parsed);
        } else {
            field.clone_into(&mut format);
        }
    }
    (format, size)
}

fn classify_listing(rest: &str) -> MemberListing {
    if rest.contains("requires-extraction") {
        MemberListing::RequiresExtraction
    } else if rest.contains("unreadable") {
        MemberListing::Unreadable
    } else {
        MemberListing::Enumerated
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(container_detect, m)?)?;
    m.add_function(wrap_pyfunction!(container_members, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_members_rejects_oversized_input_before_artifact_copy() {
        let result: PyResult<()> = ensure_container_input_within_cap(5, 4);
        assert!(result.is_err());
    }
}
