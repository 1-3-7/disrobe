use serde::{Deserialize, Serialize};

const MARKER_PYEMBED: &[u8] = b"pyembed";
const MARKER_PYOXIDIZER: &[u8] = b"PyOxidizer";
const MARKER_RUNTIME_ANCHOR: &[u8] = b"pyoxidizer_run";
const MARKER_RESOURCES: &[u8] = b"python-stdlib";
const MARKER_INTERPRETER: &[u8] = b"PythonInterpreterConfig";
const BLOB_MAGIC_V3: &[u8] = b"pyembed\x03";
const BLOB_MAGIC_LEGACY: &[u8] = b"pyembed-resources-0";
const RES_FIELD_END_OF_INDEX: u8 = 0x00;
const RES_FIELD_START_OF_ENTRY: u8 = 0x01;
const RES_FIELD_END_OF_ENTRY: u8 = 0xff;
const RES_FIELD_NAME: u8 = 0x03;
const MAX_BLOB_SLICE: usize = 64 * 1024 * 1024;
const MAX_REASONABLE_NAME_LEN: usize = 4 * 1024;

pub fn scan(bytes: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let pairs: [(&[u8], &str); 7] = [
        (MARKER_PYEMBED, "pyembed"),
        (MARKER_PYOXIDIZER, "PyOxidizer"),
        (MARKER_RUNTIME_ANCHOR, "pyoxidizer_run"),
        (MARKER_RESOURCES, "python-stdlib"),
        (MARKER_INTERPRETER, "PythonInterpreterConfig"),
        (BLOB_MAGIC_V3, "pyembed-resources-v3"),
        (BLOB_MAGIC_LEGACY, "pyembed-resources-legacy"),
    ];
    for (pat, label) in pairs {
        if contains(bytes, pat) {
            found.push(label.to_owned());
        }
    }
    found
}

#[must_use]
pub fn is_present(markers: &[String]) -> bool {
    let has_runtime: bool = markers.iter().any(|m| {
        matches!(
            m.as_str(),
            "pyembed"
                | "PyOxidizer"
                | "pyoxidizer_run"
                | "pyembed-resources-v3"
                | "pyembed-resources-legacy"
        )
    });
    let has_aux: bool = markers.len() >= 2;
    has_runtime && has_aux
}

pub fn infer_python_version(bytes: &[u8]) -> (Option<u8>, Option<u8>, Option<String>) {
    let candidates: [(&str, u8, u8); 16] = [
        ("python314.dll", 3u8, 14u8),
        ("python313.dll", 3, 13),
        ("python312.dll", 3, 12),
        ("python311.dll", 3, 11),
        ("python310.dll", 3, 10),
        ("python39.dll", 3, 9),
        ("python38.dll", 3, 8),
        ("python37.dll", 3, 7),
        ("libpython3.14", 3, 14),
        ("libpython3.13", 3, 13),
        ("libpython3.12", 3, 12),
        ("libpython3.11", 3, 11),
        ("libpython3.10", 3, 10),
        ("libpython3.9", 3, 9),
        ("libpython3.8", 3, 8),
        ("libpython3.7", 3, 7),
    ];
    for (needle, major, minor) in candidates {
        if contains(bytes, needle.as_bytes()) {
            return (Some(major), Some(minor), Some(needle.to_owned()));
        }
    }
    (None, None, None)
}

pub fn extract_resources_blob(bytes: &[u8]) -> Option<&[u8]> {
    let start: usize = find(bytes, BLOB_MAGIC_V3).or_else(|| find(bytes, BLOB_MAGIC_LEGACY))?;
    let cap: usize = bytes.len().min(start + MAX_BLOB_SLICE);
    Some(&bytes[start..cap])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceTier {
    Source,
    Bytecode,
    BytecodeOpt1,
    BytecodeOpt2,
    Extension,
    Resource,
    Unknown,
}

impl ResourceTier {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Bytecode => "bytecode",
            Self::BytecodeOpt1 => "bytecode-opt-1",
            Self::BytecodeOpt2 => "bytecode-opt-2",
            Self::Extension => "extension",
            Self::Resource => "resource",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedResourceEntry {
    pub tier: ResourceTier,
    pub name: String,
    pub content_offset: usize,
    pub content_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedResourcesParse {
    pub format_version: u8,
    pub declared_count: u32,
    pub entries: Vec<ParsedResourceEntry>,
    pub best_effort: bool,
    pub diagnostics: Vec<String>,
}

pub fn parse_packed_resources(blob: &[u8]) -> Option<PackedResourcesParse> {
    let magic_pos: usize = find(blob, BLOB_MAGIC_V3)?;
    let after_magic: usize = magic_pos + BLOB_MAGIC_V3.len();
    let format_version: u8 = blob.get(magic_pos + b"pyembed".len()).copied()?;
    let index_region: &[u8] = blob.get(after_magic..)?;
    let mut diagnostics: Vec<String> = Vec::new();
    let names: Vec<String> = scan_resources_index_names(index_region);
    if names.is_empty() {
        diagnostics.push(
            "v3 resources-index yielded no Name fields; falling back to heuristic walk".to_owned(),
        );
        return Some(heuristic_walk(blob, format_version, 0, diagnostics));
    }
    let declared_count: u32 = u32::try_from(names.len()).unwrap_or(u32::MAX);
    let entries: Vec<ParsedResourceEntry> = names
        .into_iter()
        .map(|name: String| ParsedResourceEntry {
            tier: tier_for_name(&name),
            name,
            content_offset: 0,
            content_len: 0,
        })
        .collect();
    diagnostics.push(format!(
        "v3 resources-index name recovery surfaced {n} entries; tier from name suffix, payload offsets resolved lazily downstream",
        n = entries.len()
    ));
    Some(PackedResourcesParse {
        format_version,
        declared_count,
        entries,
        best_effort: false,
        diagnostics,
    })
}

fn scan_resources_index_names(region: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cursor: usize = 0;
    let mut in_entry: bool = false;
    while cursor < region.len() {
        let opcode: u8 = region[cursor];
        cursor += 1;
        if opcode == RES_FIELD_END_OF_INDEX {
            break;
        }
        match opcode {
            RES_FIELD_START_OF_ENTRY => {
                in_entry = true;
            }
            RES_FIELD_END_OF_ENTRY => {
                in_entry = false;
            }
            RES_FIELD_NAME if in_entry => {
                let Some(len_bytes): Option<[u8; 2]> = region
                    .get(cursor..cursor + 2)
                    .and_then(|s| s.try_into().ok())
                else {
                    break;
                };
                let name_len: usize = u16::from_le_bytes(len_bytes) as usize;
                cursor += 2;
                if name_len > MAX_REASONABLE_NAME_LEN {
                    break;
                }
                let Some(name_slice): Option<&[u8]> = region.get(cursor..cursor + name_len) else {
                    break;
                };
                cursor += name_len;
                if let Ok(text) = std::str::from_utf8(name_slice) {
                    names.push(text.to_owned());
                }
            }
            _ => break,
        }
    }
    names
}

fn tier_for_name(name: &str) -> ResourceTier {
    let ext: Option<String> = std::path::Path::new(name)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("py") => ResourceTier::Source,
        Some("pyc") => ResourceTier::Bytecode,
        Some("pyd" | "so") => ResourceTier::Extension,
        _ if name.contains("__pycache__") => ResourceTier::Bytecode,
        _ => ResourceTier::Resource,
    }
}

fn heuristic_walk(
    blob: &[u8],
    format_version: u8,
    declared_count: u32,
    mut diagnostics: Vec<String>,
) -> PackedResourcesParse {
    let mut entries: Vec<ParsedResourceEntry> = Vec::new();
    let needles: [(&[u8], ResourceTier); 4] = [
        (b"__pycache__/", ResourceTier::Bytecode),
        (b".pyc", ResourceTier::Bytecode),
        (b".py\0", ResourceTier::Source),
        (b".pyd", ResourceTier::Extension),
    ];
    for (needle, tier) in needles {
        let mut start: usize = 0;
        while let Some(pos) = find_from(blob, needle, start) {
            let name_start: usize = scan_name_start(blob, pos);
            let name_end: usize = pos + needle.len();
            let raw_name: &[u8] = &blob[name_start..name_end];
            if let Ok(text) = std::str::from_utf8(raw_name) {
                entries.push(ParsedResourceEntry {
                    tier,
                    name: text.trim_end_matches('\0').to_owned(),
                    content_offset: name_end,
                    content_len: 0,
                });
            }
            start = pos + needle.len();
        }
    }

    if find(blob, b"PK\x05\x06").is_some() || find(blob, b"PK\x01\x02").is_some() {
        diagnostics.push(
            "blob contains zip central-directory markers; treat content as embedded zip archive"
                .to_owned(),
        );
    }

    diagnostics.push(format!(
        "heuristic walk surfaced {n} candidate names (best-effort, format not authoritative)",
        n = entries.len()
    ));
    PackedResourcesParse {
        format_version,
        declared_count,
        entries,
        best_effort: true,
        diagnostics,
    }
}

fn scan_name_start(blob: &[u8], anchor: usize) -> usize {
    let mut i: usize = anchor;
    while i > 0 {
        let prev: u8 = blob[i - 1];
        let printable: bool =
            prev.is_ascii_alphanumeric() || matches!(prev, b'_' | b'-' | b'.' | b'/' | b'\\');
        if !printable {
            break;
        }
        i -= 1;
    }
    i
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(haystack, needle, 0)
}

fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || haystack.len() - start < needle.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn scan_picks_up_pyembed_runtime() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf.extend_from_slice(b"pyembed");
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(b"python-stdlib");
        let markers: Vec<String> = scan(&buf);
        assert!(is_present(&markers), "markers: {markers:?}");
    }

    #[test]
    fn scan_rejects_unrelated_strings() {
        let buf: Vec<u8> = b"random bytes with no markers at all".to_vec();
        let markers: Vec<String> = scan(&buf);
        assert!(!is_present(&markers));
    }

    #[test]
    fn scan_requires_runtime_marker_not_just_aux() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"python-stdlib");
        buf.extend_from_slice(b"PythonInterpreterConfig");
        let markers: Vec<String> = scan(&buf);
        assert!(!is_present(&markers));
    }

    #[test]
    fn version_inference_python_312() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"python312.dll\0");
        let (maj, min, hint): (Option<u8>, Option<u8>, Option<String>) = infer_python_version(&buf);
        assert_eq!(maj, Some(3));
        assert_eq!(min, Some(12));
        assert_eq!(hint.as_deref(), Some("python312.dll"));
    }

    #[test]
    fn version_inference_libpython_311() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"libpython3.11.so.1\0");
        let (maj, min, _): (Option<u8>, Option<u8>, Option<String>) = infer_python_version(&buf);
        assert_eq!(maj, Some(3));
        assert_eq!(min, Some(11));
    }

    #[test]
    fn version_inference_returns_none_without_marker() {
        let (maj, _, _): (Option<u8>, Option<u8>, Option<String>) =
            infer_python_version(b"nothing python here");
        assert_eq!(maj, None);
    }

    #[test]
    fn blob_extraction_anchors_on_real_v3_magic() {
        let mut buf: Vec<u8> = vec![0xAB; 128];
        let marker_off: usize = buf.len();
        buf.extend_from_slice(b"pyembed\x03");
        buf.extend_from_slice(&[0xCD; 256]);
        let slice: &[u8] = extract_resources_blob(&buf).expect("blob present");
        assert!(slice.starts_with(b"pyembed\x03"));
        let expected_len: usize = buf.len() - marker_off;
        assert_eq!(slice.len(), expected_len);
    }

    #[test]
    fn blob_extraction_falls_back_to_legacy_string_anchor() {
        let mut buf: Vec<u8> = vec![0xAB; 64];
        buf.extend_from_slice(b"pyembed-resources-0");
        buf.extend_from_slice(&[0xCD; 32]);
        let slice: &[u8] = extract_resources_blob(&buf).expect("legacy blob present");
        assert!(slice.starts_with(b"pyembed-resources-0"));
    }

    #[test]
    fn blob_extraction_returns_none_when_absent() {
        assert!(extract_resources_blob(b"plain bytes").is_none());
    }

    fn push_v3_name_entry(out: &mut Vec<u8>, name: &str) {
        out.push(RES_FIELD_START_OF_ENTRY);
        out.push(RES_FIELD_NAME);
        let name_len: u16 = u16::try_from(name.len()).unwrap();
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(RES_FIELD_END_OF_ENTRY);
    }

    fn build_v3_resources_index(names: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(BLOB_MAGIC_V3);
        for name in names {
            push_v3_name_entry(&mut out, name);
        }
        out.push(RES_FIELD_END_OF_INDEX);
        out
    }

    #[test]
    fn parse_v3_index_recovers_names_and_tiers_via_real_opcodes() {
        let blob: Vec<u8> =
            build_v3_resources_index(&["pkg.mod", "pkg/mod.py", "pkg/mod.pyc", "pkg/_native.pyd"]);
        let parsed: PackedResourcesParse = parse_packed_resources(&blob).expect("parse");
        assert_eq!(parsed.format_version, 0x03);
        assert_eq!(parsed.declared_count, 4);
        assert_eq!(parsed.entries.len(), 4);
        assert_eq!(parsed.entries[0].name, "pkg.mod");
        assert_eq!(parsed.entries[0].tier, ResourceTier::Resource);
        assert_eq!(parsed.entries[1].tier, ResourceTier::Source);
        assert_eq!(parsed.entries[2].tier, ResourceTier::Bytecode);
        assert_eq!(parsed.entries[3].tier, ResourceTier::Extension);
        assert!(!parsed.best_effort);
    }

    #[test]
    fn parse_v3_index_stops_at_end_of_index_opcode() {
        let blob: Vec<u8> = build_v3_resources_index(&["only.py"]);
        let parsed: PackedResourcesParse = parse_packed_resources(&blob).expect("parse");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "only.py");
    }

    #[test]
    fn parse_v3_magic_with_unparseable_index_falls_back_to_heuristic() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BLOB_MAGIC_V3);
        blob.push(RES_FIELD_START_OF_ENTRY);
        blob.push(RES_FIELD_NAME);
        blob.extend_from_slice(&0xFFFFu16.to_le_bytes());
        blob.extend_from_slice(b"__pycache__/mod.pyc");
        let parsed: PackedResourcesParse =
            parse_packed_resources(&blob).expect("must fall back, not fail");
        assert!(parsed.best_effort);
        assert!(
            parsed
                .entries
                .iter()
                .any(|e| e.name.contains("__pycache__")),
            "heuristic should surface __pycache__ name"
        );
    }

    #[test]
    fn parse_returns_none_without_v3_magic() {
        assert!(parse_packed_resources(b"pyembed-resources-0\x01\x02\x03").is_none());
    }
}
