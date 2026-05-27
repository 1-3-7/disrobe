use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::detect::{Detection, DetectionConfidence, ProtectionKind, PyarmorVersion};
use crate::error::{Error, Result};
use crate::v8v9::BccBlob;

pub mod bcdetect;
pub mod decrypt_v6;
pub mod decrypt_v7;
pub mod decrypt_v8;
pub mod decrypt_v9;
pub mod header;
pub mod mutual_info;
pub mod runtime;

pub use bcdetect::{WrapperMagic, sniff};
pub use header::{HeaderMetadata, parse_header};
pub use mutual_info::{MutualInfoHint, recover_with_mutual_info_hint};
pub use runtime::{RuntimeInfoSummary, load_runtime_info};

#[derive(Debug, Clone, Default)]
pub struct UnpackConfig {
    pub runtime_path: Option<PathBuf>,
    pub runtime_bytes: Option<Vec<u8>>,
    pub allow_bcc: bool,
    pub emit_llm_metadata: bool,
    pub strict: bool,
}

#[derive(Debug, Clone)]
pub struct LlmMetadata {
    pub function_count: usize,
    pub class_count: usize,
    pub import_symbols: BTreeSet<String>,
    pub string_constants: Vec<String>,
    pub name_to_co_addr: BTreeMap<String, u64>,
    pub ast_summary: Option<String>,
    pub byte_entropy: f64,
    pub suspected_obfuscation_layers: Vec<String>,
}

impl LlmMetadata {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.function_count == 0
            && self.class_count == 0
            && self.import_symbols.is_empty()
            && self.string_constants.is_empty()
            && self.name_to_co_addr.is_empty()
            && self.ast_summary.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecryptStatus {
    Functional,
    BccPartial,
    #[default]
    DetectOnly,
    Skeleton,
}

#[derive(Debug, Clone)]
pub struct InnerCipherStats {
    pub recovered_co_count: usize,
    pub recovered_co_code_bytes: usize,
    pub descriptor_cache_hits: usize,
    pub descriptor_cache_misses: usize,
}

impl InnerCipherStats {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            recovered_co_count: 0,
            recovered_co_code_bytes: 0,
            descriptor_cache_hits: 0,
            descriptor_cache_misses: 0,
        }
    }
}

impl Default for InnerCipherStats {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug)]
pub struct UnpackOutput {
    pub pyarmor_version: PyarmorVersion,
    pub protection_kind: ProtectionKind,
    pub python_version: Option<(u8, u8)>,
    pub pyc_magic: Option<u16>,
    pub serial: Option<String>,
    pub confidence: DetectionConfidence,
    pub header_metadata: HeaderMetadata,
    pub runtime_info: Option<RuntimeInfoSummary>,
    pub original_bytecode: Option<Vec<u8>>,
    pub plaintext: Vec<u8>,
    pub bcc_blobs: Vec<BccBlob>,
    pub inner_cipher_stats: InnerCipherStats,
    pub encrypted_funcs_recovered: usize,
    pub status: DecryptStatus,
    pub llm_metadata: Option<LlmMetadata>,
    pub diagnostics: Vec<String>,
}

#[inline]
pub fn unpack_static(bytes: &[u8]) -> Result<UnpackOutput> {
    unpack_static_with_config(bytes, &UnpackConfig::default())
}

pub fn unpack_static_with_config(bytes: &[u8], cfg: &UnpackConfig) -> Result<UnpackOutput> {
    let magic: WrapperMagic = sniff(bytes)?;
    let detection: Detection = bcdetect::detect_payload(bytes)?;
    let header_metadata: HeaderMetadata = parse_header(bytes, magic)?;

    let runtime_info: Option<RuntimeInfoSummary> =
        match (cfg.runtime_bytes.as_deref(), cfg.runtime_path.as_deref()) {
            (Some(rb), _) => Some(load_runtime_info(rb)?),
            (None, Some(rp)) => {
                let rb: Vec<u8> = std::fs::read(rp)?;
                Some(load_runtime_info(&rb)?)
            }
            (None, None) => None,
        };

    let outcome: VersionedOutcome = match detection.version {
        PyarmorVersion::V6 => decrypt_v6::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V7 => decrypt_v7::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V8 => decrypt_v8::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V9 => decrypt_v9::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5 => {
            return Err(Error::LegacyDetectedOnly {
                version: detection.version,
            });
        }
    };

    let llm_metadata: Option<LlmMetadata> = if cfg.emit_llm_metadata {
        Some(extract_llm_metadata(
            &outcome.plaintext,
            &outcome.diagnostics,
        ))
    } else {
        None
    };

    Ok(UnpackOutput {
        pyarmor_version: detection.version,
        protection_kind: detection.protection,
        python_version: zip_pyver(detection.python_major, detection.python_minor),
        pyc_magic: detection.pyc_magic,
        serial: detection.serial.clone(),
        confidence: detection.confidence,
        header_metadata,
        runtime_info,
        original_bytecode: outcome.original_bytecode,
        plaintext: outcome.plaintext,
        bcc_blobs: outcome.bcc_blobs,
        inner_cipher_stats: outcome.inner_cipher_stats,
        encrypted_funcs_recovered: outcome.encrypted_funcs_recovered,
        status: outcome.status,
        llm_metadata,
        diagnostics: outcome.diagnostics,
    })
}

#[derive(Debug, Default)]
pub(crate) struct VersionedOutcome {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) original_bytecode: Option<Vec<u8>>,
    pub(crate) bcc_blobs: Vec<BccBlob>,
    pub(crate) encrypted_funcs_recovered: usize,
    pub(crate) inner_cipher_stats: InnerCipherStats,
    pub(crate) status: DecryptStatus,
    pub(crate) diagnostics: Vec<String>,
}

#[inline]
const fn zip_pyver(major: Option<u8>, minor: Option<u8>) -> Option<(u8, u8)> {
    match (major, minor) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => None,
    }
}

fn extract_llm_metadata(plaintext: &[u8], diagnostics: &[String]) -> LlmMetadata {
    let byte_entropy: f64 = shannon_entropy(plaintext);
    let import_symbols: BTreeSet<String> = scan_import_symbols(plaintext);
    let string_constants: Vec<String> = scan_printable_strings(plaintext, 4);
    let mut suspected_obfuscation_layers: Vec<String> = Vec::new();
    for d in diagnostics {
        if d.contains("super") || d.contains("BCC") || d.contains("nine") {
            suspected_obfuscation_layers.push(d.clone());
        }
    }
    LlmMetadata {
        function_count: 0,
        class_count: 0,
        import_symbols,
        string_constants,
        name_to_co_addr: BTreeMap::new(),
        ast_summary: None,
        byte_entropy,
        suspected_obfuscation_layers,
    }
}

#[allow(clippy::cast_precision_loss)]
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts: [u32; 256] = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len: f64 = data.len() as f64;
    let mut h: f64 = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p: f64 = f64::from(c) / len;
        h -= p * p.log2();
    }
    h
}

fn scan_import_symbols(plaintext: &[u8]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let needles: [&[u8]; 4] = [b"import ", b"from ", b"__import__", b"importlib"];
    for needle in needles {
        let mut start: usize = 0;
        while let Some(pos) = find_subslice(&plaintext[start..], needle) {
            let abs: usize = start + pos + needle.len();
            let cap: usize = plaintext.len().min(abs + 96);
            let end: usize = (abs..cap)
                .find(|&i: &usize| !is_module_name_byte(plaintext[i]))
                .unwrap_or(cap);
            if end > abs
                && let Ok(name) = core::str::from_utf8(&plaintext[abs..end])
                && !name.is_empty()
            {
                out.insert(name.to_owned());
            }
            start = abs.max(start + 1);
            if start >= plaintext.len() {
                break;
            }
        }
    }
    out
}

#[inline]
const fn is_module_name_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_')
}

fn scan_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut run_start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable: bool = matches!(b, 0x20..=0x7e | b'\t');
        if printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take()
            && i - start >= min_len
            && let Ok(s) = core::str::from_utf8(&data[start..i])
        {
            out.push(s.to_owned());
        }
    }
    if let Some(start) = run_start
        && data.len() - start >= min_len
        && let Ok(s) = core::str::from_utf8(&data[start..])
    {
        out.push(s.to_owned());
    }
    out.truncate(2048);
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_bytes() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let h: f64 = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.01, "uniform entropy ~ 8.0, got {h}");
    }

    #[test]
    fn entropy_single_byte() {
        let data: Vec<u8> = vec![0u8; 1024];
        let h: f64 = shannon_entropy(&data);
        assert!(h.abs() < 0.0001, "single-byte data is 0 entropy, got {h}");
    }

    #[test]
    fn scan_printable_strings_finds_runs() {
        let data: &[u8] = b"\x00\x01hello world\x00garbage\x00\x00alpha";
        let strings: Vec<String> = scan_printable_strings(data, 4);
        assert!(strings.iter().any(|s| s == "hello world"));
        assert!(strings.iter().any(|s| s == "alpha"));
    }

    #[test]
    fn import_symbol_scan() {
        let src: &[u8] = b"import os\nfrom collections import deque\n";
        let syms: BTreeSet<String> = scan_import_symbols(src);
        assert!(syms.contains("os"));
        assert!(syms.contains("collections"));
    }

    #[test]
    fn unpack_static_rejects_garbage() {
        let result: Result<UnpackOutput> = unpack_static(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn unpack_static_rejects_too_short_v8() {
        let bytes: Vec<u8> = b"PY009000".to_vec();
        let result: Result<UnpackOutput> = unpack_static(&bytes);
        assert!(result.is_err());
    }
}
