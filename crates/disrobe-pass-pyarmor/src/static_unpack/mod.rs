use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::debug::dbg_enabled;
use crate::detect::{Detection, DetectionConfidence, ProtectionKind, PyarmorVersion};
use crate::error::{Error, Result};
use crate::key_class::{RuntimeKeyClassification, classify_runtime_key};
use crate::v8v9::BccBlob;
use crate::{MAX_RUNTIME_FILE_BYTES, read_file_bounded};

pub mod bcdetect;
pub mod decrypt_v6;
pub mod decrypt_v7;
pub mod decrypt_v8;
pub mod decrypt_v9;
pub mod header;
pub mod runtime;

pub use bcdetect::{WrapperMagic, sniff};
pub use header::{HeaderMetadata, parse_header};
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
    #[must_use]
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
    #[must_use]
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
    pub key_classification: Option<RuntimeKeyClassification>,
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
    crate::debug::dbg_section("pyarmor static-unpack");
    crate::debug::dbg_hex("input-magic", bytes, 16);
    let magic: WrapperMagic = sniff(bytes)?;
    crate::debug::dbg_kv("wrapper-magic", || magic.label().to_owned());
    let detection: Detection = bcdetect::detect_payload(bytes)?;
    let header_metadata: HeaderMetadata = parse_header(bytes, magic)?;

    let runtime_summary_optional: bool =
        matches!(detection.version, PyarmorVersion::V6 | PyarmorVersion::V7);
    let runtime_info: Option<RuntimeInfoSummary> =
        match (cfg.runtime_bytes.as_deref(), cfg.runtime_path.as_deref()) {
            (Some(rb), _) => load_runtime_summary(rb, runtime_summary_optional)?,
            (None, Some(rp)) => {
                let rb: Vec<u8> = read_file_bounded(rp, MAX_RUNTIME_FILE_BYTES)?;
                load_runtime_summary(&rb, runtime_summary_optional)?
            }
            (None, None) => None,
        };
    crate::debug::dbg_kv("runtime-supplied", || runtime_info.is_some().to_string());

    let mut detection: Detection = detection;
    if detection.confidence != DetectionConfidence::High
        && let Some(rt) = runtime_info.as_ref()
        && let Some(rt_ver) = rt.descriptor_version
    {
        detection.version = rt_ver;
        detection.confidence = DetectionConfidence::High;
        detection.diagnostics.push(
            "DR-PYARM-DISCRIM: serial 000000 ambiguous; version resolved from runtime descriptor word"
                .to_owned(),
        );
        crate::debug::dbg_kv("version-discriminator", || {
            format!("ambiguous serial resolved from runtime descriptor -> {rt_ver:?}")
        });
    }

    if let Some(serial) = detection.serial.as_deref() {
        let class: RuntimeKeyClassification = classify_runtime_key(serial, &detection.raw_header);
        crate::debug::dbg_kv("serial-class", || {
            format!(
                "serial={serial} kind={} runtime_key={}",
                class.serial.kind.label(),
                class.runtime_key_class.label()
            )
        });
        if let Some(flags) = class.mode_flags.as_ref() {
            crate::debug::dbg_kv("mode-flags", || {
                format!(
                    "restrict={} advanced={} obf_module={} obf_code={} wrap={} outer_key={} bcc={}",
                    flags.restrict_mode,
                    flags.advanced_restrict,
                    flags.obf_module,
                    flags.obf_code,
                    flags.wrap_mode,
                    flags.outer_runtime_key,
                    flags.bcc_protection
                )
            });
        }
    }

    crate::debug::dbg_kv("decrypt-route", || format!("{:?}", detection.version));
    let outcome: VersionedOutcome = match detection.version {
        PyarmorVersion::V6 => decrypt_v6::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V7 => decrypt_v7::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V8 => decrypt_v8::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V9 => decrypt_v9::run(bytes, &detection, runtime_info.as_ref(), cfg)?,
        PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5 => {
            crate::debug::dbg_line(|| {
                format!(
                    "legacy {:?} wall: AES-128-CTR key RSA-wrapped in capsule, absent from artifact",
                    detection.version
                )
            });
            return Err(Error::LegacyDetectedOnly {
                version: detection.version,
            });
        }
    };
    crate::debug::dbg_kv("decrypt-status", || format!("{:?}", outcome.status));
    crate::debug::dbg_kv("plaintext-len", || outcome.plaintext.len().to_string());
    if dbg_enabled() {
        for diag in &outcome.diagnostics {
            crate::debug::dbg_line(|| format!("diag: {diag}"));
        }
    }

    let llm_metadata: Option<LlmMetadata> = if cfg.emit_llm_metadata {
        Some(extract_llm_metadata(
            &outcome.plaintext,
            &outcome.diagnostics,
        ))
    } else {
        None
    };

    let key_classification: Option<RuntimeKeyClassification> = detection
        .serial
        .as_deref()
        .map(|serial: &str| classify_runtime_key(serial, &detection.raw_header));

    Ok(UnpackOutput {
        pyarmor_version: detection.version,
        protection_kind: detection.protection,
        python_version: zip_pyver(detection.python_major, detection.python_minor),
        pyc_magic: detection.pyc_magic,
        serial: detection.serial.clone(),
        confidence: detection.confidence,
        key_classification,
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

fn load_runtime_summary(
    runtime_bytes: &[u8],
    optional: bool,
) -> Result<Option<RuntimeInfoSummary>> {
    match load_runtime_info(runtime_bytes) {
        Ok(summary) => Ok(Some(summary)),
        Err(err) if optional => {
            crate::debug::dbg_kv("v6v7-runtime-summary-skipped", || format!("{err}"));
            Ok(None)
        }
        Err(err) => Err(err),
    }
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
        h = p.mul_add(-p.log2(), h);
    }
    h
}

const MAX_IMPORT_SYMBOLS: usize = 4096;
const MAX_IMPORT_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRING_CONSTANTS: usize = 2048;
const MAX_STRING_SCAN_BYTES: usize = MAX_IMPORT_SCAN_BYTES;
const MAX_STRING_BYTES: usize = 4096;

fn scan_import_symbols(plaintext: &[u8]) -> BTreeSet<String> {
    let scan_window: &[u8] = &plaintext[..plaintext.len().min(MAX_IMPORT_SCAN_BYTES)];
    let needles: [&[u8]; 4] = [b"import ", b"from ", b"__import__", b"importlib"];
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut pos: usize = 0;
    while pos < scan_window.len() {
        let tail: &[u8] = &scan_window[pos..];
        let Some(needle): Option<&[u8]> = needles
            .iter()
            .copied()
            .find(|needle: &&[u8]| tail.starts_with(needle))
        else {
            pos += 1;
            continue;
        };
        let abs: usize = pos + needle.len();
        let cap: usize = scan_window.len().min(abs + 96);
        let end: usize = (abs..cap)
            .find(|&i: &usize| !is_module_name_byte(scan_window[i]))
            .unwrap_or(cap);
        if end > abs
            && let Ok(name) = core::str::from_utf8(&scan_window[abs..end])
            && !name.is_empty()
        {
            out.insert(name.to_owned());
            if out.len() >= MAX_IMPORT_SYMBOLS {
                return out;
            }
        }
        pos = end.max(pos + 1);
    }
    out
}

#[inline]
const fn is_module_name_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_')
}

fn scan_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let scan_window: &[u8] = &data[..data.len().min(MAX_STRING_SCAN_BYTES)];
    let mut out: Vec<String> = Vec::with_capacity(MAX_STRING_CONSTANTS.min(32));
    let mut run_start: Option<usize> = None;
    for (i, &b) in scan_window.iter().enumerate() {
        let printable: bool = matches!(b, 0x20..=0x7e | b'\t');
        if printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            push_printable_string(&mut out, &scan_window[start..i], min_len);
            if out.len() >= MAX_STRING_CONSTANTS {
                return out;
            }
        }
    }
    if let Some(start) = run_start {
        push_printable_string(&mut out, &scan_window[start..], min_len);
    }
    out
}

fn push_printable_string(out: &mut Vec<String>, bytes: &[u8], min_len: usize) {
    let keep_len: usize = bytes.len().min(MAX_STRING_BYTES);
    if keep_len < min_len {
        return;
    }
    if let Ok(s) = core::str::from_utf8(&bytes[..keep_len]) {
        out.push(s.to_owned());
    }
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
    fn scan_printable_strings_stops_at_cap() {
        let mut data: Vec<u8> = Vec::new();
        for i in 0..(MAX_STRING_CONSTANTS + 500) {
            data.extend_from_slice(format!("s{i:04}").as_bytes());
            data.push(0);
        }
        let strings: Vec<String> = scan_printable_strings(&data, 4);
        assert_eq!(strings.len(), MAX_STRING_CONSTANTS);
        assert_eq!(strings.last().map(String::as_str), Some("s2047"));
    }

    #[test]
    fn scan_printable_strings_caps_single_long_run() {
        let data: Vec<u8> = vec![b'a'; MAX_STRING_BYTES + 1024];
        let strings: Vec<String> = scan_printable_strings(&data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].len(), MAX_STRING_BYTES);
    }

    #[test]
    fn scan_printable_strings_caps_scan_window() {
        let mut data: Vec<u8> = vec![b'a'; MAX_STRING_SCAN_BYTES];
        data.push(0);
        data.extend_from_slice(b"tailafter");
        let strings: Vec<String> = scan_printable_strings(&data, 4);
        assert!(strings.iter().all(|s: &String| s != "tailafter"));
    }

    #[test]
    fn import_symbol_scan() {
        let src: &[u8] = b"import os\nfrom collections import deque\n";
        let syms: BTreeSet<String> = scan_import_symbols(src);
        assert!(syms.contains("os"));
        assert!(syms.contains("collections"));
    }

    #[test]
    fn import_symbol_scan_bounds_overlapping_needle_run() {
        let hostile: Vec<u8> = b"from ".repeat(2_000_000);
        let start: std::time::Instant = std::time::Instant::now();
        let syms: BTreeSet<String> = scan_import_symbols(&hostile);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(syms.len() <= MAX_IMPORT_SYMBOLS);
        assert!(
            elapsed.as_secs() < 5,
            "single-pass scan must stay linear on adversarial repeated needles, took {elapsed:?}"
        );
    }

    #[test]
    fn import_symbol_scan_caps_distinct_symbols() {
        let mut hostile: Vec<u8> = Vec::new();
        for i in 0..(MAX_IMPORT_SYMBOLS + 500) {
            hostile.extend_from_slice(b"import mod");
            hostile.extend_from_slice(i.to_string().as_bytes());
            hostile.push(b'\n');
        }
        let syms: BTreeSet<String> = scan_import_symbols(&hostile);
        assert!(syms.len() <= MAX_IMPORT_SYMBOLS);
    }

    #[test]
    fn unpack_static_rejects_garbage() {
        let result: Result<UnpackOutput> = unpack_static(&[0u8; 4]);
        assert!(
            matches!(result, Err(Error::NotPyarmor)),
            "non-pyarmor garbage must be rejected at the wrapper sniff; got {result:?}"
        );
    }

    #[test]
    fn unpack_static_rejects_too_short_v8() {
        let bytes: Vec<u8> = b"PY009000".to_vec();
        let result: Result<UnpackOutput> = unpack_static(&bytes);
        assert!(
            matches!(result, Err(Error::HeaderTruncated { need: 64, got: 8 })),
            "a valid PY magic with a sub-64-byte header must report header truncation; got {result:?}"
        );
    }
}
