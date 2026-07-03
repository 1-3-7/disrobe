use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_py_marshal::{Object, PyVersion, PycFile, PycHeader, load, write_pyc};

use crate::bcc_lift::{BccLiftOutput, lift_bcc_native};
use crate::descriptor_cache::{DescriptorCache, DescriptorCacheConfig};
use crate::detect::{Detection, ProtectionKind, PyarmorVersion, detect_from_wrapper};
use crate::dynamic_hook::{
    CaptureManifestEntry, CaptureSource, DynamicHookOptions, run_dynamic_hook_with_target,
};
use crate::error::{Error, Result};
use crate::inner_cipher::{
    DecryptionStats, PyarmorModuleState, decrypt_module_with_cache, parse_plaintext_xor_procedure,
};
use crate::mode_class::{ModeClassification, classify_modes};
use crate::nine_pro::{NineProDetection, detect_nine_pro};
use crate::provenance::{ProvenanceStage, PyarmorProvenance};
use crate::runtime::{RuntimeLocation, locate_runtime};
use crate::sourcedefender_cross::{CrossoverFinding, detect_sourcedefender_cross};
use crate::v3v4v5::{self, LegacyAnalysis};
use crate::v6v7;
use crate::v8v9::{self, V8V9DecryptedPayload, parse_plaintext_header};
use crate::wrap;
use crate::{MAX_CAPTURE_FILE_BYTES, read_file_bounded};

const DYNAMIC_FALLBACK_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModeOverride {
    #[default]
    Auto,
    Standard,
    Super,
}

impl ModeOverride {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Standard => "standard",
            Self::Super => "super",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "standard" => Some(Self::Standard),
            "super" => Some(Self::Super),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetPyVersion {
    pub major: u8,
    pub minor: u8,
}

impl TargetPyVersion {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed: &str = raw.trim();
        let mut parts: std::str::Split<'_, char> = trimmed.split('.');
        let major: u8 = parts.next()?.parse().ok()?;
        let minor: u8 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self { major, minor })
    }

    #[must_use]
    pub const fn pyc_magic_u16(self) -> Option<u16> {
        match (self.major, self.minor) {
            (2, 7) => Some(62211),
            (3, 3) => Some(3230),
            (3, 4) => Some(3310),
            (3, 5) => Some(3351),
            (3, 6) => Some(3379),
            (3, 7) => Some(3394),
            (3, 8) => Some(3413),
            (3, 9) => Some(3425),
            (3, 10) => Some(3439),
            (3, 11) => Some(3495),
            (3, 12) => Some(3531),
            (3, 13) => Some(3571),
            (3, 14) => Some(3627),
            (3, 15) => Some(3666),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnpackOptions {
    pub allow_dynamic: bool,
    pub dynamic_out_dir: Option<PathBuf>,
    pub dynamic_timeout: Option<Duration>,
    pub descriptor_cache: Option<DescriptorCacheConfig>,
    pub descriptor_cache_dir: Option<PathBuf>,
    pub emit_provenance: bool,
    pub allow_bcc: bool,
    pub mode_override: ModeOverride,
    pub target_pyver: Option<TargetPyVersion>,
    pub all_emits: bool,
    pub strict: bool,
    pub no_cextract: bool,
    pub cextract_only: bool,
}

#[derive(Debug, Clone)]
pub struct UserCodeCandidate {
    pub pyc_path: PathBuf,
    pub source: CaptureSource,
    pub index: usize,
    pub size: usize,
    pub sha256: String,
    pub has_armor_enter: bool,
    pub distinct_names: usize,
    pub names_sample: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone)]
pub struct DynamicHookSummary {
    pub manifest_path: PathBuf,
    pub interpreter: PathBuf,
    pub interpreter_version: (u8, u8, u8),
    pub stderr_excerpt: String,
    pub exit_code: Option<i32>,
    pub total_captures: usize,
    pub user_code_candidates: Vec<UserCodeCandidate>,
    pub primary_candidate: Option<UserCodeCandidate>,
    pub limitations: Vec<crate::dynamic_hook::CaptureLimitation>,
}

#[derive(Debug)]
pub struct UnpackOutput {
    pub detection: Detection,
    pub runtime_path: std::path::PathBuf,
    pub key_hex: String,
    pub iv_hex: String,
    pub plaintext: Vec<u8>,
    pub pyc: Option<Vec<u8>>,
    pub wrap_stripped: bool,
    pub py_version: Option<PyVersion>,
    pub marshal_error: Option<String>,
    pub marshal_offset: usize,
    pub inner_cipher_stats: Option<DecryptionStats>,
    pub dynamic_hook: Option<DynamicHookSummary>,
    pub fallback_reason: Option<String>,
    pub nine_pro: NineProDetection,
    pub mode_classification: ModeClassification,
    pub sourcedefender_crossover: Vec<CrossoverFinding>,
    pub provenance: Option<PyarmorProvenance>,
    pub bcc_blobs: Vec<crate::v8v9::BccBlob>,
    pub bcc_lifts: Vec<BccLiftOutput>,
    pub bcc_lift_skipped_reason: Option<String>,
}

pub fn unpack_wrapper_text(wrapper_text: &str, wrapper_path: &Path) -> Result<UnpackOutput> {
    unpack_wrapper_text_with_options(wrapper_text, wrapper_path, &UnpackOptions::default())
}

pub fn unpack_wrapper_text_with_options(
    wrapper_text: &str,
    wrapper_path: &Path,
    options: &UnpackOptions,
) -> Result<UnpackOutput> {
    let (mut detection, payload): (Detection, Vec<u8>) = detect_from_wrapper(wrapper_text)?;
    apply_mode_override(&mut detection, options.mode_override)?;

    if matches!(
        detection.version,
        PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5
    ) {
        let mut legacy_output: UnpackOutput =
            legacy_detection_only_output(&detection, wrapper_path, &payload);
        match v3v4v5::analyze_legacy(&payload, &detection) {
            Ok(analysis) => {
                let LegacyAnalysis {
                    version,
                    format,
                    wall_reason,
                    diagnostics,
                    ..
                }: LegacyAnalysis = analysis;
                legacy_output.fallback_reason = Some(format!(
                    "{version:?} {}: static decryption is an information-theoretic wall (AES-128-CTR key RSA-wrapped in capsule, absent from artifact)",
                    format.label()
                ));
                let mut diag_combined: Vec<String> = legacy_output.detection.diagnostics.clone();
                diag_combined.extend(diagnostics);
                diag_combined.push(wall_reason);
                legacy_output.detection.diagnostics = diag_combined;
            }
            Err(err) => {
                legacy_output.fallback_reason = Some(format!(
                    "{:?} detect-only; legacy format analysis failed: {err}",
                    detection.version
                ));
            }
        }
        if options.strict {
            return Err(Error::StrictPartial(format!(
                "{:?} legacy static wall: AES-128-CTR key is RSA-wrapped in the capsule and not present in the distributed artifact",
                detection.version
            )));
        }
        return Ok(legacy_output);
    }

    let runtime: RuntimeLocation = locate_runtime(wrapper_path, detection.serial.as_deref())?;

    let nine_pro: NineProDetection = detect_nine_pro(&payload);
    let mode_classification: ModeClassification = classify_modes(wrapper_text, &payload);
    let crossover: Vec<CrossoverFinding> =
        detect_sourcedefender_cross(wrapper_text, Some(wrapper_path), &payload);

    if matches!(detection.protection, ProtectionKind::Bcc) && !options.allow_bcc {
        crate::debug::dbg_line(|| {
            "BCC wall: native bytecode protection present, --allow-bcc not set".to_owned()
        });
        return Err(Error::BccRequiresAllowBcc);
    }
    let mut output: UnpackOutput = match detection.version {
        PyarmorVersion::V8 | PyarmorVersion::V9 => {
            unpack_v8v9(&payload, &detection, &runtime, options)
        }
        PyarmorVersion::V6 | PyarmorVersion::V7 => {
            unpack_v6v7(&payload, &detection, &runtime, wrapper_path, options)
        }
        PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5 => {
            Err(Error::LegacyNotImplemented)
        }
    }?;

    output.nine_pro = nine_pro;
    output.mode_classification = mode_classification;
    output.sourcedefender_crossover = crossover;

    if let Some(target) = options.target_pyver {
        rewrite_pyc_for_target(&mut output, target)?;
    }

    if options.strict
        && (output.pyc.is_none()
            || output.fallback_reason.is_some()
            || output.marshal_error.is_some())
    {
        let reason: String = output
            .marshal_error
            .clone()
            .or_else(|| output.fallback_reason.clone())
            .unwrap_or_else(|| "no pyc emitted".to_owned());
        return Err(Error::StrictPartial(reason));
    }

    Ok(output)
}

fn apply_mode_override(detection: &mut Detection, override_mode: ModeOverride) -> Result<()> {
    match override_mode {
        ModeOverride::Auto => Ok(()),
        ModeOverride::Standard => {
            if matches!(detection.protection, ProtectionKind::Bcc) {
                return Err(Error::ModeOverrideIncompatible(
                    "standard".to_owned(),
                    format!("{:?}", detection.protection),
                ));
            }
            detection.protection = ProtectionKind::Standard;
            Ok(())
        }
        ModeOverride::Super => {
            detection.protection = ProtectionKind::SuperMode;
            Ok(())
        }
    }
}

fn legacy_detection_only_output(
    detection: &Detection,
    wrapper_path: &Path,
    payload: &[u8],
) -> UnpackOutput {
    let runtime_guess: PathBuf = wrapper_path
        .parent()
        .map_or_else(|| PathBuf::from("."), |p| p.join("pytransform"));
    let reason: String = detection.diagnostics.first().cloned().unwrap_or_else(|| {
        format!(
            "{:?} detect-only; no sample corpus available",
            detection.version
        )
    });
    UnpackOutput {
        detection: detection.clone(),
        runtime_path: runtime_guess,
        key_hex: String::new(),
        iv_hex: String::new(),
        plaintext: payload.to_vec(),
        pyc: None,
        wrap_stripped: false,
        py_version: None,
        marshal_error: None,
        marshal_offset: 0,
        inner_cipher_stats: None,
        dynamic_hook: None,
        fallback_reason: Some(reason),
        nine_pro: crate::nine_pro::NineProDetection {
            is_nine_pro: false,
            bind_mode: crate::nine_pro::NineProBindMode::None,
            bind_flags: 0,
            restrict_byte: 0,
            expiration_ts: None,
            bind_markers_found: Vec::new(),
        },
        mode_classification: ModeClassification::unclassified(),
        sourcedefender_crossover: Vec::new(),
        provenance: None,
        bcc_blobs: Vec::new(),
        bcc_lifts: Vec::new(),
        bcc_lift_skipped_reason: None,
    }
}

fn rewrite_pyc_for_target(output: &mut UnpackOutput, target: TargetPyVersion) -> Result<()> {
    let Some(pyc_bytes): Option<Vec<u8>> = output.pyc.clone() else {
        return Ok(());
    };
    let Some(target_magic): Option<u16> = target.pyc_magic_u16() else {
        return Err(Error::UnknownTargetPyVersion(format!(
            "{}.{}",
            target.major, target.minor
        )));
    };
    if pyc_bytes.len() < 16 {
        return Ok(());
    }
    let mut rewritten: Vec<u8> = pyc_bytes;
    rewritten[0..2].copy_from_slice(&target_magic.to_le_bytes());
    output.pyc = Some(rewritten);
    output.py_version = Some(PyVersion::new(target.major, target.minor));
    Ok(())
}

fn unpack_v8v9(
    payload: &[u8],
    detection: &Detection,
    runtime: &RuntimeLocation,
    options: &UnpackOptions,
) -> Result<UnpackOutput> {
    let decrypted: V8V9DecryptedPayload = v8v9::decrypt(payload, detection, runtime)?;
    Ok(finalize_v8v9(detection, runtime, decrypted, options))
}

fn unpack_v6v7(
    payload: &[u8],
    detection: &Detection,
    runtime: &RuntimeLocation,
    wrapper_path: &Path,
    options: &UnpackOptions,
) -> Result<UnpackOutput> {
    if matches!(detection.protection, ProtectionKind::SuperMode) {
        if !options.allow_dynamic {
            crate::debug::dbg_line(|| {
                format!(
                    "{:?} super-mode wall: static unpack inapplicable and --allow-dynamic not set",
                    detection.version
                )
            });
            return Err(Error::DynamicHookRequiresAllow);
        }
        let reason: String = format!(
            "{:?} super-mode: static unpack inapplicable (no AES; pytransform.pyd mutates PyCode_Type at import); routed to dynamic-hook pipeline",
            detection.version
        );
        crate::debug::dbg_line(|| reason.clone());
        return attempt_dynamic_fallback(detection, runtime, wrapper_path, options, reason);
    }

    let static_result: Result<v6v7::V6V7DecryptedPayload> =
        v6v7::decrypt(payload, detection, runtime);

    match static_result {
        Ok(decrypted) => {
            let iv: [u8; 12] = [0u8; 12];
            let mut out: UnpackOutput = finalize(
                detection,
                runtime,
                &decrypted.key,
                &iv,
                decrypted.plaintext,
                None,
                options,
            );
            out.fallback_reason = None;
            Ok(out)
        }
        Err(err) => {
            if !options.allow_dynamic {
                return Err(err);
            }
            if !matches!(err, Error::KeyExtraction(_)) {
                return Err(err);
            }
            let reason: String = format!("{err}");
            attempt_dynamic_fallback(detection, runtime, wrapper_path, options, reason)
        }
    }
}

fn attempt_dynamic_fallback(
    detection: &Detection,
    runtime: &RuntimeLocation,
    wrapper_path: &Path,
    options: &UnpackOptions,
    reason: String,
) -> Result<UnpackOutput> {
    let out_dir: PathBuf = options.dynamic_out_dir.clone().unwrap_or_else(|| {
        wrapper_path.parent().map_or_else(
            || PathBuf::from(".disrobe_dynamic"),
            |p| p.join(".disrobe_dynamic"),
        )
    });

    let hook_options: DynamicHookOptions = DynamicHookOptions {
        allow_dynamic: true,
        timeout: options
            .dynamic_timeout
            .unwrap_or_else(|| Duration::from_secs(DYNAMIC_FALLBACK_TIMEOUT_SECS)),
        disable_pytrace: options.cextract_only,
        disable_cextract: options.no_cextract,
    };
    crate::debug::dbg_kv("dynamic-capture-path", || {
        match (hook_options.disable_cextract, hook_options.disable_pytrace) {
            (false, false) => "cextract + pytrace".to_owned(),
            (false, true) => "cextract only (pytrace disabled)".to_owned(),
            (true, false) => "pytrace only (cextract disabled)".to_owned(),
            (true, true) => {
                "monkeypatch/audithook only (both runtime captures disabled)".to_owned()
            }
        }
    });

    let target: Option<(u8, u8)> = detection.python_major.zip(detection.python_minor);
    let result: crate::dynamic_hook::DynamicHookResult =
        run_dynamic_hook_with_target(wrapper_path, &out_dir, hook_options, target)?;

    let py_major: u8 = detection.python_major.unwrap_or(3);
    let py_minor: u8 = detection.python_minor.unwrap_or(9);
    let py_version: PyVersion = PyVersion::new(py_major, py_minor);

    let mut all_entries: Vec<(CaptureSource, CaptureManifestEntry)> = Vec::new();
    for entry in &result.manifest.captures.monkeypatch {
        all_entries.push((CaptureSource::Monkeypatch, entry.clone()));
    }
    for entry in &result.manifest.captures.audithook {
        all_entries.push((CaptureSource::AuditHook, entry.clone()));
    }
    for entry in &result.manifest.captures.exec_calls {
        all_entries.push((CaptureSource::Exec, entry.clone()));
    }
    for entry in &result.manifest.captures.compile_calls {
        all_entries.push((CaptureSource::Compile, entry.clone()));
    }
    for entry in &result.manifest.captures.trace_calls {
        all_entries.push((CaptureSource::Trace, entry.clone()));
    }
    for entry in &result.manifest.captures.gcwalk {
        all_entries.push((CaptureSource::GcWalk, entry.clone()));
    }
    for entry in &result.manifest.captures.pytrace {
        all_entries.push((CaptureSource::Pytrace, entry.clone()));
    }
    for entry in &result.manifest.captures.cextract {
        all_entries.push((CaptureSource::Cextract, entry.clone()));
    }

    let wrapper_stem: String = wrapper_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .unwrap_or_default();
    let mut candidates: Vec<UserCodeCandidate> =
        classify_candidates_with_stem(&out_dir, &all_entries, py_version, &wrapper_stem);
    candidates.sort_by_key(|c| core::cmp::Reverse(c.score));
    let primary: Option<UserCodeCandidate> = candidates.first().cloned();
    let total_captures: usize = all_entries.len();

    let limitations: Vec<crate::dynamic_hook::CaptureLimitation> =
        result.manifest.limitations.clone();
    let summary: DynamicHookSummary = DynamicHookSummary {
        manifest_path: result.manifest_path,
        interpreter: result.interpreter,
        interpreter_version: result.interpreter_version,
        stderr_excerpt: result.stderr_excerpt,
        exit_code: result.exit_code,
        total_captures,
        user_code_candidates: candidates,
        primary_candidate: primary.clone(),
        limitations,
    };

    let primary_pyc_bytes: Option<Vec<u8>> = primary
        .as_ref()
        .and_then(|c| read_file_bounded(&c.pyc_path, MAX_CAPTURE_FILE_BYTES).ok());

    Ok(UnpackOutput {
        detection: detection.clone(),
        runtime_path: runtime.path.clone(),
        key_hex: String::new(),
        iv_hex: String::new(),
        plaintext: Vec::new(),
        pyc: primary_pyc_bytes,
        wrap_stripped: false,
        py_version: Some(py_version),
        marshal_error: None,
        marshal_offset: 0,
        inner_cipher_stats: None,
        dynamic_hook: Some(summary),
        fallback_reason: Some(reason),
        nine_pro: crate::nine_pro::NineProDetection {
            is_nine_pro: false,
            bind_mode: crate::nine_pro::NineProBindMode::None,
            bind_flags: 0,
            restrict_byte: 0,
            expiration_ts: None,
            bind_markers_found: Vec::new(),
        },
        mode_classification: ModeClassification::unclassified(),
        sourcedefender_crossover: Vec::new(),
        provenance: None,
        bcc_blobs: Vec::new(),
        bcc_lifts: Vec::new(),
        bcc_lift_skipped_reason: None,
    })
}

#[cfg(test)]
fn classify_candidates(
    out_dir: &Path,
    entries: &[(CaptureSource, CaptureManifestEntry)],
    py_version: PyVersion,
) -> Vec<UserCodeCandidate> {
    classify_candidates_with_stem(out_dir, entries, py_version, "")
}

fn classify_candidates_with_stem(
    out_dir: &Path,
    entries: &[(CaptureSource, CaptureManifestEntry)],
    py_version: PyVersion,
    wrapper_stem: &str,
) -> Vec<UserCodeCandidate> {
    let mut out: Vec<UserCodeCandidate> = Vec::with_capacity(entries.len());
    for (source, entry) in entries {
        let pyc_path: PathBuf = if Path::new(&entry.pyc_path).is_absolute() {
            PathBuf::from(&entry.pyc_path)
        } else {
            out_dir.join(&entry.pyc_path)
        };
        let Ok(bytes): Result<Vec<u8>> = read_file_bounded(&pyc_path, MAX_CAPTURE_FILE_BYTES)
        else {
            out.push(UserCodeCandidate {
                pyc_path,
                source: *source,
                index: entry.index,
                size: entry.size,
                sha256: entry.sha256.clone(),
                has_armor_enter: false,
                distinct_names: 0,
                names_sample: Vec::new(),
                score: 0,
            });
            continue;
        };

        let mut inspection: PycInspection = inspect_pyc(&bytes, py_version);
        if inspection.co_filename.is_empty() && !entry.co_filename.is_empty() {
            inspection.co_filename.clone_from(&entry.co_filename);
        }
        if inspection.distinct_names == 0 && entry.co_names_count > 0 {
            inspection.distinct_names = entry.co_names_count;
        }

        let mut score: u32 = 0;
        if inspection.has_armor_enter {
            score = score.saturating_add(5_000);
        }
        if is_decrypted_user_marker(&inspection.co_filename) {
            let bonus: u32 =
                if !wrapper_stem.is_empty() && inspection.co_filename.contains(wrapper_stem) {
                    40_000
                } else if is_cpython_frozen_internal(&inspection.co_filename) {
                    0
                } else {
                    10_000
                };
            score = score.saturating_add(bonus);
        }
        if matches!(source, CaptureSource::Cextract) {
            score = score.saturating_add(8_000);
        }
        if matches!(source, CaptureSource::Pytrace) {
            score = score.saturating_add(6_000);
        }
        if matches!(source, CaptureSource::GcWalk) {
            score = score.saturating_add(4_000);
        }
        if matches!(source, CaptureSource::Trace) {
            score = score.saturating_add(3_000);
        }
        if matches!(source, CaptureSource::Exec | CaptureSource::Compile) {
            score = score.saturating_add(2_000);
        }
        if is_runtime_module(&inspection.co_filename) {
            score = score.saturating_sub(score.min(7_000));
        }
        score =
            score.saturating_add(usize_to_u32_clamped(inspection.distinct_names).saturating_mul(5));
        score = score.saturating_add(usize_to_u32_clamped(entry.size) / 64);

        out.push(UserCodeCandidate {
            pyc_path,
            source: *source,
            index: entry.index,
            size: entry.size,
            sha256: entry.sha256.clone(),
            has_armor_enter: inspection.has_armor_enter,
            distinct_names: inspection.distinct_names,
            names_sample: inspection.names_sample,
            score,
        });
    }
    out
}

#[inline]
fn usize_to_u32_clamped(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

#[inline]
fn u64_to_usize_clamped(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[inline]
fn is_decrypted_user_marker(co_filename: &str) -> bool {
    let trimmed: &str = co_filename.trim();
    trimmed.starts_with("<frozen ") && trimmed.ends_with('>')
}

#[inline]
fn is_cpython_frozen_internal(co_filename: &str) -> bool {
    matches!(
        co_filename,
        "<frozen zipimport>"
            | "<frozen importlib._bootstrap>"
            | "<frozen importlib._bootstrap_external>"
            | "<frozen os>"
            | "<frozen posixpath>"
            | "<frozen ntpath>"
            | "<frozen codecs>"
            | "<frozen abc>"
            | "<frozen _collections_abc>"
            | "<frozen io>"
            | "<frozen genericpath>"
            | "<frozen _sitebuiltins>"
            | "<frozen site>"
            | "<frozen runpy>"
    )
}

#[inline]
fn is_runtime_module(co_filename: &str) -> bool {
    let lower: String = co_filename.to_lowercase();
    lower.contains("\\pytransform\\")
        || lower.contains("/pytransform/")
        || lower.contains("\\_pytransform")
        || lower.contains("/_pytransform")
        || lower.contains("\\disrobe_")
        || lower.contains("/disrobe_")
        || lower.contains(".disrobe_v6v7_helper")
        || lower.contains("\\runpy.py")
        || lower.contains("/runpy.py")
}

#[derive(Debug, Default)]
struct PycInspection {
    has_armor_enter: bool,
    distinct_names: usize,
    names_sample: Vec<String>,
    co_filename: String,
}

fn inspect_pyc(bytes: &[u8], py_version: PyVersion) -> PycInspection {
    let stream: &[u8] = strip_pyc_header(bytes, py_version);
    let Ok(obj): std::result::Result<Object, disrobe_py_marshal::Error> = load(stream, py_version)
    else {
        return PycInspection::default();
    };
    let Object::Code(co) = obj else {
        return PycInspection::default();
    };
    let names: Vec<String> = co
        .names
        .iter()
        .filter_map(|n| match n {
            Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
            _ => None,
        })
        .collect();
    let has_armor_enter: bool = names.iter().any(|n| n == "__armor_enter__");
    let mut sample: Vec<String> = names.iter().take(12).cloned().collect();
    sample.sort();
    sample.dedup();
    let co_filename: String = match &co.filename {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        _ => String::new(),
    };
    PycInspection {
        has_armor_enter,
        distinct_names: names.len(),
        names_sample: sample,
        co_filename,
    }
}

fn strip_pyc_header(bytes: &[u8], py_version: PyVersion) -> &[u8] {
    let header_len: usize =
        if py_version.major <= 2 || (py_version.major == 3 && py_version.minor < 3) {
            8
        } else if py_version.major == 3 && py_version.minor < 7 {
            12
        } else {
            16
        };
    if bytes.len() >= header_len {
        &bytes[header_len..]
    } else {
        bytes
    }
}

fn finalize_v8v9(
    detection: &Detection,
    runtime: &RuntimeLocation,
    decrypted: V8V9DecryptedPayload,
    options: &UnpackOptions,
) -> UnpackOutput {
    let (xor_key, xor_enabled): ([u8; 12], bool) =
        parse_plaintext_xor_procedure(&decrypted.plaintext);
    let py_major: u8 = detection.python_major.unwrap_or(3);
    let py_minor: u8 = detection.python_minor.unwrap_or(12);
    let py_version: PyVersion = PyVersion::new(py_major, py_minor);
    let state: PyarmorModuleState = PyarmorModuleState {
        aes_key: decrypted.key,
        mix_str_nonce: decrypted.mix_str_nonce,
        co_code_nonce_xor_key: xor_key,
        xor_enabled,
        py_version,
    };
    let bcc_blobs: Vec<crate::v8v9::BccBlob> = decrypted.bcc_blobs.clone();
    let mut out: UnpackOutput = finalize(
        detection,
        runtime,
        &decrypted.key,
        &decrypted.nonce,
        decrypted.plaintext,
        Some(&state),
        options,
    );
    if !bcc_blobs.is_empty() && options.allow_bcc {
        let mut lifts: Vec<BccLiftOutput> = Vec::with_capacity(bcc_blobs.len());
        let mut skip_msg: Option<String> = None;
        for blob in &bcc_blobs {
            match lift_bcc_native(&blob.bytes, blob.architecture) {
                Ok(lifted) => lifts.push(lifted),
                Err(e) => {
                    skip_msg = Some(format!(
                        "in-crate pseudo-C lift failed for {}: {e}",
                        blob.architecture.label()
                    ));
                    break;
                }
            }
        }
        out.bcc_lifts = lifts;
        out.bcc_lift_skipped_reason = skip_msg;
    } else if !bcc_blobs.is_empty() {
        out.bcc_lift_skipped_reason =
            Some("v9 BCC blobs present but --allow-bcc not set; lift skipped".to_owned());
    }
    out.bcc_blobs = bcc_blobs;
    out
}

struct MarshalLoadOutcome {
    pyc_bytes: Option<Vec<u8>>,
    wrap_stripped: bool,
    marshal_error: Option<String>,
    inner_cipher_stats: Option<DecryptionStats>,
}

fn record_v8v9_outer_provenance(
    provenance: Option<&mut PyarmorProvenance>,
    detection: &Detection,
    plaintext_len: usize,
    inner_offset: usize,
) {
    let Some(prov): Option<&mut PyarmorProvenance> = provenance else {
        return;
    };
    prov.record_range(
        0,
        detection.raw_header.len().min(plaintext_len),
        ProvenanceStage::HeaderParse,
        Some("v8/v9 outer header".to_owned()),
    );
    prov.record_range(
        detection.raw_header.len().min(plaintext_len),
        inner_offset.min(plaintext_len),
        ProvenanceStage::PlaintextHeader,
        None,
    );
    prov.record_range(
        inner_offset.min(plaintext_len),
        plaintext_len,
        ProvenanceStage::OuterCtrDecrypt,
        Some(format!(
            "aes-ctr {} bytes",
            plaintext_len - inner_offset.min(plaintext_len)
        )),
    );
}

fn run_marshal_load(
    marshal_stream: &[u8],
    plaintext_len: usize,
    inner_offset: usize,
    py_version: PyVersion,
    inner_state: Option<&PyarmorModuleState>,
    descriptor_cache: &mut DescriptorCache,
    mut provenance: Option<&mut PyarmorProvenance>,
) -> MarshalLoadOutcome {
    let mut obj: Object = match load(marshal_stream, py_version) {
        Ok(o) => o,
        Err(e) => {
            return MarshalLoadOutcome {
                pyc_bytes: None,
                wrap_stripped: false,
                marshal_error: Some(format!("{e}")),
                inner_cipher_stats: None,
            };
        }
    };

    let mut inner_cipher_stats: Option<DecryptionStats> = None;
    if let Some(state) = inner_state {
        let stats: DecryptionStats = decrypt_module_with_cache(&mut obj, state, descriptor_cache);
        if let Some(prov) = provenance.as_deref_mut() {
            prov.record_range(
                inner_offset.min(plaintext_len),
                inner_offset.min(plaintext_len) + u64_to_usize_clamped(stats.bytes_decrypted),
                ProvenanceStage::InnerDescriptorCtr,
                Some(format!("descriptors={}", stats.descriptors_applied)),
            );
        }
        inner_cipher_stats = Some(stats);

        let mix_count: usize =
            crate::mix_string::decrypt_mix_strings(&mut obj, &state.aes_key, &state.mix_str_nonce);
        if let Some(prov) = provenance.as_deref_mut()
            && mix_count > 0
        {
            prov.record_range(
                0,
                mix_count,
                ProvenanceStage::MixStringCtr,
                Some(format!("{mix_count} string objects rewritten")),
            );
        }
    }

    let mut wrap_stripped: bool = false;
    if let Object::Code(co) = &mut obj {
        wrap_stripped = wrap::strip_wrap(co);
        let rft_neutralized: usize = wrap::strip_rft_wrap(co, py_version);
        if let Some(prov) = provenance.as_deref_mut() {
            if wrap_stripped {
                prov.record_range(
                    0,
                    co.code.len(),
                    ProvenanceStage::WrapHeaderStrip,
                    Some("__armor_enter__/__armor_exit__ wrap removed".to_owned()),
                );
            }
            if rft_neutralized > 0 {
                prov.record_range(
                    0,
                    co.code.len(),
                    ProvenanceStage::WrapHeaderStrip,
                    Some(format!(
                        "__pyarmor_enter/exit/assert RFT wrap neutralized in {rft_neutralized} code objects"
                    )),
                );
            }
        }
        wrap_stripped = wrap_stripped || rft_neutralized > 0;
    }

    let pyc_bytes: Option<Vec<u8>> = PycHeader::deterministic(py_version)
        .ok()
        .and_then(|header| {
            let file: PycFile = PycFile { header, code: obj };
            write_pyc(&file).ok()
        });
    if let Some(prov) = provenance
        && let Some(bytes) = pyc_bytes.as_ref()
    {
        prov.record_range(0, 16, ProvenanceStage::PycHeader, None);
        prov.record_range(16, bytes.len(), ProvenanceStage::MarshalEmit, None);
    }

    MarshalLoadOutcome {
        pyc_bytes,
        wrap_stripped,
        marshal_error: None,
        inner_cipher_stats,
    }
}

fn finalize(
    detection: &Detection,
    runtime: &RuntimeLocation,
    key: &[u8],
    iv: &[u8],
    plaintext: Vec<u8>,
    inner_state: Option<&PyarmorModuleState>,
    options: &UnpackOptions,
) -> UnpackOutput {
    let py_major: u8 = detection.python_major.unwrap_or(3);
    let py_minor: u8 = detection.python_minor.unwrap_or(12);
    let py_version: PyVersion = PyVersion::new(py_major, py_minor);
    let inner_offset: usize = parse_plaintext_header(&plaintext)
        .map_or_else(|_| locate_marshal_start(&plaintext), |h| h.marshal_offset);

    let mut provenance: Option<PyarmorProvenance> =
        options.emit_provenance.then(PyarmorProvenance::new);
    record_v8v9_outer_provenance(
        provenance.as_mut(),
        detection,
        plaintext.len(),
        inner_offset,
    );

    let marshal_stream: &[u8] = if inner_offset < plaintext.len() {
        &plaintext[inner_offset..]
    } else {
        &[][..]
    };

    let mut descriptor_cache: DescriptorCache = options.descriptor_cache.map_or_else(
        || DescriptorCache::new(DescriptorCacheConfig::default()),
        DescriptorCache::new,
    );

    let outcome: MarshalLoadOutcome = run_marshal_load(
        marshal_stream,
        plaintext.len(),
        inner_offset,
        py_version,
        inner_state,
        &mut descriptor_cache,
        provenance.as_mut(),
    );

    UnpackOutput {
        detection: detection.clone(),
        runtime_path: runtime.path.clone(),
        key_hex: hex_encode(key),
        iv_hex: hex_encode(iv),
        plaintext,
        pyc: outcome.pyc_bytes,
        wrap_stripped: outcome.wrap_stripped,
        py_version: Some(py_version),
        marshal_error: outcome.marshal_error,
        marshal_offset: inner_offset,
        inner_cipher_stats: outcome.inner_cipher_stats,
        dynamic_hook: None,
        fallback_reason: None,
        nine_pro: crate::nine_pro::NineProDetection {
            is_nine_pro: false,
            bind_mode: crate::nine_pro::NineProBindMode::None,
            bind_flags: 0,
            restrict_byte: 0,
            expiration_ts: None,
            bind_markers_found: Vec::new(),
        },
        mode_classification: ModeClassification::unclassified(),
        sourcedefender_crossover: Vec::new(),
        provenance,
        bcc_blobs: Vec::new(),
        bcc_lifts: Vec::new(),
        bcc_lift_skipped_reason: None,
    }
}

fn locate_marshal_start(plaintext: &[u8]) -> usize {
    const MARSHAL_HEAD: &[u8] = &[0xE3];
    for (i, w) in plaintext.windows(1).enumerate() {
        if w == MARSHAL_HEAD {
            let after: &[u8] = &plaintext[i..];
            if after.len() > 16 && (after[1] & 0x7F) <= 0x20 {
                return i;
            }
        }
    }
    0x20.min(plaintext.len())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        s.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        s.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
    }

    #[test]
    fn decrypted_user_marker_matches_frozen_brackets() {
        assert!(is_decrypted_user_marker("<frozen hello>"));
        assert!(is_decrypted_user_marker("<frozen my_module>"));
        assert!(!is_decrypted_user_marker("hello.py"));
        assert!(!is_decrypted_user_marker("<module>"));
        assert!(!is_decrypted_user_marker("frozen hello"));
    }

    #[test]
    fn runtime_module_detection_matches_pytransform_paths() {
        assert!(is_runtime_module("C:\\foo\\pytransform\\__init__.py"));
        assert!(is_runtime_module("/home/u/pytransform/__init__.py"));
        assert!(is_runtime_module("/lib/python3.9/runpy.py"));
        assert!(is_runtime_module("C:/Users/-/disrobe_v6v7_helper.py"));
        assert!(!is_runtime_module("/home/u/myapp/main.py"));
        assert!(!is_runtime_module("<frozen hello>"));
    }

    #[test]
    fn unpack_options_default_is_static_only() {
        let opts: UnpackOptions = UnpackOptions::default();
        assert!(!opts.allow_dynamic);
        assert!(opts.dynamic_out_dir.is_none());
        assert!(opts.dynamic_timeout.is_none());
    }

    #[test]
    fn classify_candidates_scores_cextract_highest() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let seq: u64 = N.fetch_add(1, Ordering::Relaxed);
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "disrobe_unpack_score_{}_{}",
            std::process::id(),
            seq
        ));
        let _: std::io::Result<()> = std::fs::create_dir_all(&dir);

        let placeholder_body: [u8; 16] = [0u8; 16];
        let names: [&str; 3] = ["trace.pyc", "cextract.pyc", "pytrace.pyc"];
        for n in names {
            let _: std::io::Result<()> = std::fs::write(dir.join(n), placeholder_body);
        }

        let entries: Vec<(CaptureSource, CaptureManifestEntry)> = vec![
            (
                CaptureSource::Trace,
                CaptureManifestEntry {
                    index: 0,
                    size: 16,
                    sha256: "a".to_owned(),
                    pyc_path: "trace.pyc".to_owned(),
                    co_filename: String::new(),
                    co_name: String::new(),
                    co_names_count: 0,
                },
            ),
            (
                CaptureSource::Cextract,
                CaptureManifestEntry {
                    index: 0,
                    size: 16,
                    sha256: "b".to_owned(),
                    pyc_path: "cextract.pyc".to_owned(),
                    co_filename: String::new(),
                    co_name: String::new(),
                    co_names_count: 0,
                },
            ),
            (
                CaptureSource::Pytrace,
                CaptureManifestEntry {
                    index: 0,
                    size: 16,
                    sha256: "c".to_owned(),
                    pyc_path: "pytrace.pyc".to_owned(),
                    co_filename: String::new(),
                    co_name: String::new(),
                    co_names_count: 0,
                },
            ),
        ];
        let py_version: PyVersion = PyVersion::new(3, 11);
        let candidates: Vec<UserCodeCandidate> = classify_candidates(&dir, &entries, py_version);
        let cext_score: u32 = candidates
            .iter()
            .find(|c| matches!(c.source, CaptureSource::Cextract))
            .map_or(0, |c: &UserCodeCandidate| c.score);
        let pyt_score: u32 = candidates
            .iter()
            .find(|c| matches!(c.source, CaptureSource::Pytrace))
            .map_or(0, |c: &UserCodeCandidate| c.score);
        let trace_score: u32 = candidates
            .iter()
            .find(|c| matches!(c.source, CaptureSource::Trace))
            .map_or(0, |c: &UserCodeCandidate| c.score);
        assert!(
            cext_score > pyt_score,
            "cextract {cext_score} should beat pytrace {pyt_score}"
        );
        assert!(
            pyt_score > trace_score,
            "pytrace {pyt_score} should beat trace {trace_score}"
        );
        let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);
    }
}
