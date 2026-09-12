use disrobe_core::scratch::ScratchDir;
use std::io::Read as _;
use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use crate::corpus::{CorpusEntry, CorpusKind};
use crate::metrics::SampleMetrics;

#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub samples: Vec<SampleMetrics>,
}

const MAX_HASH_DEPTH: usize = 64;
const MAX_HASH_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HASH_FILES: usize = 65_536;
const MAX_SAMPLE_BYTES: u64 = 256 * 1024 * 1024;

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn bytes_len(bytes: &[u8]) -> u64 {
    len_u64(bytes.len())
}

#[must_use]
pub fn run_sample(entry: &CorpusEntry) -> Vec<SampleMetrics> {
    let bytes: Vec<u8> = match read_bounded_file(&entry.path, MAX_SAMPLE_BYTES) {
        Ok(b) => b,
        Err(e) => {
            return vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: kind_to_pass(entry.kind).to_owned(),
                ok: false,
                recovered: false,
                input_bytes: 0,
                output_bytes: 0,
                micros: 0,
                blake3_input: String::new(),
                blake3_output: None,
                message: Some(format!("read: {e}")),
            }];
        }
    };
    let blake_in: String = blake3::hash(&bytes).to_hex().to_string();

    match entry.kind {
        CorpusKind::JsObfuscatorIo | CorpusKind::JsWebpack => run_js(entry, &bytes, &blake_in),
        CorpusKind::Wasm => run_wasm(entry, &bytes, &blake_in),
        CorpusKind::PyArmor => run_pyarmor(entry, &bytes, &blake_in),
        CorpusKind::PyInstaller => run_pyinstaller(entry, &bytes, &blake_in),
        CorpusKind::Nuitka => run_nuitka(entry, &bytes, &blake_in),
        CorpusKind::CxFreeze | CorpusKind::Py2exe | CorpusKind::Shiv | CorpusKind::Pex => {
            run_pyfreeze(entry, &bytes, &blake_in)
        }
    }
}

fn run_pyarmor(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let Ok(text): core::result::Result<&str, core::str::Utf8Error> = std::str::from_utf8(bytes)
    else {
        return vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyarmor".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros: 0,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some("input not utf-8 (pyarmor wrappers are .py)".to_owned()),
        }];
    };
    let start: Instant = Instant::now();
    let result: disrobe_pass_pyarmor::Result<disrobe_pass_pyarmor::UnpackOutput> =
        disrobe_pass_pyarmor::unpack_wrapper_text(text, &entry.path);
    let micros: u128 = start.elapsed().as_micros();
    match result {
        Ok(unpacked) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyarmor".to_owned(),
            ok: true,
            recovered: unpacked.pyc.is_some(),
            input_bytes: bytes_len(bytes),
            output_bytes: unpacked.pyc.as_ref().map_or(0, |p| len_u64(p.len())),
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: unpacked
                .pyc
                .as_ref()
                .map(|p| blake3::hash(p).to_hex().to_string()),
            message: Some(format!(
                "detected={:?} pyc={} marshal_err={:?}",
                unpacked.detection.version,
                unpacked.pyc.is_some(),
                unpacked.marshal_error
            )),
        }],
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyarmor".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("{e}")),
        }],
    }
}

fn run_pyinstaller(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let start: Instant = Instant::now();
    let extraction: disrobe_pass_pyinstaller::Result<disrobe_pass_pyinstaller::ExtractOutput> =
        disrobe_pass_pyinstaller::extract_archive(bytes);
    let micros: u128 = start.elapsed().as_micros();
    match extraction {
        Ok(out) => {
            let mut hasher: blake3::Hasher = blake3::Hasher::new();
            let mut output_bytes: u64 = 0;
            for member in &out.entries {
                hasher.update(&member.data);
                output_bytes = output_bytes.saturating_add(len_u64(member.data.len()));
            }
            let pyc_carriers: usize = out
                .entries
                .iter()
                .filter(|m: &&disrobe_pass_pyinstaller::ExtractedEntry| {
                    m.toc.entry_type.is_pyc_carrier()
                })
                .count();
            let recovered: bool = !out.entries.is_empty();
            let blake_out: Option<String> =
                recovered.then(|| hasher.finalize().to_hex().to_string());
            vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: "pyinstaller".to_owned(),
                ok: true,
                recovered,
                input_bytes: bytes_len(bytes),
                output_bytes,
                micros,
                blake3_input: blake_in.to_owned(),
                blake3_output: blake_out,
                message: Some(format!(
                    "python={}.{} entries={} pyc_carriers={} keyed={}",
                    out.cookie.python_major,
                    out.cookie.python_minor,
                    out.entries.len(),
                    pyc_carriers,
                    out.encryption_key.is_some()
                )),
            }]
        }
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyinstaller".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("{e}")),
        }],
    }
}

fn run_nuitka(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let start: Instant = Instant::now();
    let classification: disrobe_pass_nuitka::Result<disrobe_pass_nuitka::VariantClassification> =
        disrobe_pass_nuitka::classify(bytes);
    let class: disrobe_pass_nuitka::VariantClassification = match classification {
        Ok(c) => c,
        Err(err) => {
            let micros: u128 = start.elapsed().as_micros();
            return vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: "nuitka".to_owned(),
                ok: false,
                recovered: false,
                input_bytes: bytes_len(bytes),
                output_bytes: 0,
                micros,
                blake3_input: blake_in.to_owned(),
                blake3_output: None,
                message: Some(format!("{err}")),
            }];
        }
    };

    match class.variant {
        disrobe_pass_nuitka::NuitkaVariant::OnefileKax
        | disrobe_pass_nuitka::NuitkaVariant::OnefileKay => {
            let Some(offset): Option<usize> = class.onefile_offset else {
                let micros: u128 = start.elapsed().as_micros();
                return vec![SampleMetrics {
                    entry: entry.clone(),
                    pass_name: "nuitka".to_owned(),
                    ok: false,
                    recovered: false,
                    input_bytes: bytes_len(bytes),
                    output_bytes: 0,
                    micros,
                    blake3_input: blake_in.to_owned(),
                    blake3_output: None,
                    message: Some("onefile payload offset missing".to_owned()),
                }];
            };
            let payload: disrobe_pass_nuitka::Result<disrobe_pass_nuitka::OnefilePayload> =
                disrobe_pass_nuitka::extract_onefile(bytes, offset);
            let micros: u128 = start.elapsed().as_micros();
            match payload {
                Ok(p) => {
                    let mut hasher: blake3::Hasher = blake3::Hasher::new();
                    let mut output_bytes: u64 = 0;
                    for member in &p.entries {
                        hasher.update(&member.data);
                        output_bytes = output_bytes.saturating_add(len_u64(member.data.len()));
                    }
                    let recovered: bool = !p.entries.is_empty();
                    let blake_out: Option<String> =
                        recovered.then(|| hasher.finalize().to_hex().to_string());
                    vec![SampleMetrics {
                        entry: entry.clone(),
                        pass_name: "nuitka".to_owned(),
                        ok: true,
                        recovered,
                        input_bytes: bytes_len(bytes),
                        output_bytes,
                        micros,
                        blake3_input: blake_in.to_owned(),
                        blake3_output: blake_out,
                        message: Some(format!(
                            "onefile compressed={} entries={} payload_bytes={}",
                            p.compressed,
                            p.entries.len(),
                            output_bytes
                        )),
                    }]
                }
                Err(e) => vec![SampleMetrics {
                    entry: entry.clone(),
                    pass_name: "nuitka".to_owned(),
                    ok: false,
                    recovered: false,
                    input_bytes: bytes_len(bytes),
                    output_bytes: 0,
                    micros,
                    blake3_input: blake_in.to_owned(),
                    blake3_output: None,
                    message: Some(format!("{e}")),
                }],
            }
        }
        other => {
            let micros: u128 = start.elapsed().as_micros();
            let reason: &str = match other {
                disrobe_pass_nuitka::NuitkaVariant::Standalone => {
                    "standalone: payload lives in sibling .dist/ files, not embedded in this image"
                }
                disrobe_pass_nuitka::NuitkaVariant::Module => {
                    "single module: PyInit_ entry; constants and impl_ symbols recovered via the nuitka surface/symbol passes, not a single embedded payload"
                }
                disrobe_pass_nuitka::NuitkaVariant::SignedPe => {
                    "signed pe: strip authenticode then re-classify via the nuitka pass for onefile payload"
                }
                disrobe_pass_nuitka::NuitkaVariant::Wheel => {
                    "wheel: route via the pyfreeze wheel extractor"
                }
                _ => "unrecognized nuitka variant",
            };
            vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: "nuitka".to_owned(),
                ok: true,
                recovered: false,
                input_bytes: bytes_len(bytes),
                output_bytes: 0,
                micros,
                blake3_input: blake_in.to_owned(),
                blake3_output: None,
                message: Some(format!("variant={other:?} {reason}")),
            }]
        }
    }
}

fn run_pyfreeze(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let start: Instant = Instant::now();
    let scratch: ScratchDir = match ScratchDir::create("validate-pyfreeze") {
        Ok(dir) => dir,
        Err(e) => {
            let micros: u128 = start.elapsed().as_micros();
            return vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: "pyfreeze".to_owned(),
                ok: false,
                recovered: false,
                input_bytes: bytes_len(bytes),
                output_bytes: 0,
                micros,
                blake3_input: blake_in.to_owned(),
                blake3_output: None,
                message: Some(format!("temp dir: {e}")),
            }];
        }
    };
    let out_dir: std::path::PathBuf = scratch.path().to_path_buf();
    let result: disrobe_pass_pyfreeze::Result<disrobe_pass_pyfreeze::PyfreezeOutput> =
        disrobe_pass_pyfreeze::extract(&entry.path, &out_dir);
    let micros: u128 = start.elapsed().as_micros();
    let metrics: Vec<SampleMetrics> = match result {
        Ok(out) => match hash_dir_tree(&out_dir) {
            Ok((output_bytes, blake_out)) => {
                let recovered: bool = out.extracted_count > 0;
                vec![SampleMetrics {
                    entry: entry.clone(),
                    pass_name: "pyfreeze".to_owned(),
                    ok: true,
                    recovered,
                    input_bytes: bytes_len(bytes),
                    output_bytes,
                    micros,
                    blake3_input: blake_in.to_owned(),
                    blake3_output: blake_out,
                    message: Some(format!(
                        "kind={:?} entries={} python={:?}.{:?}",
                        out.manifest.kind,
                        out.extracted_count,
                        out.manifest.python_major,
                        out.manifest.python_minor
                    )),
                }]
            }
            Err(e) => vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: "pyfreeze".to_owned(),
                ok: false,
                recovered: false,
                input_bytes: bytes_len(bytes),
                output_bytes: 0,
                micros,
                blake3_input: blake_in.to_owned(),
                blake3_output: None,
                message: Some(format!("output hash: {e}")),
            }],
        },
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyfreeze".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("{e}")),
        }],
    };
    if let Err(e) = scratch.close() {
        let cleanup_message: String = format!("temp cleanup: {e}");
        return metrics
            .into_iter()
            .map(|mut metric: SampleMetrics| {
                metric.ok = false;
                metric.recovered = false;
                metric.message = Some(metric.message.map_or_else(
                    || cleanup_message.clone(),
                    |msg: String| format!("{msg}; {cleanup_message}"),
                ));
                metric
            })
            .collect();
    }
    metrics
}

fn hash_dir_tree(root: &std::path::Path) -> Result<(u64, Option<String>), String> {
    hash_dir_tree_with_file_limit(root, MAX_HASH_FILE_BYTES)
}

fn hash_dir_tree_with_file_limit(
    root: &std::path::Path,
    max_file_bytes: u64,
) -> Result<(u64, Option<String>), String> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_files(root, &mut files, 0)?;
    files.sort();
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    let mut total: u64 = 0;
    for path in &files {
        let data: Vec<u8> = read_bounded_file(path, max_file_bytes)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        hasher.update(&data);
        total = total.saturating_add(len_u64(data.len()));
    }
    if files.is_empty() {
        Ok((0, None))
    } else {
        Ok((total, Some(hasher.finalize().to_hex().to_string())))
    }
}

fn collect_files(
    dir: &Path,
    out: &mut Vec<std::path::PathBuf>,
    depth: usize,
) -> Result<(), String> {
    if depth >= MAX_HASH_DEPTH {
        return Err(format!(
            "hash walk exceeded depth cap {MAX_HASH_DEPTH} at {}",
            dir.display()
        ));
    }
    if out.len() >= MAX_HASH_FILES {
        return Err(format!("hash walk exceeded file cap {MAX_HASH_FILES}"));
    }
    let entries: std::fs::ReadDir =
        std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry_result in entries {
        let entry: std::fs::DirEntry =
            entry_result.map_err(|e| format!("read_dir entry {}: {e}", dir.display()))?;
        if out.len() >= MAX_HASH_FILES {
            return Err(format!("hash walk exceeded file cap {MAX_HASH_FILES}"));
        }
        let file_type: std::fs::FileType = entry
            .file_type()
            .map_err(|e| format!("file_type {}: {e}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        let path: std::path::PathBuf = entry.path();
        if file_type.is_dir() {
            collect_files(&path, out, depth.saturating_add(1))?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file: std::fs::File =
        std::fs::File::open(path).map_err(|e: std::io::Error| format!("{e}"))?;
    let reserve: usize = file.metadata().map_or(0, |metadata: std::fs::Metadata| {
        usize::try_from(metadata.len().min(limit)).map_or(0, std::convert::identity)
    });
    let mut reader: std::io::Take<std::fs::File> = file.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    reader
        .read_to_end(&mut bytes)
        .map_err(|e: std::io::Error| format!("{e}"))?;
    let len: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > limit {
        return Err(format!("input exceeds {limit} bytes"));
    }
    Ok(bytes)
}

fn run_js(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let Ok(source): core::result::Result<&str, core::str::Utf8Error> = std::str::from_utf8(bytes)
    else {
        return vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "js-deob".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros: 0,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some("input not utf-8".to_owned()),
        }];
    };
    let start: Instant = Instant::now();
    let mut pass_errors: Vec<String> = Vec::new();
    let recovery: Option<disrobe_pass_js_deob::StringArrayRecovery> = record_js_stage_error(
        &mut pass_errors,
        "string_array",
        disrobe_pass_js_deob::recover_string_array(source),
    )
    .flatten();
    let mid: String = recovery
        .as_ref()
        .map_or_else(|| source.to_owned(), |r| r.rewritten_source.clone());
    let (after_unminify, _u): (String, disrobe_pass_js_deob::UnminifyStats) =
        disrobe_pass_js_deob::unminify(&mid);
    let (after_rename, _r): (String, disrobe_pass_js_deob::RenameStats) =
        disrobe_pass_js_deob::rename_hex_idents(&after_unminify);
    let (final_source, _s): (String, disrobe_pass_js_deob::ScopeAwareStats) =
        record_js_stage_error(
            &mut pass_errors,
            "scope_aware_rename",
            disrobe_pass_js_deob::rename_scope_aware(&after_rename),
        )
        .unwrap_or_else(|| {
            (
                after_rename.clone(),
                disrobe_pass_js_deob::ScopeAwareStats::default(),
            )
        });
    let micros: u128 = start.elapsed().as_micros();
    let blake_out: String = blake3::hash(final_source.as_bytes()).to_hex().to_string();
    let recovered: bool = final_source.as_str() != source;
    let (ok, message): (bool, String) =
        js_stage_outcome(recovery.is_some(), recovered, &pass_errors);
    vec![SampleMetrics {
        entry: entry.clone(),
        pass_name: "js-deob".to_owned(),
        ok,
        recovered,
        input_bytes: bytes_len(bytes),
        output_bytes: len_u64(final_source.len()),
        micros,
        blake3_input: blake_in.to_owned(),
        blake3_output: Some(blake_out),
        message: Some(message),
    }]
}

fn record_js_stage_error<T>(
    errors: &mut Vec<String>,
    stage: &str,
    result: disrobe_pass_js_deob::Result<T>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(e) => {
            errors.push(format!("{stage}: {e}"));
            None
        }
    }
}

fn js_stage_outcome(
    string_array_found: bool,
    recovered: bool,
    pass_errors: &[String],
) -> (bool, String) {
    if pass_errors.is_empty() {
        (
            true,
            format!("string_array={string_array_found} rewrote={recovered}"),
        )
    } else {
        (
            false,
            format!(
                "string_array={string_array_found} rewrote={recovered} errors=[{}]",
                pass_errors.join("; ")
            ),
        )
    }
}

fn run_wasm(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let start: Instant = Instant::now();
    let det: disrobe_pass_wasm_deob::Result<disrobe_pass_wasm_deob::WasmDetection> =
        disrobe_pass_wasm_deob::detect(bytes);
    let micros: u128 = start.elapsed().as_micros();
    match det {
        Ok(d) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "wasm-detect".to_owned(),
            ok: true,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!(
                "detected={:?} confidence={:.2} (detection only)",
                d.obfuscator, d.confidence
            )),
        }],
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "wasm-detect".to_owned(),
            ok: false,
            recovered: false,
            input_bytes: bytes_len(bytes),
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("{e}")),
        }],
    }
}

const fn kind_to_pass(k: CorpusKind) -> &'static str {
    match k {
        CorpusKind::PyArmor => "pyarmor",
        CorpusKind::PyInstaller => "pyinstaller",
        CorpusKind::Nuitka => "nuitka",
        CorpusKind::CxFreeze | CorpusKind::Py2exe | CorpusKind::Shiv | CorpusKind::Pex => {
            "pyfreeze"
        }
        CorpusKind::JsObfuscatorIo | CorpusKind::JsWebpack => "js-deob",
        CorpusKind::Wasm => "wasm",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bounded_file_reader_rejects_limit_overrun() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_validator_read_limit_test")
                .expect("create scratch directory");
        let base: std::path::PathBuf = scratch.path().to_path_buf();
        let path: std::path::PathBuf = base.join("sample.bin");
        std::fs::write(&path, b"abcd").unwrap();
        let err: String = read_bounded_file(&path, 3).expect_err("limit must reject");
        assert!(err.contains("exceeds 3 bytes"));
    }

    #[test]
    fn collect_files_stops_at_file_cap() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_validator_collect_cap_test")
                .expect("create scratch directory");
        let base: std::path::PathBuf = scratch.path().to_path_buf();
        for i in 0..4usize {
            std::fs::write(base.join(format!("{i}.bin")), [u8::try_from(i).unwrap()]).unwrap();
        }
        let mut out: Vec<std::path::PathBuf> = Vec::with_capacity(MAX_HASH_FILES);
        out.resize(MAX_HASH_FILES - 2, std::path::PathBuf::from("seed"));
        let err: String = collect_files(&base, &mut out, 0).expect_err("file cap must reject");
        assert!(err.contains("file cap"));
        assert_eq!(out.len(), MAX_HASH_FILES);
    }

    #[test]
    fn hash_dir_tree_reports_file_read_errors() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_validator_hash_read_error_test")
                .expect("create scratch directory");
        let base: std::path::PathBuf = scratch.path().to_path_buf();
        let path: std::path::PathBuf = base.join("sample.bin");
        std::fs::write(&path, b"abcd").unwrap();
        let err: String =
            hash_dir_tree_with_file_limit(&base, 3).expect_err("read cap must reject");
        assert!(err.contains("sample.bin"));
        assert!(err.contains("exceeds 3 bytes"));
    }

    #[test]
    fn pyfreeze_leaves_no_scratch_directory_behind() {
        let blake_in: String = format!("no-leak-{}", std::process::id());
        let entry: CorpusEntry = CorpusEntry {
            kind: CorpusKind::CxFreeze,
            path: std::path::PathBuf::from("a-path-that-does-not-exist.input"),
            size_bytes: 0,
        };
        let before: std::collections::BTreeSet<String> = extraction_directories();
        let metrics: Vec<SampleMetrics> = run_pyfreeze(&entry, b"", &blake_in);
        assert_eq!(metrics.len(), 1);
        assert!(
            !metrics[0].ok,
            "an absent input must not report a successful run"
        );
        let after: std::collections::BTreeSet<String> = extraction_directories();
        let gained: Vec<&String> = after.difference(&before).collect::<Vec<&String>>();
        assert!(
            gained.is_empty(),
            "the extraction directory must not outlive the call, even on the failure path: {gained:?}"
        );
    }

    fn extraction_directories() -> std::collections::BTreeSet<String> {
        let Ok(entries): std::io::Result<std::fs::ReadDir> =
            std::fs::read_dir(disrobe_core::scratch::scratch_root())
        else {
            return std::collections::BTreeSet::new();
        };
        entries
            .flatten()
            .filter_map(|entry: std::fs::DirEntry| {
                let name: String = entry.file_name().to_string_lossy().into_owned();
                name.starts_with("validate-pyfreeze-").then_some(name)
            })
            .collect()
    }

    #[test]
    fn collect_files_skips_symlinked_dirs() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_validator_collect_symlink_test")
                .expect("create scratch directory");
        let base: std::path::PathBuf = scratch.path().to_path_buf();
        let root: std::path::PathBuf = base.join("root");
        let outside: std::path::PathBuf = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("hidden.bin"), b"hidden").unwrap();
        let link: std::path::PathBuf = root.join("linked");
        if create_dir_symlink(&outside, &link).is_err() {
            return;
        }
        let mut out: Vec<std::path::PathBuf> = Vec::new();
        collect_files(&root, &mut out, 0).unwrap();
        assert!(out.is_empty(), "unexpected entries: {out:?}");
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[test]
    fn js_stage_error_is_recorded_not_silently_dropped() {
        let mut errors: Vec<String> = Vec::new();
        let ok_outcome: Option<disrobe_pass_js_deob::StringArrayRecovery> = record_js_stage_error(
            &mut errors,
            "string_array",
            disrobe_pass_js_deob::recover_string_array("const x = 1;"),
        )
        .flatten();
        assert!(ok_outcome.is_none());
        assert!(
            errors.is_empty(),
            "a genuinely successful pass must not be reported as errored: {errors:?}"
        );

        let failing: disrobe_pass_js_deob::Result<(String, disrobe_pass_js_deob::ScopeAwareStats)> =
            Err(disrobe_pass_js_deob::Error::NoFamilyMatched);
        let failed_outcome: Option<(String, disrobe_pass_js_deob::ScopeAwareStats)> =
            record_js_stage_error(&mut errors, "scope_aware_rename", failing);
        assert!(
            failed_outcome.is_none(),
            "an errored pass must not be papered over with a silent fallback value"
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("scope_aware_rename:"));
        assert!(errors[0].contains("DR-JSDEOB-0001"));
    }

    #[test]
    fn js_stage_outcome_reports_ok_false_when_a_pass_errored() {
        let (ok, message): (bool, String) = js_stage_outcome(true, true, &[]);
        assert!(ok, "no recorded errors must stay ok=true: {message}");
        assert!(!message.contains("errors="));

        let pass_errors: Vec<String> = vec!["scope_aware_rename: DR-JSDEOB-0001: boom".to_owned()];
        let (ok, message): (bool, String) = js_stage_outcome(true, true, &pass_errors);
        assert!(
            !ok,
            "a pass error must flip SampleMetrics::ok to false instead of silently passing"
        );
        assert!(message.contains("scope_aware_rename"));
    }
}
