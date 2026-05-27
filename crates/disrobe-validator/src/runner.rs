use std::time::Instant;

use serde::Serialize;

use crate::corpus::{CorpusEntry, CorpusKind};
use crate::metrics::SampleMetrics;

#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub samples: Vec<SampleMetrics>,
}

pub fn run_sample(entry: &CorpusEntry) -> Vec<SampleMetrics> {
    let bytes: Vec<u8> = match std::fs::read(&entry.path) {
        Ok(b) => b,
        Err(e) => {
            return vec![SampleMetrics {
                entry: entry.clone(),
                pass_name: kind_to_pass(entry.kind).to_owned(),
                ok: false,
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
            input_bytes: bytes.len() as u64,
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
            input_bytes: bytes.len() as u64,
            output_bytes: unpacked.pyc.as_ref().map_or(0, |p| p.len() as u64),
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
            input_bytes: bytes.len() as u64,
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
    let cookie: disrobe_pass_pyinstaller::Result<disrobe_pass_pyinstaller::Cookie> =
        disrobe_pass_pyinstaller::find_cookie(bytes);
    let micros: u128 = start.elapsed().as_micros();
    match cookie {
        Ok(c) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyinstaller".to_owned(),
            ok: true,
            input_bytes: bytes.len() as u64,
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!(
                "python={}.{} toc_entries~{}",
                c.python_major, c.python_minor, c.toc_length
            )),
        }],
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "pyinstaller".to_owned(),
            ok: false,
            input_bytes: bytes.len() as u64,
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
    let det: disrobe_pass_nuitka::Result<disrobe_pass_nuitka::Detection> =
        disrobe_pass_nuitka::detect_in_bytes(bytes);
    let micros: u128 = start.elapsed().as_micros();
    match det {
        Ok(d) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "nuitka".to_owned(),
            ok: true,
            input_bytes: bytes.len() as u64,
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("flavor={:?} sigs={}", d.flavor, d.hits.len())),
        }],
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "nuitka".to_owned(),
            ok: false,
            input_bytes: bytes.len() as u64,
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!("{e}")),
        }],
    }
}

fn run_pyfreeze(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let start: Instant = Instant::now();
    let det: disrobe_pass_pyfreeze::Detection =
        disrobe_pass_pyfreeze::detect_bytes(bytes, Some(&entry.path));
    let micros: u128 = start.elapsed().as_micros();
    vec![SampleMetrics {
        entry: entry.clone(),
        pass_name: "pyfreeze".to_owned(),
        ok: !matches!(det.kind, disrobe_pass_pyfreeze::FreezerKind::Unknown),
        input_bytes: bytes.len() as u64,
        output_bytes: 0,
        micros,
        blake3_input: blake_in.to_owned(),
        blake3_output: None,
        message: Some(format!(
            "kind={:?} confidence={:.2}",
            det.kind, det.confidence
        )),
    }]
}

fn run_js(entry: &CorpusEntry, bytes: &[u8], blake_in: &str) -> Vec<SampleMetrics> {
    let Ok(source): core::result::Result<&str, core::str::Utf8Error> = std::str::from_utf8(bytes)
    else {
        return vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "js-deob".to_owned(),
            ok: false,
            input_bytes: bytes.len() as u64,
            output_bytes: 0,
            micros: 0,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some("input not utf-8".to_owned()),
        }];
    };
    let start: Instant = Instant::now();
    let recovery: Option<disrobe_pass_js_deob::StringArrayRecovery> =
        disrobe_pass_js_deob::recover_string_array(source)
            .ok()
            .flatten();
    let mid: String = recovery
        .as_ref()
        .map_or_else(|| source.to_owned(), |r| r.rewritten_source.clone());
    let (after_unminify, _u): (String, disrobe_pass_js_deob::UnminifyStats) =
        disrobe_pass_js_deob::unminify(&mid);
    let (after_rename, _r): (String, disrobe_pass_js_deob::RenameStats) =
        disrobe_pass_js_deob::rename_hex_idents(&after_unminify);
    let (final_source, _s): (String, disrobe_pass_js_deob::ScopeAwareStats) =
        disrobe_pass_js_deob::rename_scope_aware(&after_rename).unwrap_or_else(|_| {
            (
                after_rename.clone(),
                disrobe_pass_js_deob::ScopeAwareStats::default(),
            )
        });
    let micros: u128 = start.elapsed().as_micros();
    let blake_out: String = blake3::hash(final_source.as_bytes()).to_hex().to_string();
    vec![SampleMetrics {
        entry: entry.clone(),
        pass_name: "js-deob".to_owned(),
        ok: true,
        input_bytes: bytes.len() as u64,
        output_bytes: final_source.len() as u64,
        micros,
        blake3_input: blake_in.to_owned(),
        blake3_output: Some(blake_out),
        message: None,
    }]
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
            input_bytes: bytes.len() as u64,
            output_bytes: 0,
            micros,
            blake3_input: blake_in.to_owned(),
            blake3_output: None,
            message: Some(format!(
                "detected={:?} confidence={:.2}",
                d.obfuscator, d.confidence
            )),
        }],
        Err(e) => vec![SampleMetrics {
            entry: entry.clone(),
            pass_name: "wasm-detect".to_owned(),
            ok: false,
            input_bytes: bytes.len() as u64,
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
