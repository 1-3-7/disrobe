#![allow(clippy::case_sensitive_file_extension_comparisons)]
use std::path::{Path, PathBuf};

use serde::Serialize;

const MAX_CORPUS_DEPTH: usize = 64;
const MAX_CORPUS_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CorpusKind {
    PyArmor,
    PyInstaller,
    Nuitka,
    CxFreeze,
    Py2exe,
    Shiv,
    Pex,
    JsObfuscatorIo,
    JsWebpack,
    Wasm,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusEntry {
    pub kind: CorpusKind,
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[must_use]
pub fn walk_corpus(root: &Path) -> Vec<CorpusEntry> {
    let mut out: Vec<CorpusEntry> = Vec::new();
    collect(root, &mut out, 0);
    out
}

fn collect(dir: &Path, out: &mut Vec<CorpusEntry>, depth: usize) {
    if depth >= MAX_CORPUS_DEPTH || out.len() >= MAX_CORPUS_ENTRIES {
        return;
    }
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_CORPUS_ENTRIES {
            return;
        }
        let path: PathBuf = entry.path();
        let Ok(file_type): std::io::Result<std::fs::FileType> = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect(&path, out, depth.saturating_add(1));
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let size: u64 = std::fs::metadata(&path).map_or(0, |m| m.len());
        if let Some(kind) = classify_path(&path) {
            out.push(CorpusEntry {
                kind,
                path,
                size_bytes: size,
            });
        }
    }
}

fn classify_path(path: &Path) -> Option<CorpusKind> {
    let s: String = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if is_pyarmor_path(path, &s) {
        return Some(CorpusKind::PyArmor);
    }
    if s.contains("pyinstaller") || s.ends_with(".exe") && s.contains("pyinst") {
        return Some(CorpusKind::PyInstaller);
    }
    if s.contains("/nuitka") {
        return Some(CorpusKind::Nuitka);
    }
    if s.contains("cxfreeze") || s.contains("cx_freeze") {
        return Some(CorpusKind::CxFreeze);
    }
    if (s.contains("/js/") || s.contains("/javascript/") || s.contains("/typescript/"))
        && (s.ends_with(".js") || s.ends_with(".ts") || s.ends_with(".mjs") || s.ends_with(".cjs"))
    {
        return Some(CorpusKind::JsObfuscatorIo);
    }
    if s.ends_with(".wasm") || s.ends_with(".wat") {
        return Some(CorpusKind::Wasm);
    }
    None
}

fn is_pyarmor_path(path: &Path, normalized: &str) -> bool {
    if normalized.contains("/pyarmor/") || normalized.ends_with("/pyarmor") {
        return true;
    }
    is_python_source(path)
        && normalized.contains("/generated/")
        && has_pyarmor_version_marker(normalized)
}

fn is_python_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext: &std::ffi::OsStr| ext.to_str())
        .is_some_and(|ext: &str| ext.eq_ignore_ascii_case("py"))
}

fn has_pyarmor_version_marker(normalized: &str) -> bool {
    ["/v3-", "/v4-", "/v5-", "/v6-", "/v7-", "/v8-", "/v9-"]
        .into_iter()
        .any(|marker: &str| normalized.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_js_file_under_js_dir() {
        let p: PathBuf = PathBuf::from("corpus/src/js/sample.js");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_v9_pyarmor_dir() {
        let p: PathBuf = PathBuf::from("corpus/generated/pyarmor/v9-default/hello.py");
        assert_eq!(classify_path(&p), Some(CorpusKind::PyArmor));
    }

    #[test]
    fn classify_legacy_v3_v4_v5_dirs() {
        let p3: PathBuf = PathBuf::from("corpus/generated/pyarmor/v3-default/hello.py");
        assert_eq!(classify_path(&p3), Some(CorpusKind::PyArmor));
        let p4: PathBuf = PathBuf::from("corpus/generated/pyarmor/v4-default/hello.py");
        assert_eq!(classify_path(&p4), Some(CorpusKind::PyArmor));
        let p5: PathBuf = PathBuf::from("corpus/generated/pyarmor/v5-default/hello.py");
        assert_eq!(classify_path(&p5), Some(CorpusKind::PyArmor));
    }

    #[test]
    fn classify_generated_versioned_python_wrapper_as_pyarmor() {
        let p: PathBuf = PathBuf::from("corpus/generated/v9-default/hello.py");
        assert_eq!(classify_path(&p), Some(CorpusKind::PyArmor));
    }

    #[test]
    fn classify_wasm_module() {
        let p: PathBuf = PathBuf::from("corpus/src/wasm/hello.wasm");
        assert_eq!(classify_path(&p), Some(CorpusKind::Wasm));
    }

    #[test]
    fn classify_wat_source() {
        let p: PathBuf = PathBuf::from("corpus/src/wasm/sources/add.wat");
        assert_eq!(classify_path(&p), Some(CorpusKind::Wasm));
    }

    #[test]
    fn classify_js_under_javascript_dir() {
        let p: PathBuf = PathBuf::from("corpus/src/javascript/full-pipeline.js");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_ts_under_typescript_dir() {
        let p: PathBuf = PathBuf::from("corpus/src/typescript/class-target.ts");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_unknown_returns_none() {
        let p: PathBuf = PathBuf::from("README.md");
        assert!(classify_path(&p).is_none());
    }

    #[test]
    fn classify_python_edge_case_dir_is_not_misclassified_as_pyarmor() {
        let p: PathBuf = PathBuf::from("corpus/src/python/edge_cases/fstring_deep.py");
        assert_eq!(classify_path(&p), None);
    }

    #[test]
    fn classify_javascript_edge_case_js_file() {
        let p: PathBuf = PathBuf::from("corpus/src/javascript/edge_cases/proxy_all_traps.js");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_javascript_under_versioned_dir_as_javascript() {
        let p: PathBuf = PathBuf::from("corpus/src/javascript/v9-default/sample.js");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_python_under_versioned_dir_is_not_pyarmor_without_generated_root() {
        let p: PathBuf = PathBuf::from("corpus/src/python/v9-fstring/sample.py");
        assert_eq!(classify_path(&p), None);
    }

    #[test]
    fn classify_javascript_edge_case_mjs_file() {
        let p: PathBuf = PathBuf::from("corpus/src/javascript/edge_cases/top_level_await.mjs");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_typescript_edge_case_ts_file() {
        let p: PathBuf = PathBuf::from("corpus/src/typescript/edge_cases/satisfies_operator.ts");
        assert_eq!(classify_path(&p), Some(CorpusKind::JsObfuscatorIo));
    }

    #[test]
    fn classify_wasm_edge_case_wat_file() {
        let p: PathBuf = PathBuf::from("corpus/src/wasm/edge_cases/component_preamble.wat");
        assert_eq!(classify_path(&p), Some(CorpusKind::Wasm));
    }

    #[test]
    fn classify_java_edge_case_is_unknown() {
        let p: PathBuf = PathBuf::from("corpus/src/java/edge_cases/SealedHierarchy.java");
        assert_eq!(classify_path(&p), None);
    }

    #[test]
    fn classify_lua_edge_case_is_unknown() {
        let p: PathBuf = PathBuf::from("corpus/src/lua/edge_cases/coroutines.lua");
        assert_eq!(classify_path(&p), None);
    }

    #[test]
    fn classify_native_edge_case_c_is_unknown() {
        let p: PathBuf = PathBuf::from("corpus/src/native/edge_cases/stripped_elf.c");
        assert_eq!(classify_path(&p), None);
    }

    #[test]
    fn walk_corpus_ignores_excessively_deep_entries() {
        let scratch_result: std::io::Result<disrobe_core::scratch::ScratchDir> =
            disrobe_core::scratch::ScratchDir::create("disrobe-validator-depth");
        assert!(scratch_result.is_ok(), "create scratch directory");
        let Ok(scratch): Result<disrobe_core::scratch::ScratchDir, std::io::Error> = scratch_result
        else {
            return;
        };
        let base: PathBuf = scratch.path().to_path_buf();
        let mut dir: PathBuf = base.clone();
        for idx in 0..70usize {
            dir = dir.join(format!("d{idx}"));
            assert!(std::fs::create_dir_all(&dir).is_ok());
        }
        let js_dir: PathBuf = dir.join("js");
        assert!(std::fs::create_dir_all(&js_dir).is_ok());
        assert!(std::fs::write(js_dir.join("sample.js"), b"var x = 1;").is_ok());
        let entries: Vec<CorpusEntry> = walk_corpus(&base);
        assert!(entries.is_empty(), "unexpected entries: {entries:?}");
    }
}
