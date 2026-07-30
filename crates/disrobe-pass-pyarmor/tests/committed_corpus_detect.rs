#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    Detection, ProtectionKind, PyarmorVersion, UnpackOptions, UnpackOutput, detect_from_wrapper,
    unpack_wrapper_text_with_options,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};

fn corpus_dir(version_subdir: &str) -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .join("corpus")
        .join("python")
        .join("pyarmor")
        .join(version_subdir)
}

fn collect_wrappers(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries): Result<std::fs::ReadDir, _> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_wrappers(&path, out);
            continue;
        }
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("py") {
            continue;
        }
        if path
            .components()
            .any(|c: std::path::Component<'_>| c.as_os_str() == "pyarmor_runtime_000000")
        {
            continue;
        }
        out.push(path);
    }
}

fn assert_real_wrapper_detects(path: &Path, expected: PyarmorVersion) {
    let text: String = std::fs::read_to_string(path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    if !(text.contains("__pyarmor__") || text.contains("pyarmor_runtime")) {
        return;
    }
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).unwrap_or_else(|e: disrobe_pass_pyarmor::Error| {
            panic!(
                "real corpus wrapper failed to detect {}: {e}",
                path.display()
            )
        });

    assert_eq!(
        det.version,
        expected,
        "version mismatch for {}",
        path.display()
    );
    assert!(
        &payload[..2] == b"PY",
        "real wrapper payload must carry PY magic: {}",
        path.display()
    );
    assert!(
        &payload[..8] == b"PY000000",
        "trial corpus wrappers carry serial 000000: {}",
        path.display()
    );
    assert_eq!(
        det.python_major,
        Some(3),
        "trial corpus targets python 3.x: {}",
        path.display()
    );
    assert_eq!(
        det.python_minor,
        Some(12),
        "trial corpus targets python 3.12: {}",
        path.display()
    );
    assert_eq!(
        payload[20],
        0x08,
        "trial header version byte is 0x08: {}",
        path.display()
    );
    assert_eq!(
        u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]),
        64,
        "trial encrypted-body offset is 64: {}",
        path.display()
    );
    assert!(
        payload.len() > 256,
        "real encrypted payload is non-trivial: {}",
        path.display()
    );
    assert_eq!(
        det.protection,
        ProtectionKind::Standard,
        "trial basic samples are standard protection: {}",
        path.display()
    );
}

fn run_version_corpus(version_subdir: &str, expected: PyarmorVersion) {
    let dir: PathBuf = corpus_dir(version_subdir);
    assert!(
        dir.is_dir(),
        "the {version_subdir} wrapper corpus is tracked in git and is what this case reads, so its \
         absence is a damaged checkout rather than an optional dependency: {}",
        dir.display()
    );
    let mut wrappers: Vec<PathBuf> = Vec::new();
    collect_wrappers(&dir, &mut wrappers);
    assert!(
        !wrappers.is_empty(),
        "{} holds no .py wrapper, so this case would sweep an empty set and report success \
         without detecting anything",
        dir.display()
    );
    for wrapper in &wrappers {
        assert_real_wrapper_detects(wrapper, expected);
    }
    eprintln!(
        "asserted detection on {} real pyarmor {version_subdir} wrapper(s)",
        wrappers.len()
    );
}

#[test]
fn detect_real_committed_v8_corpus() {
    run_version_corpus("v8", PyarmorVersion::V9);
}

#[test]
fn detect_real_committed_v9_corpus() {
    run_version_corpus("v9", PyarmorVersion::V9);
}

const WRAP_MARKER_KINDS: [&str; 3] = ["assert", "enter", "exit"];

fn per_build_wrap_marker_kind(s: &str) -> bool {
    WRAP_MARKER_KINDS.iter().any(|kind: &&str| {
        let prefix: String = format!("__pyarmor_{kind}_");
        s.strip_prefix(prefix.as_str())
            .and_then(|rest: &str| rest.strip_suffix("__"))
            .is_some_and(|digits: &str| {
                !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
            })
    })
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredStructureFingerprint {
    names: BTreeSet<String>,
    string_constants: BTreeSet<String>,
    code_object_count: usize,
    total_bytecode_len: usize,
    per_build_wrap_marker_count: usize,
}

fn collect_structure(code: &CodeObject, out: &mut RecoveredStructureFingerprint) {
    out.code_object_count += 1;
    out.total_bytecode_len += code.code.len();
    for n in &code.names {
        if let Object::String { value, .. }
        | Object::ShortAscii { value, .. }
        | Object::Unicode { value, .. } = n
        {
            if per_build_wrap_marker_kind(value) {
                out.per_build_wrap_marker_count += 1;
            } else {
                out.names.insert(value.clone());
            }
        }
    }
    for c in &code.consts {
        match c {
            Object::String { value, .. }
            | Object::ShortAscii { value, .. }
            | Object::Unicode { value, .. } => {
                if per_build_wrap_marker_kind(value) {
                    out.per_build_wrap_marker_count += 1;
                } else {
                    out.string_constants.insert(value.clone());
                }
            }
            Object::Code(inner) => collect_structure(inner, out),
            _ => {}
        }
    }
}

fn recovered_structure_fingerprint(
    pyc: &[u8],
    py_version: PyVersion,
) -> RecoveredStructureFingerprint {
    let mut out: RecoveredStructureFingerprint = RecoveredStructureFingerprint {
        names: BTreeSet::new(),
        string_constants: BTreeSet::new(),
        code_object_count: 0,
        total_bytecode_len: 0,
        per_build_wrap_marker_count: 0,
    };
    let header_len: usize = if py_version.major == 3 && py_version.minor < 7 {
        12
    } else {
        16
    };
    let marshal_stream: &[u8] = pyc.get(header_len..).unwrap_or(&[]);
    let obj: Object = disrobe_py_marshal::load(marshal_stream, py_version)
        .expect("recovered pyc marshal-decodes");
    let Object::Code(code) = obj else {
        panic!("recovered pyc top level must be a real CodeObject");
    };
    collect_structure(&code, &mut out);
    out
}

fn assert_runtime_prefix_layout_matches_sibling_default_layout(
    version_subdir: &str,
    expected: PyarmorVersion,
) {
    let prefix_wrapper: PathBuf = corpus_dir(version_subdir)
        .join("runtime_prefix")
        .join("chunk_00_try_except_basic_try_except_else.py");
    let basic_wrapper: PathBuf = corpus_dir(version_subdir)
        .join("basic")
        .join("chunk_00_try_except_basic_try_except_else")
        .join("chunk_00_try_except_basic_try_except_else.py");
    if !(prefix_wrapper.is_file() && basic_wrapper.is_file()) {
        eprintln!(
            "skipped: runtime_prefix/basic pair absent under {} (gitignored large fixture)",
            corpus_dir(version_subdir).display()
        );
        return;
    }

    let prefix_text: String = std::fs::read_to_string(&prefix_wrapper).unwrap_or_else(|e| {
        panic!("read {}: {e}", prefix_wrapper.display());
    });
    assert!(
        prefix_text.contains(".pyarmor_runtime_")
            && !prefix_text
                .trim_start()
                .starts_with("from pyarmor_runtime_"),
        "runtime_prefix fixture must import the runtime package through a namespaced parent package: {}",
        prefix_wrapper.display()
    );

    let prefix_out: UnpackOutput =
        unpack_wrapper_text_with_options(&prefix_text, &prefix_wrapper, &UnpackOptions::default())
            .unwrap_or_else(|e| {
                panic!(
                    "a pyarmor gen --prefix runtime layout must resolve the nested pyarmor_runtime_NNNNNN package and fully unpack {}: {e}",
                    prefix_wrapper.display()
                )
            });
    assert_eq!(
        prefix_out.detection.version,
        expected,
        "runtime_prefix wrapper must resolve to {expected:?}: {}",
        prefix_wrapper.display()
    );
    assert!(
        prefix_out.marshal_error.is_none(),
        "runtime_prefix recovery must marshal-decode cleanly: {:?}",
        prefix_out.marshal_error
    );
    let prefix_pyc: Vec<u8> = prefix_out
        .pyc
        .expect("runtime_prefix recovery must emit a real pyc");

    let basic_text: String = std::fs::read_to_string(&basic_wrapper).unwrap_or_else(|e| {
        panic!("read {}: {e}", basic_wrapper.display());
    });
    let basic_out: UnpackOutput =
        unpack_wrapper_text_with_options(&basic_text, &basic_wrapper, &UnpackOptions::default())
            .unwrap_or_else(|e| {
                panic!(
                    "sibling default-layout build must unpack {}: {e}",
                    basic_wrapper.display()
                )
            });
    let basic_pyc: Vec<u8> = basic_out
        .pyc
        .expect("basic-mode recovery must emit a real pyc");

    let py_version: PyVersion = prefix_out
        .py_version
        .expect("runtime_prefix recovery reports a python version");
    let prefix_fp: RecoveredStructureFingerprint =
        recovered_structure_fingerprint(&prefix_pyc, py_version);
    let basic_fp: RecoveredStructureFingerprint =
        recovered_structure_fingerprint(&basic_pyc, py_version);

    assert!(
        prefix_fp.code_object_count > 1,
        "recovered module must contain nested code objects (functions/classes), got {}",
        prefix_fp.code_object_count
    );
    assert_eq!(
        prefix_fp.names, basic_fp.names,
        "the --prefix build and the default-layout sibling build compile the identical source (same input_sha256 per MANIFEST.toml); recovered identifier names must match exactly even though each build carries its own runtime-embedded AES key and per-build anti-tamper padding"
    );
    assert_eq!(
        prefix_fp.string_constants, basic_fp.string_constants,
        "recovered string constants must match exactly between the two independently-encrypted real builds of the identical source"
    );
    assert_eq!(
        prefix_fp.code_object_count, basic_fp.code_object_count,
        "recovered code-object count (functions/classes/module) must match exactly between the two builds"
    );
    assert_eq!(
        prefix_fp.per_build_wrap_marker_count, basic_fp.per_build_wrap_marker_count,
        "both builds inject the same number of __pyarmor_{{enter,exit,assert}}_NNNNN__ wrap markers even though the per-build random numeric suffixes differ"
    );
    assert!(
        prefix_fp.per_build_wrap_marker_count > 0,
        "this fixture is not built with --nowrap, so wrap markers must be present in both builds"
    );
}

#[test]
fn unpack_real_committed_v8_runtime_prefix_matches_basic_layout() {
    assert_runtime_prefix_layout_matches_sibling_default_layout("v8", PyarmorVersion::V9);
}

#[test]
fn unpack_real_committed_v9_runtime_prefix_matches_basic_layout() {
    assert_runtime_prefix_layout_matches_sibling_default_layout("v9", PyarmorVersion::V9);
}
