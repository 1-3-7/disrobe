#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    Detection, PyarmorVersion, StaticDecryptStatus, StaticUnpackConfig, StaticUnpackOutput,
    WrapperMagic, detect_from_wrapper, unpack_static, unpack_static_with_config,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};

const RECOVERY_FLOOR: usize = 72;
const KNOWN_MARKER: &[u8] = b"try_except_basic";
const PY312: PyVersion = PyVersion::new(3, 12);

const PUBLISHED_HEADING: &str = "Detection and extraction breadth";
const PUBLISHED_BAR: &str = "PyArmor samples";

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = workspace_root()
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

#[test]
fn rejects_zero_bytes() {
    let err: bool = unpack_static(&[]).is_err();
    assert!(err);
}

#[test]
fn rejects_garbage_bytes() {
    let err: bool = unpack_static(&[0xffu8; 64]).is_err();
    assert!(err);
}

#[test]
fn detect_only_v8_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY008106");
    bytes[9] = 3;
    bytes[10] = 11;
    bytes[20] = 0x08;
    let output: StaticUnpackOutput =
        unpack_static(&bytes).expect("v8 detect-only succeeds with no runtime");
    assert_eq!(output.header_metadata.magic, WrapperMagic::Py8Or9);
    assert_eq!(output.header_metadata.serial.as_deref(), Some("008106"));
    assert_eq!(output.python_version, Some((3, 11)));
}

#[test]
fn detect_only_v9_bcc_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY009070");
    bytes[9] = 3;
    bytes[10] = 13;
    bytes[20] = 0x09;
    let output: StaticUnpackOutput = unpack_static(&bytes).expect("v9 detect-only");
    assert_eq!(output.header_metadata.protection_type, Some(0x09));
}

#[test]
fn corpus_pyc_smoke_does_not_panic() {
    let corpus_dir: PathBuf = workspace_root().join("corpus/python/pyarmor");
    assert!(
        corpus_dir.is_dir(),
        "the pyarmor corpus is tracked in git and is what this case sweeps, so its absence is a \
         damaged checkout rather than an optional dependency: {}",
        corpus_dir.display()
    );
    let mut swept: usize = 0;
    walk_files(&corpus_dir, &mut |path: &Path| {
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("pyc") {
            return;
        }
        let bytes: Vec<u8> = std::fs::read(path)
            .unwrap_or_else(|e: std::io::Error| panic!("{} is unreadable: {e}", path.display()));
        let cfg: StaticUnpackConfig = StaticUnpackConfig {
            emit_llm_metadata: true,
            ..StaticUnpackConfig::default()
        };
        let _ = unpack_static_with_config(&bytes, &cfg);
        swept += 1;
    });
    assert!(
        swept > 0,
        "{} carries no .pyc, so this case swept nothing and would report success without running \
         the unpacker over a single sample",
        corpus_dir.display()
    );
}

struct Fixture {
    wrapper_py: PathBuf,
    runtime: PathBuf,
    expected_version: PyarmorVersion,
    relative_id: String,
    carries_marker: bool,
}

#[test]
fn recovers_real_source_from_v8_and_v9_corpus() {
    let corpus_dir: PathBuf = workspace_root().join("corpus/python/pyarmor");
    assert!(
        corpus_dir.is_dir(),
        "the v8 and v9 wrapper corpus is committed and is the evidence behind the published \
         PyArmor samples figure; expected it at {}",
        corpus_dir.display()
    );

    let fixtures: Vec<Fixture> = collect_fixtures(&corpus_dir);
    assert!(
        fixtures.len() >= RECOVERY_FLOOR,
        "expected the full committed corpus (>= {RECOVERY_FLOOR} wrappers), found {}",
        fixtures.len()
    );

    let mut recovered: usize = 0;
    let mut markers_seen: usize = 0;

    for fx in &fixtures {
        let text: String =
            std::fs::read_to_string(&fx.wrapper_py).expect("wrapper .py is readable");
        let (_detection, payload): (Detection, Vec<u8>) =
            detect_from_wrapper(&text).expect("wrapper carries an extractable payload literal");
        let runtime_bytes: Vec<u8> =
            std::fs::read(&fx.runtime).expect("runtime binary is readable");

        let cfg: StaticUnpackConfig = StaticUnpackConfig {
            runtime_bytes: Some(runtime_bytes),
            strict: true,
            ..StaticUnpackConfig::default()
        };
        let out: StaticUnpackOutput =
            unpack_static_with_config(&payload, &cfg).expect("in-house decrypt+unpack succeeds");

        assert_eq!(
            out.pyarmor_version, fx.expected_version,
            "{}: runtime-descriptor discrimination must override the serial-000000 default",
            fx.relative_id
        );
        assert_eq!(
            out.status,
            StaticDecryptStatus::Functional,
            "{}: AES body must decrypt (Functional)",
            fx.relative_id
        );

        assert_eq!(
            out.plaintext.first(),
            Some(&0x20u8),
            "{}: decrypted body starts with the PyArmor 0x20 structural header",
            fx.relative_id
        );

        let (offset, code): (usize, Box<CodeObject>) = locate_real_code_object(&out.plaintext)
            .unwrap_or_else(|| {
                panic!(
                    "{}: decrypted body must contain a genuine marshalled CodeObject",
                    fx.relative_id
                )
            });
        assert!(
            offset >= 0x20,
            "{}: marshal stream lives at or beyond the structural header",
            fx.relative_id
        );
        assert!(
            !code.names.is_empty(),
            "{}: recovered CodeObject must carry real co_names",
            fx.relative_id
        );

        if fx.carries_marker {
            markers_seen += 1;
            assert!(
                contains_subslice(&out.plaintext, KNOWN_MARKER),
                "{}: original identifier `try_except_basic` survives in the decrypted source bytes",
                fx.relative_id
            );
            assert!(
                co_names_contains(&code, "try_except_basic"),
                "{}: recovered co_names carry the pre-obfuscation identifier `try_except_basic`",
                fx.relative_id
            );
        }

        recovered += 1;
    }

    assert!(
        markers_seen >= 36,
        "expected the chunk_00 `try_except_basic` source marker across both versions, saw {markers_seen}"
    );
    eprintln!("recovered {recovered}/{} fixtures", fixtures.len());
    assert!(
        recovered >= RECOVERY_FLOOR,
        "expected >= {RECOVERY_FLOOR}/72 real source recoveries on the committed corpus, got {recovered}"
    );

    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let detected: u64 = bar["detected"]
        .as_u64()
        .expect("the PyArmor samples bar must carry a detected count");
    let delivered: u64 = bar["delivered"]
        .as_u64()
        .expect("the PyArmor samples bar must carry a delivered count");
    assert_eq!(
        u64::try_from(fixtures.len()).expect("fixture count fits u64"),
        detected,
        "xtask/data/recovery.json publishes {detected} PyArmor corpus samples and every document \
         renders that number, but the committed v8 and v9 corpus carries {}",
        fixtures.len()
    );
    assert!(
        u64::try_from(recovered).expect("recovered fits u64") >= delivered,
        "recovery.json publishes {delivered} of {detected} samples recovered to source; this run \
         recovered {recovered}"
    );
}

fn collect_fixtures(corpus_dir: &Path) -> Vec<Fixture> {
    let mut fixtures: Vec<Fixture> = Vec::new();
    for version_dir in ["v8", "v9"] {
        let expected_version: PyarmorVersion = if version_dir == "v8" {
            PyarmorVersion::V8
        } else {
            PyarmorVersion::V9
        };
        gather(
            &corpus_dir.join(version_dir),
            corpus_dir,
            expected_version,
            &mut fixtures,
        );
    }
    fixtures.sort_by(|a: &Fixture, b: &Fixture| a.wrapper_py.cmp(&b.wrapper_py));
    fixtures
}

fn gather(dir: &Path, corpus_dir: &Path, expected_version: PyarmorVersion, out: &mut Vec<Fixture>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut wrappers: Vec<PathBuf> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if is_chunk_wrapper(&path) {
            wrappers.push(path);
        }
    }

    if let Some(runtime) = find_runtime(dir)
        && !wrappers.is_empty()
    {
        for wrapper_py in wrappers {
            let relative_id: String = wrapper_py
                .parent()
                .and_then(|p: &Path| p.strip_prefix(corpus_dir).ok())
                .map(|p: &Path| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let carries_marker: bool = wrapper_py
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n: &str| n.starts_with("chunk_00_"));
            out.push(Fixture {
                wrapper_py,
                runtime: runtime.clone(),
                expected_version,
                relative_id,
                carries_marker,
            });
        }
        return;
    }

    for subdir in subdirs {
        gather(&subdir, corpus_dir, expected_version, out);
    }
}

fn is_chunk_wrapper(path: &Path) -> bool {
    let Some(name): Option<&str> = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    name.starts_with("chunk")
        && path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|ext: &str| ext.eq_ignore_ascii_case("py"))
}

fn find_runtime(dir: &Path) -> Option<PathBuf> {
    let entries: std::fs::ReadDir = std::fs::read_dir(dir).ok()?;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if is_runtime_binary(&path) {
            return Some(path);
        }
    }
    for subdir in subdirs {
        if let Some(found) = find_runtime(&subdir) {
            return Some(found);
        }
    }
    None
}

fn is_runtime_binary(path: &Path) -> bool {
    let Some(name): Option<&str> = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    name.starts_with("pyarmor_runtime")
        && matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("pyd" | "so" | "dylib")
        )
}

fn locate_real_code_object(plaintext: &[u8]) -> Option<(usize, Box<CodeObject>)> {
    for (i, &b) in plaintext.iter().enumerate() {
        if b == 0xE3
            && let Ok(Object::Code(code)) = load(&plaintext[i..], PY312)
        {
            return Some((i, code));
        }
    }
    None
}

fn co_names_contains(code: &CodeObject, needle: &str) -> bool {
    code.names.iter().any(|name: &Object| match name {
        Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. }
        | Object::String { value, .. } => value == needle,
        _ => false,
    })
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window: &[u8]| window == needle)
}

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn walk_files(dir: &Path, visitor: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            walk_files(&path, visitor);
        } else {
            visitor(&path);
        }
    }
}
