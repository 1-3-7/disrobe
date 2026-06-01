#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{Detection, ProtectionKind, PyarmorVersion, detect_from_wrapper};

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
    if !dir.is_dir() {
        eprintln!(
            "skipped: committed pyarmor corpus absent at {} (gitignored large fixture; run scripts/bake/pyarmor.{{ps1,sh}})",
            dir.display()
        );
        return;
    }
    let mut wrappers: Vec<PathBuf> = Vec::new();
    collect_wrappers(&dir, &mut wrappers);
    if wrappers.is_empty() {
        eprintln!(
            "skipped: no .py wrappers under {} (corpus dir present but empty)",
            dir.display()
        );
        return;
    }
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
