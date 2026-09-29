#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn committed(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

struct AutoRun {
    _output: disrobe_core::scratch::ScratchDir,
    root: PathBuf,
    chain: serde_json::Value,
}

fn auto(rel: &str) -> AutoRun {
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-default-tree").expect("output dir");
    let root: PathBuf = output.path().join("out");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(committed(rel))
        .arg("--out")
        .arg(&root)
        .output()
        .expect("run disrobe auto");
    assert!(
        process.status.success(),
        "disrobe auto {rel} failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let bytes: Vec<u8> = std::fs::read(root.join("chain.json")).expect("read chain.json");
    let chain: serde_json::Value = serde_json::from_slice(&bytes).expect("parse chain.json");
    AutoRun {
        _output: output,
        root,
        chain,
    }
}

fn files_under(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries {
            let path: PathBuf = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative: String = path
                    .strip_prefix(dir)
                    .expect("inside the walked dir")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(relative, std::fs::read(&path).expect("read output file"));
            }
        }
    }
    found
}

fn verdict(run: &AutoRun) -> &str {
    run.chain["verdict"]
        .as_str()
        .unwrap_or_else(|| panic!("chain.json has no verdict: {}", run.chain))
}

fn recovered_with_extension(run: &AutoRun, extension: &str) -> Vec<String> {
    files_under(&run.root.join("extracted/recovered"))
        .into_keys()
        .filter(|path: &String| {
            Path::new(path)
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext == extension)
        })
        .collect()
}

#[test]
fn a_pyc_run_writes_its_python_source_and_is_complete() {
    let run: AutoRun =
        auto("corpus/python/decompile/playground/__pycache__/tiny_3_14.cpython-314.pyc");
    assert_eq!(verdict(&run), "complete", "{}", run.chain);
    let sources: Vec<String> = recovered_with_extension(&run, "py");
    assert_eq!(sources.len(), 1, "{sources:?}");
}

#[test]
fn a_jar_run_writes_java_sources_and_is_complete() {
    let run: AutoRun = auto("corpus/jvm/proguard/Hello-obf.jar");
    assert_eq!(verdict(&run), "complete", "{}", run.chain);
    assert!(
        !recovered_with_extension(&run, "java").is_empty(),
        "{:?}",
        files_under(&run.root.join("extracted"))
            .into_keys()
            .collect::<Vec<String>>()
    );
}

#[test]
fn a_dotnet_dll_run_writes_csharp_and_is_complete() {
    let run: AutoRun = auto("corpus/dotnet/ranges/Ranges.dll");
    assert_eq!(verdict(&run), "complete", "{}", run.chain);
    assert!(
        !recovered_with_extension(&run, "cs").is_empty(),
        "{:?}",
        files_under(&run.root.join("extracted"))
            .into_keys()
            .collect::<Vec<String>>()
    );
}

#[test]
fn an_iso_run_writes_every_member_byte_for_byte() {
    let run: AutoRun = auto("corpus/binfmt/iso/joliet-rockridge.iso");
    assert_eq!(verdict(&run), "extracted", "{}", run.chain);
    let expected: BTreeMap<String, Vec<u8>> = files_under(&committed("corpus/binfmt/iso/expected"));
    let written: BTreeMap<String, Vec<u8>> = files_under(&run.root.join("extracted"));
    for (path, bytes) in &expected {
        let found: Option<&Vec<u8>> = written
            .iter()
            .find(|(written_path, _): &(&String, &Vec<u8>)| {
                written_path
                    .to_ascii_lowercase()
                    .ends_with(&path.to_ascii_lowercase())
            })
            .map(|(_, written_bytes): (&String, &Vec<u8>)| written_bytes);
        assert_eq!(
            found,
            Some(bytes),
            "{path} missing or different among {:?}",
            written.keys().collect::<Vec<&String>>()
        );
    }
}

#[test]
fn a_rar_whose_only_member_is_refused_is_not_graded_ok() {
    let run: AutoRun = auto("corpus/binfmt/rar/mixed-ppmd-lz-rar3.rar");
    let graded: &str = verdict(&run);
    assert!(
        !matches!(graded, "ok" | "complete" | "extracted" | "not-applicable"),
        "a run that wrote none of its container's members reported {graded}: {}",
        run.chain
    );
}
