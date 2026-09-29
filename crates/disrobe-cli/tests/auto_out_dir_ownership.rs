#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn committed(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn disrobe(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .args(args)
        .output()
        .expect("run disrobe")
}

fn auto_into(input: &Path, out: &Path, force: bool) -> Output {
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "auto".as_ref(),
        input.as_os_str(),
        "--out".as_ref(),
        out.as_os_str(),
    ];
    if force {
        args.push("--force".as_ref());
    }
    disrobe(&args)
}

fn relative_files(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
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
                found.push(
                    path.strip_prefix(dir)
                        .expect("inside the walked dir")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_second_run_into_a_used_directory_is_refused_and_forced_runs_cite_only_their_files() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-out-dir").expect("scratch");
    let out: PathBuf = scratch.path().join("out");
    let iso: PathBuf = committed("corpus/binfmt/iso/joliet-rockridge.iso");
    let pyc: PathBuf =
        committed("corpus/python/decompile/playground/__pycache__/tiny_3_14.cpython-314.pyc");

    let first: Output = auto_into(&iso, &out, false);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        relative_files(&out.join("extracted"))
            .iter()
            .any(|path: &String| path.ends_with("hello.txt")),
        "the first run extracts the iso members"
    );

    let refused: Output = auto_into(&pyc, &out, false);
    assert!(
        !refused.status.success(),
        "a used output directory must be refused"
    );
    let stderr: String = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(stderr.contains("DR-CLI-0913"), "{stderr}");

    let forced: Output = auto_into(&pyc, &out, true);
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let extracted: Vec<String> = relative_files(&out.join("extracted"));
    assert!(
        extracted
            .iter()
            .all(|path: &String| !path.ends_with("hello.txt")),
        "the forced run still holds the earlier run's members: {extracted:?}"
    );
    let report: String = std::fs::read_to_string(out.join("report.json"))
        .expect("the forced run writes report.json");
    assert!(
        !report.contains("hello.txt") && !report.contains("lorem.txt"),
        "report.json cites a file the forced run did not write"
    );
}

#[test]
fn batch_inputs_whose_names_collapse_get_their_own_directories() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-out-stems").expect("scratch");
    let root: PathBuf = scratch.path().join("in");
    std::fs::create_dir_all(root.join("a")).expect("mkdir a");
    std::fs::create_dir_all(root.join("a-b")).expect("mkdir a-b");
    std::fs::write(root.join("a/b-c.bin"), b"first input bytes").expect("write a/b-c.bin");
    std::fs::write(root.join("a-b/c.bin"), b"second input bytes").expect("write a-b/c.bin");
    let out: PathBuf = scratch.path().join("out");

    let run: Output = disrobe(&[
        "auto".as_ref(),
        root.as_os_str(),
        "--out".as_ref(),
        out.as_os_str(),
        "--jobs".as_ref(),
        "4".as_ref(),
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("manifest.json")).expect("read manifest.json"),
    )
    .expect("parse manifest.json");
    let entries: &Vec<serde_json::Value> = manifest["entries"].as_array().expect("entries array");
    let dirs: std::collections::BTreeMap<String, String> = entries
        .iter()
        .map(|entry: &serde_json::Value| {
            (
                entry["relative"]
                    .as_str()
                    .expect("relative")
                    .replace('\\', "/"),
                entry["output_dir"].as_str().expect("output_dir").to_owned(),
            )
        })
        .collect();
    assert_eq!(dirs.len(), 2, "{manifest}");
    let unique: std::collections::BTreeSet<&String> = dirs.values().collect();
    assert_eq!(unique.len(), 2, "two inputs share one directory: {dirs:?}");
}

#[test]
fn a_chain_pass_argument_is_refused_by_name() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-chain-args").expect("scratch");
    let out: PathBuf = scratch.path().join("out");
    let input: PathBuf = committed("corpus/binfmt/iso/joliet-rockridge.iso");
    let run: Output = disrobe(&[
        "chain".as_ref(),
        input.as_os_str(),
        "--chain".as_ref(),
        "pyarmor.unpack(key=x)".as_ref(),
        "--out".as_ref(),
        out.as_os_str(),
    ]);
    assert!(
        !run.status.success(),
        "a pass argument the pass cannot take must fail the run"
    );
    let stderr: String = String::from_utf8_lossy(&run.stderr).into_owned();
    assert!(
        stderr.contains("DR-CORE-0109") && stderr.contains("key"),
        "{stderr}"
    );
}
