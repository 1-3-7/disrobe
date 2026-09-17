#![allow(clippy::expect_used, clippy::panic)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

mod common;

use common::{Run, run_disrobe_env, temp_dir};

const BCC_WRAPPER: &str = "corpus/python/pyarmor/v9-bcc/default/known_plaintext.py";

fn workspace_root() -> PathBuf {
    let crate_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir: &Path = crate_dir.parent().expect("CLI crate must be inside crates");
    let root: &Path = crates_dir
        .parent()
        .expect("crates directory must be inside workspace");
    assert!(
        root.join("Cargo.lock").is_file(),
        "workspace root must have Cargo.lock"
    );
    root.to_path_buf()
}

fn write_poison_tool(dir: &Path, name: &str, marker: &Path) {
    #[cfg(windows)]
    {
        let tool: PathBuf = dir.join(format!("{name}.bat"));
        let body: String = format!(
            "@echo off\r\necho invoked>\"{}\"\r\nexit /b 91\r\n",
            marker.display()
        );
        std::fs::write(&tool, body).expect("write poison command");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let tool: PathBuf = dir.join(name);
        let body: String = format!(
            "#!/bin/sh\nprintf invoked > '{}'\nexit 91\n",
            marker.display()
        );
        std::fs::write(&tool, body).expect("write poison command");
        let mut permissions: std::fs::Permissions = std::fs::metadata(&tool)
            .expect("stat poison command")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool, permissions).expect("mark poison command executable");
    }
}

#[test]
fn pyarmor_bcc_allow_is_in_tree_static() {
    let input: PathBuf = workspace_root().join(BCC_WRAPPER);
    assert!(
        input.is_file(),
        "tracked BCC wrapper must be available at {}",
        input.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("pyarmor-bcc-static");
    let tool_dir: PathBuf = scratch.path().join("poison-bin");
    let ghidra_home: PathBuf = scratch.path().join("poison-ghidra");
    let support_dir: PathBuf = ghidra_home.join("support");
    let marker: PathBuf = scratch.path().join("poison-tool-invoked");
    std::fs::create_dir_all(&tool_dir).expect("create poison tool directory");
    std::fs::create_dir_all(&support_dir).expect("create poison Ghidra support directory");
    write_poison_tool(&tool_dir, "ghidra-headless", &marker);
    write_poison_tool(&tool_dir, "analyzeHeadless", &marker);
    write_poison_tool(&support_dir, "analyzeHeadless", &marker);

    let inherited_path: OsString = env::var_os("PATH").unwrap_or_default();
    let mut path_entries: Vec<PathBuf> = vec![tool_dir];
    path_entries.extend(env::split_paths(&inherited_path));
    let child_path: OsString = env::join_paths(path_entries).expect("join child PATH");
    let child_path_text: String = child_path.to_string_lossy().into_owned();
    let ghidra_home_text: String = ghidra_home.to_string_lossy().into_owned();
    let input_text: String = input.to_string_lossy().into_owned();
    let out: PathBuf = scratch.path().join("out");
    let out_text: String = out.to_string_lossy().into_owned();
    let run: Run = run_disrobe_env(
        &[
            "pyarmor",
            "unpack",
            &input_text,
            "--out",
            &out_text,
            "--allow-bcc",
        ],
        &[
            ("PATH", &child_path_text),
            ("GHIDRA_HOME", &ghidra_home_text),
        ],
    );
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    assert!(
        !marker.exists(),
        "BCC static analysis must not launch a Ghidra entry point"
    );

    let manifest_text: String =
        std::fs::read_to_string(out.join("manifest.json")).expect("BCC unpack must write manifest");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_text).expect("BCC manifest must be valid JSON");
    assert_eq!(
        manifest["schema"], "disrobe.pyarmor.manifest/v0",
        "BCC manifest schema must remain stable"
    );
    assert_eq!(manifest["protection"], "Bcc");
    assert_eq!(manifest["allow_bcc"], true);
    assert_eq!(manifest["pass_path"], "pure-static");
    assert!(manifest["dynamic_hook"].is_null());
    let limitations: &Vec<serde_json::Value> = manifest["limitations"]
        .as_array()
        .expect("BCC manifest must carry limitations");
    let limitation_text: Vec<&str> = limitations
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        limitation_text
            .iter()
            .any(|entry: &&str| entry.contains("BCC in-tree static analysis")),
        "BCC manifest must identify the static in-tree analysis boundary: {limitation_text:?}"
    );
    for forbidden in [
        "ghidra",
        "watchdog",
        "requires --allow-bcc",
        "not lifted here",
    ] {
        assert!(
            limitation_text
                .iter()
                .all(|entry: &&str| !entry.to_ascii_lowercase().contains(forbidden)),
            "BCC limitations must not contain {forbidden:?}: {limitation_text:?}"
        );
    }
}
