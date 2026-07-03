#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_disasm::opname;
use disrobe_py_marshal::PyVersion;

const PROBE: &str = "\
import dis, json, sys
print(json.dumps({\
'v': list(sys.version_info[:2]), \
'have_arg': getattr(dis, 'HAVE_ARGUMENT', None), \
'names': list(dis.opname)}))\
";

#[derive(Debug, Clone)]
struct Interpreter {
    label: String,
    path: PathBuf,
    version: (u8, u8),
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn uv_python_store(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData/Roaming/uv/python")
    } else {
        home.join(".local/share/uv/python")
    }
}

fn python_exe_name(minor: u8) -> String {
    if cfg!(windows) {
        format!("python3.{minor}{}", std::env::consts::EXE_SUFFIX)
    } else {
        format!("python3.{minor}")
    }
}

fn probe_version(path: &Path) -> Option<(u8, u8)> {
    let output = Command::new(path)
        .args([
            "-c",
            "import sys;print('%d.%d'%(sys.version_info[0],sys.version_info[1]))",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let (major, minor): (&str, &str) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn push_candidate(out: &mut Vec<Interpreter>, label: String, path: PathBuf) {
    if out.iter().any(|i: &Interpreter| i.path == path) {
        return;
    }
    if !path.exists() {
        return;
    }
    let Some(version): Option<(u8, u8)> = probe_version(&path) else {
        return;
    };
    if version.0 != 3 || version.1 < 6 {
        return;
    }
    if out.iter().any(|i: &Interpreter| i.version == version) {
        return;
    }
    out.push(Interpreter {
        label,
        path,
        version,
    });
}

fn find_via_uv(version: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", version])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn resolve_py_launcher(version: &str) -> Option<PathBuf> {
    let output = Command::new("py")
        .args([
            &format!("-{version}"),
            "-c",
            "import sys;print(sys.executable)",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return None;
    }
    Some(PathBuf::from(text))
}

fn discover_interpreters() -> Vec<Interpreter> {
    let mut out: Vec<Interpreter> = Vec::new();

    for minor in 6u8..=15 {
        let version: String = format!("3.{minor}");
        if let Some(path) = find_via_uv(&version) {
            push_candidate(&mut out, format!("uv-3.{minor}"), path);
        }
    }

    if let Some(home) = home_dir() {
        let uv_root: PathBuf = uv_python_store(&home);
        if let Ok(entries) = std::fs::read_dir(&uv_root) {
            let mut dirs: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p: &PathBuf| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n: &str| n.starts_with("cpython-"))
                })
                .collect();
            dirs.sort();
            for dir in dirs {
                let exe: PathBuf = dir.join(format!("python{}", std::env::consts::EXE_SUFFIX));
                let label: String = dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("uv")
                    .to_owned();
                push_candidate(&mut out, label, exe);
            }
        }

        if !cfg!(windows) {
            let local_bin: PathBuf = home.join(".local/bin");
            for minor in 6u8..=15 {
                push_candidate(
                    &mut out,
                    format!("local-3.{minor}"),
                    local_bin.join(python_exe_name(minor)),
                );
            }
            for minor in 6u8..=15 {
                push_candidate(
                    &mut out,
                    format!("usr-3.{minor}"),
                    PathBuf::from(format!("/usr/bin/python3.{minor}")),
                );
            }
        }
    }

    for version in [
        "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15",
    ] {
        if let Some(path) = resolve_py_launcher(version) {
            push_candidate(&mut out, format!("py-{version}"), path);
        }
    }

    out.sort_by_key(|i: &Interpreter| i.version);
    out
}

fn real_opnames(interp: &Interpreter) -> (Vec<String>, Option<u64>) {
    let output = Command::new(&interp.path)
        .args(["-c", PROBE])
        .output()
        .expect("spawn interpreter probe");
    assert!(
        output.status.success(),
        "{} opname probe failed: {}",
        interp.label,
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse opname probe json");
    let names: Vec<String> = payload["names"]
        .as_array()
        .expect("names array")
        .iter()
        .map(|v: &serde_json::Value| v.as_str().expect("opname string").to_owned())
        .collect();
    let have_arg: Option<u64> = payload["have_arg"].as_u64();
    (names, have_arg)
}

fn is_placeholder(name: &str) -> bool {
    name.starts_with('<') && name.ends_with('>')
}

#[test]
fn opname_table_matches_cpython_dis_opname_across_versions() {
    let interpreters: Vec<Interpreter> = discover_interpreters();
    if interpreters.is_empty() {
        eprintln!(
            "no CPython 3.6+ interpreters discovered; skipping opname-table oracle \
             (install uv toolchains or the py launcher to exercise it)"
        );
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    let mut checked: Vec<(u8, u8)> = Vec::new();

    for interp in &interpreters {
        let version: PyVersion = PyVersion {
            major: interp.version.0,
            minor: interp.version.1,
        };
        let (names, _have_arg): (Vec<String>, Option<u64>) = real_opnames(interp);
        assert!(
            names.len() >= 256,
            "{} dis.opname shorter than 256 ({})",
            interp.label,
            names.len()
        );

        for (op, real) in names.iter().take(256).enumerate() {
            if is_placeholder(real) {
                continue;
            }
            let got: &str = opname(op as u8, version);
            if got != real {
                failures.push(format!(
                    "{} [3.{}] op {}: disrobe={got:?} cpython={real:?}",
                    interp.label, interp.version.1, op
                ));
            }
        }
        checked.push(interp.version);
    }

    assert!(
        failures.is_empty(),
        "opname-table mismatches against CPython dis.opname ({} total):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked.len() >= 2,
        "expected at least two CPython versions for the opname-table oracle, saw {checked:?}"
    );
}
