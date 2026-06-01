use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::v8v9::BccArch;

const DECOMPILE_SCRIPT: &str = include_str!("ghidra/DecompileToJsonScript.java");
const GHIDRA_ANALYSIS_TIMEOUT_SECS: u64 = 600;
const PROJECT_NAME: &str = "bcc";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionId {
    pub entry_va: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoCFunction {
    pub id: FunctionId,
    pub signature: String,
    pub pseudo_c: String,
    pub size: u32,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccLiftOutput {
    pub architecture: BccArch,
    pub functions: BTreeMap<FunctionId, PseudoCFunction>,
    pub calls: BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub ghidra_stderr: String,
    pub ghidra_exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct JsonFunction {
    entry: String,
    name: String,
    signature: String,
    #[serde(rename = "pseudoC")]
    pseudo_c: String,
    size: u32,
    #[serde(rename = "paramCount")]
    parameter_count: u32,
    #[serde(default)]
    calls: Vec<JsonCallTarget>,
}

#[derive(Debug, Deserialize)]
struct JsonCallTarget {
    entry: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct JsonRoot {
    #[serde(default)]
    functions: Vec<JsonFunction>,
    #[serde(default)]
    strings: Vec<String>,
    #[serde(default)]
    imports: Vec<String>,
}

pub fn lift_bcc_native(blob: &[u8], arch: BccArch, ghidra_path: &Path) -> Result<BccLiftOutput> {
    if blob.is_empty() {
        return Err(Error::BccLiftEmptyBlob);
    }

    let analyze_headless: PathBuf = resolve_analyze_headless(ghidra_path)?;

    let stage_dir: PathBuf = staging_dir()?;
    let _ = fs::create_dir_all(&stage_dir);
    let blob_path: PathBuf = stage_dir.join(format!("bcc_input_{}.bin", arch.label()));
    fs::write(&blob_path, blob)?;

    let script_dir: PathBuf = stage_dir.join("ghidra-scripts");
    fs::create_dir_all(&script_dir)?;
    let script_path: PathBuf = script_dir.join("DecompileToJsonScript.java");
    fs::write(&script_path, DECOMPILE_SCRIPT)?;

    let output_json: PathBuf = stage_dir.join(format!("bcc_output_{}.json", arch.label()));
    if output_json.exists() {
        let _ = fs::remove_file(&output_json);
    }

    let project_dir: PathBuf = stage_dir.join(format!("ghidra-project-{}", arch.label()));
    let _ = fs::remove_dir_all(&project_dir);
    fs::create_dir_all(&project_dir)?;

    let mut cmd: Command = Command::new(&analyze_headless);
    cmd.arg(&project_dir)
        .arg(PROJECT_NAME)
        .arg("-import")
        .arg(&blob_path)
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-postScript")
        .arg("DecompileToJsonScript.java")
        .arg(&output_json)
        .arg("-deleteProject")
        .arg("-processor")
        .arg(arch_to_ghidra_language(arch))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let started: Instant = Instant::now();
    let mut child: std::process::Child = cmd.spawn().map_err(Error::Io)?;
    let timeout: Duration = Duration::from_secs(GHIDRA_ANALYSIS_TIMEOUT_SECS);

    let exit_status: std::process::ExitStatus = loop {
        if let Some(status) = child.try_wait().map_err(Error::Io)? {
            break status;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            return Err(Error::BccLiftGhidraTimedOut {
                secs: GHIDRA_ANALYSIS_TIMEOUT_SECS,
            });
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    let mut stderr_buf: String = String::new();
    if let Some(mut s) = child.stderr.take() {
        use std::io::Read as _;
        let _ = s.read_to_string(&mut stderr_buf);
    }

    if !output_json.exists() {
        return Err(Error::BccLiftGhidraSubprocess {
            exit_code: exit_status.code(),
            stderr: head(stderr_buf.as_str(), 4096),
        });
    }

    let json_text: String = fs::read_to_string(&output_json).map_err(Error::Io)?;
    let root: JsonRoot =
        serde_json::from_str(&json_text).map_err(|e| Error::BccLiftJsonParse(format!("{e}")))?;

    let mut functions: BTreeMap<FunctionId, PseudoCFunction> = BTreeMap::new();
    let mut calls: BTreeMap<FunctionId, BTreeSet<FunctionId>> = BTreeMap::new();
    for func in root.functions {
        let id: FunctionId = parse_function_id(&func.entry, &func.name)?;
        let mut callee_ids: BTreeSet<FunctionId> = BTreeSet::new();
        for callee in &func.calls {
            let cid: FunctionId = parse_function_id(&callee.entry, &callee.name)?;
            callee_ids.insert(cid);
        }
        calls.insert(id.clone(), callee_ids);
        functions.insert(
            id.clone(),
            PseudoCFunction {
                id,
                signature: func.signature,
                pseudo_c: func.pseudo_c,
                size: func.size,
                parameter_count: func.parameter_count,
            },
        );
    }

    Ok(BccLiftOutput {
        architecture: arch,
        functions,
        calls,
        strings: root.strings,
        imports: root.imports,
        ghidra_stderr: head(stderr_buf.as_str(), 4096),
        ghidra_exit_code: exit_status.code(),
    })
}

fn parse_function_id(entry_hex: &str, name: &str) -> Result<FunctionId> {
    let trimmed: &str = entry_hex.trim_start_matches("0x").trim_start_matches("0X");
    let entry_va: u64 = u64::from_str_radix(trimmed, 16).map_err(|_| {
        Error::BccLiftJsonParse(format!("function entry address not hex: {entry_hex}"))
    })?;
    Ok(FunctionId {
        entry_va,
        name: name.to_owned(),
    })
}

const fn arch_to_ghidra_language(arch: BccArch) -> &'static str {
    match arch {
        BccArch::DarwinArm64 => "AARCH64:LE:64:v8A",
        BccArch::WinX64 | BccArch::LinuxX64 | BccArch::Other(_) => "x86:LE:64:default",
    }
}

fn resolve_analyze_headless(ghidra_path: &Path) -> Result<PathBuf> {
    let stem: &Path = ghidra_path;
    if stem.is_file() {
        return Ok(stem.to_path_buf());
    }
    if stem.is_dir() {
        for candidate_name in [
            "analyzeHeadless",
            "analyzeHeadless.bat",
            "support/analyzeHeadless",
            "support/analyzeHeadless.bat",
        ] {
            let candidate: PathBuf = stem.join(candidate_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let parent: Option<&Path> = stem.parent();
    if let Some(p) = parent {
        for candidate_name in ["analyzeHeadless", "analyzeHeadless.bat"] {
            let candidate: PathBuf = p.join(candidate_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(Error::BccGhidraMissing)
}

fn staging_dir() -> Result<PathBuf> {
    let base: PathBuf = std::env::temp_dir().join("disrobe-bcc-lift");
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn head(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        s[..n].to_owned()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
mod tests {
    use super::*;

    fn fake_blob(size: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(size);
        for i in 0..size {
            v.push(u8::try_from(i & 0xff).unwrap_or(0));
        }
        v
    }

    #[test]
    fn empty_blob_returns_specific_error() {
        let missing: PathBuf = std::env::temp_dir().join("disrobe-no-ghidra-here-empty");
        let err: Error = lift_bcc_native(&[], BccArch::LinuxX64, &missing).unwrap_err();
        assert!(matches!(err, Error::BccLiftEmptyBlob));
    }

    #[test]
    fn missing_ghidra_returns_ghidra_missing() {
        let blob: Vec<u8> = fake_blob(256);
        let missing: PathBuf = std::env::temp_dir().join("disrobe-no-ghidra-here-256");
        let err: Error = lift_bcc_native(&blob, BccArch::WinX64, &missing).unwrap_err();
        assert!(matches!(err, Error::BccGhidraMissing));
    }

    #[test]
    fn missing_ghidra_for_darwin_arm64() {
        let blob: Vec<u8> = fake_blob(256);
        let missing: PathBuf = std::env::temp_dir().join("disrobe-no-ghidra-arm64");
        let err: Error = lift_bcc_native(&blob, BccArch::DarwinArm64, &missing).unwrap_err();
        assert!(matches!(err, Error::BccGhidraMissing));
    }

    #[test]
    fn arch_label_round_trips() {
        assert_eq!(BccArch::WinX64.label(), "win-x64");
        assert_eq!(BccArch::LinuxX64.label(), "linux-x64");
        assert_eq!(BccArch::DarwinArm64.label(), "darwin-arm64");
        assert_eq!(BccArch::Other(0xDEAD).label(), "other");
    }

    #[test]
    fn arch_from_id_maps_known_ids() {
        assert_eq!(BccArch::from_id(0x20_01), BccArch::WinX64);
        assert_eq!(BccArch::from_id(0x20_03), BccArch::LinuxX64);
        assert_eq!(BccArch::from_id(0x30_02), BccArch::DarwinArm64);
        assert_eq!(BccArch::from_id(0x99_99), BccArch::Other(0x99_99));
    }

    #[test]
    fn arch_to_language_maps_supported() {
        assert_eq!(
            arch_to_ghidra_language(BccArch::WinX64),
            "x86:LE:64:default"
        );
        assert_eq!(
            arch_to_ghidra_language(BccArch::LinuxX64),
            "x86:LE:64:default"
        );
        assert_eq!(
            arch_to_ghidra_language(BccArch::DarwinArm64),
            "AARCH64:LE:64:v8A"
        );
    }

    #[test]
    fn parse_function_id_accepts_0x_prefix_and_bare_hex() {
        let a: FunctionId = parse_function_id("0x401020", "foo").unwrap();
        let b: FunctionId = parse_function_id("401020", "foo").unwrap();
        assert_eq!(a.entry_va, 0x0040_1020);
        assert_eq!(a, b);
    }

    #[test]
    fn parse_function_id_rejects_garbage() {
        let err: Error = parse_function_id("not-hex", "foo").unwrap_err();
        assert!(matches!(err, Error::BccLiftJsonParse(_)));
    }

    #[test]
    fn function_id_is_ordered_by_entry_then_name() {
        let a: FunctionId = FunctionId {
            entry_va: 0x10,
            name: "z".to_owned(),
        };
        let b: FunctionId = FunctionId {
            entry_va: 0x20,
            name: "a".to_owned(),
        };
        let mut set: BTreeSet<FunctionId> = BTreeSet::new();
        set.insert(b.clone());
        set.insert(a.clone());
        let v: Vec<FunctionId> = set.into_iter().collect();
        assert_eq!(v[0], a);
        assert_eq!(v[1], b);
    }

    #[cfg(feature = "ghidra-integration")]
    #[test]
    fn lift_bcc_native_real_ghidra_invocation() {
        let Some(ghidra_os): Option<std::ffi::OsString> = std::env::var_os("DISROBE_GHIDRA") else {
            eprintln!("DISROBE_GHIDRA not set; skipping ghidra-integration test");
            return;
        };
        let ghidra: PathBuf = PathBuf::from(ghidra_os);
        let blob: Vec<u8> = fake_blob(4096);
        let _ = lift_bcc_native(&blob, BccArch::LinuxX64, &ghidra);
    }
}
