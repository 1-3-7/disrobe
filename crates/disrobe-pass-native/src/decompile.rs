use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAX_BACKEND_CAPTURE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecompilerBackend {
    Ghidra,
    Rizin,
    BinaryNinja,
    Ida,
    Angr,
    Retdec,
    LlvmIr,
}

impl DecompilerBackend {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ghidra => "ghidra",
            Self::Rizin => "rizin",
            Self::BinaryNinja => "binja",
            Self::Ida => "ida",
            Self::Angr => "angr",
            Self::Retdec => "retdec",
            Self::LlvmIr => "llvm-ir",
        }
    }

    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Ghidra => "analyzeHeadless",
            Self::Rizin => "rizin",
            Self::BinaryNinja => "binaryninja",
            Self::Ida => "idat64",
            Self::Angr => "angr",
            Self::Retdec => "retdec-decompiler",
            Self::LlvmIr => "llvm-dis",
        }
    }

    #[must_use]
    pub const fn license_required(self) -> bool {
        matches!(self, Self::BinaryNinja | Self::Ida)
    }

    #[must_use]
    pub const fn override_env(self) -> &'static str {
        match self {
            Self::Ghidra => "DISROBE_BACKEND_GHIDRA",
            Self::Rizin => "DISROBE_BACKEND_RIZIN",
            Self::BinaryNinja => "DISROBE_BACKEND_BINJA",
            Self::Ida => "DISROBE_BACKEND_IDA",
            Self::Angr => "DISROBE_BACKEND_ANGR",
            Self::Retdec => "DISROBE_BACKEND_RETDEC",
            Self::LlvmIr => "DISROBE_BACKEND_LLVM_IR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub backend: DecompilerBackend,
    pub found: bool,
    pub path: Option<PathBuf>,
    pub note: Option<String>,
}

#[must_use]
pub fn probe_all() -> BTreeMap<DecompilerBackend, Probe> {
    let backends: [DecompilerBackend; 7] = [
        DecompilerBackend::Ghidra,
        DecompilerBackend::Rizin,
        DecompilerBackend::BinaryNinja,
        DecompilerBackend::Ida,
        DecompilerBackend::Angr,
        DecompilerBackend::Retdec,
        DecompilerBackend::LlvmIr,
    ];
    let mut out: BTreeMap<DecompilerBackend, Probe> = BTreeMap::new();
    for b in backends {
        let p: Probe = probe(b);
        out.insert(b, p);
    }
    out
}

#[must_use]
pub fn probe(backend: DecompilerBackend) -> Probe {
    if let Ok(path) = std::env::var(backend.override_env()) {
        let pb: PathBuf = PathBuf::from(&path);
        let exists: bool = pb.exists();
        return Probe {
            backend,
            found: exists,
            path: exists.then_some(pb),
            note: Some(format!("env override {}={path}", backend.override_env())),
        };
    }
    if backend.license_required() {
        return Probe {
            backend,
            found: false,
            path: None,
            note: Some(format!(
                "license-required backend; set {} to enable",
                backend.override_env()
            )),
        };
    }
    let found: Option<PathBuf> = which_on_path(backend.binary_name());
    Probe {
        backend,
        found: found.is_some(),
        path: found,
        note: None,
    }
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var: String = std::env::var("PATH").ok()?;
    let exe_exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.BAT;.CMD".to_owned())
            .split(';')
            .map(|s: &str| s.trim().to_owned())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in path_var.split(if cfg!(windows) { ';' } else { ':' }) {
        for ext in &exe_exts {
            let candidate: PathBuf = PathBuf::from(dir).join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileOutput {
    pub backend: DecompilerBackend,
    pub stdout: String,
    pub stderr: String,
    pub artifact_path: Option<PathBuf>,
}

#[expect(
    clippy::duration_suboptimal_units,
    reason = "from_mins is unstable (duration_constructors, rust#120301); from_secs is the stable form"
)]
pub fn run(backend: DecompilerBackend, input: &Path, out_dir: &Path) -> Result<DecompileOutput> {
    if backend.license_required() && std::env::var(backend.override_env()).is_err() {
        return Err(Error::LicenseRequired(backend.label()));
    }
    let probe_result: Probe = probe(backend);
    if !probe_result.found {
        return Err(Error::MissingTool(backend.binary_name().to_owned()));
    }
    let tool: PathBuf = probe_result
        .path
        .unwrap_or_else(|| PathBuf::from(backend.binary_name()));
    let mut cmd: Command = Command::new(&tool);
    match backend {
        DecompilerBackend::Ghidra => {
            cmd.arg(out_dir)
                .arg("disrobe_project")
                .arg("-import")
                .arg(input)
                .arg("-deleteProject");
        }
        DecompilerBackend::Rizin => {
            cmd.arg("-q").arg("-c").arg("aaa; pdc").arg(input);
        }
        DecompilerBackend::BinaryNinja => {
            cmd.arg("--decompile").arg(input);
        }
        DecompilerBackend::Ida => {
            cmd.arg("-A").arg("-B").arg(input);
        }
        DecompilerBackend::Angr => {
            cmd.arg("-c")
                .arg("import angr; angr.Project(__import__('sys').argv[1]).analyses.CFG()")
                .arg(input);
        }
        DecompilerBackend::Retdec => {
            let out_file: PathBuf = out_dir.join("retdec.c");
            cmd.arg(input).arg("--output").arg(&out_file);
        }
        DecompilerBackend::LlvmIr => {
            cmd.arg(input);
        }
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child: std::process::Child = cmd.spawn().map_err(|e: std::io::Error| match e.kind() {
        std::io::ErrorKind::NotFound => Error::MissingTool(backend.binary_name().to_owned()),
        _ => Error::Io(e),
    })?;
    let timeout: Duration = Duration::from_secs(300);
    let Some(captured): Option<disrobe_core::subprocess::CapturedOutput> =
        disrobe_core::subprocess::wait_with_output_timeout(child, timeout, MAX_BACKEND_CAPTURE)
    else {
        return Err(Error::BackendTimeout(
            backend.binary_name().to_owned(),
            timeout.as_millis() as u64,
        ));
    };
    let stdout_text: String = String::from_utf8_lossy(&captured.stdout).into_owned();
    let stderr_text: String = String::from_utf8_lossy(&captured.stderr).into_owned();
    if captured.exit_code != Some(0) {
        return Err(Error::BackendFailed {
            tool: backend.binary_name().to_owned(),
            status: captured.exit_code.unwrap_or(-1),
            stderr: stderr_text,
        });
    }
    Ok(DecompileOutput {
        backend,
        stdout: stdout_text,
        stderr: stderr_text,
        artifact_path: None,
    })
}

pub fn lift_llvm_ir_to_pseudo_c(ir_text: &str) -> Result<String> {
    if ir_text.trim().is_empty() {
        return Err(Error::LlvmIr("empty IR text".to_owned()));
    }
    let mut pseudo: String = String::new();
    pseudo.push_str("// pseudo-C from disrobe llvm-ir surface lift\n");
    for line in ir_text.lines() {
        let trimmed: &str = line.trim();
        if let Some(rest) = trimmed.strip_prefix("define ") {
            let header: &str = rest.split('{').next().unwrap_or(rest).trim();
            pseudo.push_str(&format!("{header} {{\n"));
        } else if trimmed == "}" {
            pseudo.push_str("}\n");
        } else if trimmed.starts_with("ret ") {
            pseudo.push_str(&format!("    return {};\n", &trimmed[4..]));
        } else if let Some(call) = trimmed.strip_prefix("call ") {
            pseudo.push_str(&format!("    {call};\n"));
        }
    }
    if pseudo.lines().count() == 1 {
        return Err(Error::LlvmIr(
            "no recognisable LLVM IR constructs in input".to_owned(),
        ));
    }
    Ok(pseudo)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn license_required_backends_block_without_override() {
        let p: Probe = probe(DecompilerBackend::BinaryNinja);
        assert!(!p.found);
        let p2: Probe = probe(DecompilerBackend::Ida);
        assert!(!p2.found);
    }

    #[test]
    fn probe_all_returns_seven_entries() {
        let map: BTreeMap<DecompilerBackend, Probe> = probe_all();
        assert_eq!(map.len(), 7);
    }

    #[test]
    fn license_run_yields_license_required_error() {
        let tmp: PathBuf = std::env::temp_dir();
        let dummy: PathBuf = tmp.join(format!(
            "disrobe-decompile-input-{}.bin",
            std::process::id()
        ));
        std::fs::write(&dummy, b"\x7FELF").expect("write dummy");
        let res: Result<DecompileOutput> = run(DecompilerBackend::Ida, &dummy, &tmp);
        match res {
            Err(Error::LicenseRequired(label)) => assert_eq!(label, "ida"),
            other => panic!("expected LicenseRequired, got {other:?}"),
        }
    }

    #[test]
    fn lift_llvm_ir_emits_pseudo_for_define_ret() {
        let ir: &str = "define i32 @main() {\n  ret i32 0\n}\n";
        let out: String = lift_llvm_ir_to_pseudo_c(ir).expect("lift");
        assert!(out.contains("i32 @main()"));
        assert!(out.contains("return"));
    }

    #[test]
    fn lift_llvm_ir_empty_input_rejected() {
        let err: Error = lift_llvm_ir_to_pseudo_c("").expect_err("empty");
        assert!(matches!(err, Error::LlvmIr(_)));
    }
}
