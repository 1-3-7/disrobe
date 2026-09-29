use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
}
