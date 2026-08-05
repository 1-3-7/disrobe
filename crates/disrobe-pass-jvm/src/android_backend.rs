#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::duration_suboptimal_units
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use serde::{Deserialize, Serialize};

use crate::backends::{AndroidBackend, BackendInvocation, invoke_android};
use crate::dalvik_decompile::{DecompiledDex, decompile_dex_bytes};
use crate::error::{Error, Result};

const JADX_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AndroidDecompiler {
    InHouseDalvik,
    Jadx,
}

impl AndroidDecompiler {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InHouseDalvik => "in-house Dalvik decompiler",
            Self::Jadx => "jadx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidDecompileOutput {
    pub engine: AndroidDecompiler,
    pub sources: BTreeMap<String, String>,
    pub class_count: usize,
    pub method_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPreference {
    PreferInHouse,
    PreferJadxIfAvailable,
    ForceJadx,
}

impl Default for BackendPreference {
    #[inline]
    fn default() -> Self {
        Self::PreferInHouse
    }
}

pub fn decompile_dex(
    dex_bytes: &[u8],
    preference: BackendPreference,
) -> Result<AndroidDecompileOutput> {
    match preference {
        BackendPreference::ForceJadx => run_jadx_on_bytes(dex_bytes, "input.dex"),
        BackendPreference::PreferJadxIfAvailable => {
            match run_jadx_on_bytes(dex_bytes, "input.dex") {
                Ok(out) => Ok(out),
                Err(Error::MissingTool(_)) => decompile_dex_in_house(dex_bytes),
                Err(e) => Err(e),
            }
        }
        BackendPreference::PreferInHouse => decompile_dex_in_house(dex_bytes),
    }
}

fn decompile_dex_in_house(dex_bytes: &[u8]) -> Result<AndroidDecompileOutput> {
    let decompiled: DecompiledDex = decompile_dex_bytes(dex_bytes)?;
    let mut sources: BTreeMap<String, String> = decompiled.sources;
    if sources.is_empty() {
        sources.insert("decompiled.java".to_string(), decompiled.source);
    }
    Ok(AndroidDecompileOutput {
        engine: AndroidDecompiler::InHouseDalvik,
        sources,
        class_count: decompiled.class_count,
        method_count: decompiled.method_count,
        notes: vec![format!(
            "in-house Dalvik decompiler: {} fully lifted, {} fallback methods",
            decompiled.fully_lifted_methods, decompiled.fallback_methods
        )],
    })
}

pub fn run_jadx_on_bytes(input_bytes: &[u8], file_name: &str) -> Result<AndroidDecompileOutput> {
    let work: ScratchDir = make_work_dir()?;
    let input_path: PathBuf = work.path().join(file_name);
    std::fs::write(&input_path, input_bytes)?;
    let out_dir: PathBuf = work.path().join("out");
    let result: Result<AndroidDecompileOutput> = run_jadx_on_path(&input_path, &out_dir);
    result
}

fn run_jadx_on_path(input_path: &Path, out_dir: &Path) -> Result<AndroidDecompileOutput> {
    let args: Vec<String> = vec![
        "--no-debug-info".to_string(),
        "-d".to_string(),
        out_dir.to_string_lossy().into_owned(),
        input_path.to_string_lossy().into_owned(),
    ];
    let invocation: Result<BackendInvocation> =
        invoke_android(AndroidBackend::Jadx, &args, JADX_TIMEOUT);
    let stderr: String = match invocation {
        Ok(inv) => String::from_utf8_lossy(&inv.stderr).into_owned(),
        Err(Error::BackendFailed { stderr, .. }) => stderr,
        Err(e) => return Err(e),
    };
    let sources: BTreeMap<String, String> = collect_java_sources(out_dir)?;
    if sources.is_empty() {
        return Err(Error::BackendFailed {
            tool: "jadx".to_string(),
            status: -1,
            stderr: format!("jadx produced no .java sources; stderr: {stderr}"),
        });
    }
    let method_count: usize = sources
        .values()
        .map(|s: &String| count_method_signatures(s))
        .sum();
    Ok(AndroidDecompileOutput {
        engine: AndroidDecompiler::Jadx,
        class_count: sources.len(),
        method_count,
        notes: vec!["jadx external backend".to_string()],
        sources,
    })
}

fn make_work_dir() -> Result<ScratchDir> {
    Ok(ScratchDir::create("disrobe_jadx")?)
}

fn collect_java_sources(out_dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let sources_root: PathBuf = out_dir.join("sources");
    let scan_root: &Path = if sources_root.is_dir() {
        sources_root.as_path()
    } else {
        out_dir
    };
    if scan_root.is_dir() {
        walk_java(scan_root, scan_root, &mut sources)?;
    }
    Ok(sources)
}

fn walk_java(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry: std::fs::DirEntry = entry?;
        let path: PathBuf = entry.path();
        if path.is_dir() {
            walk_java(root, &path, out)?;
        } else if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) == Some("java") {
            let rel: String = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if let Ok(content) = std::fs::read_to_string(&path) {
                out.insert(rel, content);
            }
        }
    }
    Ok(())
}

fn count_method_signatures(src: &str) -> usize {
    src.lines()
        .filter(|line: &&str| {
            let t: &str = line.trim();
            (t.contains('(') && t.contains(')'))
                && (t.ends_with('{') || t.ends_with(';'))
                && (t.contains("public ")
                    || t.contains("private ")
                    || t.contains("protected ")
                    || t.contains("static "))
                && !t.starts_with("//")
                && !t.starts_with('*')
        })
        .count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_preference_is_in_house() {
        assert_eq!(
            BackendPreference::default(),
            BackendPreference::PreferInHouse
        );
    }

    #[test]
    fn engine_labels() {
        assert_eq!(AndroidDecompiler::Jadx.label(), "jadx");
        assert_eq!(
            AndroidDecompiler::InHouseDalvik.label(),
            "in-house Dalvik decompiler"
        );
    }

    #[test]
    fn count_method_signatures_counts_declarations() {
        let src: &str = "public class Foo {\n  public int bar() {\n  private void baz(int x) {\n}";
        assert_eq!(count_method_signatures(src), 2);
    }
}
