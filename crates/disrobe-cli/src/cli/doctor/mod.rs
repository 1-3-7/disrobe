#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Serialize;

use disrobe_core::subprocess::{CapturedOutput, wait_with_output_timeout};

use super::install::{self, InstallSpec, Platform};
use super::output::{OutputFormat, emit};
use catalog::tool_catalog;

mod catalog;

const CAPTURE_CAP_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolKind {
    Required,
    RecommendedNative,
    Optional,
}

impl ToolKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RecommendedNative => "recommended",
            Self::Optional => "optional",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ToolEntry {
    pub(crate) key: &'static str,
    pub(crate) probe_names: &'static [&'static str],
    pub(crate) env_overrides: &'static [&'static str],
    pub(crate) kind: ToolKind,
    pub(crate) used_by: &'static str,
    pub(crate) version_args: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) disrobe_version: &'static str,
    pub(crate) platform: &'static str,
    pub(crate) tools: Vec<ToolStatus>,
    pub(crate) config_dir: ConfigDirStatus,
    pub(crate) disk: DiskStatus,
    pub(crate) network: NetworkStatus,
    pub(crate) install_attempts: Vec<install::InstallReport>,
    pub(crate) exit_code: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolStatus {
    pub(crate) name: String,
    pub(crate) kind: &'static str,
    pub(crate) available: bool,
    pub(crate) version: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) env_source: Option<String>,
    pub(crate) used_by: &'static str,
    pub(crate) install_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigDirStatus {
    pub(crate) path: String,
    pub(crate) exists: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct DiskStatus {
    pub(crate) cwd: String,
    pub(crate) low_free_warning: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct NetworkStatus {
    pub(crate) probed: bool,
    pub(crate) url: &'static str,
    pub(crate) note: &'static str,
}

pub(crate) fn run_with_options(
    fmt: OutputFormat,
    auto_install: bool,
    yes: bool,
) -> miette::Result<()> {
    let catalog: Vec<ToolEntry> = tool_catalog();
    let mut tools: Vec<ToolStatus> = Vec::with_capacity(catalog.len());
    let mut missing_required: bool = false;

    for entry in &catalog {
        let status: ToolStatus = probe_entry(entry);
        if !status.available && matches!(entry.kind, ToolKind::Required) {
            missing_required = true;
        }
        tools.push(status);
    }

    let cfg_path: PathBuf = config_dir();
    let cfg_status: ConfigDirStatus = ConfigDirStatus {
        path: cfg_path.display().to_string(),
        exists: cfg_path.exists(),
    };

    let cwd: PathBuf = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let disk_status: DiskStatus = DiskStatus {
        cwd: cwd.display().to_string(),
        low_free_warning: false,
    };

    let net_status: NetworkStatus = NetworkStatus {
        probed: false,
        url: "https://api.github.com/repos/1-3-7/disrobe/releases/latest",
        note: "doctor does not hit the network; use `disrobe self-update --check-only` to probe",
    };

    let mut install_attempts: Vec<install::InstallReport> = Vec::new();
    if auto_install {
        let platform: Platform = Platform::detect();
        let install_map: BTreeMap<&'static str, InstallSpec> = install::install_action_map();
        for t in &tools {
            if t.available {
                continue;
            }
            let canonical: &str = install::canonicalize_alias(&t.name);
            let Some(spec): Option<&InstallSpec> = install_map.get(canonical) else {
                continue;
            };
            let r: install::InstallReport =
                install::perform_install(canonical, spec, platform, false, yes);
            let _: Result<(), std::io::Error> = install::log_install_attempt(&r);
            install_attempts.push(r);
        }
    }

    let exit_code: i32 = i32::from(missing_required);

    let report: DoctorReport = DoctorReport {
        disrobe_version: env!("CARGO_PKG_VERSION"),
        platform: Platform::detect().as_str(),
        tools,
        config_dir: cfg_status,
        disk: disk_status,
        network: net_status,
        install_attempts,
        exit_code,
    };

    emit(fmt, &report, || render_text(&report))?;

    if report.exit_code != 0 {
        std::process::exit(report.exit_code);
    }
    Ok(())
}

fn render_text(report: &DoctorReport) {
    println!("disrobe doctor");
    println!("  version:   {}", report.disrobe_version);
    println!("  platform:  {}", report.platform);
    println!("  config dir:");
    println!(
        "    path:      {} ({})",
        report.config_dir.path,
        if report.config_dir.exists {
            "exists"
        } else {
            "missing"
        }
    );
    println!("  disk:");
    println!("    cwd:       {}", report.disk.cwd);
    println!("  network probe:");
    println!("    url:       {}", report.network.url);
    println!("    note:      {}", report.network.note);
    println!("  tools:");
    let mut grouped: BTreeMap<&'static str, Vec<&ToolStatus>> = BTreeMap::new();
    for t in &report.tools {
        grouped.entry(t.kind).or_default().push(t);
    }
    for (kind, list) in &grouped {
        println!("    [{kind}]");
        for t in list {
            let mark: &'static str = if t.available { "OK" } else { "--" };
            println!(
                "      [{mark}] {:<18} version={} path={} used-by: {}",
                t.name,
                t.version.as_deref().unwrap_or("?"),
                t.path.as_deref().unwrap_or("?"),
                t.used_by,
            );
            if let Some(ref e) = t.env_source {
                println!("              env:       {e}");
            }
            if let Some(ref hint) = t.install_hint {
                println!("              install:   {hint}");
            }
        }
    }
    if !report.install_attempts.is_empty() {
        println!("  auto-install attempts:");
        for a in &report.install_attempts {
            println!("    {:<18} -> {} ({} ms)", a.tool, a.status, a.duration_ms);
        }
    }
    println!(
        "  exit code: {} ({})",
        report.exit_code,
        exit_code_label(report.exit_code)
    );
}

const fn exit_code_label(c: i32) -> &'static str {
    match c {
        0 => "all-good",
        1 => "missing-required",
        2 => "missing-optional",
        _ => "unknown",
    }
}

pub(crate) fn probe_entry(entry: &ToolEntry) -> ToolStatus {
    let mut env_source: Option<String> = None;
    for env in entry.env_overrides {
        if let Some(v) = std::env::var_os(env) {
            let p: PathBuf = PathBuf::from(&v);
            if p.is_file() {
                env_source = Some((*env).to_owned());
                let version: Option<String> = probe_version_at(&p, entry.version_args);
                return ToolStatus {
                    name: entry.key.to_owned(),
                    kind: entry.kind.as_str(),
                    available: true,
                    version,
                    path: Some(p.display().to_string()),
                    env_source,
                    used_by: entry.used_by,
                    install_hint: None,
                };
            }
            if p.is_dir() {
                env_source = Some((*env).to_owned());
                if let Some(candidate) = find_executable_in_dir(&p, entry.probe_names) {
                    let version: Option<String> = probe_version_at(&candidate, entry.version_args);
                    return ToolStatus {
                        name: entry.key.to_owned(),
                        kind: entry.kind.as_str(),
                        available: true,
                        version,
                        path: Some(candidate.display().to_string()),
                        env_source,
                        used_by: entry.used_by,
                        install_hint: None,
                    };
                }
            }
        }
    }
    for probe in entry.probe_names {
        if let Some(path) = which_on_path(probe) {
            let version: Option<String> =
                probe_version_at(&PathBuf::from(&path), entry.version_args);
            return ToolStatus {
                name: entry.key.to_owned(),
                kind: entry.kind.as_str(),
                available: true,
                version,
                path: Some(path),
                env_source,
                used_by: entry.used_by,
                install_hint: None,
            };
        }
    }
    ToolStatus {
        name: entry.key.to_owned(),
        kind: entry.kind.as_str(),
        available: false,
        version: None,
        path: None,
        env_source,
        used_by: entry.used_by,
        install_hint: Some(format!("disrobe install {}", entry.key)),
    }
}

fn find_executable_in_dir(root: &std::path::Path, probe_names: &[&str]) -> Option<PathBuf> {
    let search_dirs: [PathBuf; 2] = [root.to_path_buf(), root.join("bin")];
    let exts: Vec<String> = executable_extensions();
    for dir in &search_dirs {
        if !dir.is_dir() {
            continue;
        }
        for probe in probe_names {
            for ext in &exts {
                let candidate: PathBuf = if ext.is_empty() {
                    dir.join(probe)
                } else {
                    dir.join(format!("{probe}{ext}"))
                };
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn executable_extensions() -> Vec<String> {
    if cfg!(windows) {
        std::env::var("PATHEXT").ok().map_or_else(
            || {
                vec![
                    ".exe".to_owned(),
                    ".bat".to_owned(),
                    ".cmd".to_owned(),
                    ".com".to_owned(),
                ]
            },
            |s| {
                s.split(';')
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            },
        )
    } else {
        vec![String::new()]
    }
}

fn which_on_path(name: &str) -> Option<String> {
    let path_env: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: Vec<String> = executable_extensions();
    for dir in std::env::split_paths(&path_env) {
        for ext in &exts {
            let candidate: PathBuf = if ext.is_empty() {
                dir.join(name)
            } else {
                dir.join(format!("{name}{ext}"))
            };
            if candidate.is_file() {
                return Some(candidate.display().to_string());
            }
        }
    }
    None
}

fn probe_version_at(path: &std::path::Path, args: &[&str]) -> Option<String> {
    let arg_list: Vec<&str> = if args.is_empty() {
        vec!["--version"]
    } else {
        args.to_vec()
    };
    let child: Result<std::process::Child, std::io::Error> = Command::new(path)
        .args(arg_list)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let child: std::process::Child = child.ok()?;
    let out: CapturedOutput =
        wait_with_output_timeout(child, Duration::from_secs(3), CAPTURE_CAP_BYTES)?;
    let stdout: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    let first: String = stdout
        .lines()
        .next()
        .or_else(|| stderr.lines().next())
        .unwrap_or("")
        .to_owned();
    if first.is_empty() {
        return None;
    }
    Some(first)
}

fn config_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(appdata) = std::env::var_os("APPDATA")
    {
        return PathBuf::from(appdata).join("disrobe");
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("disrobe");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("disrobe");
    }
    PathBuf::from(".disrobe")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_required_minimum() {
        let cat: Vec<ToolEntry> = tool_catalog();
        assert!(cat.len() >= 30, "expected >= 30 entries, got {}", cat.len());
        let python: Option<&ToolEntry> = cat.iter().find(|e: &&ToolEntry| e.key == "python");
        assert!(python.is_some(), "python entry missing");
        assert_eq!(python.expect("present").kind, ToolKind::Required);
    }

    #[test]
    fn find_executable_in_dir_probes_bin_subdir() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-doctor-bin")
                .expect("create scratch directory");
        let root: PathBuf = scratch.path().to_path_buf();
        let bin: PathBuf = root.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        let exe_name: &str = if cfg!(windows) { "tool.exe" } else { "tool" };
        let exe_path: PathBuf = bin.join(exe_name);
        std::fs::write(&exe_path, b"#!/bin/sh\n").expect("write fake exe");
        let found: Option<PathBuf> = find_executable_in_dir(&root, &["tool"]);
        assert_eq!(
            found.as_deref(),
            Some(exe_path.as_path()),
            "JAVA_HOME-style dir must resolve bin/<tool>"
        );
    }

    #[test]
    fn find_executable_in_dir_probes_dir_root() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-doctor-root")
                .expect("create scratch directory");
        let root: PathBuf = scratch.path().to_path_buf();
        let exe_name: &str = if cfg!(windows) { "tool.exe" } else { "tool" };
        let exe_path: PathBuf = root.join(exe_name);
        std::fs::write(&exe_path, b"#!/bin/sh\n").expect("write fake exe");
        let found: Option<PathBuf> = find_executable_in_dir(&root, &["tool"]);
        assert_eq!(found.as_deref(), Some(exe_path.as_path()));
    }

    #[test]
    fn unknown_tool_yields_install_hint() {
        let entry: ToolEntry = ToolEntry {
            key: "definitely-not-a-real-tool-xyz",
            probe_names: &["definitely-not-a-real-tool-xyz"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "test",
            version_args: &["--version"],
        };
        let s: ToolStatus = probe_entry(&entry);
        assert!(!s.available);
        assert!(s.install_hint.is_some());
    }
}
