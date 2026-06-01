#![allow(clippy::too_many_lines, clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;

use super::output::{OutputFormat, emit};
pub(crate) use actions::install_action_map;

mod actions;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Platform {
    Windows,
    MacOs,
    LinuxApt,
    LinuxDnf,
    LinuxPacman,
    LinuxApk,
    LinuxUnknown,
}

impl Platform {
    pub(crate) fn detect() -> Self {
        if cfg!(target_os = "windows") {
            return Self::Windows;
        }
        if cfg!(target_os = "macos") {
            return Self::MacOs;
        }
        if cfg!(target_os = "linux") {
            return detect_linux_distro();
        }
        Self::LinuxUnknown
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::LinuxApt => "linux-apt",
            Self::LinuxDnf => "linux-dnf",
            Self::LinuxPacman => "linux-pacman",
            Self::LinuxApk => "linux-apk",
            Self::LinuxUnknown => "linux-unknown",
        }
    }
}

fn detect_linux_distro() -> Platform {
    let body: String = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id_like: String = body
        .lines()
        .filter_map(|line: &str| {
            let trimmed: &str = line.trim();
            if let Some(rest) = trimmed.strip_prefix("ID=") {
                return Some(rest.trim_matches('"').to_ascii_lowercase());
            }
            if let Some(rest) = trimmed.strip_prefix("ID_LIKE=") {
                return Some(rest.trim_matches('"').to_ascii_lowercase());
            }
            None
        })
        .collect::<Vec<String>>()
        .join(" ");
    if id_like.contains("debian") || id_like.contains("ubuntu") {
        return Platform::LinuxApt;
    }
    if id_like.contains("fedora") || id_like.contains("rhel") || id_like.contains("centos") {
        return Platform::LinuxDnf;
    }
    if id_like.contains("arch") {
        return Platform::LinuxPacman;
    }
    if id_like.contains("alpine") {
        return Platform::LinuxApk;
    }
    Platform::LinuxUnknown
}

#[derive(Clone, Debug)]
pub(crate) struct InstallAction {
    pub(crate) cmd: &'static str,
    pub(crate) args: Vec<&'static str>,
    pub(crate) requires_admin: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct InstallSpec {
    pub(crate) per_platform: BTreeMap<Platform, InstallAction>,
    pub(crate) note: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallReport {
    pub(crate) tool: String,
    pub(crate) platform: &'static str,
    pub(crate) action_cmd: Option<String>,
    pub(crate) status: String,
    pub(crate) stdout_tail: String,
    pub(crate) stderr_tail: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) dry_run: bool,
    pub(crate) timestamp_unix_s: u64,
    pub(crate) duration_ms: u128,
    pub(crate) note: Option<String>,
}

pub(crate) fn run(tool: &str, dry_run: bool, yes: bool, fmt: OutputFormat) -> miette::Result<()> {
    let map: BTreeMap<&'static str, InstallSpec> = install_action_map();
    let canonical: &str = canonicalize_alias(tool);
    let Some(spec) = map.get(canonical) else {
        return Err(miette::miette!(
            "DR-CLI-0270: unknown tool '{tool}'; run `disrobe install --list` to see every known tool, or `disrobe doctor` to probe what is already on PATH",
        ));
    };
    let platform: Platform = Platform::detect();
    let report: InstallReport = perform_install(canonical, spec, platform, dry_run, yes);
    let _: Result<(), std::io::Error> = log_install_attempt(&report);
    let exit_nonzero: bool = !matches!(
        report.status.as_str(),
        "installed" | "dry-run" | "skipped-already-present",
    );
    let owned: InstallReport = report;
    emit(fmt, &owned, || render_text(&owned))?;
    if exit_nonzero {
        std::process::exit(3);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallListEntry {
    pub(crate) tool: &'static str,
    pub(crate) note: Option<&'static str>,
    pub(crate) per_platform: BTreeMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallList {
    pub(crate) current_platform: &'static str,
    pub(crate) total: usize,
    pub(crate) entries: Vec<InstallListEntry>,
}

pub(crate) fn run_list(fmt: OutputFormat) -> miette::Result<()> {
    let map: BTreeMap<&'static str, InstallSpec> = install_action_map();
    let current: Platform = Platform::detect();
    let mut entries: Vec<InstallListEntry> = Vec::with_capacity(map.len());
    for (tool, spec) in &map {
        let mut per_platform: BTreeMap<&'static str, String> = BTreeMap::new();
        for (plat, action) in &spec.per_platform {
            per_platform.insert(plat.as_str(), format_cmd(action));
        }
        entries.push(InstallListEntry {
            tool,
            note: spec.note,
            per_platform,
        });
    }
    let total: usize = entries.len();
    let list: InstallList = InstallList {
        current_platform: current.as_str(),
        total,
        entries,
    };
    emit(fmt, &list, || render_list(&list, current))
}

fn render_list(list: &InstallList, current: Platform) {
    println!("disrobe install --list");
    println!("  current platform: {}", list.current_platform);
    println!("  total tools:      {}", list.total);
    println!();
    println!("  {:<14} {:<14} install command", "tool", "current-plat");
    println!("  {}", "-".repeat(72));
    let current_key: &'static str = current.as_str();
    for entry in &list.entries {
        let current_cmd: &str = entry
            .per_platform
            .get(current_key)
            .map_or("(no install action for this platform)", String::as_str);
        let supported: bool = entry.per_platform.contains_key(current_key);
        let marker: &'static str = if supported { "OK" } else { "--" };
        println!("  {:<14} [{}] {}", entry.tool, marker, current_cmd);
        if let Some(note) = entry.note {
            println!("                  note: {note}");
        }
        let other: Vec<String> = entry
            .per_platform
            .iter()
            .filter(|(k, _)| **k != current_key)
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        if !other.is_empty() {
            println!("                  other platforms:");
            for line in &other {
                println!("                    - {line}");
            }
        }
    }
}

pub(crate) fn perform_install(
    tool: &str,
    spec: &InstallSpec,
    platform: Platform,
    dry_run: bool,
    yes: bool,
) -> InstallReport {
    let start: std::time::Instant = std::time::Instant::now();
    let ts: u64 = epoch_seconds();
    let Some(action) = spec.per_platform.get(&platform) else {
        return InstallReport {
            tool: tool.to_owned(),
            platform: platform.as_str(),
            action_cmd: None,
            status: "unsupported-platform".to_owned(),
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            exit_code: None,
            dry_run,
            timestamp_unix_s: ts,
            duration_ms: start.elapsed().as_millis(),
            note: spec.note.map(str::to_owned),
        };
    };
    let cmd_str: String = format_cmd(action);
    if dry_run {
        return InstallReport {
            tool: tool.to_owned(),
            platform: platform.as_str(),
            action_cmd: Some(cmd_str),
            status: "dry-run".to_owned(),
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            exit_code: None,
            dry_run: true,
            timestamp_unix_s: ts,
            duration_ms: start.elapsed().as_millis(),
            note: spec.note.map(str::to_owned),
        };
    }
    if !yes && !confirm_prompt(tool, &cmd_str) {
        return InstallReport {
            tool: tool.to_owned(),
            platform: platform.as_str(),
            action_cmd: Some(cmd_str),
            status: "declined".to_owned(),
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            exit_code: None,
            dry_run: false,
            timestamp_unix_s: ts,
            duration_ms: start.elapsed().as_millis(),
            note: spec.note.map(str::to_owned),
        };
    }
    let exec_res: ExecResult = execute_action(action);
    let status: &'static str = if exec_res.exit_code == Some(0) {
        "installed"
    } else {
        "install-failed"
    };
    InstallReport {
        tool: tool.to_owned(),
        platform: platform.as_str(),
        action_cmd: Some(cmd_str),
        status: status.to_owned(),
        stdout_tail: tail(&exec_res.stdout, 800),
        stderr_tail: tail(&exec_res.stderr, 800),
        exit_code: exec_res.exit_code,
        dry_run: false,
        timestamp_unix_s: ts,
        duration_ms: start.elapsed().as_millis(),
        note: spec.note.map(str::to_owned),
    }
}

struct ExecResult {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

fn execute_action(action: &InstallAction) -> ExecResult {
    let use_sudo: bool = action.requires_admin && cfg!(unix);
    let (program, leading_args): (&str, &[&'static str]) = if use_sudo {
        ("sudo", std::slice::from_ref(&action.cmd))
    } else {
        (action.cmd, &[])
    };
    let spawn: Result<std::process::Output, std::io::Error> = Command::new(program)
        .args(leading_args)
        .args(&action.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match spawn {
        Ok(o) => ExecResult {
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            exit_code: o.status.code(),
        },
        Err(e) => ExecResult {
            stdout: String::new(),
            stderr: format!("spawn error: {e}"),
            exit_code: None,
        },
    }
}

fn confirm_prompt(tool: &str, cmd: &str) -> bool {
    eprintln!("about to install '{tool}' via:");
    eprintln!("  {cmd}");
    eprint!("proceed? [y/N] ");
    let _: Result<(), std::io::Error> = std::io::stderr().flush();
    let mut buf: String = String::new();
    if std::io::stdin().read_line(&mut buf).is_err() {
        return false;
    }
    let answer: &str = buf.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

fn render_text(r: &InstallReport) {
    println!("disrobe install {}", r.tool);
    println!("  platform:     {}", r.platform);
    if let Some(ref c) = r.action_cmd {
        println!("  command:      {c}");
    }
    println!("  status:       {}", r.status);
    if let Some(code) = r.exit_code {
        println!("  exit code:    {code}");
    }
    println!("  duration:     {} ms", r.duration_ms);
    if let Some(ref n) = r.note {
        println!("  note:         {n}");
    }
    if !r.stdout_tail.trim().is_empty() {
        println!("  stdout tail:");
        for line in r.stdout_tail.lines().take(20) {
            println!("    {line}");
        }
    }
    if !r.stderr_tail.trim().is_empty() {
        println!("  stderr tail:");
        for line in r.stderr_tail.lines().take(20) {
            println!("    {line}");
        }
    }
}

fn format_cmd(action: &InstallAction) -> String {
    let mut out: String = String::with_capacity(64);
    if action.requires_admin && cfg!(unix) {
        out.push_str("sudo ");
    }
    out.push_str(action.cmd);
    for a in &action.args {
        out.push(' ');
        if a.contains(' ') {
            out.push('"');
            out.push_str(a);
            out.push('"');
        } else {
            out.push_str(a);
        }
    }
    out
}

fn tail(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let start: usize = s.len().saturating_sub(max_bytes);
    let mut cut: usize = start;
    while cut < s.len() && !s.is_char_boundary(cut) {
        cut += 1;
    }
    s[cut..].to_owned()
}

pub(crate) fn log_install_attempt(report: &InstallReport) -> std::io::Result<()> {
    let dir: PathBuf = disrobe_state_dir();
    std::fs::create_dir_all(&dir)?;
    let log: PathBuf = dir.join("doctor-log.jsonl");
    let json: String =
        serde_json::to_string(report).unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_owned());
    let mut f: std::fs::File = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    f.write_all(json.as_bytes())?;
    f.write_all(b"\n")
}

fn epoch_seconds() -> u64 {
    disrobe_core::time::now_secs()
}

pub(crate) fn disrobe_state_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".disrobe");
    }
    if cfg!(windows)
        && let Some(profile) = std::env::var_os("USERPROFILE")
    {
        return PathBuf::from(profile).join(".disrobe");
    }
    PathBuf::from(".disrobe")
}

pub(crate) fn canonicalize_alias(tool: &str) -> &str {
    let lower: &str = tool.trim_start_matches("--").trim();
    match lower {
        "g" | "ghidra-headless" => "ghidra",
        "proguard" | "ProGuard" => "proguard",
        "r8" | "R8" => "r8",
        "d8" | "D8" => "d8",
        "luajit2" => "luajit",
        "py3" | "py" => "python",
        "py2" => "python2",
        "uv-pip" => "uv",
        _ => lower,
    }
}

#[cfg(test)]
mod tests;
