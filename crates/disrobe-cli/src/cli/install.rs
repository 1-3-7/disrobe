#![allow(clippy::too_many_lines, clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;

use super::output::{OutputFormat, emit};

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
    let spawn: Result<std::process::Output, std::io::Error> = Command::new(action.cmd)
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

pub(crate) fn install_action_map() -> BTreeMap<&'static str, InstallSpec> {
    let mut m: BTreeMap<&'static str, InstallSpec> = BTreeMap::new();
    add_simple_pkg(
        &mut m,
        "ghidra",
        "use `disrobe install-deps ghidra` for the official NSA Ghidra zip release; this entry uses your platform's package manager",
        ToolPkg {
            winget: Some("Ghidra.Ghidra"),
            brew: Some("ghidra"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: Some("ghidra"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "rizin",
        "command-line reverse engineering framework",
        ToolPkg {
            winget: Some("rizinorg.rizin"),
            brew: Some("rizin"),
            brew_cask: false,
            apt: Some("rizin"),
            dnf: Some("rizin"),
            pacman: Some("rizin"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "binaryninja",
        "Binary Ninja is commercial; place a license to enable",
        ToolPkg {
            winget: Some("Vector35.BinaryNinja"),
            brew: None,
            brew_cask: true,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "angr",
        "python symbolic execution toolkit",
        ToolPkg {
            winget: None,
            brew: None,
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: Some("angr"),
        },
    );
    add_simple_pkg(
        &mut m,
        "retdec",
        "open-source machine-code decompiler",
        ToolPkg {
            winget: Some("avast.retdec"),
            brew: Some("retdec"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "llvm",
        "provides llvm-objdump and llvm-mc",
        ToolPkg {
            winget: Some("LLVM.LLVM"),
            brew: Some("llvm"),
            brew_cask: false,
            apt: Some("llvm"),
            dnf: Some("llvm"),
            pacman: Some("llvm"),
            apk: Some("llvm"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "upx",
        "ultimate packer for executables",
        ToolPkg {
            winget: Some("upx.upx"),
            brew: Some("upx"),
            brew_cask: false,
            apt: Some("upx-ucl"),
            dnf: Some("upx"),
            pacman: Some("upx"),
            apk: Some("upx"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "mpress",
        "high-performance executable packer (legacy)",
        ToolPkg {
            winget: None,
            brew: None,
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "kkrunchy",
        "demoscene executable packer (manual install only)",
        ToolPkg {
            winget: None,
            brew: None,
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "java",
        "OpenJDK 21 runtime (Java)",
        ToolPkg {
            winget: Some("EclipseAdoptium.Temurin.21.JDK"),
            brew: Some("openjdk@21"),
            brew_cask: false,
            apt: Some("openjdk-21-jdk"),
            dnf: Some("java-21-openjdk"),
            pacman: Some("jdk21-openjdk"),
            apk: Some("openjdk21"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "kotlinc",
        "Kotlin compiler",
        ToolPkg {
            winget: Some("JetBrains.Kotlin"),
            brew: Some("kotlin"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: Some("kotlin"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "proguard",
        "ProGuard: Java / Android shrinker and obfuscator",
        ToolPkg {
            winget: None,
            brew: Some("proguard"),
            brew_cask: false,
            apt: Some("proguard"),
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "r8",
        "R8 ships with the Android SDK build-tools; install the Android SDK",
        ToolPkg {
            winget: Some("Google.AndroidStudio"),
            brew: None,
            brew_cask: true,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "d8",
        "D8 ships with the Android SDK build-tools",
        ToolPkg {
            winget: Some("Google.AndroidStudio"),
            brew: None,
            brew_cask: true,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "dotnet",
        ".NET 9 SDK (Microsoft)",
        ToolPkg {
            winget: Some("Microsoft.DotNet.SDK.9"),
            brew: Some("dotnet-sdk"),
            brew_cask: false,
            apt: Some("dotnet-sdk-9.0"),
            dnf: Some("dotnet-sdk-9.0"),
            pacman: Some("dotnet-sdk"),
            apk: Some("dotnet9-sdk"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "php",
        "PHP CLI interpreter",
        ToolPkg {
            winget: Some("PHP.PHP"),
            brew: Some("php"),
            brew_cask: false,
            apt: Some("php-cli"),
            dnf: Some("php-cli"),
            pacman: Some("php"),
            apk: Some("php"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "composer",
        "Composer: PHP package manager",
        ToolPkg {
            winget: Some("ComposerSetup.Composer"),
            brew: Some("composer"),
            brew_cask: false,
            apt: Some("composer"),
            dnf: Some("composer"),
            pacman: Some("composer"),
            apk: Some("composer"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "erl",
        "Erlang / OTP",
        ToolPkg {
            winget: Some("Erlang.Erlang"),
            brew: Some("erlang"),
            brew_cask: false,
            apt: Some("erlang"),
            dnf: Some("erlang"),
            pacman: Some("erlang"),
            apk: Some("erlang"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "elixir",
        "Elixir language",
        ToolPkg {
            winget: Some("Elixir.Elixir"),
            brew: Some("elixir"),
            brew_cask: false,
            apt: Some("elixir"),
            dnf: Some("elixir"),
            pacman: Some("elixir"),
            apk: Some("elixir"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "ruby",
        "Ruby MRI",
        ToolPkg {
            winget: Some("RubyInstallerTeam.Ruby.3.3"),
            brew: Some("ruby"),
            brew_cask: false,
            apt: Some("ruby-full"),
            dnf: Some("ruby"),
            pacman: Some("ruby"),
            apk: Some("ruby"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "mrbc",
        "mruby compiler (build mruby from source)",
        ToolPkg {
            winget: None,
            brew: Some("mruby"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: Some("mruby"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "lua",
        "Lua 5.4",
        ToolPkg {
            winget: Some("DEVCOM.Lua"),
            brew: Some("lua"),
            brew_cask: false,
            apt: Some("lua5.4"),
            dnf: Some("lua"),
            pacman: Some("lua"),
            apk: Some("lua5.4"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "luajit",
        "LuaJIT 2.1",
        ToolPkg {
            winget: None,
            brew: Some("luajit"),
            brew_cask: false,
            apt: Some("luajit"),
            dnf: Some("luajit"),
            pacman: Some("luajit"),
            apk: Some("luajit"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "luau",
        "Roblox Luau interpreter",
        ToolPkg {
            winget: None,
            brew: Some("luau"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "python",
        "CPython 3.13",
        ToolPkg {
            winget: Some("Python.Python.3.13"),
            brew: Some("python@3.13"),
            brew_cask: false,
            apt: Some("python3"),
            dnf: Some("python3"),
            pacman: Some("python"),
            apk: Some("python3"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "python2",
        "CPython 2.7 (legacy, EOL)",
        ToolPkg {
            winget: Some("Python.Python.2"),
            brew: None,
            brew_cask: false,
            apt: Some("python2"),
            dnf: Some("python2"),
            pacman: Some("python2"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "pypy3",
        "PyPy3 alternative interpreter",
        ToolPkg {
            winget: None,
            brew: Some("pypy3"),
            brew_cask: false,
            apt: Some("pypy3"),
            dnf: Some("pypy3"),
            pacman: Some("pypy3"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "uv",
        "Python package and project manager (Astral)",
        ToolPkg {
            winget: Some("astral-sh.uv"),
            brew: Some("uv"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: Some("uv"),
            apk: None,
            cargo: Some("uv"),
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "docker",
        "container runtime",
        ToolPkg {
            winget: Some("Docker.DockerDesktop"),
            brew: None,
            brew_cask: true,
            apt: Some("docker.io"),
            dnf: Some("docker"),
            pacman: Some("docker"),
            apk: Some("docker"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "mksquashfs",
        "build squashfs images",
        ToolPkg {
            winget: None,
            brew: Some("squashfs"),
            brew_cask: false,
            apt: Some("squashfs-tools"),
            dnf: Some("squashfs-tools"),
            pacman: Some("squashfs-tools"),
            apk: Some("squashfs-tools"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "mke2fs",
        "build ext2/3/4 images (e2fsprogs)",
        ToolPkg {
            winget: None,
            brew: Some("e2fsprogs"),
            brew_cask: false,
            apt: Some("e2fsprogs"),
            dnf: Some("e2fsprogs"),
            pacman: Some("e2fsprogs"),
            apk: Some("e2fsprogs"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "mkcramfs",
        "build cramfs images",
        ToolPkg {
            winget: None,
            brew: None,
            brew_cask: false,
            apt: Some("cramfs-tools"),
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "makeappx",
        "MakeAppx ships in Windows SDK",
        ToolPkg {
            winget: Some("Microsoft.WindowsSDK.10.0.22621"),
            brew: None,
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "wix",
        "WiX Toolset for MSI authoring",
        ToolPkg {
            winget: Some("WiXToolset.WiX"),
            brew: None,
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "makensis",
        "NSIS installer compiler",
        ToolPkg {
            winget: Some("NSIS.NSIS"),
            brew: Some("nsis"),
            brew_cask: false,
            apt: Some("nsis"),
            dnf: Some("mingw32-nsis"),
            pacman: Some("nsis"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "swift",
        "Swift toolchain (Xcode CLT on macOS)",
        ToolPkg {
            winget: Some("Swift.Toolchain"),
            brew: Some("swift"),
            brew_cask: false,
            apt: Some("swiftlang"),
            dnf: None,
            pacman: Some("swift-bin"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "apktool",
        "APK reverse-engineering wrapper",
        ToolPkg {
            winget: Some("iBotPeaches.Apktool"),
            brew: Some("apktool"),
            brew_cask: false,
            apt: Some("apktool"),
            dnf: None,
            pacman: Some("apktool"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "ipatool",
        "iOS .ipa download tool",
        ToolPkg {
            winget: None,
            brew: Some("ipatool"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        &mut m,
        "bat",
        "self-test target: cat clone, reversible cargo install",
        ToolPkg {
            winget: Some("sharkdp.bat"),
            brew: Some("bat"),
            brew_cask: false,
            apt: Some("bat"),
            dnf: Some("bat"),
            pacman: Some("bat"),
            apk: Some("bat"),
            cargo: Some("bat"),
            pip: None,
        },
    );
    m
}

struct ToolPkg {
    winget: Option<&'static str>,
    brew: Option<&'static str>,
    brew_cask: bool,
    apt: Option<&'static str>,
    dnf: Option<&'static str>,
    pacman: Option<&'static str>,
    apk: Option<&'static str>,
    cargo: Option<&'static str>,
    pip: Option<&'static str>,
}

fn add_simple_pkg(
    m: &mut BTreeMap<&'static str, InstallSpec>,
    key: &'static str,
    note: &'static str,
    pkg: ToolPkg,
) {
    let mut per: BTreeMap<Platform, InstallAction> = BTreeMap::new();
    if let Some(id) = pkg.winget {
        per.insert(
            Platform::Windows,
            InstallAction {
                cmd: "winget",
                args: vec![
                    "install",
                    "--id",
                    id,
                    "--silent",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                    "--disable-interactivity",
                ],
                requires_admin: false,
            },
        );
    }
    if let Some(pkgname) = pkg.brew {
        let args: Vec<&'static str> = if pkg.brew_cask {
            vec!["install", "--cask", pkgname]
        } else {
            vec!["install", pkgname]
        };
        per.insert(
            Platform::MacOs,
            InstallAction {
                cmd: "brew",
                args,
                requires_admin: false,
            },
        );
    }
    if let Some(pkgname) = pkg.apt {
        per.insert(
            Platform::LinuxApt,
            InstallAction {
                cmd: "apt-get",
                args: vec!["install", "-y", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.dnf {
        per.insert(
            Platform::LinuxDnf,
            InstallAction {
                cmd: "dnf",
                args: vec!["install", "-y", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.pacman {
        per.insert(
            Platform::LinuxPacman,
            InstallAction {
                cmd: "pacman",
                args: vec!["-S", "--noconfirm", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.apk {
        per.insert(
            Platform::LinuxApk,
            InstallAction {
                cmd: "apk",
                args: vec!["add", "--no-cache", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.cargo {
        for plat in [
            Platform::Windows,
            Platform::MacOs,
            Platform::LinuxApt,
            Platform::LinuxDnf,
            Platform::LinuxPacman,
            Platform::LinuxApk,
            Platform::LinuxUnknown,
        ] {
            per.entry(plat).or_insert_with(|| InstallAction {
                cmd: "cargo",
                args: vec!["install", pkgname],
                requires_admin: false,
            });
        }
    }
    if let Some(pkgname) = pkg.pip {
        for plat in [
            Platform::Windows,
            Platform::MacOs,
            Platform::LinuxApt,
            Platform::LinuxDnf,
            Platform::LinuxPacman,
            Platform::LinuxApk,
            Platform::LinuxUnknown,
        ] {
            per.entry(plat).or_insert_with(|| InstallAction {
                cmd: "pip",
                args: vec!["install", "--user", pkgname],
                requires_admin: false,
            });
        }
    }
    m.insert(
        key,
        InstallSpec {
            per_platform: per,
            note: Some(note),
        },
    );
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn map_has_minimum_coverage() {
        let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
        assert!(m.len() >= 30, "expected >= 30 tools, got {}", m.len());
        for key in [
            "ghidra", "rizin", "upx", "java", "kotlinc", "dotnet", "php", "ruby", "lua", "luajit",
            "python", "uv", "docker", "swift", "apktool",
        ] {
            assert!(m.contains_key(key), "missing tool key: {key}");
        }
    }

    #[test]
    fn upx_resolves_on_all_platforms() {
        let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
        let spec: &InstallSpec = m.get("upx").expect("upx");
        for plat in [
            Platform::Windows,
            Platform::MacOs,
            Platform::LinuxApt,
            Platform::LinuxDnf,
            Platform::LinuxPacman,
            Platform::LinuxApk,
        ] {
            assert!(
                spec.per_platform.contains_key(&plat),
                "upx missing platform {}",
                plat.as_str()
            );
        }
    }

    #[test]
    fn alias_python_canonicalizes() {
        assert_eq!(canonicalize_alias("py"), "python");
        assert_eq!(canonicalize_alias("py3"), "python");
        assert_eq!(canonicalize_alias("ProGuard"), "proguard");
        assert_eq!(canonicalize_alias("ghidra-headless"), "ghidra");
    }

    #[test]
    fn unknown_tool_passes_through() {
        assert_eq!(canonicalize_alias("nonsense-tool"), "nonsense-tool");
    }

    #[test]
    fn dry_run_does_not_execute() {
        let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
        let spec: &InstallSpec = m.get("bat").expect("bat");
        let r: InstallReport = perform_install("bat", spec, Platform::Windows, true, true);
        assert_eq!(r.status, "dry-run");
        assert!(r.action_cmd.is_some());
    }

    #[test]
    fn unsupported_platform_reported() {
        let mut per: BTreeMap<Platform, InstallAction> = BTreeMap::new();
        per.insert(
            Platform::Windows,
            InstallAction {
                cmd: "echo",
                args: vec!["ok"],
                requires_admin: false,
            },
        );
        let spec: InstallSpec = InstallSpec {
            per_platform: per,
            note: None,
        };
        let r: InstallReport = perform_install("x", &spec, Platform::MacOs, true, true);
        assert_eq!(r.status, "unsupported-platform");
    }

    #[test]
    fn tail_respects_char_boundaries() {
        let s: String = "hÃ©llo, world! ä½ å¥½".repeat(50);
        let t: String = tail(&s, 50);
        assert!(t.len() <= 50);
    }
}
