#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Serialize;

use super::install::{self, InstallSpec, Platform};
use super::output::{OutputFormat, emit};

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
            let Some(spec) = install_map.get(canonical) else {
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

pub(crate) fn tool_catalog() -> Vec<ToolEntry> {
    let mut v: Vec<ToolEntry> = Vec::with_capacity(64);
    v.push(ToolEntry {
        key: "python",
        probe_names: &["python3", "python"],
        env_overrides: &[],
        kind: ToolKind::Required,
        used_by: "pyarmor (dyn-hook), py decompile, pyinstaller",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "ghidra",
        probe_names: &["ghidra-headless", "analyzeHeadless"],
        env_overrides: &["DISROBE_GHIDRA", "DISROBE_BACKEND_GHIDRA"],
        kind: ToolKind::RecommendedNative,
        used_by: "native pass headless decompile",
        version_args: &["-help"],
    });
    v.push(ToolEntry {
        key: "rizin",
        probe_names: &["rizin", "rz"],
        env_overrides: &["DISROBE_BACKEND_RIZIN"],
        kind: ToolKind::RecommendedNative,
        used_by: "native pass disasm/lift fallback",
        version_args: &["-v"],
    });
    v.push(ToolEntry {
        key: "binaryninja",
        probe_names: &["binaryninja", "bn"],
        env_overrides: &["DISROBE_BACKEND_BINJA"],
        kind: ToolKind::Optional,
        used_by: "native pass (commercial)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "ida",
        probe_names: &["ida", "ida64", "ida-pro"],
        env_overrides: &["DISROBE_BACKEND_IDA"],
        kind: ToolKind::Optional,
        used_by: "native pass (commercial)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "angr",
        probe_names: &["angr"],
        env_overrides: &["DISROBE_BACKEND_ANGR"],
        kind: ToolKind::Optional,
        used_by: "native pass symbolic execution",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "retdec",
        probe_names: &["retdec-decompiler", "retdec-decompiler.py"],
        env_overrides: &["DISROBE_BACKEND_RETDEC"],
        kind: ToolKind::Optional,
        used_by: "native pass open-source decompile",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "llvm-objdump",
        probe_names: &["llvm-objdump"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "native pass disasm + IR lift",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "llvm-mc",
        probe_names: &["llvm-mc"],
        env_overrides: &["DISROBE_BACKEND_LLVM_IR"],
        kind: ToolKind::Optional,
        used_by: "native pass IR backend",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "upx",
        probe_names: &["upx"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "native packers: UPX",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "mpress",
        probe_names: &["mpress"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "native packers: MPRESS (manual install)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "kkrunchy",
        probe_names: &["kkrunchy", "kkrunchy_k7"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "native packers: kkrunchy (manual install)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "java",
        probe_names: &["java"],
        env_overrides: &["JAVA_HOME"],
        kind: ToolKind::Optional,
        used_by: "jvm pass runtime + ProGuard/R8",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "javac",
        probe_names: &["javac"],
        env_overrides: &["JAVA_HOME"],
        kind: ToolKind::Optional,
        used_by: "jvm pass round-trip recompile",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "kotlinc",
        probe_names: &["kotlinc"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "jvm pass Kotlin support",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "proguard",
        probe_names: &["proguard", "proguard.sh"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "jvm pass ProGuard mapping",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "r8",
        probe_names: &["r8"],
        env_overrides: &["ANDROID_HOME"],
        kind: ToolKind::Optional,
        used_by: "jvm pass R8 mapping (Android)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "d8",
        probe_names: &["d8"],
        env_overrides: &["ANDROID_HOME"],
        kind: ToolKind::Optional,
        used_by: "jvm pass D8 dex (Android)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "dotnet",
        probe_names: &["dotnet"],
        env_overrides: &["DOTNET_ROOT"],
        kind: ToolKind::Optional,
        used_by: ".net pass runtime + ILSpy/de4dot",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "ilspycmd",
        probe_names: &["ilspycmd", "ilspy"],
        env_overrides: &["DISROBE_EXTERNAL_ILSPY"],
        kind: ToolKind::Optional,
        used_by: ".net pass decompile (ILSpy)",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "de4dot",
        probe_names: &["de4dot", "de4dot.exe"],
        env_overrides: &["DISROBE_EXTERNAL_DE4DOT"],
        kind: ToolKind::Optional,
        used_by: ".net pass deobfuscator",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "php",
        probe_names: &["php"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "php pass interpreter",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "composer",
        probe_names: &["composer", "composer.phar"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "php pass dependency walk",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "erl",
        probe_names: &["erl"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "beam pass Erlang OTP",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "elixir",
        probe_names: &["elixir"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "beam pass Elixir Dbgi",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "ruby",
        probe_names: &["ruby"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "ruby pass YARV runtime",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "mrbc",
        probe_names: &["mrbc"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "ruby pass mruby compiler",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "lua",
        probe_names: &["lua", "lua5.4", "lua5.3", "lua5.1"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "lua pass interpreter",
        version_args: &["-v"],
    });
    v.push(ToolEntry {
        key: "luajit",
        probe_names: &["luajit"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "lua pass LuaJIT 2.x",
        version_args: &["-v"],
    });
    v.push(ToolEntry {
        key: "luau",
        probe_names: &["luau"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "lua pass Roblox Luau",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "pypy3",
        probe_names: &["pypy3"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "py pass alt-runtime PyPy",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "uv",
        probe_names: &["uv"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "py pass venv + dep mgmt",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "docker",
        probe_names: &["docker"],
        env_overrides: &["DOCKER_HOST"],
        kind: ToolKind::Optional,
        used_by: "containers pass docker images",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "mksquashfs",
        probe_names: &["mksquashfs"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "containers pass squashfs",
        version_args: &["-version"],
    });
    v.push(ToolEntry {
        key: "mke2fs",
        probe_names: &["mke2fs"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "containers pass ext2/3/4",
        version_args: &["-V"],
    });
    v.push(ToolEntry {
        key: "mkcramfs",
        probe_names: &["mkcramfs"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "containers pass cramfs",
        version_args: &["-V"],
    });
    if cfg!(target_os = "windows") {
        v.push(ToolEntry {
            key: "makeappx",
            probe_names: &["MakeAppx", "MakeAppx.exe", "makeappx"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "containers pass MSIX/APPX (Windows SDK)",
            version_args: &["/?"],
        });
        v.push(ToolEntry {
            key: "wix",
            probe_names: &["wix", "candle", "light"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "containers pass MSI/WiX (Windows)",
            version_args: &["--version"],
        });
    }
    v.push(ToolEntry {
        key: "makensis",
        probe_names: &["makensis"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "containers pass NSIS",
        version_args: &["/VERSION"],
    });
    if cfg!(target_os = "macos") {
        v.push(ToolEntry {
            key: "swift",
            probe_names: &["swift"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "swift-objc pass",
            version_args: &["--version"],
        });
        v.push(ToolEntry {
            key: "swiftc",
            probe_names: &["swiftc"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "swift-objc pass round-trip",
            version_args: &["--version"],
        });
        v.push(ToolEntry {
            key: "otool",
            probe_names: &["otool"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "swift-objc pass Mach-O inspect",
            version_args: &["--version"],
        });
        v.push(ToolEntry {
            key: "lipo",
            probe_names: &["lipo"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "swift-objc pass fat-binary split",
            version_args: &["-version"],
        });
        v.push(ToolEntry {
            key: "codesign",
            probe_names: &["codesign"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "swift-objc pass signature inspect",
            version_args: &["--version"],
        });
    }
    v.push(ToolEntry {
        key: "apktool",
        probe_names: &["apktool"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "mobile pass APK reverse",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "ipatool",
        probe_names: &["ipatool"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "mobile pass iOS .ipa",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "node",
        probe_names: &["node"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "js pass + v8 bytenode",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "npm",
        probe_names: &["npm"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "js pass dependency walk",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "wasmtime",
        probe_names: &["wasmtime"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "wasm pass sandbox runtime",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "wat2wasm",
        probe_names: &["wat2wasm"],
        env_overrides: &[],
        kind: ToolKind::Optional,
        used_by: "wasm pass round-trip",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "7z",
        probe_names: &["7z", "7zz", "7za"],
        env_overrides: &["DISROBE_EXTERNAL_7Z"],
        kind: ToolKind::Optional,
        used_by: "containers pass 7z archives",
        version_args: &["--help"],
    });
    v.push(ToolEntry {
        key: "unrar",
        probe_names: &["unrar"],
        env_overrides: &["DISROBE_EXTERNAL_UNRAR"],
        kind: ToolKind::Optional,
        used_by: "containers pass rar archives",
        version_args: &["--version"],
    });
    v.push(ToolEntry {
        key: "bsdtar",
        probe_names: &["bsdtar", "tar"],
        env_overrides: &["DISROBE_EXTERNAL_BSDTAR"],
        kind: ToolKind::Optional,
        used_by: "containers pass tar variants",
        version_args: &["--version"],
    });
    v
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
                for probe in entry.probe_names {
                    let candidate: PathBuf = p.join(probe);
                    if candidate.is_file() {
                        let version: Option<String> =
                            probe_version_at(&candidate, entry.version_args);
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

fn which_on_path(name: &str) -> Option<String> {
    let path_env: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
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
    };
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
    let out: std::process::Output = child.wait_with_output_timeout(Duration::from_secs(3))?;
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

trait ChildExt {
    fn wait_with_output_timeout(self, timeout: Duration) -> Option<std::process::Output>;
}

impl ChildExt for std::process::Child {
    fn wait_with_output_timeout(mut self, timeout: Duration) -> Option<std::process::Output> {
        use std::time::Instant;
        let deadline: Instant = Instant::now() + timeout;
        loop {
            match self.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _: Result<(), std::io::Error> = self.kill();
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return None,
            }
        }
        self.wait_with_output().ok()
    }
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
