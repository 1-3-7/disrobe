use super::super::install::Platform;
use super::{ToolEntry, ToolKind};

pub(crate) fn tool_catalog() -> Vec<ToolEntry> {
    tool_catalog_for_platform(Platform::detect())
}

#[cfg(test)]
pub(crate) fn tool_catalog_all_platforms() -> Vec<ToolEntry> {
    let mut v: Vec<ToolEntry> = Vec::with_capacity(64);
    v.extend(tool_catalog_for_platform(Platform::Windows));
    v.extend(tool_catalog_for_platform(Platform::MacOs));
    v.extend(tool_catalog_for_platform(Platform::LinuxApt));
    v
}

pub(crate) fn tool_catalog_for_platform(platform: Platform) -> Vec<ToolEntry> {
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
    if matches!(platform, Platform::Windows) {
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
    if matches!(platform, Platform::MacOs) {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod published_roster_tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::tool_catalog;
    use crate::cli::doctor::exceptions::DOCTOR_ROSTER_CANARY_KEY;
    use crate::cli::doctor::{ToolEntry, ToolKind, ToolStatus, probe_entry};

    const BASE_TOOLS: usize = 46;
    const WINDOWS_ONLY_TOOLS: usize = 2;
    const MACOS_ONLY_TOOLS: usize = 5;

    const README: &str = "README.md";
    const README_PHRASE: &str = "probe 46 to 51 external tools depending on the platform";
    const INSTALLATION_GUIDE: &str = "docs/src/installation.md";
    const CLI_REFERENCE: &str = "docs/src/cli/reference.md";
    const CLI_REFERENCE_PHRASE: &str =
        "Probe 46 to 51 optional external tools depending on the platform";

    fn expected_tools() -> usize {
        let mut total: usize = BASE_TOOLS;
        if cfg!(target_os = "windows") {
            total = total.saturating_add(WINDOWS_ONLY_TOOLS);
        }
        if cfg!(target_os = "macos") {
            total = total.saturating_add(MACOS_ONLY_TOOLS);
        }
        total
    }

    fn repo_root() -> PathBuf {
        let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
            panic!(
                "the doctor roster figure is published in {README}, two directories above this crate"
            )
        };
        root.to_path_buf()
    }

    #[test]
    fn the_probed_roster_is_the_size_the_readme_publishes_for_this_platform() {
        let catalog: Vec<ToolEntry> = tool_catalog();
        assert_eq!(
            catalog.len(),
            expected_tools(),
            "the doctor catalog probes {} tools on this platform against the {} the published \
             split states; the roster is {BASE_TOOLS} everywhere plus {WINDOWS_ONLY_TOOLS} on \
             Windows and {MACOS_ONLY_TOOLS} on macOS, so a single number cannot describe it and \
             each leg is pinned by equality",
            catalog.len(),
            expected_tools()
        );

        let keys: BTreeSet<&str> = catalog.iter().map(|entry: &ToolEntry| entry.key).collect();
        assert_eq!(
            keys.len(),
            catalog.len(),
            "two catalog entries share a key, so `disrobe doctor` reports fewer distinct tools than \
             the published count claims"
        );

        let path: PathBuf = repo_root().join(README);
        let doc: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{README} publishes the doctor roster size: {error} at {}",
                path.display()
            )
        });
        assert!(
            doc.contains(README_PHRASE),
            "{README} must state `{README_PHRASE}`; the catalog probes {BASE_TOOLS} tools on Linux, \
             {} on Windows and {} on macOS, so an approximate figure leaves the number a reader is \
             given bound to nothing",
            BASE_TOOLS + WINDOWS_ONLY_TOOLS,
            BASE_TOOLS + MACOS_ONLY_TOOLS
        );
    }

    fn read_doc(relative_path: &str) -> String {
        let path: PathBuf = repo_root().join(relative_path);
        fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{relative_path} publishes the doctor roster size: {error} at {}",
                path.display()
            )
        })
    }

    #[test]
    fn the_installation_guide_and_the_cli_reference_publish_the_same_roster_size() {
        let installation_guide: String = read_doc(INSTALLATION_GUIDE);
        assert!(
            installation_guide.contains(README_PHRASE),
            "{INSTALLATION_GUIDE} must state `{README_PHRASE}`, matching {README}, so the doctor \
             roster size is published once and cannot drift between the two pages a reader sees"
        );

        let cli_reference: String = read_doc(CLI_REFERENCE);
        assert!(
            cli_reference.contains(CLI_REFERENCE_PHRASE),
            "{CLI_REFERENCE} must state `{CLI_REFERENCE_PHRASE}` in the doctor row, matching the \
             roster size published in {README} and {INSTALLATION_GUIDE}"
        );
    }

    #[test]
    fn every_catalog_entry_is_probed_and_answers_for_itself() {
        let catalog: Vec<ToolEntry> = tool_catalog();
        let mut answered: BTreeSet<String> = BTreeSet::new();

        for entry in &catalog {
            assert!(
                !entry.probe_names.is_empty(),
                "`{}` is counted in the published roster but names no executable to probe, so it \
                 can never be found",
                entry.key
            );
            assert!(
                !entry.version_args.is_empty(),
                "`{}` names no version arguments, so a present tool would report no version",
                entry.key
            );
            assert!(
                !entry.used_by.trim().is_empty(),
                "`{}` states no pass that uses it, so a reader cannot tell why it is probed",
                entry.key
            );

            let status: ToolStatus = probe_entry(entry);
            assert_eq!(
                status.name, entry.key,
                "probing `{}` returned a status named `{}`, so the row a reader sees is attributed \
                 to a different tool",
                entry.key, status.name
            );
            assert_eq!(
                status.used_by, entry.used_by,
                "probing `{}` lost the passes it is used by",
                entry.key
            );
            if status.available {
                assert!(
                    status.path.is_some(),
                    "`{}` is reported available with no path, so nothing says what was found",
                    entry.key
                );
            } else {
                assert!(
                    status.install_hint.is_some(),
                    "`{}` is reported missing with no install hint, so the row tells a reader \
                     nothing they can act on",
                    entry.key
                );
            }
            answered.insert(status.name);
        }

        assert_eq!(
            answered.len(),
            expected_tools(),
            "the probe answered for {} tools against the {} this platform declares, so a tool that \
             stopped being probed could be replaced by one that started and the count would not \
             move",
            answered.len(),
            expected_tools()
        );
    }

    #[test]
    fn a_tool_that_cannot_be_found_is_reported_missing_rather_than_present() {
        let absent: ToolEntry = ToolEntry {
            key: DOCTOR_ROSTER_CANARY_KEY,
            probe_names: &["disrobe-tool-that-is-not-installed-anywhere"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "the control that proves an absent tool is reported absent",
            version_args: &["--version"],
        };
        let status: ToolStatus = probe_entry(&absent);
        assert!(
            !status.available,
            "the probe reported a tool that does not exist as available, so every availability \
             answer above would be worthless"
        );
        assert!(status.path.is_none(), "an absent tool must carry no path");
        assert!(
            status.install_hint.is_some(),
            "an absent tool must carry an install hint"
        );
    }
}
