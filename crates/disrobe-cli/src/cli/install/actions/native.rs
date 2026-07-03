use std::collections::BTreeMap;

use super::super::InstallSpec;
use super::{ToolPkg, add_simple_pkg};

pub(super) fn add_native_and_runtime_pkgs(m: &mut BTreeMap<&'static str, InstallSpec>) {
    add_simple_pkg(
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
        "llvm",
        "provides llvm-objdump & llvm-mc",
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
        "proguard",
        "ProGuard: Java / Android shrinker & obfuscator",
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
}
