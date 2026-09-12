use std::collections::BTreeMap;

use super::super::InstallSpec;
use super::{ToolPkg, add_simple_pkg};

pub(super) fn add_lang_and_packaging_pkgs(m: &mut BTreeMap<&'static str, InstallSpec>) {
    add_simple_pkg(
        m,
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
        m,
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
        m,
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
        m,
        "uv",
        "Python package & project manager (Astral)",
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
        m,
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
    add_simple_pkg(
        m,
        "7z",
        "7-Zip archiver; Homebrew installs the `7zz` binary",
        ToolPkg {
            winget: Some("7zip.7zip"),
            brew: Some("sevenzip"),
            brew_cask: false,
            apt: Some("p7zip-full"),
            dnf: Some("p7zip"),
            pacman: Some("p7zip"),
            apk: Some("p7zip"),
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        m,
        "unrar",
        "RARLab unrar; Debian and Ubuntu carry it in a non-free component",
        ToolPkg {
            winget: None,
            brew: None,
            brew_cask: false,
            apt: Some("unrar"),
            dnf: None,
            pacman: Some("unrar"),
            apk: None,
            cargo: None,
            pip: None,
        },
    );
    add_simple_pkg(
        m,
        "wasmtime",
        "WebAssembly runtime from the Bytecode Alliance",
        ToolPkg {
            winget: Some("BytecodeAlliance.Wasmtime"),
            brew: Some("wasmtime"),
            brew_cask: false,
            apt: None,
            dnf: None,
            pacman: None,
            apk: None,
            cargo: Some("wasmtime-cli"),
            pip: None,
        },
    );
    add_simple_pkg(
        m,
        "wat2wasm",
        "part of the WABT WebAssembly Binary Toolkit",
        ToolPkg {
            winget: None,
            brew: Some("wabt"),
            brew_cask: false,
            apt: Some("wabt"),
            dnf: None,
            pacman: None,
            apk: None,
            cargo: None,
            pip: None,
        },
    );
}
