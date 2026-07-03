from __future__ import annotations

import shutil
import subprocess
from typing import Callable

from binaryninja import BinaryView, PluginCommand, log_error, log_info, log_warn


DISROBE_BINARY: str = "disrobe"


def _resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def _input_path(bv: BinaryView) -> str | None:
    original: str | None = bv.file.original_filename
    if original:
        return original
    fallback: str | None = bv.file.filename
    return fallback if fallback else None


def _run_disrobe(subcommand: str, path: str) -> None:
    exe: str = _resolve_binary()
    args: list[str] = [exe, subcommand, path]
    result: subprocess.CompletedProcess[str] = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=300,
    )
    log_info(f"[disrobe] $ {' '.join(args)}")
    if result.stdout:
        log_info(result.stdout)
    if result.stderr:
        log_warn(result.stderr)
    if result.returncode != 0:
        log_error(f"disrobe {subcommand} exited {result.returncode}")


def _make_action(subcommand: str) -> Callable[[BinaryView], None]:
    def _action(bv: BinaryView) -> None:
        path: str | None = _input_path(bv)
        if path is None:
            log_warn("disrobe: no input file path available from this BinaryView")
            return
        _run_disrobe(subcommand, path)

    return _action


PluginCommand.register(
    "disrobe \\ Auto: run full deobfuscation pipeline",
    "Auto: run full deobfuscation pipeline",
    _make_action("auto"),
)

PluginCommand.register(
    "disrobe \\ Detect: identify obfuscator / packer",
    "Detect: identify obfuscator / packer",
    _make_action("detect"),
)

PluginCommand.register(
    "disrobe \\ Strings: extract and deobfuscate strings",
    "Strings: extract and deobfuscate strings",
    _make_action("strings"),
)

PluginCommand.register(
    "disrobe \\ IOC: extract indicators of compromise",
    "IOC: extract indicators of compromise",
    _make_action("ioc"),
)

PluginCommand.register(
    "disrobe \\ Behavior: summarize binary capabilities (MITRE)",
    "Behavior: summarize binary capabilities (MITRE)",
    _make_action("behavior"),
)

PluginCommand.register(
    "disrobe \\ Identify: compiler / packer / protector fingerprint",
    "Identify: compiler / packer / protector fingerprint",
    _make_action("identify"),
)

PluginCommand.register(
    "disrobe \\ Scan: leak credentials scanner",
    "Scan: leak credentials scanner",
    _make_action("scan"),
)


log_info("[disrobe] plugin loaded")


# Supported ecosystems (derived from disrobe catalog):
# Python pyc
# PyArmor
# PyInstaller
# Nuitka
# Python pickle
# JavaScript
# WebAssembly
# .NET / CIL
# JVM classfile
# Android DEX
# Go
# Lua
# PHP
# Ruby YARV
# BEAM
# Swift / Obj-C
# ActionScript 3
# Hermes
# Flutter
# Shell / PowerShell
# Native PE/ELF/Mach-O
# Nim / Zig / Crystal
# Containers
