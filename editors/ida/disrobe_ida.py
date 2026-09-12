from __future__ import annotations

import subprocess
import shutil
import idaapi
import ida_kernwin


DISROBE_BINARY: str = "disrobe"


def _resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def _run_disrobe(subcommand: str, path: str) -> None:
    exe: str = _resolve_binary()
    args: list[str]
    if subcommand == "auto":
        args = [exe, "auto", path]
    else:
        args = [exe, subcommand, path]
    result: subprocess.CompletedProcess[str] = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=300,
    )
    output: str = result.stdout + result.stderr
    ida_kernwin.msg(f"[disrobe] $ {' '.join(args)}\n{output}\n")
    if result.returncode != 0:
        ida_kernwin.warning(f"disrobe {subcommand} exited {result.returncode}")


class DisrobeAction(ida_kernwin.action_handler_t):
    def __init__(self, subcommand: str) -> None:
        super().__init__()
        self._subcommand: str = subcommand

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        path: str = idaapi.get_input_file_path()
        if not path:
            ida_kernwin.warning("disrobe: no input file open")
            return 0
        _run_disrobe(self._subcommand, path)
        return 1

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class DisrobePlugin(idaapi.plugin_t):
    flags: int = idaapi.PLUGIN_KEEP
    comment: str = "disrobe: deobfuscate, decompile, and unpack via the disrobe CLI"
    help: str = ""
    wanted_name: str = "disrobe"
    wanted_hotkey: str = ""

    def init(self) -> int:
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:auto",
            "Auto: run full deobfuscation pipeline",
            DisrobeAction("auto"),
            "Alt-Shift-A",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Auto: run full deobfuscation pipeline", "disrobe:auto", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:detect",
            "Detect: identify obfuscator / packer",
            DisrobeAction("detect"),
            "Alt-Shift-D",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Detect: identify obfuscator / packer", "disrobe:detect", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:strings",
            "Strings: extract and deobfuscate strings",
            DisrobeAction("strings"),
            "Alt-Shift-S",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Strings: extract and deobfuscate strings", "disrobe:strings", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:ioc",
            "IOC: extract indicators of compromise",
            DisrobeAction("ioc"),
            "Alt-Shift-I",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/IOC: extract indicators of compromise", "disrobe:ioc", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:behavior",
            "Behavior: summarize binary capabilities (MITRE)",
            DisrobeAction("behavior"),
            "Alt-Shift-B",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Behavior: summarize binary capabilities (MITRE)", "disrobe:behavior", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:identify",
            "Identify: compiler / packer / protector fingerprint",
            DisrobeAction("identify"),
            "Alt-Shift-F",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Identify: compiler / packer / protector fingerprint", "disrobe:identify", 0)

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "disrobe:scan",
            "Scan: leak credentials scanner",
            DisrobeAction("scan"),
            "Alt-Shift-C",
        ))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/disrobe/Scan: leak credentials scanner", "disrobe:scan", 0)
        ida_kernwin.msg("[disrobe] plugin loaded\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        pass

    def term(self) -> None:
        ida_kernwin.unregister_action("disrobe:auto")
        ida_kernwin.unregister_action("disrobe:detect")
        ida_kernwin.unregister_action("disrobe:strings")
        ida_kernwin.unregister_action("disrobe:ioc")
        ida_kernwin.unregister_action("disrobe:behavior")
        ida_kernwin.unregister_action("disrobe:identify")
        ida_kernwin.unregister_action("disrobe:scan")


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return DisrobePlugin()


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
