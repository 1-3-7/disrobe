"""disrobe for IDA Pro.

Surfaces disrobe's recovery inside IDA. Either runs the disrobe CLI on the open
database's input file (`disrobe native symbols <input> --json`, `capabilities`,
`strings`, or ingests a previously saved disrobe `--json` report) and applies the
recovery to the IDB: recovered function names at their addresses (set_name /
add_func), capability and IOC findings as comments (set_cmt / set_func_cmt),
recovered strings, and recovered structs (add_struc) where a report carries them.

Install: copy this directory into your IDA `plugins/` folder (the file
`disrobe_ida.py` is the loadable plugin). It registers actions under
`Edit > disrobe` and `Edit > Plugins`:

    disrobe: apply native symbols   (runs `disrobe native symbols`)
    disrobe: apply capabilities     (runs `disrobe capabilities`)
    disrobe: apply strings          (runs `disrobe strings`)
    disrobe: load saved --json report

Requires the `disrobe` binary on PATH (or edit DISROBE_BINARY below). The
parse/map core lives in `disrobe_report.py` and is unit-tested headless against
real disrobe reports; the in-IDA application path is exercised when loaded inside
IDA.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol

from disrobe_report import Annotations, parse_report, rebase

try:
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_name
    import ida_struct
    import idaapi
    import idc

    _IN_IDA: bool = True
except ImportError:
    _IN_IDA = False


DISROBE_BINARY: str = "disrobe"
_CLI_TIMEOUT_SECS: int = 300


@dataclass(frozen=True, slots=True)
class ApplyResult:
    names_applied: int
    funcs_created: int
    comments_applied: int
    strings_seen: int
    structs_created: int
    rebased: bool


class IdaAdapter(Protocol):
    def image_base(self) -> int: ...
    def set_name(self, ea: int, name: str) -> bool: ...
    def ensure_func(self, ea: int) -> bool: ...
    def set_comment(self, ea: int, text: str, repeatable: bool) -> bool: ...
    def add_struct(self, name: str, fields: tuple[tuple[str, int], ...]) -> bool: ...
    def log(self, message: str) -> None: ...


def apply_annotations(ann: Annotations, ida: IdaAdapter) -> ApplyResult:
    ida_base: int = ida.image_base()
    names_applied: int = 0
    funcs_created: int = 0
    comments_applied: int = 0
    structs_created: int = 0
    report_base: int | None = ann.image_base
    rebased: bool = report_base is not None
    for fn in ann.function_names:
        ea: int = rebase(fn.address, report_base if fn.rebase_relative else None, ida_base)
        if fn.is_func and ida.ensure_func(ea):
            funcs_created += 1
        if ida.set_name(ea, fn.name):
            names_applied += 1
    for comment in ann.comments:
        ea = rebase(comment.address, report_base, ida_base)
        if ida.set_comment(ea, comment.text, comment.repeatable):
            comments_applied += 1
    for struct in ann.structs:
        fields: tuple[tuple[str, int], ...] = tuple((f.name, f.size) for f in struct.fields)
        if ida.add_struct(struct.name, fields):
            structs_created += 1
    return ApplyResult(
        names_applied=names_applied,
        funcs_created=funcs_created,
        comments_applied=comments_applied,
        strings_seen=len(ann.strings),
        structs_created=structs_created,
        rebased=rebased,
    )


def render_summary(ann: Annotations, result: ApplyResult) -> str:
    lines: list[str] = [
        f"disrobe report: {ann.schema}",
        f"  source:        {ann.source or '(unknown)'}",
        f"  function names: {result.names_applied} applied ({result.funcs_created} funcs created)",
        f"  comments:      {result.comments_applied} applied",
        f"  strings:       {result.strings_seen} recovered",
        f"  structs:       {result.structs_created} created",
        f"  rebased:       {result.rebased}",
    ]
    if ann.strings:
        lines.append("  recovered strings:")
        for s in ann.strings[:40]:
            lines.append(f"    @{s.offset} [{s.tag}] {s.value!r}")
        if len(ann.strings) > 40:
            lines.append(f"    ... ({len(ann.strings) - 40} more)")
    return "\n".join(lines)


def _resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def run_disrobe_json(args: tuple[str, ...], input_path: str) -> str:
    exe: str = _resolve_binary()
    argv: list[str] = [exe, "--json", *args, input_path]
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=_CLI_TIMEOUT_SECS,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"disrobe {' '.join(args)} exited {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout


if _IN_IDA:

    class _LiveIdaAdapter:
        def image_base(self) -> int:
            return idaapi.get_imagebase()

        def set_name(self, ea: int, name: str) -> bool:
            return bool(ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE))

        def ensure_func(self, ea: int) -> bool:
            if ida_funcs.get_func(ea) is not None:
                return False
            return bool(ida_funcs.add_func(ea))

        def set_comment(self, ea: int, text: str, repeatable: bool) -> bool:
            func = ida_funcs.get_func(ea)
            if func is not None and func.start_ea == ea:
                return bool(ida_funcs.set_func_cmt(func, text, repeatable))
            return bool(idc.set_cmt(ea, text, 1 if repeatable else 0))

        def add_struct(self, name: str, fields: tuple[tuple[str, int], ...]) -> bool:
            tid: int = ida_struct.add_struc(idaapi.BADADDR, name)
            if tid == idaapi.BADADDR:
                tid = ida_struct.get_struc_id(name)
                if tid == idaapi.BADADDR:
                    return False
            sptr = ida_struct.get_struc(tid)
            if sptr is None:
                return False
            offset: int = 0
            for field_name, size in fields:
                flag: int = ida_bytes.byte_flag()
                ida_struct.add_struc_member(sptr, field_name, offset, flag, None, max(size, 1))
                offset += max(size, 1)
            return True

        def log(self, message: str) -> None:
            ida_kernwin.msg(message + "\n")

    def _input_path() -> str | None:
        path: str = idaapi.get_input_file_path()
        return path if path and os.path.exists(path) else None

    def _apply_and_report(args: tuple[str, ...]) -> None:
        path: str | None = _input_path()
        if path is None:
            ida_kernwin.warning("disrobe: cannot resolve the open database's input file path")
            return
        adapter: _LiveIdaAdapter = _LiveIdaAdapter()
        try:
            payload: str = run_disrobe_json(args, path)
            ann: Annotations = parse_report(payload)
        except (RuntimeError, OSError, ValueError) as exc:
            ida_kernwin.warning(f"disrobe {' '.join(args)} failed: {exc}")
            return
        result: ApplyResult = apply_annotations(ann, adapter)
        summary: str = render_summary(ann, result)
        adapter.log(summary)
        ida_kernwin.info(summary)

    def _load_saved_report() -> None:
        chosen: str | None = ida_kernwin.ask_file(False, "*.json", "disrobe --json report")
        if not chosen:
            return
        adapter: _LiveIdaAdapter = _LiveIdaAdapter()
        try:
            with open(chosen, "r", encoding="utf-8") as handle:
                ann: Annotations = parse_report(handle.read())
        except (OSError, ValueError) as exc:
            ida_kernwin.warning(f"disrobe: cannot load report {chosen}: {exc}")
            return
        result: ApplyResult = apply_annotations(ann, adapter)
        summary: str = render_summary(ann, result)
        adapter.log(summary)
        ida_kernwin.info(summary)

    class _ActionHandler(ida_kernwin.action_handler_t):
        def __init__(self, callback) -> None:
            super().__init__()
            self._callback = callback

        def activate(self, ctx) -> int:
            self._callback()
            return 1

        def update(self, ctx) -> int:
            return ida_kernwin.AST_ENABLE_ALWAYS

    _ACTIONS: tuple[tuple[str, str, object], ...] = (
        ("disrobe:symbols", "disrobe: apply native symbols", lambda: _apply_and_report(("native", "symbols"))),
        ("disrobe:capabilities", "disrobe: apply capabilities", lambda: _apply_and_report(("capabilities",))),
        ("disrobe:strings", "disrobe: apply strings", lambda: _apply_and_report(("strings",))),
        ("disrobe:load", "disrobe: load saved --json report", _load_saved_report),
    )

    class DisrobePlugin(idaapi.plugin_t):
        flags: int = idaapi.PLUGIN_KEEP
        comment: str = "Apply disrobe recovery to the database"
        help: str = "Runs the disrobe CLI or ingests a saved --json report and annotates the IDB"
        wanted_name: str = "disrobe"
        wanted_hotkey: str = ""

        def init(self) -> int:
            for action_id, label, callback in _ACTIONS:
                desc = ida_kernwin.action_desc_t(action_id, label, _ActionHandler(callback))
                ida_kernwin.register_action(desc)
                ida_kernwin.attach_action_to_menu(
                    "Edit/Plugins/", action_id, ida_kernwin.SETMENU_APP
                )
            ida_kernwin.msg("[disrobe] plugin loaded\n")
            return idaapi.PLUGIN_KEEP

        def run(self, arg: int) -> None:
            _apply_and_report(("native", "symbols"))

        def term(self) -> None:
            for action_id, _, _ in _ACTIONS:
                ida_kernwin.unregister_action(action_id)

    def PLUGIN_ENTRY() -> idaapi.plugin_t:
        return DisrobePlugin()
