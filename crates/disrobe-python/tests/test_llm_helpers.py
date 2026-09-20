from __future__ import annotations

import importlib.util
import marshal
import struct
from collections.abc import Callable
from typing import Any

import pytest

import disrobe
from json_values import JsonValue, json_object

UNVALIDATED_RENDERERS: tuple[Callable[..., object], ...] = (
    disrobe.agents_md,
    disrobe.skill_md,
    disrobe.provenance,
)
UNVALIDATED_AGENTS_MD: Callable[..., str] = disrobe.agents_md


def _make_pyc() -> bytes:
    code = compile("def add(a, b):\n    return a + b\n", "<llm-helpers>", "exec")
    header: bytes = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0)
    return header + marshal.dumps(code)


def _reports() -> list[disrobe.PyDecompileReport | disrobe.PyDeobReport]:
    decompiled: disrobe.PyDecompileReport = disrobe.py_decompile(_make_pyc(), pack="pack-2")
    deobfuscated: disrobe.PyDeobReport = disrobe.py_deob(
        "x = 1\nprint(x)\n", cleanup=False, pack="pack-1"
    )
    return [decompiled, deobfuscated]


@pytest.mark.parametrize("render", [disrobe.agents_md, disrobe.skill_md])
def test_markdown_renders_accept_typed_reports(render: Callable[[Any], str]) -> None:
    for report in _reports():
        raw: dict[str, JsonValue] = json_object(report.raw)
        assert raw["llm"] is not None
        from_report: str = render(report)
        assert from_report == render(raw)
        assert from_report


def test_provenance_accepts_typed_reports() -> None:
    for report in _reports():
        raw: dict[str, JsonValue] = json_object(report.raw)
        from_report: disrobe.Provenance = disrobe.provenance(report)
        assert from_report == disrobe.provenance(raw)
        assert from_report.schema is not None


def test_from_obj_accepts_another_typed_report() -> None:
    report: disrobe.PyDecompileReport = disrobe.py_decompile(_make_pyc(), pack="pack-2")
    rewrapped: disrobe.PyDecompileReport = disrobe.PyDecompileReport.from_obj(report)
    assert rewrapped == report
    assert rewrapped.raw == report.raw


def test_unrelated_objects_raise_type_error_naming_the_accepted_inputs() -> None:
    for render in UNVALIDATED_RENDERERS:
        with pytest.raises(TypeError, match="expected a disrobe report, dict"):
            render(object())


def test_a_foreign_object_claiming_the_report_method_is_not_trusted() -> None:
    class Impostor:
        def __disrobe_report_json__(self) -> str:
            return "{}"

    with pytest.raises(TypeError, match="unsupported Python type for conversion: Impostor"):
        UNVALIDATED_AGENTS_MD(Impostor())
