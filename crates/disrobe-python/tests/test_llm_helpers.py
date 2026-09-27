from __future__ import annotations

import importlib.util
import marshal
import re
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


def _llm_bundle(report: disrobe.PyDecompileReport) -> dict[str, JsonValue]:
    return json_object(json_object(report.raw)["llm"])


def test_the_bundle_records_no_duration_and_takes_its_date_only_from_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pyc: bytes = _make_pyc()
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    unstamped: dict[str, JsonValue] = _llm_bundle(disrobe.py_decompile(pyc, pack="pack-2"))
    assert "generated_at" not in unstamped
    version: JsonValue = json_object(unstamped["tool"])["version"]
    step: dict[str, JsonValue] = {
        "pass": "disrobe-pass-py-decompile",
        "version": version,
        "rung_in": "disasm",
        "rung_out": "surface",
    }
    assert unstamped["pipeline"] == [step]
    assert json_object(json_object(unstamped["categories"])["provenance"])["chain"] == [step]

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    stamped: dict[str, JsonValue] = _llm_bundle(disrobe.py_decompile(pyc, pack="pack-2"))
    assert stamped.pop("generated_at") == "2023-11-14T22:13:20.000Z"
    assert stamped == unstamped

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    rejected: str = (
        "llm bundle: SOURCE_DATE_EPOCH must be a whole number of seconds since 1970, "
        "got `yesterday`"
    )
    with pytest.raises(disrobe.DisrobeError, match=re.escape(rejected)):
        disrobe.py_decompile(pyc, pack="pack-2")


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
