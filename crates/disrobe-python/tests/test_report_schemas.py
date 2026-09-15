from __future__ import annotations

import pathlib
from typing import Any

import disrobe

FIXTURES: pathlib.Path = pathlib.Path(__file__).parent / "fixtures"
SAMPLE_ELF: bytes = (FIXTURES / "sample.elf").read_bytes()
HYPERION_SOURCE: str = "__obfuscator__ = 'Hyperion'\nprint(1)\n"
BASE64_EXEC_SOURCE: str = "exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n"


def _build_disasm_dr() -> bytes:
    obj: disrobe.CodeObject = disrobe.CodeObject()
    obj.add_symbol(disrobe.Symbol(0x1000, "main", "function"))
    obj.add_symbol(disrobe.Symbol(0x1040, "helper", "function"))
    obj.add_instruction(disrobe.Instruction(0x1000, "mov", ["eax", "ebx"], b"\x89\xd8"))
    obj.add_instruction(disrobe.Instruction(0x1002, "ret", [], b"\xc3"))
    return obj.to_dr()


def _first_function_address() -> int:
    functions: list[dict[str, Any]] = disrobe.native_disasm(SAMPLE_ELF).raw["functions"]
    address: int = functions[0]["address"]
    return address


def test_native_disasm_counts_follow_the_disasm_view() -> None:
    payload: disrobe.DisasmPayload = disrobe.native_disasm(SAMPLE_ELF)
    raw: dict[str, Any] = payload.raw
    functions: list[dict[str, Any]] = raw["functions"]

    assert payload.instruction_count == raw["instruction_count"]
    assert payload.instruction_count == sum(f["instruction_count"] for f in functions)
    assert payload.instruction_count > 0
    assert payload.function_count == len(functions) == raw["function_count"]
    assert payload.function_count > 0
    assert not hasattr(payload, "symbol_count")
    assert not hasattr(payload, "source_hash")


def test_capabilities_counts_follow_the_report() -> None:
    caps: disrobe.Capabilities = disrobe.capabilities(SAMPLE_ELF)
    raw: dict[str, Any] = caps.raw

    assert caps.match_count == len(raw["capabilities"])
    assert caps.match_count >= 1
    assert caps.matched_rules == raw["matched_rules"]
    assert not hasattr(caps, "format")


def test_query_kind_is_the_query_tag() -> None:
    dr: bytes = _build_disasm_dr()
    functions: disrobe.FunctionList = disrobe.query_functions(dr)
    decoders: disrobe.QueryReport = disrobe.query_string_decoders(dr)

    assert functions.kind == functions.raw["query"] == "functions"
    assert functions.count == len(functions.raw["matches"])
    assert functions.count >= 1
    assert decoders.kind == decoders.raw["query"] == "string-decoders"
    assert decoders.match_count == len(decoders.raw["matches"])


def test_py_deob_detection_counts_matched_markers() -> None:
    detection: disrobe.PyDeobDetection = disrobe.py_deob_detect(HYPERION_SOURCE)
    raw: dict[str, Any] = detection.raw

    assert detection.match_count == len(raw["markers"]) == 1
    assert detection.confidence == raw["confidence"]
    assert detection.confidence is not None
    assert detection.confidence > 0.0


def test_py_deob_layer_count_follows_the_peel_steps() -> None:
    report: disrobe.PyDeobReport = disrobe.py_deob(BASE64_EXEC_SOURCE, cleanup=False)
    steps: list[dict[str, Any]] = report.raw["peel"]["steps"]

    assert report.layer_count == len(steps) == 1


def test_yara_rule_count_covers_parsed_and_generated_rules() -> None:
    generated: disrobe.YaraReport = disrobe.yara_generate(SAMPLE_ELF, name="elf_sample")
    parsed: disrobe.YaraReport = disrobe.yara_parse(
        "rule a { condition: true }\nrule b { condition: false }\n"
    )

    assert "rules" not in generated.raw
    assert generated.raw["rule"]["name"] == "elf_sample"
    assert generated.rule_count == 1
    assert parsed.rule_count == len(parsed.raw["rules"]) == 2


def test_sigmaker_pattern_follows_the_signature() -> None:
    signature: disrobe.SigmakerReport = disrobe.native_sigmaker(
        SAMPLE_ELF, _first_function_address()
    )
    raw: dict[str, Any] = signature.raw

    assert signature.ida_pattern == raw["ida_pattern"]
    assert signature.ida_pattern
    assert signature.byte_count == len(raw["bytes"]) == raw["byte_length"]


def test_patch_report_follows_the_applied_edits() -> None:
    address: int = _first_function_address()
    patched: bytes
    report: disrobe.PatchReport
    patched, report = disrobe.native_patch(SAMPLE_ELF, at=address, replacement=b"\x90\x90")
    raw: dict[str, Any] = report.raw
    edits: list[dict[str, Any]] = raw["edits"]
    offset: int = edits[0]["file_offset"]

    assert report.at == edits[0]["virtual_address"] == address
    assert report.bytes_written == raw["bytes_changed"] == 2
    assert report.edit_count == len(edits) == 1
    assert report.format == raw["format"] == "elf"
    assert report.image_base == raw["image_base"]
    assert patched[offset : offset + 2] == b"\x90\x90"
    assert SAMPLE_ELF[offset : offset + 2] != b"\x90\x90"
    assert not hasattr(report, "revalidated")
