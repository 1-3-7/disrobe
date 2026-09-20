from __future__ import annotations

import pathlib

import disrobe
from json_values import JsonValue, json_array, json_object

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
    raw: dict[str, JsonValue] = json_object(disrobe.native_disasm(SAMPLE_ELF).raw)
    functions: list[JsonValue] = json_array(raw["functions"])
    first: dict[str, JsonValue] = json_object(functions[0])
    address: JsonValue = first["address"]
    assert isinstance(address, int)
    return address


def test_native_disasm_counts_follow_the_disasm_view() -> None:
    payload: disrobe.DisasmPayload = disrobe.native_disasm(SAMPLE_ELF)
    raw: dict[str, JsonValue] = json_object(payload.raw)
    functions: list[dict[str, JsonValue]] = [
        json_object(value) for value in json_array(raw["functions"])
    ]
    instruction_count: JsonValue = raw["instruction_count"]
    function_count: JsonValue = raw["function_count"]
    assert isinstance(instruction_count, int)
    assert isinstance(function_count, int)

    instruction_counts: list[int] = []
    for function in functions:
        value: JsonValue = function["instruction_count"]
        assert isinstance(value, int)
        instruction_counts.append(value)

    assert payload.instruction_count == instruction_count
    assert payload.instruction_count == sum(instruction_counts)
    assert payload.instruction_count > 0
    assert payload.function_count == len(functions) == function_count
    assert payload.function_count > 0
    assert not hasattr(payload, "symbol_count")
    assert not hasattr(payload, "source_hash")


def test_capabilities_counts_follow_the_report() -> None:
    caps: disrobe.Capabilities = disrobe.capabilities(SAMPLE_ELF)
    raw: dict[str, JsonValue] = json_object(caps.raw)
    capabilities: list[JsonValue] = json_array(raw["capabilities"])
    matched_rules: JsonValue = raw["matched_rules"]
    assert isinstance(matched_rules, int)

    assert caps.match_count == len(capabilities)
    assert caps.match_count >= 1
    assert caps.matched_rules == matched_rules
    assert not hasattr(caps, "format")


def test_query_kind_is_the_query_tag() -> None:
    dr: bytes = _build_disasm_dr()
    functions: disrobe.FunctionList = disrobe.query_functions(dr)
    decoders: disrobe.QueryReport = disrobe.query_string_decoders(dr)
    function_raw: dict[str, JsonValue] = json_object(functions.raw)
    decoder_raw: dict[str, JsonValue] = json_object(decoders.raw)

    assert functions.kind == function_raw["query"] == "functions"
    assert functions.count == len(json_array(function_raw["matches"]))
    assert functions.count >= 1
    assert decoders.kind == decoder_raw["query"] == "string-decoders"
    assert decoders.match_count == len(json_array(decoder_raw["matches"]))


def test_py_deob_detection_counts_matched_markers() -> None:
    detection: disrobe.PyDeobDetection = disrobe.py_deob_detect(HYPERION_SOURCE)
    raw: dict[str, JsonValue] = json_object(detection.raw)
    markers: list[JsonValue] = json_array(raw["markers"])
    confidence: JsonValue = raw["confidence"]
    assert isinstance(confidence, float)

    assert detection.match_count == len(markers) == 1
    assert detection.confidence == confidence
    assert detection.confidence is not None
    assert detection.confidence > 0.0


def test_py_deob_layer_count_follows_the_peel_steps() -> None:
    report: disrobe.PyDeobReport = disrobe.py_deob(BASE64_EXEC_SOURCE, cleanup=False)
    raw: dict[str, JsonValue] = json_object(report.raw)
    peel: dict[str, JsonValue] = json_object(raw["peel"])
    steps: list[JsonValue] = json_array(peel["steps"])

    assert report.layer_count == len(steps) == 1


def test_yara_rule_count_covers_parsed_and_generated_rules() -> None:
    generated: disrobe.YaraReport = disrobe.yara_generate(SAMPLE_ELF, name="elf_sample")
    parsed: disrobe.YaraReport = disrobe.yara_parse(
        "rule a { condition: true }\nrule b { condition: false }\n"
    )
    generated_raw: dict[str, JsonValue] = json_object(generated.raw)
    parsed_raw: dict[str, JsonValue] = json_object(parsed.raw)
    rule: dict[str, JsonValue] = json_object(generated_raw["rule"])

    assert "rules" not in generated_raw
    assert rule["name"] == "elf_sample"
    assert generated.rule_count == 1
    assert parsed.rule_count == len(json_array(parsed_raw["rules"])) == 2


def test_sigmaker_pattern_follows_the_signature() -> None:
    signature: disrobe.SigmakerReport = disrobe.native_sigmaker(
        SAMPLE_ELF, _first_function_address()
    )
    raw: dict[str, JsonValue] = json_object(signature.raw)
    pattern: JsonValue = raw["ida_pattern"]
    pattern_bytes: list[JsonValue] = json_array(raw["bytes"])
    byte_length: JsonValue = raw["byte_length"]
    assert isinstance(pattern, str)
    assert isinstance(byte_length, int)

    assert signature.ida_pattern == pattern
    assert signature.ida_pattern
    assert signature.byte_count == len(pattern_bytes) == byte_length


def test_patch_report_follows_the_applied_edits() -> None:
    address: int = _first_function_address()
    patched: bytes
    report: disrobe.PatchReport
    patched, report = disrobe.native_patch(SAMPLE_ELF, at=address, replacement=b"\x90\x90")
    raw: dict[str, JsonValue] = json_object(report.raw)
    edits: list[dict[str, JsonValue]] = [
        json_object(value) for value in json_array(raw["edits"])
    ]
    first_edit: dict[str, JsonValue] = edits[0]
    offset: JsonValue = first_edit["file_offset"]
    bytes_changed: JsonValue = raw["bytes_changed"]
    image_base: JsonValue = raw["image_base"]
    format_name: JsonValue = raw["format"]
    virtual_address: JsonValue = first_edit["virtual_address"]
    assert isinstance(offset, int)
    assert isinstance(bytes_changed, int)
    assert isinstance(image_base, int)
    assert isinstance(format_name, str)
    assert isinstance(virtual_address, int)

    assert report.at == virtual_address == address
    assert report.bytes_written == bytes_changed == 2
    assert report.edit_count == len(edits) == 1
    assert report.format == format_name == "elf"
    assert report.image_base == image_base
    assert patched[offset : offset + 2] == b"\x90\x90"
    assert SAMPLE_ELF[offset : offset + 2] != b"\x90\x90"
    assert not hasattr(report, "revalidated")
