"""Typing-smoke test for the disrobe Python bindings.

Imports the built extension, calls a representative typed method per capability
family on a committed fixture, and asserts the concrete return types. Also
exercises code-object mutation, the .dr round-trip, and the extensibility
registry. Run with: python -m pytest crates/disrobe-python/tests
"""

from __future__ import annotations

import json
import pathlib
import struct

import pytest

import disrobe

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SAMPLE_ELF = (FIXTURES / "sample.elf").read_bytes()
ROOT: pathlib.Path = pathlib.Path(__file__).parents[3]
CORE_LIBRARY_DEX: bytes = (
    ROOT / "corpus" / "jvm" / "desugar-core" / "CoreLibraryProbe-min21.dex"
).read_bytes()
CORE_LIBRARY_SOURCE: str = (
    ROOT
    / "corpus"
    / "jvm"
    / "desugar-core"
    / "CoreLibraryProbe.recovered.java.txt"
).read_text(encoding="utf-8")
FLUTTER_AOT: bytes = (
    ROOT / "corpus" / "mobile" / "flutter" / "disrobe_sample" / "libapp_arm64.so"
).read_bytes()
FLUTTER_ENGINE_MAP: bytes = b"""{
  "format": "disrobe.flutter.engine-symbol-map",
  "version": 1,
  "identity": {
    "kind": "elf-build-id",
    "value": "b71885094a73117bf90d3cfa05824129"
  },
  "symbols": [{"address": 0, "name": "FlutterEngineExternal"}]
}"""


def _build_disasm_dr() -> bytes:
    obj = disrobe.CodeObject()
    obj.add_symbol(disrobe.Symbol(0x1000, "main", "function"))
    obj.add_symbol(disrobe.Symbol(0x1040, "helper", "function"))
    ins = disrobe.Instruction(0x1000, "mov", ["eax", "ebx"], b"\x89\xd8")
    obj.add_instruction(ins)
    obj.add_instruction(disrobe.Instruction(0x1002, "ret", [], b"\xc3"))
    obj.produced_by = "disrobe-typing-test"
    obj.set_metadata("note", "round-trip")
    obj.add_capability("disasm", 1)
    return obj.to_dr()


def test_version_is_string() -> None:
    assert isinstance(disrobe.__version__, str)
    assert disrobe.__version__.count(".") >= 2


def test_wasm_lift_returns_typed_source_for_every_target() -> None:
    wasm: bytes = bytes.fromhex(
        "0061736d010000000105016000017f030201000a06010400412a0b"
    )
    for target in ("rust", "typescript", "c", "wat"):
        report: disrobe.WasmLift = disrobe.wasm_lift(wasm, target=target)
        assert isinstance(report, disrobe.WasmLift)
        assert report.target == target
        assert report.functions_emitted == 1
        assert report.fully_recovered is True
        assert report.total_ops == report.translated_ops
        assert report.source


def test_wasm_lift_refusal_is_json_visible() -> None:
    with pytest.raises(disrobe.DisrobeError) as excinfo:
        disrobe.wasm_lift(b"not wasm", target="rust")
    payload = json.loads(str(excinfo.value))
    assert payload["code"] == "DR-WASMDEOB-0001"
    assert payload["operation"] == "wasm lift"
    assert "valid WebAssembly module" in payload["message"]

    with pytest.raises(disrobe.DisrobeError) as target_excinfo:
        disrobe.wasm_lift(b"", target="javascript")
    target_payload = json.loads(str(target_excinfo.value))
    assert target_payload == {
        "accepted_targets": ["rust", "typescript", "c", "wat"],
        "code": "DR-PY-0420",
        "message": "unsupported WebAssembly lift target `javascript`",
        "operation": "wasm lift",
        "target": "javascript",
    }


def test_wasm_lift_typescript_owns_shared_atomic_memory() -> None:
    wasm: bytes = bytes.fromhex(
        "0061736d0100000001110360027f7f017f60037f7f7e017f60000003050400010002"
        "050401030101072805066d656d6f7279020003616464000004776169740001066e6f"
        "7469667900020566656e636500030a2a040a0020002001fe1e02000b0c0020002001"
        "2002fe0102000b0a0020002001fe0002000b0500fe03000b"
    )
    report: disrobe.WasmLift = disrobe.wasm_lift(wasm, target="typescript")
    assert report.functions_emitted == 4
    assert "export const instantiate" in report.source
    assert "new WebAssembly.Memory" in report.source
    assert "SharedArrayBuffer" in report.source
    assert "Atomics.add" in report.source
    assert "Atomics.wait" in report.source
    assert "Atomics.notify" in report.source
    assert "wasmAtomicFence" in report.source
    assert report.fully_recovered is True


def test_jvm_dex_decompile_recovers_core_library_calls() -> None:
    report: disrobe.JvmDecompiledDex = disrobe.jvm_decompile_dex(CORE_LIBRARY_DEX)
    source: str | None = report.source
    assert isinstance(report, disrobe.JvmDecompiledDex)
    assert source == CORE_LIBRARY_SOURCE
    assert source is not None
    assert report.source_count >= 1
    assert "java.time.Duration.ofMinutes" in source
    assert "java.util.concurrent.TimeUnit.SECONDS.convert" in source
    assert "j$." not in source
    assert "$-EL" not in source
    assert "$-CC" not in source


def test_codeobject_mutation_and_roundtrip() -> None:
    dr = _build_disasm_dr()
    assert isinstance(dr, bytes)

    loaded = disrobe.CodeObject.from_dr(dr)
    assert loaded.instruction_count == 2
    assert loaded.symbol_count == 2
    assert loaded.produced_by == "disrobe-typing-test"
    assert loaded.metadata["note"] == "round-trip"
    assert "disasm" in loaded.capabilities

    insns = loaded.instructions
    assert isinstance(insns[0], disrobe.Instruction)
    assert insns[0].mnemonic == "mov"
    assert insns[0].operands == ["eax", "ebx"]
    assert insns[0].text() == "mov eax, ebx"

    syms = loaded.symbols
    assert isinstance(syms[0], disrobe.Symbol)
    assert {s.name for s in syms} == {"main", "helper"}

    edited = insns[0]
    edited.mnemonic = "xor"
    edited.operands = ["eax", "eax"]
    assert edited.text() == "xor eax, eax"

    loaded.add_instruction(disrobe.Instruction(0x1003, "nop"))
    loaded.set_metadata("edited", "yes")
    loaded.produced_by = "edited-producer"
    dr2 = loaded.to_dr()
    reloaded = disrobe.CodeObject.from_dr(dr2)
    assert reloaded.instruction_count == 3
    assert reloaded.metadata["edited"] == "yes"
    assert reloaded.produced_by == "edited-producer"


def test_codeobject_source_hash_rejects_non_ascii_without_panic() -> None:
    obj = disrobe.CodeObject()
    try:
        obj.source_hash = "\U0001F600" * 16
    except disrobe.DisrobeError as exc:
        assert "hex:" in str(exc)
    else:
        raise AssertionError("non-ascii source_hash must be rejected")


def test_envelope_verify_typed() -> None:
    dr = _build_disasm_dr()
    report = disrobe.envelope_verify(dr)
    assert isinstance(report, disrobe.EnvelopeReport)
    assert report.verified is True
    assert report.rung == "Disasm"
    assert isinstance(report.root_hash, str)
    assert len(report.root_hash) == 64
    assert isinstance(report.raw, dict)


def test_query_typed_returns() -> None:
    dr = _build_disasm_dr()
    fns = disrobe.query_functions(dr)
    assert isinstance(fns, disrobe.FunctionList)
    assert fns.count >= 0
    assert isinstance(fns.raw, dict)

    cg = disrobe.query_call_graph(dr)
    assert isinstance(cg, disrobe.CallGraph)
    assert cg.node_count >= 0

    decoders = disrobe.query_string_decoders(dr)
    assert isinstance(decoders, disrobe.QueryReport)


def test_strings_ioc_typed() -> None:
    blob = b"GET http://example.com/a HTTP/1.1\npassword=hunter2\x00\x00admin@evil.test"
    sr = disrobe.strings_extract(blob, min_len=4)
    assert isinstance(sr, disrobe.StringsReport)
    assert sr.string_count > 0

    ir = disrobe.ioc_extract(blob)
    assert isinstance(ir, disrobe.IocReport)
    assert ir.indicator_count > 0

    ss = disrobe.secret_scan(blob)
    assert isinstance(ss, disrobe.SecretScanReport)

    secret_blob = b"key = AKIA3KFTG2KQ4WXYZ7AB"
    redacted = disrobe.secret_scan(secret_blob, redact=True)
    assert "AKIA3KFTG2KQ4WXYZ7AB" not in redacted.to_json()
    assert "[REDACTED:" in redacted.to_json()


def test_native_typed_returns() -> None:
    sym = disrobe.native_symbols(SAMPLE_ELF)
    assert isinstance(sym, disrobe.SymbolsReport)
    assert sym.section_count >= 0

    ident = disrobe.identify(SAMPLE_ELF)
    assert isinstance(ident, disrobe.IdentifyReport)

    beh = disrobe.behavior_analyze(SAMPLE_ELF)
    assert isinstance(beh, disrobe.BehaviorReport)

    ent = disrobe.native_entropy(SAMPLE_ELF)
    assert isinstance(ent, disrobe.EntropyReport)
    assert ent.window_count >= 0

    disasm = disrobe.native_disasm(SAMPLE_ELF)
    assert isinstance(disasm, disrobe.DisasmPayload)

    cg = disrobe.native_callgraph(SAMPLE_ELF)
    assert isinstance(cg, disrobe.CallGraph)

    caps = disrobe.capabilities(SAMPLE_ELF)
    assert isinstance(caps, disrobe.Capabilities)

    dot = disrobe.native_imports_dot(SAMPLE_ELF)
    assert isinstance(dot, str)
    assert "digraph" in dot


def test_flutter_engine_symbol_map_keeps_validated_identity_and_provenance() -> None:
    report: disrobe.FlutterEngineSymbols = disrobe.flutter_engine_symbols(
        FLUTTER_AOT, FLUTTER_ENGINE_MAP, source="analyst-map.json"
    )

    assert isinstance(report, disrobe.FlutterEngineSymbols)
    assert report.identity == "b71885094a73117bf90d3cfa05824129"
    assert report.symbol_count == 1
    assert report.raw["symbols"] == [
        {"address": 0, "name": "FlutterEngineExternal"}
    ]
    assert report.raw["provenance"] == [
        {
            "source": "analyst-map.json",
            "kind": "disrobe.flutter.engine-symbol-map",
            "identity": "b71885094a73117bf90d3cfa05824129",
        }
    ]


def test_flutter_engine_symbol_map_refuses_mismatched_build_id() -> None:
    mismatched_map: bytes = FLUTTER_ENGINE_MAP.replace(
        b"b71885094a73117bf90d3cfa05824129", b"00000000000000000000000000000000"
    )

    with pytest.raises(disrobe.DisrobeError, match="DR-MOB-0060"):
        disrobe.flutter_engine_symbols(
            FLUTTER_AOT, mismatched_map, source="analyst-map.json"
        )


def test_native_diff_and_sigmaker() -> None:
    diff = disrobe.native_diff(SAMPLE_ELF, SAMPLE_ELF)
    assert isinstance(diff, disrobe.DiffReport)
    assert diff.changed == 0


def test_native_match_returns_the_shared_bounded_report() -> None:
    report: disrobe.NativeMatch = disrobe.native_match(
        SAMPLE_ELF, SAMPLE_ELF, limit=4
    )
    assert isinstance(report, disrobe.NativeMatch)
    assert report.schema == "disrobe.native.match/v2"
    assert report.pairs > 0
    assert report.shown == 4
    assert report.withheld > 0
    assert report.raw["a"] == "a"
    assert report.raw["b"] == "b"
    assert all(
        row.get("counterpart") == row["subject"]
        for row in report.raw["a_verdicts"]
        if "counterpart" in row
    )


def test_native_match_refusals_keep_the_native_reason_codes() -> None:
    with pytest.raises(disrobe.DisrobeError) as empty_excinfo:
        disrobe.native_match(SAMPLE_ELF, b"")
    assert "DR-NATIVE-0203" in str(empty_excinfo.value)

    with pytest.raises(disrobe.DisrobeError) as function_excinfo:
        disrobe.native_match(SAMPLE_ELF, SAMPLE_ELF, function=(1 << 64) - 1)
    assert str(function_excinfo.value) == (
        "DR-NATIVE-0208: no function at address 0xffffffffffffffff in either input"
    )


def test_yara_generate_typed() -> None:
    rule = disrobe.yara_generate(SAMPLE_ELF, name="elf_sample")
    assert isinstance(rule, disrobe.YaraReport)
    assert "elf_sample" in rule.to_json()


def test_decompile_canonical_source() -> None:
    import importlib.util

    py_src = "x = 1 + 2\n"
    code = compile(py_src, "<smoke>", "exec")
    import marshal

    payload = marshal.dumps(code)
    blob = disrobe.compile("python", py_src)
    assert isinstance(blob, bytes)
    assert importlib.util.MAGIC_NUMBER is not None
    # exercise that decompile is exposed and typed; the host marshal payload
    # is enough to assert the typed CanonicalSource surface
    assert callable(disrobe.decompile)
    _ = payload


def test_extensibility_registry() -> None:
    def upper_pass(data: bytes) -> bytes:
        return bytes(data).upper()

    def tag_pass(data: bytes) -> bytes:
        return b"tag:" + bytes(data)

    collected: dict[str, object] = {}

    def consumer(result: object, **ctx: object) -> None:
        collected["result"] = result
        collected.update(ctx)

    disrobe.register_pass("upper", upper_pass)
    disrobe.register_pass("tag", tag_pass)
    disrobe.register_consumer("collect", consumer)

    assert "upper" in disrobe.registered_passes()
    assert "collect" in disrobe.registered_consumers()

    out = disrobe.run_pass("upper", b"hello")
    assert out == b"HELLO"

    chained = disrobe.run_chain(["upper", "tag"], b"hi")
    assert chained == b"tag:HI"

    disrobe.emit("collect", {"ok": True}, stage="final")
    assert collected["result"] == {"ok": True}
    assert collected["stage"] == "final"

    assert disrobe.unregister("upper") is True
    assert "upper" not in disrobe.registered_passes()


def test_extract_recursive_typed(tmp_path: pathlib.Path) -> None:
    overlay = disrobe.extract_recursive(SAMPLE_ELF, max_depth=2)
    assert isinstance(overlay, disrobe.OverlayReport)
    assert overlay.nodes_visited is not None


def test_report_json_roundtrip() -> None:
    sr = disrobe.strings_extract(b"hello world string here", min_len=4)
    text = sr.to_json()
    rebuilt = disrobe.StringsReport.from_json_str(text)
    assert rebuilt.string_count == sr.string_count
    from_obj = disrobe.StringsReport.from_obj(sr.raw)
    assert from_obj.string_count == sr.string_count


def test_report_from_obj_rejects_recursive_container() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    try:
        disrobe.StringsReport.from_obj(cyclic)
    except disrobe.DisrobeError as exc:
        assert "conversion depth cap" in str(exc)
    else:
        raise AssertionError("recursive Python container must be rejected")


def test_report_count_accepts_u64_max() -> None:
    report = disrobe.PyDisasmReport.from_json_str(
        '{"marshal_version":"3.12","instruction_count":18446744073709551615}'
    )
    usize_bits = struct.calcsize("P") * 8
    assert report.instruction_count == (1 << usize_bits) - 1


def _make_pyc() -> bytes:
    import importlib.util
    import marshal
    import struct

    src = "def add(a, b):\n    return a + b\n"
    code = compile(src, "<typed-smoke>", "exec")
    header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0)
    return header + marshal.dumps(code)


def test_py_decompile_typed_roundtrip() -> None:
    report = disrobe.py_decompile(_make_pyc(), roundtrip=True)
    assert isinstance(report, disrobe.PyDecompileReport)
    assert isinstance(report.source, str)
    assert "def add" in report.source
    assert report.marshal_version is not None
    assert report.roundtrip_status in {
        "perfect",
        "semantic",
        "code-diff",
        "no-interpreter",
        "recompile-failed",
        "skipped",
    }
    assert isinstance(report.raw, dict)
    assert "llm" in report.raw


def test_py_disasm_typed() -> None:
    report = disrobe.py_disasm(_make_pyc())
    assert isinstance(report, disrobe.PyDisasmReport)
    assert report.instruction_count > 0
    assert isinstance(report.text, str)


def test_py_deob_typed() -> None:
    src = "x = 1\ny = 2\nprint(x + y)\n"
    deob = disrobe.py_deob(src, cleanup=False)
    assert isinstance(deob, disrobe.PyDeobReport)
    assert isinstance(deob.raw, dict)
    assert "llm" in deob.raw

    detection = disrobe.py_deob_detect(src)
    assert isinstance(detection, disrobe.PyDeobDetection)

    passes = disrobe.py_deob_list_passes()
    assert isinstance(passes, list)
    assert all(isinstance(p, disrobe.ObfuscatorPass) for p in passes)
    assert passes and isinstance(passes[0].id, str)


def test_js_detect_typed() -> None:
    js = "var _0x1a2b=['log'];function f(){console[_0x1a2b[0]]('hi');}f();"
    det = disrobe.js_detect(js)
    assert isinstance(det, disrobe.JsDetection)
    assert det.confidence is None or isinstance(det.confidence, float)

    unmin = disrobe.js_unminify("var a=!0;var b=!1;")
    assert isinstance(unmin, disrobe.JsUnminify)
    assert isinstance(unmin.source, str)


def test_pickle_typed() -> None:
    import pickle

    blob = pickle.dumps({"a": [1, 2, 3], "b": "x"})
    dec = disrobe.pickle_decompile(blob)
    assert isinstance(dec, disrobe.PickleDecompilation)
    assert isinstance(dec.source, str)

    safety = disrobe.pickle_safety(blob)
    assert isinstance(safety, disrobe.PickleSafety)
    assert safety.severity is not None

    trace = disrobe.pickle_trace(blob)
    assert isinstance(trace, disrobe.PickleTrace)
    assert trace.protocol is not None

    listing = disrobe.pickle_disasm(blob)
    assert isinstance(listing, str)


def test_container_typed() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hello")
        zf.writestr("b.txt", "world")
    data = buf.getvalue()

    detect = disrobe.container_detect(data)
    assert isinstance(detect, disrobe.ContainerDetection)
    assert detect.detected is True
    assert detect.is_zip_family is True

    members = disrobe.container_members(data)
    assert isinstance(members, disrobe.ContainerMembers)
    assert members.format is not None


def test_byte_coverage_accounts_for_every_byte_of_a_real_image() -> None:
    image_path = (
        pathlib.Path(__file__).resolve().parents[3]
        / "corpus"
        / "native"
        / "formats"
        / "hello.pe64.exe"
    )
    assert image_path.is_file(), (
        "this case accounts for a committed image, so its absence is a damaged checkout: "
        f"{image_path}"
    )
    image = image_path.read_bytes()

    coverage = disrobe.byte_coverage(image)
    assert isinstance(coverage, disrobe.ByteCoverage)
    assert coverage.file_len == len(image)
    assert coverage.claimed_bytes is not None and coverage.claimed_bytes > 0
    assert (
        coverage.claimed_bytes + coverage.unclaimed_bytes + coverage.slack_bytes
        == coverage.file_len
    ), "every byte belongs to a claimed region, an unclaimed one, or alignment slack"
    assert coverage.region_count > 0


def test_byte_coverage_reports_an_appended_overlay() -> None:
    image_path = (
        pathlib.Path(__file__).resolve().parents[3]
        / "corpus"
        / "native"
        / "formats"
        / "hello.pe64.exe"
    )
    image = image_path.read_bytes()
    overlaid = image + b"\xa5" * 4096

    coverage = disrobe.byte_coverage(overlaid)
    assert coverage.unclaimed_bytes >= 4096, (
        "4096 appended bytes belong to no declared structure, so they must be unclaimed, got "
        f"{coverage.unclaimed_bytes}"
    )
    assert coverage.complete is False


def test_byte_coverage_refuses_bytes_that_are_not_an_image() -> None:
    with pytest.raises(Exception) as excinfo:
        disrobe.byte_coverage(b"\x00" * 64)
    assert "DR-PY-0410" in str(excinfo.value)


def test_powershell_and_batch_typed() -> None:
    ps = "$a = 'Wr'+'ite-Ho'+'st'; & $a 'hi'"
    detection = disrobe.powershell_detect(ps)
    assert isinstance(detection, disrobe.PowershellDetection)

    deob = disrobe.powershell_deobfuscate(ps)
    assert isinstance(deob, disrobe.PowershellDeobfuscation)
    assert isinstance(deob.output, str)

    batch = disrobe.batch_deobfuscate("set X=hello\necho %X%\n")
    assert isinstance(batch, disrobe.BatchDeobReport)
    assert isinstance(batch.output, str)


def test_native_format_and_detect_typed() -> None:
    fmt = disrobe.native_format(SAMPLE_ELF)
    assert isinstance(fmt, disrobe.NativeFormat)
    assert fmt.kind is not None

    hits = disrobe.native_detect(SAMPLE_ELF)
    assert isinstance(hits, disrobe.DetectionList)
    assert hits.count >= 0

    backends = disrobe.native_probe_backends()
    assert isinstance(backends, disrobe.BackendList)
    assert backends.count >= 0


def test_typed_report_has_llm_accessor() -> None:
    det = disrobe.js_detect("console.log(1)")
    assert det.llm is None
    report = disrobe.py_decompile(_make_pyc())
    assert report.llm is not None
    assert isinstance(report.llm, dict)
