from __future__ import annotations

import ast
import hashlib
import pathlib
from collections.abc import Callable
from typing import Any

import pytest

import disrobe

UNTYPED_UNPACK: Callable[..., disrobe.PyarmorUnpack] = disrobe.pyarmor_unpack

ROOT: pathlib.Path = pathlib.Path(__file__).parents[3]
FIXTURE: pathlib.Path = (
    ROOT
    / "corpus"
    / "python"
    / "pyarmor"
    / "v8"
    / "basic"
    / "chunk_00_try_except_basic_try_except_else"
)
WRAPPER: pathlib.Path = FIXTURE / "chunk_00_try_except_basic_try_except_else.py"
RUNTIME: pathlib.Path = FIXTURE / "pyarmor_runtime_000000" / "pyarmor_runtime.pyd"
WRAPPER_SHA256: str = "2798ea24ea28d2aeb4bf5099495eedd923efb1b0d661ac86fbf27f619a08840c"
RUNTIME_SHA256: str = "efbe633622d88accb359b26b316660237dc515d7d17bbe8e5a8f3a5d24ef9967"


def _verified(path: pathlib.Path, sha256: str) -> bytes:
    data: bytes = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha256
    return data


def _payload() -> bytes:
    source: str = _verified(WRAPPER, WRAPPER_SHA256).decode("utf-8")
    tree: ast.Module = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "__pyarmor__"
        ):
            literal: Any = ast.literal_eval(node.args[2])
            assert isinstance(literal, bytes)
            return literal
    raise AssertionError(f"{WRAPPER} has no __pyarmor__ payload literal")


def _static_fields(report: disrobe.PyarmorUnpack) -> dict[str, Any]:
    raw: dict[str, Any] = report.raw
    return {key: value for key, value in raw.items() if key != "llm"}


def test_pyarmor_unpack_accepts_the_payload_under_both_keywords() -> None:
    payload: bytes = _payload()
    positional: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(payload)
    keyword: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(payload=payload)
    legacy: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(wrapper_bytes=payload)

    assert _static_fields(keyword) == _static_fields(positional)
    assert _static_fields(legacy) == _static_fields(positional)
    assert positional.status == "detect-only"
    assert positional.plaintext_len == 0


def test_pyarmor_unpack_rejects_both_payload_keywords() -> None:
    payload: bytes = _payload()
    with pytest.raises(TypeError, match="both 'payload' and 'wrapper_bytes'"):
        UNTYPED_UNPACK(payload, wrapper_bytes=payload)
    with pytest.raises(TypeError, match="both 'payload' and 'wrapper_bytes'"):
        UNTYPED_UNPACK(payload=payload, wrapper_bytes=payload)


def test_pyarmor_unpack_requires_a_payload() -> None:
    with pytest.raises(TypeError, match="missing required argument 'payload'"):
        UNTYPED_UNPACK()
    with pytest.raises(TypeError, match="missing required argument 'payload'"):
        UNTYPED_UNPACK(runtime=b"")


def test_pyarmor_unpack_with_the_matching_runtime_decrypts_the_payload() -> None:
    payload: bytes = _payload()
    runtime: bytes = _verified(RUNTIME, RUNTIME_SHA256)
    detect_only: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(payload)
    decrypted: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(payload, runtime=runtime)
    legacy: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(
        wrapper_bytes=payload, runtime=runtime
    )
    raw: dict[str, Any] = decrypted.raw

    assert decrypted.status == "functional"
    assert decrypted.plaintext_len is not None
    assert decrypted.plaintext_len > 0
    assert decrypted.plaintext_blake3_hex != detect_only.plaintext_blake3_hex
    assert raw["python_version"] == [3, 12]
    assert raw["serial"] == "000000"
    assert _static_fields(legacy) == _static_fields(decrypted)


def test_pyarmor_unpack_rejects_a_runtime_that_is_not_a_pyarmor_runtime() -> None:
    with pytest.raises(disrobe.DisrobeError):
        disrobe.pyarmor_unpack(_payload(), runtime=b"MZ" + bytes(62))
