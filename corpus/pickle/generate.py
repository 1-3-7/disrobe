"""Generate the disrobe pickle fixture corpus across protocols 0-5.

Run: python corpus/pickle/generate.py
Writes .pkl binaries (gitignored) into category subdirs and rewrites
MANIFEST.toml (sha256-pinned), mirroring the sibling corpus manifests.
"""

from __future__ import annotations

import copyreg
import hashlib
import io
import json
import pickle
import pickletools
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT: Path = Path(__file__).resolve().parent
PROTOCOLS: tuple[int, ...] = (0, 1, 2, 3, 4, 5)


@dataclass(frozen=True)
class Sample:
    name: str
    source_tool: str
    size_bytes: int
    sha256: str
    notes: str


class ReduceShell:
    """A __reduce__-bearing object: unpickling calls os.system('echo pwned')."""

    def __reduce__(self) -> tuple[Callable[..., Any], tuple[str, ...]]:
        import os

        return (os.system, ("echo pwned",))


class StateObj:
    def __init__(self) -> None:
        self.a: int = 1
        self.b: str = "two"


def benign_values() -> dict[str, Any]:
    return {
        "int": 42,
        "neg_int": -7,
        "big_int": 2**128 + 1,
        "float": 3.14159,
        "str": "hello é world",
        "bytes": b"\x00\x01\x02\xff",
        "bool_true": True,
        "bool_false": False,
        "none": None,
        "list": [1, 2, [3, 4], "five"],
        "nested_dict": {"k": {"inner": [1, 2, 3]}, "n": 9},
        "tuple": (1, "a", (2, 3)),
        "set": {1, 2, 3},
        "frozenset": frozenset({4, 5, 6}),
        "instance": StateObj(),
    }


def malicious_values() -> dict[str, Any]:
    return {
        "reduce_os_system": ReduceShell(),
    }


def write_bytes_sample(path: Path, data: bytes, source_tool: str, notes: str) -> Sample:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return Sample(
        name=str(path.relative_to(ROOT)).replace("\\", "/"),
        source_tool=source_tool,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        notes=notes,
    )


def write_pickle(path: Path, obj: Any, proto: int) -> Sample:
    data: bytes = pickle.dumps(obj, protocol=proto)
    return write_bytes_sample(
        path,
        data,
        f"CPython pickle.dumps(protocol={proto})",
        f"protocol {proto}",
    )


def structural_samples() -> list[Sample]:
    samples: list[Sample] = []

    cyclic_list: list[Any] = []
    cyclic_list.append(cyclic_list)
    samples.append(
        write_pickle(ROOT / "structural" / "cyclic_list.pkl", cyclic_list, 2)
    )

    cyclic_dict: dict[str, Any] = {}
    cyclic_dict["self"] = cyclic_dict
    samples.append(
        write_pickle(ROOT / "structural" / "cyclic_dict.pkl", cyclic_dict, 4)
    )

    shared: list[int] = [1, 2, 3]
    shared_refs: list[Any] = [shared, shared]
    samples.append(
        write_pickle(ROOT / "structural" / "shared_ref.pkl", shared_refs, 2)
    )

    deep: Any = 0
    for _ in range(64):
        deep = [deep]
    samples.append(write_pickle(ROOT / "structural" / "deep_nested.pkl", deep, 4))

    class OobHolder:
        def __init__(self: OobHolder, raw: bytes) -> None:
            self.buf: pickle.PickleBuffer = pickle.PickleBuffer(raw)

        def __reduce_ex__(
            self: OobHolder, protocol: int
        ) -> tuple[Callable[..., Any], tuple[Any, ...]]:
            return (bytes, (self.buf,))

    buffers: list[pickle.PickleBuffer] = []
    oob_data: bytes = pickle.dumps(
        OobHolder(b"out-of-band-payload"),
        protocol=5,
        buffer_callback=buffers.append,
    )
    samples.append(
        write_bytes_sample(
            ROOT / "structural" / "oob_buffer.pkl",
            oob_data,
            "CPython pickle.dumps(protocol=5, buffer_callback=...)",
            "protocol 5 out-of-band buffer (NEXT_BUFFER/READONLY_BUFFER); raw data not in stream",
        )
    )

    registry_code: int = 0x10
    try:
        copyreg.add_extension("disrobe_demo", "DemoClass", registry_code)
    except ValueError:
        pass
    ext_stream: bytes = (
        b"\x80\x02"
        + b"\x82"
        + bytes([registry_code])
        + b"."
    )
    samples.append(
        write_bytes_sample(
            ROOT / "structural" / "ext1.pkl",
            ext_stream,
            "hand-assembled EXT1 opcode stream (copyreg extension registry code 16)",
            "EXT1: copyreg extension code; target resolvable only via runtime registry",
        )
    )

    return samples


def build() -> list[Sample]:
    samples: list[Sample] = []
    for proto in PROTOCOLS:
        for key, value in benign_values().items():
            p: Path = ROOT / "benign" / f"p{proto}" / f"{key}.pkl"
            samples.append(write_pickle(p, value, proto))
        for key, value in malicious_values().items():
            p = ROOT / "malicious" / f"p{proto}" / f"{key}.pkl"
            samples.append(write_pickle(p, value, proto))
    samples.extend(structural_samples())
    return samples


def opcode_reference(samples: list[Sample]) -> dict[str, list[str]]:
    reference: dict[str, list[str]] = {}
    for sample in samples:
        data: bytes = (ROOT / sample.name).read_bytes()
        names: list[str] = []
        sink: io.StringIO = io.StringIO()
        for opcode, _arg, _pos in pickletools.genops(data):
            names.append(opcode.name)
        _ = sink
        reference[sample.name] = names
    return dict(sorted(reference.items()))


def canon_arg(name: str, arg: object) -> list[str]:
    """Canonicalize a pickletools-decoded argument into a language-neutral form.

    Floats compare on their IEEE-754 big-endian byte pattern so no
    text-formatting divergence between CPython repr and Rust can leak in;
    GLOBAL/INST/OBJ split the space-joined ``module name`` into a pair;
    proto-0/1 ``I00``/``I01`` type as bool in pickletools but carry the raw
    integer value, so they canonicalize as int for a value-level compare.
    """
    if name in ("GLOBAL", "INST", "OBJ") and isinstance(arg, str) and " " in arg:
        module, _, symbol = arg.partition(" ")
        return ["pair", module, symbol]
    if arg is None:
        return ["none"]
    if isinstance(arg, bool):
        return ["int", "1" if arg else "0"]
    if isinstance(arg, int):
        return ["int", str(arg)]
    if isinstance(arg, float):
        return ["float", struct.pack(">d", arg).hex()]
    if isinstance(arg, str):
        return ["str", arg]
    if isinstance(arg, (bytes, bytearray)):
        return ["bytes", bytes(arg).hex()]
    if isinstance(arg, tuple):
        return ["pair", *[str(x) for x in arg]]
    return ["other", repr(arg)]


def arg_reference(samples: list[Sample]) -> dict[str, list[list[str]]]:
    reference: dict[str, list[list[str]]] = {}
    for sample in samples:
        data: bytes = (ROOT / sample.name).read_bytes()
        seq: list[list[str]] = [
            [opcode.name, *canon_arg(opcode.name, arg)]
            for opcode, arg, _pos in pickletools.genops(data)
        ]
        reference[sample.name] = seq
    return dict(sorted(reference.items()))


def render_manifest(samples: list[Sample]) -> str:
    lines: list[str] = [
        'schema = "disrobe-corpus-v1"',
        'category = "pickle"',
        'target_crate = "disrobe-pass-pickle"',
        'fetched_utc = "2026-05-27T00:00:00Z"',
        'notes = """',
        "Pickle fixtures generated by generate.py with CPython 3.14.",
        "Coverage: every benign Python type (int/float/str/bytes/bool/None/list/",
        "dict/tuple/set/frozenset/class-instance) and a __reduce__-bearing",
        "malicious object (os.system) emitted at all six protocols (0-5).",
        "Binaries are gitignored; regenerate with `python corpus/pickle/generate.py`.",
        '"""',
        "",
    ]
    for s in samples:
        lines.extend(
            [
                "[[sample]]",
                f'name = "{s.name}"',
                f'source_tool = "{s.source_tool}"',
                f"size_bytes = {s.size_bytes}",
                f'sha256 = "{s.sha256}"',
                f'notes = "{s.notes}"',
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    samples: list[Sample] = build()
    (ROOT / "MANIFEST.toml").write_text(render_manifest(samples), encoding="utf-8")
    reference: dict[str, list[str]] = opcode_reference(samples)
    (ROOT / "opcode_ref.json").write_text(
        json.dumps(reference, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    args: dict[str, list[list[str]]] = arg_reference(samples)
    (ROOT / "arg_ref.json").write_text(
        json.dumps(args, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {len(samples)} pickle fixtures + MANIFEST.toml"
        f" + opcode_ref.json ({len(reference)} streams)"
        f" + arg_ref.json ({len(args)} streams)"
    )


if __name__ == "__main__":
    main()
