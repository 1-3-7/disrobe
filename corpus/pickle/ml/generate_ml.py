"""Generate the disrobe pickle model-container fixtures and their CPython reference.

Run: python corpus/pickle/ml/generate_ml.py

Writes container binaries plus stream_ref.json into this directory. Every member
boundary in stream_ref.json is measured by CPython's own unpickler: the file
handle sits exactly after a member's STOP once ``Unpickler.load`` returns, which
is the same property torch._legacy_load relies on to read five stacked pickles
from one handle.

This script never touches corpus/pickle/MANIFEST.toml, opcode_ref.json or
arg_ref.json, and never writes a .pkl file, so the pinned pickle corpus figure
cannot move because of it.
"""

from __future__ import annotations

import hashlib
import io
import json
import pickle
import pickletools
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Final

ROOT: Final[Path] = Path(__file__).resolve().parent

TORCH_MAGIC_NUMBER: Final[int] = 0x1950A86A20F9469CFC6C
TORCH_PROTOCOL_VERSION: Final[int] = 1001
TORCH_DEFAULT_PROTOCOL: Final[int] = 2


class PersistentStorage:
    """Stands in for a torch storage: the pickler replaces it with a persistent id."""

    def __init__(self: PersistentStorage, key: str, numel: int) -> None:
        self.key: str = key
        self.numel: int = numel


class StoragePickler(pickle.Pickler):
    def persistent_id(self: StoragePickler, obj: Any) -> tuple[str, str, str, str, int] | None:
        if isinstance(obj, PersistentStorage):
            return ("storage", "torch.FloatStorage", obj.key, "cpu", obj.numel)
        return None


class StorageUnpickler(pickle.Unpickler):
    def persistent_load(self: StorageUnpickler, pid: object) -> object:
        return pid


@dataclass(frozen=True)
class Member:
    offset: int
    length: int
    protocol: int
    first_dot_length: int | None


@dataclass(frozen=True)
class Fixture:
    name: str
    fmt: str
    data: bytes
    members: tuple[Member, ...]
    trailing_bytes: int
    note: str


def measured_protocol(member: bytes) -> int:
    """Protocol as CPython reports it: the PROTO opcode argument, else 0."""
    for opcode, arg, _pos in pickletools.genops(member):
        if opcode.name == "PROTO":
            return int(arg) if isinstance(arg, int) else 0
        break
    return 0


def first_dot_length(member: bytes) -> int | None:
    """Length a first-``.``-byte scan would report, or None when it agrees with STOP."""
    index: int = member.find(b".")
    if index < 0 or index + 1 == len(member):
        return None
    return index + 1


def measure_members(data: bytes, expected: int) -> tuple[tuple[Member, ...], int]:
    """Walk successive pickle streams with CPython and record their real spans."""
    handle: io.BytesIO = io.BytesIO(data)
    members: list[Member] = []
    for _ in range(expected):
        start: int = handle.tell()
        StorageUnpickler(handle).load()
        end: int = handle.tell()
        body: bytes = data[start:end]
        if body[-1:] != b".":
            raise AssertionError(f"member at {start} does not end on a STOP opcode")
        members.append(
            Member(
                offset=start,
                length=end - start,
                protocol=measured_protocol(body),
                first_dot_length=first_dot_length(body),
            )
        )
    return tuple(members), len(data) - handle.tell()


def legacy_container(protocol: int, storage_payload: bytes) -> bytes:
    """The five stacked pickles of torch/serialization.py `_legacy_save`, then storage."""
    handle: BinaryIO = io.BytesIO()
    pickle.dump(TORCH_MAGIC_NUMBER, handle, protocol=protocol)
    pickle.dump(TORCH_PROTOCOL_VERSION, handle, protocol=protocol)
    sys_info: dict[str, Any] = {
        "protocol_version": TORCH_PROTOCOL_VERSION,
        "little_endian": True,
        "type_sizes": {"short": 2, "int": 4, "long": 8},
    }
    pickle.dump(sys_info, handle, protocol=protocol)
    state: dict[str, Any] = {
        "fc.weight": PersistentStorage("0", 4),
        "fc.bias": PersistentStorage("1", 2),
    }
    StoragePickler(handle, protocol=protocol).dump({"state_dict": state})
    pickle.dump(sorted(("0", "1")), handle, protocol=protocol)
    body: bytes = handle.getvalue()
    return body + storage_payload


def storage_region() -> bytes:
    """Opaque bytes standing in for the raw tensor region after the pickle members."""
    out: bytearray = bytearray()
    for numel, seed in ((4, 1.0), (2, -2.5)):
        out += struct.pack("<q", numel)
        out += b"".join(struct.pack("<f", seed + index) for index in range(numel))
    return bytes(out)


def npy_object_array(body: bytes) -> bytes:
    """A numpy .npy v1.0 object array: spec header, then a pickle stream as the body."""
    header: bytes = (
        b"{'descr': '|O', 'fortran_order': False, 'shape': (2,), }"
    )
    prelude: int = 10 + len(header) + 1
    pad: int = (64 - prelude % 64) % 64
    declared: int = len(header) + pad + 1
    out: bytearray = bytearray(b"\x93NUMPY\x01\x00")
    out += struct.pack("<H", declared)
    out += header
    out += b" " * pad
    out += b"\n"
    out += body
    return bytes(out)


def build() -> list[Fixture]:
    fixtures: list[Fixture] = []

    payload: bytes = storage_region()
    for protocol in (TORCH_DEFAULT_PROTOCOL, 0):
        data: bytes = legacy_container(protocol, payload)
        members, trailing = measure_members(data, 5)
        if trailing != len(payload):
            raise AssertionError(
                f"five members plus {len(payload)} storage bytes must account for the file, "
                f"CPython left {trailing}"
            )
        fixtures.append(
            Fixture(
                name=f"legacy_torch_p{protocol}.pt",
                fmt="py_torch_stacked_pickle",
                data=data,
                members=members,
                trailing_bytes=trailing,
                note=(
                    f"legacy torch.save container layout at pickle protocol {protocol}: magic "
                    "number, protocol version, sys_info, the persistent-id-bearing module "
                    "pickle and the storage-key list, then an opaque storage region"
                ),
            )
        )

    array_body: bytes = pickle.dumps(
        ["collections.OrderedDict", "torch.nn.modules.linear.Linear"], protocol=2
    )
    npy: bytes = npy_object_array(array_body)
    npy_members, npy_trailing = measure_members(npy[len(npy) - len(array_body) :], 1)
    offset: int = len(npy) - len(array_body)
    fixtures.append(
        Fixture(
            name="object_array.npy",
            fmt="numpy_npy",
            data=npy,
            members=(
                Member(
                    offset=offset,
                    length=npy_members[0].length,
                    protocol=npy_members[0].protocol,
                    first_dot_length=npy_members[0].first_dot_length,
                ),
            ),
            trailing_bytes=npy_trailing,
            note="numpy .npy v1.0 object array whose body is a single pickle stream",
        )
    )

    trailer: bytes = b"\xaa" * 24
    bare: bytes = pickle.dumps({"path": "os.path", "value": 7}, protocol=4) + trailer
    bare_members, bare_trailing = measure_members(bare, 1)
    fixtures.append(
        Fixture(
            name="bare_pickle_trailer.bin",
            fmt="bare_pickle",
            data=bare,
            members=bare_members,
            trailing_bytes=bare_trailing,
            note=(
                "one pickle stream followed by 24 trailing bytes: a single member is not a "
                "stacked container, and the reported length is the stream, not the file"
            ),
        )
    )

    return fixtures


def discriminating(fixtures: list[Fixture]) -> int:
    total: int = 0
    for fixture in fixtures:
        for member in fixture.members:
            if member.first_dot_length is not None:
                total += 1
    return total


def render_reference(fixtures: list[Fixture]) -> str:
    document: dict[str, Any] = {
        "schema": "disrobe-pickle-ml-ref/v1",
        "measured_by": (
            "CPython pickle.Unpickler: the handle sits immediately after a member's STOP once "
            "load() returns, so successive load() calls give the real member spans"
        ),
        "python": f"CPython {'.'.join(str(part) for part in sys.version_info[:3])}",
        "fixtures": {
            fixture.name: {
                "format": fixture.fmt,
                "size_bytes": len(fixture.data),
                "sha256": hashlib.sha256(fixture.data).hexdigest(),
                "trailing_bytes": fixture.trailing_bytes,
                "note": fixture.note,
                "members": [
                    {
                        "offset": member.offset,
                        "length": member.length,
                        "protocol": member.protocol,
                        "first_dot_length": member.first_dot_length,
                    }
                    for member in fixture.members
                ],
            }
            for fixture in sorted(fixtures, key=lambda fixture: fixture.name)
        },
    }
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def main() -> None:
    fixtures: list[Fixture] = build()
    if discriminating(fixtures) == 0:
        raise AssertionError(
            "no member carries a 0x2e byte before its STOP, so these fixtures cannot tell a "
            "real end-of-stream walk apart from a first-dot scan"
        )
    for fixture in fixtures:
        (ROOT / fixture.name).write_bytes(fixture.data)
    (ROOT / "stream_ref.json").write_text(render_reference(fixtures), encoding="utf-8")
    members: int = sum(len(fixture.members) for fixture in fixtures)
    print(
        f"wrote {len(fixtures)} model-container fixtures ({members} pickle members, "
        f"{discriminating(fixtures)} of them defeat a first-dot scan) + stream_ref.json"
    )


if __name__ == "__main__":
    main()
