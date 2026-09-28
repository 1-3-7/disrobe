"""Trusted ground truth for the fail-closed pickle fixtures.

Run: python find_class_harness.py <fixture-dir>

Reads <fixture-dir>/provenance.toml, checks every fixture's sha256, and prints
one JSON document naming every callable a real CPython unpickler requests from
each fixture. The unpickler's find_class records the (module, name) pair and
returns an inert stub, so no real callable is ever resolved or called. The
file is read as stacked streams from offset 0, then from each offset the
provenance declares, and every bytes value a load yields is itself loaded the
same way, as a consumer calling pickle.loads on it would.
"""

from __future__ import annotations

import hashlib
import io
import json
import pickle
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Any

MAX_NESTED_DEPTH: int = 3
MAX_WALK_NODES: int = 100_000


class Stub:
    def __init__(self, qualified: str) -> None:
        self.qualified: str = qualified

    def __call__(self, *args: Any, **kwargs: Any) -> "Stub":
        return Called(self.qualified, args, kwargs)


class Called(Stub):
    def __init__(self, qualified: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        super().__init__(f"{qualified}()")
        self.args: tuple[Any, ...] = args
        self.kwargs: dict[str, Any] = kwargs


class RecordingUnpickler(pickle.Unpickler):
    def __init__(self, stream: io.BytesIO, requested: list[str]) -> None:
        super().__init__(stream)
        self.requested: list[str] = requested

    def find_class(self, module: str, name: str) -> Stub:
        qualified: str = f"{module}.{name}"
        self.requested.append(qualified)
        return Stub(qualified)


def load_one(stream: io.BytesIO) -> tuple[list[str], Any, str | None]:
    requested: list[str] = []
    try:
        value: Any = RecordingUnpickler(stream, requested).load()
    except Exception as error:
        return requested, None, f"{type(error).__name__}: {error}"
    return requested, value, None


def bytes_values(value: Any) -> list[bytes]:
    found: list[bytes] = []
    pending: list[Any] = [value]
    seen: set[int] = set()
    visited: int = 0
    while pending and visited < MAX_WALK_NODES:
        item: Any = pending.pop()
        visited += 1
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, (bytes, bytearray)):
            found.append(bytes(item))
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            pending.extend(item)
        elif isinstance(item, Called):
            pending.extend(item.args)
            pending.append(item.kwargs)
    return found


def nested_loads(value: Any, depth: int) -> list[dict[str, Any]]:
    if depth >= MAX_NESTED_DEPTH:
        return []
    results: list[dict[str, Any]] = []
    for blob in bytes_values(value):
        requested, inner, error = load_one(io.BytesIO(blob))
        results.append({"depth": depth + 1, "callables": requested, "error": error})
        results.extend(nested_loads(inner, depth + 1))
    return results


def stacked_streams(data: bytes) -> tuple[list[dict[str, Any]], list[Any], dict[str, Any]]:
    stream: io.BytesIO = io.BytesIO(data)
    streams: list[dict[str, Any]] = []
    values: list[Any] = []
    while stream.tell() < len(data):
        start: int = stream.tell()
        requested, value, error = load_one(stream)
        if error is not None:
            return streams, values, {
                "offset": start,
                "remaining": len(data) - start,
                "error": error,
                "callables": requested,
            }
        streams.append({"offset": start, "end": stream.tell(), "callables": requested})
        values.append(value)
    return streams, values, {"offset": len(data), "remaining": 0, "error": None, "callables": []}


def zip_members(path: Path) -> list[str] | None:
    if not zipfile.is_zipfile(path):
        return None
    with zipfile.ZipFile(path) as archive:
        return archive.namelist()


def examine(path: Path, declared: list[int]) -> dict[str, Any]:
    data: bytes = path.read_bytes()
    streams, values, end = stacked_streams(data)
    declared_loads: list[dict[str, Any]] = []
    for offset in declared:
        requested, value, error = load_one(io.BytesIO(data[offset:]))
        declared_loads.append({"offset": offset, "callables": requested, "error": error})
        values.append(value)
    nested: list[dict[str, Any]] = []
    for value in values:
        nested.extend(nested_loads(value, 0))
    requested_all: set[str] = set(end["callables"])
    for group in (streams, declared_loads, nested):
        for entry in group:
            requested_all.update(entry["callables"])
    return {
        "streams": streams,
        "end": end,
        "declared": declared_loads,
        "nested": nested,
        "zip_members": zip_members(path),
        "requested": sorted(requested_all),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: find_class_harness.py <fixture-dir>", file=sys.stderr)
        return 2
    root: Path = Path(argv[1])
    provenance: dict[str, Any] = tomllib.loads((root / "provenance.toml").read_text(encoding="utf-8"))
    report: dict[str, Any] = {}
    for fixture in provenance["fixtures"]:
        path: Path = root / fixture["file"]
        digest: str = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != fixture["sha256"]:
            print(f"{fixture['file']}: sha256 {digest} does not match provenance {fixture['sha256']}", file=sys.stderr)
            return 1
        entry: dict[str, Any] = examine(path, list(fixture.get("pickle_offsets", [])))
        if entry["requested"] != fixture["requested"]:
            print(f"{fixture['file']}: requests {entry['requested']}, provenance records {fixture['requested']}", file=sys.stderr)
            return 1
        entry["sha256"] = digest
        report[fixture["file"]] = entry
    json.dump(report, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
