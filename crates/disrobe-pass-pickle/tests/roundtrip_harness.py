"""CPython round-trip differential oracle for the disrobe pickle decompiler.

Two phases share a working directory:

  emit  <dir>              pickle a breadth of real object graphs across
                           protocols 0-5, writing <dir>/<n>.pkl + cases.json.
  grade <dir> <sources>    for each case, unpickle the original with CPython
                           (ground truth), execute the disrobe-emitted Python
                           program, and deep-compare the reconstructed object
                           against the ground truth. Writes results.json.

Ground truth is always CPython's own ``pickle.loads`` of the same bytes; the
comparator never sees disrobe's intermediate representation, so a green score
cannot be circular. Fixture classes are defined at module scope, so when this
file runs as ``__main__`` both the emit and grade phases resolve them and the
disrobe program's ``import __main__`` references bind to the same classes.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import decimal
import fractions
import json
import math
import pickle
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

PROTOCOLS: tuple[int, ...] = (0, 1, 2, 3, 4, 5)


class StateObj:
    def __init__(self: StateObj, a: int = 1, b: str = "two") -> None:
        self.a: int = a
        self.b: str = b
        self.nested: dict[str, Any] = {"x": [a, b]}


class GetSetState:
    def __init__(self: GetSetState, value: int = 0) -> None:
        self.value: int = value
        self.doubled: int = value * 2

    def __getstate__(self: GetSetState) -> dict[str, int]:
        return {"value": self.value}

    def __setstate__(self: GetSetState, state: dict[str, int]) -> None:
        self.value = state["value"]
        self.doubled = state["value"] * 2

    def __eq__(self: GetSetState, other: object) -> bool:
        return isinstance(other, GetSetState) and other.value == self.value

    def __hash__(self: GetSetState) -> int:
        return hash(self.value)


class SlotObj:
    __slots__ = ("p", "q")

    def __init__(self: SlotObj, p: int = 3, q: str = "s") -> None:
        self.p: int = p
        self.q: str = q


@dataclasses.dataclass
class Point3:
    x: int
    y: int
    label: str


NT = collections.namedtuple("NT", ["first", "second", "third"])


def _rebuild_reduce_point(x: int, y: int) -> ReducePoint:
    obj: ReducePoint = ReducePoint.__new__(ReducePoint)
    obj.x = x
    obj.y = y
    return obj


class ReducePoint:
    def __init__(self: ReducePoint, x: int = 0, y: int = 0) -> None:
        self.x: int = x
        self.y: int = y

    def __reduce__(self: ReducePoint) -> tuple[Callable[..., Any], tuple[int, int]]:
        return (_rebuild_reduce_point, (self.x, self.y))

    def __eq__(self: ReducePoint, other: object) -> bool:
        return isinstance(other, ReducePoint) and (other.x, other.y) == (self.x, self.y)

    def __hash__(self: ReducePoint) -> int:
        return hash((self.x, self.y))


class CyclicObj:
    def __init__(self: CyclicObj) -> None:
        self.name: str = "node"
        self.me: CyclicObj | None = None


def _cyclic_list() -> list[Any]:
    box: list[Any] = [1, 2]
    box.append(box)
    return box


def _cyclic_dict() -> dict[str, Any]:
    box: dict[str, Any] = {"tag": "root"}
    box["self"] = box
    return box


def _cyclic_obj() -> CyclicObj:
    node: CyclicObj = CyclicObj()
    node.me = node
    return node


def _shared() -> list[Any]:
    inner: list[int] = [7, 8, 9]
    return [inner, inner, {"ref": inner}]


def _cyclic_deque() -> collections.deque[Any]:
    box: collections.deque[Any] = collections.deque([1, 2])
    box.append(box)
    return box


def cases() -> dict[str, Callable[[], Any]]:
    return {
        "int": lambda: 42,
        "neg_int": lambda: -7,
        "zero": lambda: 0,
        "big_int": lambda: 2**128 + 1,
        "neg_big_int": lambda: -(2**200),
        "float": lambda: 3.14159,
        "float_neg_zero": lambda: -0.0,
        "float_inf": lambda: math.inf,
        "float_nan": lambda: math.nan,
        "bool_true": lambda: True,
        "bool_false": lambda: False,
        "none": lambda: None,
        "str": lambda: "hello é ☃ world",
        "empty_str": lambda: "",
        "str_quotes": lambda: "line'one\nline\"two\ttab\\back",
        "bytes": lambda: b"\x00\x01\x02\xff\xfe",
        "empty_bytes": lambda: b"",
        "bytearray": lambda: bytearray(b"\x00\x10\xff"),
        "complex": lambda: complex(1.5, -2.25),
        "list": lambda: [1, 2, [3, 4], "five", None, True],
        "empty_list": lambda: [],
        "tuple": lambda: (1, "a", (2, 3)),
        "empty_tuple": lambda: (),
        "single_tuple": lambda: (7,),
        "dict": lambda: {"k": {"inner": [1, 2, 3]}, "n": 9, "b": b"x"},
        "empty_dict": lambda: {},
        "int_keyed_dict": lambda: {1: "a", 2: "b", 3: "c"},
        "set": lambda: {1, 2, 3, 4},
        "empty_set": lambda: set(),
        "frozenset": lambda: frozenset({4, 5, 6}),
        "nested_mixed": lambda: {"list": [1, {"s": {1, 2}}], "tup": (frozenset({9}),)},
        "fraction": lambda: fractions.Fraction(22, 7),
        "decimal": lambda: decimal.Decimal("3.14159265358979"),
        "datetime": lambda: datetime.datetime(2020, 1, 2, 3, 4, 5, 678901),
        "date": lambda: datetime.date(1999, 12, 31),
        "time": lambda: datetime.time(23, 59, 58),
        "timedelta": lambda: datetime.timedelta(days=5, seconds=42, microseconds=7),
        "ordered_dict": lambda: collections.OrderedDict([("a", 1), ("b", 2)]),
        "nested_ordered_dict": lambda: collections.OrderedDict(
            [("nums", [1, 2, 3]), ("meta", {"k": "v"}), ("t", (1, 2))]
        ),
        "counter": lambda: collections.Counter("abracadabra"),
        "default_dict": lambda: collections.defaultdict(int, {"x": 1, "y": 2}),
        "nested_default_dict": lambda: collections.defaultdict(
            list, {"a": [1, 2], "b": [3]}
        ),
        "deque": lambda: collections.deque([1, 2, 3]),
        "deque_of_containers": lambda: collections.deque([{"a": 1}, [2, 3], (4,)]),
        "cyclic_deque": _cyclic_deque,
        "state_obj": StateObj,
        "getset_state": lambda: GetSetState(21),
        "slot_obj": SlotObj,
        "dataclass": lambda: Point3(1, -2, "pt"),
        "namedtuple": lambda: NT(10, "mid", [1, 2]),
        "reduce_point": lambda: ReducePoint(4, 5),
        "global_func": lambda: math.gcd,
        "global_class": lambda: collections.OrderedDict,
        "cyclic_list": _cyclic_list,
        "cyclic_dict": _cyclic_dict,
        "cyclic_obj": _cyclic_obj,
        "shared_ref": _shared,
    }


def emit(out_dir: str) -> None:
    root: Path = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    for name, factory in cases().items():
        for proto in PROTOCOLS:
            try:
                data: bytes = pickle.dumps(factory(), protocol=proto)
            except Exception:
                continue
            rel: str = f"{name}__p{proto}.pkl"
            (root / rel).write_bytes(data)
            manifest.append({"file": rel, "name": name, "proto": proto})
    (root / "cases.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"emit: wrote {len(manifest)} pickle fixtures to {out_dir}")


def deep_equal(a: Any, b: Any, seen: set[tuple[int, int]] | None = None) -> bool:
    if seen is None:
        seen = set()
    if a is b:
        return True
    if type(a) is not type(b):
        return False
    if isinstance(a, float):
        if math.isnan(a) and math.isnan(b):
            return True
        return a == b
    if a is None or isinstance(a, (int, str, bytes, bytearray, bool, complex)):
        return a == b
    key: tuple[int, int] = (id(a), id(b))
    if key in seen:
        return True
    seen.add(key)
    if isinstance(a, (list, tuple, collections.deque)):
        return len(a) == len(b) and all(
            deep_equal(x, y, seen) for x, y in zip(a, b)
        )
    if isinstance(a, dict):
        if len(a) != len(b):
            return False
        for k in a:
            if k not in b or not deep_equal(a[k], b[k], seen):
                return False
        return True
    if isinstance(a, (set, frozenset)):
        return a == b
    if type(a).__eq__ is not object.__eq__:
        try:
            return bool(a == b)
        except Exception:
            pass
    da: Any = getattr(a, "__dict__", None)
    db: Any = getattr(b, "__dict__", None)
    if (da is not None or db is not None) and not deep_equal(da or {}, db or {}, seen):
        return False
    slots: list[str] = []
    for klass in type(a).__mro__:
        raw: Any = klass.__dict__.get("__slots__")
        if raw:
            slots.extend((raw,) if isinstance(raw, str) else list(raw))
    for attr in slots:
        if attr in ("__dict__", "__weakref__"):
            continue
        has_a: bool = hasattr(a, attr)
        has_b: bool = hasattr(b, attr)
        if has_a != has_b:
            return False
        if has_a and not deep_equal(getattr(a, attr), getattr(b, attr), seen):
            return False
    return True


def grade(out_dir: str, sources_path: str) -> None:
    root: Path = Path(out_dir)
    manifest: list[dict[str, Any]] = json.loads((root / "cases.json").read_text("utf-8"))
    sources: dict[str, Any] = json.loads(Path(sources_path).read_text("utf-8"))
    results: dict[str, dict[str, str]] = {}
    for entry in manifest:
        rel: str = entry["file"]
        src: dict[str, Any] | None = sources.get(rel)
        if src is None:
            results[rel] = {"status": "excluded", "detail": "no reconstruction emitted"}
            continue
        if not src.get("reexecutable"):
            results[rel] = {"status": "excluded", "detail": src.get("reason", "unsupported")}
            continue
        try:
            original: Any = pickle.loads((root / rel).read_bytes())
        except Exception as exc:
            results[rel] = {"status": "excluded", "detail": f"ground-truth unpickle failed: {exc}"}
            continue
        namespace: dict[str, Any] = {}
        try:
            exec(compile(src["program"], f"<disrobe:{rel}>", "exec"), namespace)
            rebuilt: Any = namespace["result"]
        except Exception:
            results[rel] = {"status": "error", "detail": traceback.format_exc(limit=3)}
            continue
        if deep_equal(rebuilt, original):
            results[rel] = {"status": "ok", "detail": ""}
        else:
            results[rel] = {
                "status": "mismatch",
                "detail": f"repr(original)={original!r} repr(rebuilt)={rebuilt!r}"[:400],
            }
    (root / "results.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"grade: scored {len(results)} cases")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "emit":
        emit(sys.argv[2])
    elif len(sys.argv) >= 4 and sys.argv[1] == "grade":
        grade(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: roundtrip_harness.py emit <dir> | grade <dir> <sources.json>")
