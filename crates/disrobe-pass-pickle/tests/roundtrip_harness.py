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

The comparator checks object identity as well as structural value: whenever
two positions in the CPython-unpickled graph are the same object, the
corresponding positions in disrobe's rebuilt graph must be too (and vice
versa), so silently deep-copying a shared reference or fabricating a shared
one that was not there originally both fail the oracle.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import decimal
import fractions
import io
import json
import math
import pickle
import pickletools
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


class KwArgsObj:
    def __init__(self: KwArgsObj, a: int = 0, b: int = 0) -> None:
        self.a: int = a
        self.b: int = b

    def __getnewargs_ex__(self: KwArgsObj) -> tuple[tuple[()], dict[str, int]]:
        return ((), {"a": self.a, "b": self.b})

    def __eq__(self: KwArgsObj, other: object) -> bool:
        return isinstance(other, KwArgsObj) and (self.a, self.b) == (other.a, other.b)

    def __hash__(self: KwArgsObj) -> int:
        return hash((self.a, self.b))


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


def _shared_object() -> list[Any]:
    obj: GetSetState = GetSetState(99)
    return [obj, obj]


def _shared_frozenset() -> list[Any]:
    fs: frozenset[int] = frozenset({10, 20, 30})
    return [fs, fs, {"fs": fs}]


def _shared_tuple() -> list[Any]:
    pair: tuple[int, list[int]] = (7, [8])
    return [pair, pair, {"tuple": pair}]


def _shared_tuple1() -> list[Any]:
    pair: tuple[list[int]] = ([7],)
    return [pair, pair, {"tuple": pair}]


def _shared_tuple3() -> list[Any]:
    pair: tuple[int, list[int], int] = (7, [8], 9)
    return [pair, pair, {"tuple": pair}]


def _tuple_list_cycle() -> tuple[list[Any]]:
    items: list[Any] = []
    pair: tuple[list[Any]] = (items,)
    items.append(pair)
    return pair


def _memo_overwrite_tuple() -> bytes:
    return bytes.fromhex("80025d7100284b075d71014b086186710268024b63710230652e")


def _dup_shared_list() -> bytes:
    return bytes.fromhex("8002285d7100326c2e")


def _memo_rebind_alias() -> bytes:
    return bytes.fromhex("80025d7100285d71014b08616801710268016802652e")


def _sparse_memoize() -> bytes:
    return bytes.fromhex("80044b2a7105304b63943028680568016c2e")


def _shared_reduce_no_state() -> list[Any]:
    rp: ReducePoint = ReducePoint(11, 22)
    return [rp, rp]


def _distinct_equal_lists() -> list[Any]:
    return [[1, 2], [1, 2]]


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
        "mid_int_binint2": lambda: 1000,
        "large_int_binint": lambda: 100_000,
        "float": lambda: 3.14159,
        "float_neg_zero": lambda: -0.0,
        "float_inf": lambda: math.inf,
        "float_nan": lambda: math.nan,
        "float_large_integral": lambda: 1e16,
        "float_large_integral_neg": lambda: -1e16,
        "float_huge_integral": lambda: 1e300,
        "float_two_pow_53": lambda: float(2**53),
        "float_scaled_integral": lambda: 2.5e16,
        "float_shared": (lambda: (lambda f: [f, f, {"f": f}])(1e17)),
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
        "shared_object": _shared_object,
        "shared_frozenset": _shared_frozenset,
        "shared_tuple": _shared_tuple,
        "shared_tuple1": _shared_tuple1,
        "shared_tuple3": _shared_tuple3,
        "tuple_list_cycle": _tuple_list_cycle,
        "shared_reduce_no_state": _shared_reduce_no_state,
        "distinct_equal_lists": _distinct_equal_lists,
        "newobj_ex_kwargs": lambda: KwArgsObj(3, 4),
        "shared_newobj_ex_kwargs": lambda: (lambda o: [o, o])(KwArgsObj(5, 6)),
        "nan_keyed_dict": lambda: {math.nan: "nan-value", 1: "one"},
        "nan_in_set": lambda: {math.nan, 1, 2},
        "nan_in_frozenset": lambda: frozenset({math.nan, 3}),
    }


def _record_case(
    root: Path,
    manifest: list[dict[str, Any]],
    name: str,
    proto: int,
    data: bytes,
) -> None:
    pickletools_output: io.StringIO = io.StringIO()
    try:
        pickletools.dis(data, out=pickletools_output)
    except ValueError:
        pickletools_output = io.StringIO()
        for opcode, opcode_arg, opcode_pos in pickletools.genops(data):
            if opcode_arg is None:
                pickletools_output.write(f"{opcode_pos}: {opcode.name}\n")
            else:
                pickletools_output.write(f"{opcode_pos}: {opcode.name} {opcode_arg!r}\n")
    opcodes: list[str] = [op.name for op, _, _ in pickletools.genops(data)]
    rel: str = f"{name}__p{proto}.pkl"
    (root / rel).write_bytes(data)
    manifest.append(
        {
            "file": rel,
            "name": name,
            "proto": proto,
            "opcodes": opcodes,
            "pickletools_dis": pickletools_output.getvalue(),
        }
    )


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
            _record_case(root, manifest, name, proto, data)
    overwrite: bytes = _memo_overwrite_tuple()
    loaded: list[Any] = pickle.loads(overwrite)
    if loaded[0] is not loaded[1]:
        raise RuntimeError("CPython did not preserve the overwritten memo snapshot")
    _record_case(root, manifest, "memo_overwrite_tuple", 2, overwrite)
    duplicated: bytes = _dup_shared_list()
    duplicated_loaded: list[Any] = pickle.loads(duplicated)
    if duplicated_loaded[0] is not duplicated_loaded[1]:
        raise RuntimeError("CPython did not preserve the DUP memo alias")
    _record_case(root, manifest, "dup_shared_list", 2, duplicated)
    rebound: bytes = _memo_rebind_alias()
    rebound_loaded: list[Any] = pickle.loads(rebound)
    if any(rebound_loaded[0] is not item for item in rebound_loaded[1:]):
        raise RuntimeError("CPython did not preserve the rebound memo alias")
    _record_case(root, manifest, "memo_rebind_alias", 2, rebound)
    sparse: bytes = _sparse_memoize()
    if pickle.loads(sparse) != [42, 99]:
        raise RuntimeError("CPython did not assign MEMOIZE by memo entry count")
    _record_case(root, manifest, "sparse_memoize", 4, sparse)
    (root / "cases.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"emit: wrote {len(manifest)} pickle fixtures to {out_dir}")


def compare(a: Any, b: Any) -> str | None:
    """Structural-and-identity comparator: `None` on success, else a
    human-readable path to the first divergence. Two positions that share
    identity in `a` must share identity in `b` (aliasing preserved) and two
    positions that do NOT share identity in `a` must not in `b` either
    (no fabricated sharing), on top of ordinary structural equality.
    """

    a_to_b: dict[int, int] = {}
    b_owner: dict[int, int] = {}

    def trackable(x: Any) -> bool:
        return not (
            x is None or isinstance(x, (int, float, str, bytes, bytearray, bool, complex))
        )

    def rec(x: Any, y: Any, path: str) -> str | None:
        if trackable(x) and trackable(y):
            idx, idy = id(x), id(y)
            prior_y: int | None = a_to_b.get(idx)
            if prior_y is not None:
                if prior_y != idy:
                    return f"{path}: original object recurs but the rebuilt graph gives it a second, distinct object (lost sharing)"
                return None
            prior_owner: int | None = b_owner.get(idy)
            if prior_owner is not None:
                return f"{path}: rebuilt object is aliased to two different original objects (fabricated sharing)"
            a_to_b[idx] = idy
            b_owner[idy] = idx
        if type(x) is not type(y):
            return f"{path}: type {type(x).__name__} != {type(y).__name__}"
        if isinstance(x, float):
            if math.isnan(x) and math.isnan(y):
                return None
            return None if x == y else f"{path}: float {x!r} != {y!r}"
        if x is None or isinstance(x, (int, str, bytes, bytearray, bool, complex)):
            return None if x == y else f"{path}: value {x!r} != {y!r}"
        if isinstance(x, (list, tuple, collections.deque)):
            if len(x) != len(y):
                return f"{path}: length {len(x)} != {len(y)}"
            for i, (xi, yi) in enumerate(zip(x, y)):
                err: str | None = rec(xi, yi, f"{path}[{i}]")
                if err is not None:
                    return err
            return None
        if isinstance(x, dict):
            if len(x) != len(y):
                return f"{path}: dict size {len(x)} != {len(y)}"
            for i, ((xk, xv), (yk, yv)) in enumerate(zip(x.items(), y.items())):
                err = rec(xk, yk, f"{path} key#{i}")
                if err is not None:
                    return err
                err = rec(xv, yv, f"{path}[{xk!r}]")
                if err is not None:
                    return err
            return None
        if isinstance(x, (set, frozenset)):
            if len(x) != len(y):
                return f"{path}: size {len(x)} != {len(y)}"
            is_nan: Callable[[Any], bool] = lambda v: isinstance(v, float) and math.isnan(v)
            x_nan_count: int = sum(1 for v in x if is_nan(v))
            y_nan_count: int = sum(1 for v in y if is_nan(v))
            if x_nan_count != y_nan_count:
                return f"{path}: nan-element count {x_nan_count} != {y_nan_count}"
            x_rest: set[Any] = {v for v in x if not is_nan(v)}
            y_rest: set[Any] = {v for v in y if not is_nan(v)}
            return None if x_rest == y_rest else f"{path}: {x!r} != {y!r}"
        if type(x).__eq__ is not object.__eq__:
            try:
                return None if bool(x == y) else f"{path}: {x!r} != {y!r}"
            except Exception:
                pass
        dx: Any = getattr(x, "__dict__", None)
        dy: Any = getattr(y, "__dict__", None)
        if dx is not None or dy is not None:
            err = rec(dx or {}, dy or {}, f"{path}.__dict__")
            if err is not None:
                return err
        slots: list[str] = []
        for klass in type(x).__mro__:
            raw: Any = klass.__dict__.get("__slots__")
            if raw:
                slots.extend((raw,) if isinstance(raw, str) else list(raw))
        for attr in slots:
            if attr in ("__dict__", "__weakref__"):
                continue
            has_x: bool = hasattr(x, attr)
            has_y: bool = hasattr(y, attr)
            if has_x != has_y:
                return f"{path}.{attr}: presence {has_x} != {has_y}"
            if has_x:
                err = rec(getattr(x, attr), getattr(y, attr), f"{path}.{attr}")
                if err is not None:
                    return err
        return None

    return rec(a, b, "root")


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
        divergence: str | None = compare(original, rebuilt)
        if divergence is None:
            results[rel] = {"status": "ok", "detail": ""}
        else:
            results[rel] = {
                "status": "mismatch",
                "detail": f"{divergence} | repr(original)={original!r} repr(rebuilt)={rebuilt!r}"[:500],
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
