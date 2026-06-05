"""Generate one self-contained .py fixture per Python construct family.

Each fixture compiles standalone on its declared minimum version. The Rust
per-construct round-trip harness compiles every fixture with every installed
interpreter at or above its floor, then drives the decompiler round-trip metric
per construct so recovery is attributable to a single language feature.
"""

from __future__ import annotations

import sys
from pathlib import Path

OUT: Path = Path(__file__).resolve().parent / "cases"

CASES: dict[str, tuple[tuple[int, int], str]] = {}


def case(name: str, floor: tuple[int, int], body: str) -> None:
    CASES[name] = (floor, body.strip("\n") + "\n")


case(
    "expr_arith",
    (3, 8),
    """
def f(a, b, c):
    return a + b * c - a // b % c
""",
)

case(
    "expr_bitwise",
    (3, 8),
    """
def f(a, b):
    return (a | b) & (a ^ b) << 2 >> 1
""",
)

case(
    "expr_compare_chain",
    (3, 8),
    """
def f(a, b, c):
    return 0 <= a < b <= c < 100
""",
)

case(
    "expr_bool_shortcircuit",
    (3, 8),
    """
def f(a, b, c):
    return a or b or c
""",
)

case(
    "expr_bool_mixed",
    (3, 8),
    """
def f(a, b, c, d):
    return (a and b) or (c and not d)
""",
)

case(
    "expr_unary",
    (3, 8),
    """
def f(x):
    return -x + ~x + (not x)
""",
)

case(
    "expr_ternary",
    (3, 8),
    """
def f(flag, a, b):
    return a if flag else b
""",
)

case(
    "expr_ternary_nested",
    (3, 8),
    """
def f(x):
    return "neg" if x < 0 else ("zero" if x == 0 else "pos")
""",
)

case(
    "expr_subscript",
    (3, 8),
    """
def f(d, k):
    return d[k]
""",
)

case(
    "expr_attr_chain",
    (3, 8),
    """
def f(o):
    return o.a.b.c
""",
)

case(
    "slice_basic",
    (3, 8),
    """
def f(seq):
    return seq[1:10]
""",
)

case(
    "slice_step",
    (3, 8),
    """
def f(seq):
    return seq[1:10:2]
""",
)

case(
    "slice_open",
    (3, 8),
    """
def f(seq):
    return seq[:] + seq[1:] + seq[:-1] + seq[::2] + seq[::-1]
""",
)

case(
    "call_positional",
    (3, 8),
    """
def f(g, a, b):
    return g(a, b, 1, 2)
""",
)

case(
    "call_keyword",
    (3, 8),
    """
def f(g):
    return g(a=1, b=2, c=3)
""",
)

case(
    "call_star",
    (3, 8),
    """
def f(g, args):
    return g(*args, 1)
""",
)

case(
    "call_doublestar",
    (3, 8),
    """
def f(g, kw):
    return g(**kw, x=1)
""",
)

case(
    "call_star_double_mix",
    (3, 8),
    """
def f(g, a, kw):
    return g(*a, x=1, **kw)
""",
)

case(
    "literal_list",
    (3, 8),
    """
def f(a, b):
    return [a, b, 1, 2]
""",
)

case(
    "literal_tuple",
    (3, 8),
    """
def f(a, b):
    return (a, b, 1, 2)
""",
)

case(
    "literal_set",
    (3, 8),
    """
def f(a, b):
    return {a, b, 1, 2}
""",
)

case(
    "literal_dict",
    (3, 8),
    """
def f(a, b):
    return {"a": a, "b": b, 1: 2}
""",
)

case(
    "literal_starred_list",
    (3, 8),
    """
def f(prefix, suffix):
    return [*prefix, 0, *suffix]
""",
)

case(
    "literal_dict_merge",
    (3, 8),
    """
def f(a, b):
    return {**a, **b, "extra": 1}
""",
)

case(
    "assign_simple",
    (3, 8),
    """
def f(x):
    a = x
    b = a
    return b
""",
)

case(
    "assign_chained",
    (3, 8),
    """
def f(x):
    a = b = c = x
    return a + b + c
""",
)

case(
    "assign_tuple_unpack",
    (3, 8),
    """
def f(values):
    a, b, c = values
    return c, b, a
""",
)

case(
    "assign_starred_unpack",
    (3, 8),
    """
def f(data):
    first, *middle, last = data
    return first, middle, last
""",
)

case(
    "assign_aug_all",
    (3, 8),
    """
def f():
    total = 0
    total += 5
    total -= 1
    total *= 2
    total //= 3
    total %= 100
    total <<= 1
    total |= 16
    return total
""",
)

case(
    "assign_annotated",
    (3, 8),
    """
def f(x):
    a: int = x
    b: list = [a]
    return a
""",
)

case(
    "del_simple",
    (3, 8),
    """
def f(store):
    temp = dict(store)
    del temp["key"]
    return len(temp)
""",
)

case(
    "del_multiple",
    (3, 8),
    """
def f():
    a = 1
    b = 2
    del a, b
    return 0
""",
)

case(
    "if_simple",
    (3, 8),
    """
def f(x):
    if x > 0:
        return 1
    return 0
""",
)

case(
    "if_else",
    (3, 8),
    """
def f(x):
    if x > 0:
        return 1
    else:
        return -1
""",
)

case(
    "if_elif_else",
    (3, 8),
    """
def f(x):
    if x > 10:
        return 3
    elif x > 5:
        return 2
    elif x > 0:
        return 1
    else:
        return 0
""",
)

case(
    "if_nested",
    (3, 8),
    """
def f(x, y):
    if x > 0:
        if y > 0:
            return 1
        return 2
    return 0
""",
)

case(
    "for_simple",
    (3, 8),
    """
def f(items):
    total = 0
    for it in items:
        total += it
    return total
""",
)

case(
    "for_unpack",
    (3, 8),
    """
def f(pairs):
    total = 0
    for a, b in pairs:
        total += a * b
    return total
""",
)

case(
    "for_else",
    (3, 8),
    """
def f(items, target):
    for it in items:
        if it == target:
            return True
    else:
        return False
""",
)

case(
    "for_break_continue",
    (3, 8),
    """
def f(values):
    total = 0
    for v in values:
        if v == 0:
            continue
        if v < 0:
            break
        total += v
    return total
""",
)

case(
    "for_nested",
    (3, 8),
    """
def f(matrix, needle):
    for i, row in enumerate(matrix):
        for j, cell in enumerate(row):
            if cell == needle:
                return (i, j)
    return None
""",
)

case(
    "while_simple",
    (3, 8),
    """
def f(n):
    i = 0
    while i < n:
        i += 1
    return i
""",
)

case(
    "while_else",
    (3, 8),
    """
def f(n):
    i = 0
    while i < n:
        if i == 5:
            break
        i += 1
    else:
        return -1
    return i
""",
)

case(
    "while_true_break",
    (3, 8),
    """
def f(queue):
    while True:
        if not queue:
            break
        item = queue.pop()
        if item < 0:
            return item
    return 0
""",
)

case(
    "while_compound_cond",
    (3, 8),
    """
def f(data):
    total = 0
    idx = 0
    while idx < len(data) and data[idx] >= 0:
        total += data[idx]
        idx += 1
    return total
""",
)

case(
    "try_except",
    (3, 8),
    """
def f(value):
    try:
        return int(value)
    except ValueError as exc:
        print(exc)
        return -1
""",
)

case(
    "try_except_else",
    (3, 8),
    """
def f(mapping, key):
    try:
        raw = mapping[key]
    except KeyError:
        return 0
    else:
        return raw * 2
""",
)

case(
    "try_finally",
    (3, 8),
    """
def f(resource):
    try:
        resource.append(1)
        return sum(resource)
    finally:
        resource.clear()
""",
)

case(
    "try_except_finally",
    (3, 8),
    """
def f(path):
    handle = None
    try:
        handle = path.upper()
        return handle
    except (TypeError, AttributeError):
        return None
    finally:
        print(handle)
""",
)

case(
    "try_except_else_finally",
    (3, 8),
    """
def f(items):
    total = 0
    try:
        for it in items:
            total += it
    except OverflowError:
        total = -1
    else:
        total += 100
    finally:
        print(total)
    return total
""",
)

case(
    "try_multi_except",
    (3, 8),
    """
def f(token):
    try:
        return str(int(token))
    except ValueError:
        return "nan"
    except TypeError:
        return "wrong-type"
    except (KeyError, IndexError):
        return "lookup-failed"
    except Exception:
        return "unknown"
""",
)

case(
    "try_bare_reraise",
    (3, 8),
    """
def f(g):
    try:
        g()
    except:
        print("cleanup")
        raise
""",
)

case(
    "raise_from",
    (3, 8),
    """
def f(cause):
    raise RuntimeError("wrapped") from cause
""",
)

case(
    "with_simple",
    (3, 8),
    """
def f(lock):
    with lock:
        print("inside")
""",
)

case(
    "with_as",
    (3, 8),
    """
def f(opener):
    with opener() as handle:
        return handle + 1
""",
)

case(
    "with_multi",
    (3, 8),
    """
def f(a, b):
    with a as x, b as y:
        return x + y
""",
)

case(
    "with_nested",
    (3, 8),
    """
def f(outer, inner, payload):
    with outer:
        with inner:
            return payload[::-1]
""",
)

case(
    "fstring_simple",
    (3, 8),
    """
def f(name, count):
    return f"{name}: {count}"
""",
)

case(
    "fstring_conversions",
    (3, 8),
    """
def f(name, count, ratio):
    return f"{name!r}: {count:04d} @ {ratio:.2%}"
""",
)

case(
    "fstring_self_doc",
    (3, 8),
    """
def f(count, ratio):
    return f"{count=}, {ratio=:.1f}"
""",
)

case(
    "fstring_concat",
    (3, 8),
    """
def f(x, width):
    return f"{x:{width}.2f}" + f"{x!r:>{width}}"
""",
)

case(
    "lambda_simple",
    (3, 8),
    """
def f(items):
    return sorted(items, key=lambda kv: (kv[1], kv[0]))
""",
)

case(
    "lambda_filter",
    (3, 8),
    """
def f(items):
    return list(filter(lambda kv: kv[1] > 0, items))
""",
)

case(
    "comp_list",
    (3, 8),
    """
def f(matrix):
    return [cell for row in matrix for cell in row if cell > 0]
""",
)

case(
    "comp_set",
    (3, 8),
    """
def f(matrix):
    return {cell for row in matrix for cell in row}
""",
)

case(
    "comp_dict",
    (3, 8),
    """
def f(d):
    return {k: v * 2 for k, v in d.items() if v > 0}
""",
)

case(
    "comp_gen",
    (3, 8),
    """
def f(values):
    return sum(v * v for v in values if v % 2)
""",
)

case(
    "comp_nested",
    (3, 8),
    """
def f(matrix):
    return [[c + 1 for c in row] for row in matrix]
""",
)

case(
    "comp_multi_if",
    (3, 8),
    """
def f(m):
    return [x * y for x in m for y in m if x != y if x + y < 10]
""",
)

case(
    "def_defaults",
    (3, 8),
    """
def f(a, b=10, c="x"):
    return a + b
""",
)

case(
    "def_full_signature",
    (3, 8),
    """
def f(pos1, pos2, /, normal=1.0, *args, kw_only=False, required_kw, **kwargs):
    return (pos1, pos2, normal, args, kw_only, required_kw, kwargs)
""",
)

case(
    "def_kwonly",
    (3, 8),
    """
def f(a, *, b, c=3):
    return a + b + c
""",
)

case(
    "def_annotations",
    (3, 8),
    """
def f(a: int, b: str = "x") -> bool:
    return bool(a)
""",
)

case(
    "def_nested_closure",
    (3, 8),
    """
def f():
    accumulator = 0
    def add(delta):
        nonlocal accumulator
        accumulator += delta
        return accumulator
    return add
""",
)

case(
    "def_nested_levels",
    (3, 8),
    """
def f(base):
    def level_one(a):
        def level_two(b):
            return base + a + b
        return level_two(2)
    return level_one(1)
""",
)

case(
    "def_global",
    (3, 8),
    """
counter = 0
def f():
    global counter
    counter += 1
    return counter
""",
)

case(
    "gen_yield",
    (3, 8),
    """
def f(limit):
    for i in range(limit):
        if i % 3 == 0:
            yield i
""",
)

case(
    "gen_yield_from",
    (3, 8),
    """
def f(xs):
    yield from xs
    yield 99
""",
)

case(
    "gen_yield_value",
    (3, 8),
    """
def f(n):
    total = 0
    for i in range(n):
        total += i
        yield total
""",
)

case(
    "decorator_simple",
    (3, 8),
    """
import functools

@functools.lru_cache(maxsize=128)
def f(n):
    return n * n
""",
)

case(
    "decorator_stacked",
    (3, 8),
    """
def deco(fn):
    return fn

@deco
@deco
def f(x):
    return x * 2
""",
)

case(
    "decorator_factory",
    (3, 8),
    """
import functools

def factory(prefix):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return decorate
""",
)

case(
    "class_simple",
    (3, 8),
    """
class C:
    def __init__(self, x):
        self.x = x
    def get(self):
        return self.x
""",
)

case(
    "class_inheritance",
    (3, 8),
    """
class Base:
    def __init__(self, name):
        self.name = name
    def describe(self):
        return self.name

class Derived(Base):
    def __init__(self, name, level):
        super().__init__(name)
        self.level = level
    def describe(self):
        return super().describe() + str(self.level)
""",
)

case(
    "class_properties",
    (3, 8),
    """
class C:
    def __init__(self):
        self._value = 0
    @property
    def value(self):
        return self._value
    @value.setter
    def value(self, new):
        self._value = max(0, new)
""",
)

case(
    "class_methods",
    (3, 8),
    """
class C:
    @classmethod
    def origin(cls):
        return cls()
    @staticmethod
    def helper(a, b):
        return a + b
""",
)

case(
    "class_slots",
    (3, 8),
    """
class C:
    __slots__ = ("x", "y")
    def __init__(self, x, y):
        self.x = x
        self.y = y
""",
)

case(
    "walrus_if",
    (3, 8),
    """
def f(data):
    if (name := data.get("name")) is not None:
        return name.upper()
    return "anon"
""",
)

case(
    "walrus_while",
    (3, 8),
    """
def f(stream):
    total = 0
    while chunk := next(stream, b""):
        total += len(chunk)
    return total
""",
)

case(
    "walrus_comprehension",
    (3, 8),
    """
def f(xs):
    return [y for x in xs if (y := x * 2) > 4]
""",
)

case(
    "walrus_call_arg",
    (3, 8),
    """
def f(data):
    return process(n) if (n := len(data)) > 0 else 0
""",
)

case(
    "async_await",
    (3, 8),
    """
async def f(client):
    token = await client.authenticate()
    data = await client.read(token)
    return data
""",
)

case(
    "async_for",
    (3, 8),
    """
async def f(stream):
    acc = 0
    async for chunk in stream:
        acc += chunk
    return acc
""",
)

case(
    "async_with",
    (3, 8),
    """
async def f(lock):
    async with lock:
        return 1
""",
)

case(
    "async_gen",
    (3, 8),
    """
async def f(source):
    async for item in source:
        if item % 2 == 0:
            yield item * 10
""",
)

case(
    "async_comprehension",
    (3, 8),
    """
async def f(ids, fetch):
    return [await fetch(i) for i in ids if i > 0]
""",
)

case(
    "match_literal",
    (3, 10),
    """
def f(token):
    match token:
        case 0:
            return "zero"
        case "init":
            return "literal-string"
        case None:
            return "literal-none"
        case _:
            return "other"
""",
)

case(
    "match_capture",
    (3, 10),
    """
def f(value):
    match value:
        case 0:
            return "zero"
        case captured:
            return captured
""",
)

case(
    "match_or",
    (3, 10),
    """
def f(token):
    match token:
        case 1 | 2 | 3:
            return "small"
        case _:
            return "other"
""",
)

case(
    "match_sequence",
    (3, 10),
    """
def f(seq):
    match seq:
        case []:
            return "empty"
        case [single]:
            return single
        case [first, *middle, last]:
            return (first, middle, last)
        case _:
            return "other"
""",
)

case(
    "match_mapping",
    (3, 10),
    """
def f(event):
    match event:
        case {"type": "click", "x": x, "y": y}:
            return (x, y)
        case {"type": kind, **extras}:
            return (kind, extras)
        case _:
            return "non-map"
""",
)

case(
    "match_class",
    (3, 10),
    """
class Point:
    __match_args__ = ("x", "y")
    def __init__(self, x, y):
        self.x = x
        self.y = y

def f(p):
    match p:
        case Point(0, 0):
            return "origin"
        case Point(x=x, y=y):
            return (x, y)
        case _:
            return "other"
""",
)

case(
    "match_guard",
    (3, 10),
    """
def f(value):
    match value:
        case n if n < 0:
            return "neg"
        case 0:
            return "zero"
        case n:
            return "pos"
""",
)

case(
    "match_as",
    (3, 10),
    """
def f(value):
    match value:
        case (1 | 2 | 3) as small:
            return small
        case _:
            return "other"
""",
)

case(
    "except_star",
    (3, 11),
    """
def f(do_work):
    counts = {"value": 0, "type": 0}
    try:
        do_work()
    except* ValueError as eg:
        counts["value"] = len(eg.exceptions)
    except* TypeError as eg:
        counts["type"] = len(eg.exceptions)
    return counts
""",
)

case(
    "type_alias",
    (3, 12),
    """
type Vector = list[float]

def f(vec):
    return sum(vec)
""",
)

case(
    "type_params_func",
    (3, 12),
    """
def f[T](item: T) -> tuple[T, T]:
    return (item, item)
""",
)

case(
    "type_params_class",
    (3, 12),
    """
class Box[T]:
    def __init__(self, item: T) -> None:
        self.item = item
""",
)

case(
    "type_params_bound",
    (3, 12),
    """
def f[T: int](value: T) -> T:
    return value
""",
)

case(
    "type_params_paramspec",
    (3, 12),
    """
import functools

def f[**P, R](fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper
""",
)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[str] = []
    for fname in sorted(p.name for p in OUT.glob("*.py")):
        (OUT / fname).unlink()
    for stem, (floor, body) in sorted(CASES.items()):
        major, minor = floor
        path: Path = OUT / f"{stem}.py"
        path.write_text(body, encoding="utf-8", newline="\n")
        manifest.append(f"{stem}\t{major}.{minor}")
    manifest_path: Path = OUT.parent / "manifest.tsv"
    manifest_path.write_text(
        "construct\tfloor\n" + "\n".join(manifest) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {len(CASES)} construct fixtures to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
