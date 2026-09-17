#!/usr/bin/env python3

from __future__ import annotations

import abc
import asyncio
import collections
import contextlib
import dataclasses
import decimal
import enum
import fractions
import functools
import inspect
import io
import itertools
import json
import math
import operator
import os
import pathlib
import random
import re
import shutil
import string
import struct
import sys
import textwrap
import threading
import time
import types
import typing
import unicodedata
import weakref

from collections import (
    ChainMap,
    Counter,
    OrderedDict,
    defaultdict,
    deque,
    namedtuple,
)
from contextlib import contextmanager, asynccontextmanager, suppress
from dataclasses import dataclass, field
from functools import lru_cache, partial, reduce, wraps
from typing import (
    Any,
    Callable,
    ClassVar,
    Final,
    Generic,
    Literal,
    NamedTuple,
    Optional,
    Protocol,
    TypeAlias,
    Union,
    cast,
    overload,
    runtime_checkable,
)

PY_GE_312 = sys.version_info >= (3, 12)
PY_GE_311 = sys.version_info >= (3, 11)
PY_GE_310 = sys.version_info >= (3, 10)
PY_GE_38 = sys.version_info >= (3, 8)

GREETING: Final[str] = "hello, disrobe"
SECRET_CONSTANT: Final[int] = 1337
PI_APPROX: Final[decimal.Decimal] = decimal.Decimal("3.141592653589793238462643")
GOLDEN_RATIO: Final[fractions.Fraction] = fractions.Fraction(1618033988, 1000000000)
LIST_OF_STRINGS: Final[list[str]] = ["alpha", "beta", "gamma", "delta", "epsilon"]
SET_OF_INTS: Final[frozenset[int]] = frozenset({2, 3, 5, 7, 11, 13, 17, 19, 23, 29})
DICT_OF_PAIRS: Final[dict[str, int]] = {s: i for i, s in enumerate(LIST_OF_STRINGS)}
BYTE_BLOB: Final[bytes] = b"\x00\x01\x02\xff\xfe\xfd\xde\xad\xbe\xef"
HEX_BLOB: Final[bytes] = bytes.fromhex("cafebabe0badf00ddeadbeef")
RAW_REGEX: Final[str] = r"^\s*(?P<key>\w+)\s*=\s*(?P<val>[\w.\-]+)\s*$"
COMPILED_REGEX: Final[re.Pattern[str]] = re.compile(RAW_REGEX, re.MULTILINE | re.VERBOSE)
UNICODE_SAMPLE: Final[str] = "ascii / αβγ / 漢字 / 😀🚀💀 / 🇯🇵🇺🇸 / ​‍"

_LOG_BUFFER: list[str] = []


def log(level: str, message: str, /, *fields: object, **kw: object) -> None:
    parts = [f"[{level}] {message}"]
    for f in fields:
        parts.append(repr(f))
    for k, v in kw.items():
        parts.append(f"{k}={v!r}")
    line = " ".join(parts)
    _LOG_BUFFER.append(line)


def add(a: int, b: int) -> int:
    return a + b


def sub(a: int, b: int) -> int:
    return a - b


def mul(a: int, b: int) -> int:
    return a * b


def div(a: float, b: float) -> float:
    if b == 0:
        raise ZeroDivisionError("nope")
    return a / b


def floor_div(a: int, b: int) -> int:
    return a // b


def modulo(a: int, b: int) -> int:
    return a % b


def power(a: int, b: int) -> int:
    return a**b


def matmul_demo(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    return [[sum(la * ra for la, ra in zip(row, col)) for col in zip(*right)] for row in left]


def greet(name: str = "world") -> str:
    return f"{GREETING} -- {name}"


def fizzbuzz(n: int) -> str:
    match (n % 3, n % 5):
        case (0, 0):
            return "fizzbuzz"
        case (0, _):
            return "fizz"
        case (_, 0):
            return "buzz"
        case _:
            return str(n)


def walrus_demo(items: list[int]) -> list[int]:
    out: list[int] = []
    while (head := next(iter(items), None)) is not None:
        out.append(head)
        items = items[1:]
    return out


def nested_loops(rows: int, cols: int) -> list[tuple[int, int, int]]:
    triples: list[tuple[int, int, int]] = []
    for r in range(rows):
        for c in range(cols):
            for k in range(min(r, c) + 1):
                if r + c + k == 0:
                    continue
                if (r * c) % 7 == 0:
                    triples.append((r, c, k))
                else:
                    triples.append((r, c, -k))
    return triples


def while_else(target: int) -> int:
    i = 0
    while i < target:
        if i == 13:
            break
        i += 1
    else:
        return i + 1000
    return i


def for_else(items: list[int], needle: int) -> int:
    for i, v in enumerate(items):
        if v == needle:
            return i
    else:
        return -1


def try_chain(value: object) -> str:
    try:
        return cast(str, value).upper()
    except AttributeError as exc:
        log("warn", "no upper()", repr(exc))
        return ""
    except TypeError:
        return "!type"
    finally:
        log("trace", "try_chain finally")


def raise_eg(values: list[int]) -> None:
    errs: list[Exception] = []
    for v in values:
        try:
            if v == 0:
                raise ValueError("zero")
            if v < 0:
                raise ZeroDivisionError("neg")
            if v > 100:
                raise OverflowError("huge")
        except Exception as e:
            errs.append(e)
    if errs and PY_GE_311:
        raise BaseExceptionGroup("validation", errs)


def chained_strs(parts: list[str]) -> str:
    return "/".join(p.strip().lower().replace(" ", "_") for p in parts if p)


def nested_with(path: pathlib.Path) -> None:
    with (
        contextlib.suppress(FileNotFoundError),
        path.open("rb") as f,
        io.BytesIO() as buf,
    ):
        buf.write(f.read(64))


def positional_only(a: int, b: int, /, c: int, *, d: int = 4) -> int:
    return a + b + c + d


def keyword_only(*, key: str, value: int = 0) -> str:
    return f"{key}={value}"


def args_kwargs_demo(*args: int, **kwargs: str) -> tuple[int, dict[str, str]]:
    return sum(args), dict(kwargs)


def starred_unpacking(seq: list[int]) -> tuple[int, list[int], int]:
    first, *middle, last = seq
    return first, middle, last


def lambda_captures(base: int) -> Callable[[int], int]:
    adder = lambda x: x + base
    return adder


def closure_chain(n: int) -> Callable[[], int]:
    counter = 0

    def step() -> int:
        nonlocal counter
        counter += 1
        return counter + n

    return step


def cell_var_demo() -> list[Callable[[], int]]:
    fns: list[Callable[[], int]] = []
    for i in range(5):
        fns.append(lambda i=i: i * 10)
    return fns


def gen_demo(n: int) -> typing.Iterator[int]:
    for i in range(n):
        yield i * i


def gen_with_send() -> typing.Generator[int, int, str]:
    received = 0
    while True:
        nxt = yield received
        if nxt is None:
            return "done"
        received += nxt


@functools.lru_cache(maxsize=128)
def fib(n: int) -> int:
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


def fib_iter(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def decorator_factory(prefix: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            log("call", f"{prefix}:{fn.__name__}", args=args, kwargs=kwargs)
            return fn(*args, **kwargs)

        return wrapper

    return deco


@decorator_factory("trace")
def traced_add(a: int, b: int) -> int:
    return a + b


class Direction(enum.Enum):
    NORTH = "N"
    SOUTH = "S"
    EAST = "E"
    WEST = "W"

    def opposite(self) -> "Direction":
        return {
            Direction.NORTH: Direction.SOUTH,
            Direction.SOUTH: Direction.NORTH,
            Direction.EAST: Direction.WEST,
            Direction.WEST: Direction.EAST,
        }[self]


class Permission(enum.IntFlag):
    NONE = 0
    READ = 1
    WRITE = 2
    EXEC = 4
    ALL = READ | WRITE | EXEC


class Color(enum.IntEnum):
    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    WHITE = 7


PointTuple: TypeAlias = tuple[int, int]


class Point(NamedTuple):
    x: int
    y: int

    def magnitude(self) -> float:
        return math.hypot(self.x, self.y)

    def translate(self, dx: int, dy: int) -> "Point":
        return Point(self.x + dx, self.y + dy)


@dataclass(frozen=True, slots=True)
class Vector3:
    x: float
    y: float
    z: float

    def dot(self, other: "Vector3") -> float:
        return self.x * other.x + self.y * other.y + self.z * other.z

    def cross(self, other: "Vector3") -> "Vector3":
        return Vector3(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x,
        )

    @property
    def length(self) -> float:
        return math.sqrt(self.dot(self))

    def __add__(self, other: "Vector3") -> "Vector3":
        return Vector3(self.x + other.x, self.y + other.y, self.z + other.z)

    def __sub__(self, other: "Vector3") -> "Vector3":
        return Vector3(self.x - other.x, self.y - other.y, self.z - other.z)

    def __mul__(self, scalar: float) -> "Vector3":
        return Vector3(self.x * scalar, self.y * scalar, self.z * scalar)

    def __rmul__(self, scalar: float) -> "Vector3":
        return self.__mul__(scalar)

    def __neg__(self) -> "Vector3":
        return Vector3(-self.x, -self.y, -self.z)


@dataclass
class Counter2D:
    x: int = 0
    y: int = 0
    history: list[PointTuple] = field(default_factory=list)
    _tag: ClassVar[str] = "Counter2D"

    def step(self, dx: int = 1, dy: int = 0) -> "Counter2D":
        self.history.append((self.x, self.y))
        self.x += dx
        self.y += dy
        return self

    def reset(self) -> None:
        self.x = 0
        self.y = 0
        self.history.clear()


class Greeter(abc.ABC):
    @abc.abstractmethod
    def greet(self, name: str) -> str: ...


class EnglishGreeter(Greeter):
    def greet(self, name: str) -> str:
        return f"Hello, {name}!"


class JapaneseGreeter(Greeter):
    def greet(self, name: str) -> str:
        return f"こんにちは、{name}さん!"


class MixedGreeter(EnglishGreeter, JapaneseGreeter):
    def greet(self, name: str) -> str:
        return f"{EnglishGreeter.greet(self, name)} // {JapaneseGreeter.greet(self, name)}"


@runtime_checkable
class HasArea(Protocol):
    def area(self) -> float: ...


class Rectangle:
    __slots__ = ("width", "height")

    def __init__(self, width: float, height: float) -> None:
        self.width = width
        self.height = height

    def area(self) -> float:
        return self.width * self.height


class Circle:
    __slots__ = ("radius",)

    def __init__(self, radius: float) -> None:
        self.radius = radius

    def area(self) -> float:
        return math.pi * self.radius**2


def total_area(shapes: typing.Iterable[HasArea]) -> float:
    return sum(s.area() for s in shapes)


class CountingMeta(type):
    instances: ClassVar[Counter[str]] = Counter()

    def __call__(cls, *args: object, **kwargs: object) -> object:
        CountingMeta.instances[cls.__name__] += 1
        return super().__call__(*args, **kwargs)


class Tracked(metaclass=CountingMeta):
    def __init__(self, label: str) -> None:
        self.label = label


class Descriptor:
    def __init__(self, name: str) -> None:
        self.name = name

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    def __get__(self, instance: object, owner: type | None = None) -> object:
        if instance is None:
            return self
        return instance.__dict__.get(self.name)

    def __set__(self, instance: object, value: object) -> None:
        log("desc", f"set {self.name}", value=value)
        instance.__dict__[self.name] = value


class HoldsThings:
    a = Descriptor("a")
    b = Descriptor("b")


class WeakHolder:
    def __init__(self, target: object) -> None:
        self.ref = weakref.ref(target)


T_co = typing.TypeVar("T_co", covariant=True)
T_contra = typing.TypeVar("T_contra", contravariant=True)


class Box(Generic[T_co]):
    def __init__(self, value: T_co) -> None:
        self._value = value

    def get(self) -> T_co:
        return self._value


class Sink(Generic[T_contra]):
    def __init__(self) -> None:
        self.items: list[T_contra] = []

    def push(self, item: T_contra) -> None:
        self.items.append(item)


if PY_GE_312:
    exec(
        textwrap.dedent(
            """
            def pep695_identity[T](value: T) -> T:
                return value

            def pep695_pair[T, U](a: T, b: U) -> tuple[T, U]:
                return (a, b)

            class PEP695Container[T]:
                def __init__(self, value: T) -> None:
                    self.value = value
                def get(self) -> T:
                    return self.value
            """
        )
    )


def maybe_overload_int(value: int) -> int: ...


def maybe_overload_str(value: str) -> str: ...


@overload
def converter(value: int) -> str: ...


@overload
def converter(value: str) -> int: ...


def converter(value: int | str) -> int | str:
    if isinstance(value, int):
        return str(value)
    return int(value)


def big_match(point: object) -> str:
    match point:
        case (0, 0):
            return "origin"
        case (0, y):
            return f"y-axis at {y}"
        case (x, 0):
            return f"x-axis at {x}"
        case (x, y) if x == y:
            return f"diagonal {x}"
        case (x, y) if x > 0 and y > 0:
            return f"quadrant-I ({x},{y})"
        case Point(x=x, y=y):
            return f"named-point ({x},{y})"
        case {"x": int(x), "y": int(y)}:
            return f"dict point ({x},{y})"
        case [first, *rest] if isinstance(first, int):
            return f"int list, head={first}, tail_len={len(rest)}"
        case str() as s:
            return f"string '{s}'"
        case _ as other:
            return f"unknown {type(other).__name__}"


async def async_add(a: int, b: int) -> int:
    await asyncio.sleep(0)
    return a + b


async def async_collect(items: typing.AsyncIterable[int]) -> list[int]:
    out: list[int] = []
    async for it in items:
        out.append(it)
    return out


async def async_gen(n: int) -> typing.AsyncIterator[int]:
    for i in range(n):
        await asyncio.sleep(0)
        yield i * 2


@asynccontextmanager
async def async_ctx(label: str) -> typing.AsyncIterator[str]:
    log("async", f"enter {label}")
    try:
        yield label
    finally:
        log("async", f"exit {label}")


async def async_gather_demo() -> list[int]:
    return await asyncio.gather(async_add(1, 2), async_add(3, 4), async_add(5, 6))


async def async_with_lock() -> int:
    lock = asyncio.Lock()
    async with lock:
        await asyncio.sleep(0)
        return 1


def memoryview_demo(data: bytes) -> int:
    mv = memoryview(data)
    return sum(mv)


def bytearray_demo(data: bytes) -> bytearray:
    ba = bytearray(data)
    for i, b in enumerate(ba):
        ba[i] = b ^ 0x55
    return ba


def struct_demo() -> bytes:
    return struct.pack(">IHb", 0xDEADBEEF, 0xCAFE, 42)


def bit_twiddle(x: int) -> int:
    return ((x << 3) | (x >> 5)) & 0xFFFFFFFF ^ 0xA5A5A5A5


def comprehensions() -> dict[str, typing.Any]:
    lst = [i * i for i in range(10) if i % 2 == 0]
    st = {math.gcd(i, j) for i in range(1, 10) for j in range(1, 10)}
    dct = {k: v for k, v in zip("abcde", range(5))}
    gen = (i**3 for i in range(5))
    return {"list": lst, "set": st, "dict": dct, "gen_list": list(gen)}


def chained_comparisons(a: int, b: int, c: int) -> bool:
    return a < b < c and c > b > a or a == c


def conditional_expr(flag: bool, a: int, b: int) -> int:
    return (a if flag else b) + (1 if a > b else -1)


def fstring_nest(items: list[int]) -> str:
    return f"items=[{', '.join(f'<{i:04x}>' for i in items)}]"


def f_format_specs(value: float) -> str:
    return f"{value:0.3f} | {value:>10.4e} | {value:+,.2f}"


def percent_format() -> str:
    return "%s -> %d (%(name)s)" % ("alpha", 7, {"name": "beta"})


def deep_recursion(n: int) -> int:
    if n <= 0:
        return 0
    return 1 + deep_recursion(n - 1)


def tail_loop(n: int) -> int:
    acc = 0
    while n > 0:
        acc += n
        n -= 1
    return acc


def conditional_imports() -> typing.Any:
    if sys.platform == "win32":
        import msvcrt

        return msvcrt
    else:
        import termios

        return termios


def dynamic_attr_access(obj: object) -> dict[str, object]:
    out: dict[str, object] = {}
    for attr in dir(obj):
        if attr.startswith("_"):
            continue
        try:
            out[attr] = getattr(obj, attr)
        except Exception:
            out[attr] = None
    return out


def exec_eval_demo(expr: str) -> object:
    safe = {"__builtins__": {"abs": abs, "min": min, "max": max, "sum": sum, "len": len}}
    return eval(expr, safe, {})


def threading_demo() -> int:
    result = []

    def worker(n: int) -> None:
        result.append(n * 2)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sum(result)


def pickle_safe_payload() -> dict[str, object]:
    return {
        "nums": list(range(10)),
        "deep": {"a": {"b": {"c": [1, 2, 3]}}},
        "tuples": [(1, 2), (3, 4), (5, 6)],
    }


def chainmap_demo() -> ChainMap[str, int]:
    base = {"a": 1, "b": 2}
    over = {"b": 20, "c": 30}
    return ChainMap(over, base)


def counter_demo(text: str) -> Counter[str]:
    return Counter(c for c in text.lower() if c.isalpha())


def deque_demo(values: list[int]) -> deque[int]:
    dq: deque[int] = deque(values, maxlen=8)
    dq.appendleft(0)
    dq.rotate(-1)
    return dq


def ordereddict_demo() -> OrderedDict[str, int]:
    od: OrderedDict[str, int] = OrderedDict()
    for i, c in enumerate("abcdef"):
        od[c] = i
    od.move_to_end("b")
    return od


def defaultdict_demo(words: list[str]) -> defaultdict[str, list[str]]:
    out: defaultdict[str, list[str]] = defaultdict(list)
    for w in words:
        out[w[:1].lower()].append(w)
    return out


def namedtuple_demo() -> typing.Any:
    Person = namedtuple("Person", ["name", "age", "email"])
    p = Person(name="Ada", age=36, email="ada@example.com")
    return p


def operator_demo() -> int:
    fns = [operator.add, operator.sub, operator.mul, operator.floordiv]
    return reduce(lambda acc, fn: fn(acc, 3), fns, 27)


def itertools_demo() -> list[tuple[int, ...]]:
    pairs = list(itertools.combinations(range(5), 2))
    chained = list(itertools.chain.from_iterable([[1, 2], [3, 4]]))
    return pairs + [tuple(chained)]


def regex_demo(text: str) -> list[tuple[str, str]]:
    return [(m.group("key"), m.group("val")) for m in COMPILED_REGEX.finditer(text)]


def json_demo() -> str:
    payload = {
        "n": SECRET_CONSTANT,
        "list": LIST_OF_STRINGS,
        "nested": {"a": [1, 2, 3], "b": [4, 5, 6]},
        "unicode": UNICODE_SAMPLE,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def random_demo(seed: int) -> list[int]:
    rng = random.Random(seed)
    return sorted(rng.randint(0, 100) for _ in range(20))


def unicodedata_demo(s: str) -> list[tuple[str, str]]:
    return [(ch, unicodedata.name(ch, "<unknown>")) for ch in s]


def itertools_groupby_demo() -> list[tuple[int, list[int]]]:
    values = [1, 1, 2, 3, 3, 3, 4, 5, 5]
    return [(k, list(g)) for k, g in itertools.groupby(values)]


def big_constants() -> dict[str, object]:
    return {
        "small_int": 42,
        "neg_int": -(2**31),
        "big_int": 2**128 + 1,
        "negbig": -(2**128),
        "float": math.pi,
        "neg_float": -math.tau,
        "inf": math.inf,
        "neg_inf": -math.inf,
        "complex": 3 + 4j,
        "neg_complex": -3 - 4j,
        "decimal": PI_APPROX,
        "fraction": GOLDEN_RATIO,
        "bytes": BYTE_BLOB,
        "bytearray": bytearray(b"mutable bytes"),
        "memoryview": memoryview(BYTE_BLOB),
        "ellipsis": ...,
        "notimpl": NotImplemented,
        "none": None,
        "false": False,
        "true": True,
        "set": {1, 2, 3},
        "frozenset": frozenset({4, 5, 6}),
        "tuple": (1, 2, (3, (4, (5, 6)))),
        "list": [[1], [2], [3, [4, [5]]]],
        "dict": {"a": {"b": {"c": {"d": "deep"}}}},
        "str_escape": "tab\there\nnewline\rcr\\back\"quote'single",
        "raw_bytes": rb"\x00\x01\x02 raw not interpreted",
        "hex_bytes": HEX_BLOB,
    }


def long_function_with_many_branches(value: int, mode: str = "default") -> str:
    if value < 0:
        if value < -100:
            return "very-negative"
        if value < -10:
            return "negative-large"
        return "negative-small"
    if value == 0:
        if mode == "strict":
            raise ValueError("zero not allowed in strict mode")
        if mode == "default":
            return "zero"
        return f"zero-{mode}"
    if value < 10:
        for i in range(value):
            if i == 3:
                continue
            if i == 7:
                break
        return "small"
    if value < 100:
        result = ""
        for c in range(value % 26):
            result += chr(ord("a") + c)
        return result
    if value < 1000:
        if mode == "hex":
            return f"{value:#06x}"
        if mode == "oct":
            return f"{value:#o}"
        if mode == "bin":
            return f"{value:#b}"
        return str(value)
    return "huge"


def shadow_builtins() -> int:
    list = [1, 2, 3]
    dict = {"a": 1}
    int = 42
    return len(list) + len(dict) + int


def conditional_with_walrus(items: list[int]) -> list[int]:
    out = []
    for it in items:
        if (doubled := it * 2) > 10:
            out.append(doubled)
        elif (negated := -it) < -5:
            out.append(negated)
    return out


def deeply_nested_try() -> None:
    try:
        try:
            try:
                try:
                    raise RuntimeError("inner")
                except RuntimeError:
                    raise ValueError("middle1")
            except ValueError:
                raise TypeError("middle2")
        except TypeError:
            raise OSError("outer")
    except OSError as e:
        log("error", "caught at top", repr(e))


def class_with_everything() -> type:
    class Everything:
        __slots__ = ("a", "b", "_c")
        class_var: ClassVar[int] = 0
        _instances: ClassVar[list["Everything"]] = []

        def __init__(self, a: int, b: int) -> None:
            self.a = a
            self.b = b
            self._c = a + b
            Everything._instances.append(self)
            Everything.class_var += 1

        def __init_subclass__(cls, **kwargs: object) -> None:
            super().__init_subclass__(**kwargs)
            cls.__subclass_marker__ = True

        def __repr__(self) -> str:
            return f"Everything(a={self.a}, b={self.b})"

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, Everything):
                return NotImplemented
            return (self.a, self.b) == (other.a, other.b)

        def __hash__(self) -> int:
            return hash((self.a, self.b))

        def __lt__(self, other: "Everything") -> bool:
            return (self.a, self.b) < (other.a, other.b)

        def __iter__(self) -> typing.Iterator[int]:
            yield self.a
            yield self.b
            yield self._c

        def __len__(self) -> int:
            return 3

        def __getitem__(self, key: int) -> int:
            return [self.a, self.b, self._c][key]

        def __contains__(self, item: int) -> bool:
            return item in (self.a, self.b, self._c)

        def __call__(self, n: int) -> int:
            return self.a * n + self.b

        def __enter__(self) -> "Everything":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        @property
        def c(self) -> int:
            return self._c

        @c.setter
        def c(self, value: int) -> None:
            self._c = value

        @classmethod
        def factory(cls, n: int) -> "Everything":
            return cls(n, n + 1)

        @staticmethod
        def helper(x: int, y: int) -> int:
            return x * y

    return Everything


def run_class_demo() -> dict[str, object]:
    Cls = class_with_everything()
    a = Cls(1, 2)
    b = Cls.factory(10)
    return {
        "repr": repr(a),
        "iter": list(a),
        "len": len(a),
        "lt": a < b,
        "call": a(5),
        "helper": Cls.helper(3, 4),
        "class_var": Cls.class_var,
        "instances_count": len(Cls._instances),
    }


def benchmark_loop(n: int) -> tuple[float, int]:
    start = time.perf_counter()
    total = 0
    for i in range(n):
        total = (total + i * i) % (10**9 + 7)
    return time.perf_counter() - start, total


async def async_main() -> dict[str, object]:
    results: dict[str, object] = {}
    async with async_ctx("demo") as label:
        results["ctx_label"] = label
        results["gather"] = await async_gather_demo()
        results["with_lock"] = await async_with_lock()
        results["async_gen"] = [v async for v in async_gen(5)]
    return results


def all_demos() -> dict[str, object]:
    out: dict[str, object] = {}
    out["greet"] = greet("disrobe")
    out["fizzbuzz_15"] = fizzbuzz(15)
    out["walrus"] = walrus_demo([1, 2, 3])
    out["nested"] = nested_loops(3, 3)[:5]
    out["while_else"] = while_else(5)
    out["for_else"] = for_else([1, 2, 3, 4], 3)
    out["try_chain"] = try_chain("abc")
    out["chained"] = chained_strs(["  Hello  ", "World", "", "Foo Bar"])
    out["pos_only"] = positional_only(1, 2, 3)
    out["kw_only"] = keyword_only(key="x", value=99)
    out["starred"] = starred_unpacking([1, 2, 3, 4, 5])
    out["lambda"] = lambda_captures(10)(5)
    out["closure"] = closure_chain(100)()
    out["cell"] = [f() for f in cell_var_demo()]
    out["gen"] = list(gen_demo(5))
    out["fib"] = fib(20)
    out["fib_iter"] = fib_iter(20)
    out["traced"] = traced_add(7, 8)
    out["direction"] = Direction.NORTH.opposite().value
    out["perm"] = (Permission.READ | Permission.WRITE).value
    out["color"] = Color.MAGENTA.name
    out["point"] = Point(3, 4).magnitude()
    out["vec_dot"] = Vector3(1, 2, 3).dot(Vector3(4, 5, 6))
    out["counter2d"] = Counter2D().step(1, 2).step(3, 4).history
    out["greeter"] = MixedGreeter().greet("there")
    out["area"] = total_area([Rectangle(3, 4), Circle(5)])
    out["match"] = big_match((3, 3))
    out["match_dict"] = big_match({"x": 1, "y": 2})
    out["match_list"] = big_match([1, 2, 3, 4])
    out["comp"] = comprehensions()
    out["chained_cmp"] = chained_comparisons(1, 2, 3)
    out["cond_expr"] = conditional_expr(True, 10, 5)
    out["fstring"] = fstring_nest([1, 16, 256, 4096])
    out["fformat"] = f_format_specs(math.tau)
    out["pct"] = percent_format()
    out["mv"] = memoryview_demo(BYTE_BLOB)
    out["barr"] = bytes(bytearray_demo(BYTE_BLOB)).hex()
    out["struct"] = struct_demo().hex()
    out["bits"] = bit_twiddle(0x12345678)
    out["json"] = json_demo()
    out["regex"] = regex_demo("alpha=1\nbeta=foo\ngamma=2.5\n")
    out["random"] = random_demo(42)
    out["unicode"] = unicodedata_demo("abc αβ 中")
    out["groupby"] = itertools_groupby_demo()
    out["big_consts_keys"] = sorted(big_constants().keys())
    out["long_branches"] = long_function_with_many_branches(123, "hex")
    out["shadow"] = shadow_builtins()
    out["walrus2"] = conditional_with_walrus([3, 7, -10, -4])
    out["class_demo"] = run_class_demo()
    bench_time, bench_total = benchmark_loop(1000)
    out["bench"] = (round(bench_time, 6), bench_total)
    return out


def main() -> None:
    print(json.dumps({"sync": all_demos()}, default=repr, indent=2))
    try:
        loop = asyncio.new_event_loop()
        try:
            async_results = loop.run_until_complete(async_main())
        finally:
            loop.close()
        print(json.dumps({"async": async_results}, default=repr, indent=2))
    except Exception as e:
        log("error", "async block failed", repr(e))


class Singleton:
    _instance: ClassVar["Singleton | None"] = None
    _initialized: ClassVar[bool] = False

    def __new__(cls) -> "Singleton":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not Singleton._initialized:
            self.value = 42
            Singleton._initialized = True


class Observer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.events: list[tuple[str, object]] = []

    def notify(self, event: str, payload: object) -> None:
        self.events.append((event, payload))


class Subject:
    def __init__(self) -> None:
        self._observers: list[Observer] = []

    def attach(self, observer: Observer) -> None:
        self._observers.append(observer)

    def detach(self, observer: Observer) -> None:
        self._observers.remove(observer)

    def publish(self, event: str, payload: object) -> None:
        for o in self._observers:
            o.notify(event, payload)


class Strategy(Protocol):
    def execute(self, x: int) -> int: ...


class DoubleStrategy:
    def execute(self, x: int) -> int:
        return x * 2


class TripleStrategy:
    def execute(self, x: int) -> int:
        return x * 3


class Context:
    def __init__(self, strategy: Strategy) -> None:
        self.strategy = strategy

    def run(self, x: int) -> int:
        return self.strategy.execute(x)


class StateMachine:
    def __init__(self) -> None:
        self.state = "idle"
        self.transitions: dict[tuple[str, str], str] = {
            ("idle", "start"): "running",
            ("running", "pause"): "paused",
            ("paused", "resume"): "running",
            ("running", "stop"): "stopped",
            ("paused", "stop"): "stopped",
        }

    def transition(self, event: str) -> bool:
        key = (self.state, event)
        if key in self.transitions:
            self.state = self.transitions[key]
            return True
        return False


class CircularBuffer:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.buffer: list[object | None] = [None] * capacity
        self.head = 0
        self.tail = 0
        self.size = 0

    def push(self, item: object) -> None:
        self.buffer[self.tail] = item
        self.tail = (self.tail + 1) % self.capacity
        if self.size < self.capacity:
            self.size += 1
        else:
            self.head = (self.head + 1) % self.capacity

    def pop(self) -> object | None:
        if self.size == 0:
            return None
        item = self.buffer[self.head]
        self.buffer[self.head] = None
        self.head = (self.head + 1) % self.capacity
        self.size -= 1
        return item


class LinkedList:
    @dataclass
    class Node:
        value: int
        next: "LinkedList.Node | None" = None

    def __init__(self) -> None:
        self.head: LinkedList.Node | None = None

    def push(self, value: int) -> None:
        node = LinkedList.Node(value)
        node.next = self.head
        self.head = node

    def pop(self) -> int | None:
        if self.head is None:
            return None
        value = self.head.value
        self.head = self.head.next
        return value

    def to_list(self) -> list[int]:
        result: list[int] = []
        cur = self.head
        while cur is not None:
            result.append(cur.value)
            cur = cur.next
        return result


class BinarySearchTree:
    @dataclass
    class Node:
        value: int
        left: "BinarySearchTree.Node | None" = None
        right: "BinarySearchTree.Node | None" = None

    def __init__(self) -> None:
        self.root: BinarySearchTree.Node | None = None

    def insert(self, value: int) -> None:
        self.root = self._insert_at(self.root, value)

    def _insert_at(
        self, node: "BinarySearchTree.Node | None", value: int
    ) -> "BinarySearchTree.Node":
        if node is None:
            return BinarySearchTree.Node(value)
        if value < node.value:
            node.left = self._insert_at(node.left, value)
        else:
            node.right = self._insert_at(node.right, value)
        return node

    def in_order(self) -> list[int]:
        result: list[int] = []
        self._in_order_at(self.root, result)
        return result

    def _in_order_at(self, node: "BinarySearchTree.Node | None", result: list[int]) -> None:
        if node is None:
            return
        self._in_order_at(node.left, result)
        result.append(node.value)
        self._in_order_at(node.right, result)


def quicksort(items: list[int]) -> list[int]:
    if len(items) <= 1:
        return items[:]
    pivot = items[len(items) // 2]
    left = [x for x in items if x < pivot]
    mid = [x for x in items if x == pivot]
    right = [x for x in items if x > pivot]
    return quicksort(left) + mid + quicksort(right)


def mergesort(items: list[int]) -> list[int]:
    if len(items) <= 1:
        return items[:]
    mid = len(items) // 2
    left = mergesort(items[:mid])
    right = mergesort(items[mid:])
    return _merge(left, right)


def _merge(left: list[int], right: list[int]) -> list[int]:
    result: list[int] = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return result


def heapsort(items: list[int]) -> list[int]:
    import heapq

    heap = items[:]
    heapq.heapify(heap)
    return [heapq.heappop(heap) for _ in range(len(heap))]


def is_palindrome(s: str) -> bool:
    cleaned = "".join(c.lower() for c in s if c.isalnum())
    return cleaned == cleaned[::-1]


def caesar_cipher(text: str, shift: int) -> str:
    result: list[str] = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif ch.isalpha():
            result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(ch)
    return "".join(result)


def matrix_transpose(matrix: list[list[int]]) -> list[list[int]]:
    if not matrix:
        return []
    return [[row[i] for row in matrix] for i in range(len(matrix[0]))]


def matrix_rotate_cw(matrix: list[list[int]]) -> list[list[int]]:
    return [list(row) for row in zip(*matrix[::-1])]


def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b) if a and b else 0


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def primes_up_to(n: int) -> list[int]:
    sieve = [True] * (n + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(math.isqrt(n)) + 1):
        if sieve[i]:
            for j in range(i * i, n + 1, i):
                sieve[j] = False
    return [i for i, prime in enumerate(sieve) if prime]


def factorial(n: int) -> int:
    if n < 0:
        raise ValueError("factorial of negative")
    if n < 2:
        return 1
    return n * factorial(n - 1)


def fibonacci_seq(n: int) -> list[int]:
    seq: list[int] = []
    a, b = 0, 1
    for _ in range(n):
        seq.append(a)
        a, b = b, a + b
    return seq


def collatz(n: int) -> list[int]:
    seq = [n]
    while n != 1:
        n = 3 * n + 1 if n % 2 else n // 2
        seq.append(n)
        if len(seq) > 10000:
            break
    return seq


def ackermann(m: int, n: int) -> int:
    if m == 0:
        return n + 1
    if n == 0:
        return ackermann(m - 1, 1)
    return ackermann(m - 1, ackermann(m, n - 1))


def levenshtein(a: str, b: str) -> int:
    if not a:
        return len(b)
    if not b:
        return len(a)
    if a[0] == b[0]:
        return levenshtein(a[1:], b[1:])
    return 1 + min(
        levenshtein(a[1:], b),
        levenshtein(a, b[1:]),
        levenshtein(a[1:], b[1:]),
    )


def levenshtein_dp(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


def knapsack_01(weights: list[int], values: list[int], capacity: int) -> int:
    n = len(weights)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for w in range(capacity + 1):
            if weights[i - 1] <= w:
                dp[i][w] = max(dp[i - 1][w], dp[i - 1][w - weights[i - 1]] + values[i - 1])
            else:
                dp[i][w] = dp[i - 1][w]
    return dp[n][capacity]


def longest_common_subseq(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


def dijkstra(graph: dict[int, list[tuple[int, int]]], start: int) -> dict[int, int]:
    import heapq

    dist: dict[int, int] = {node: float("inf") for node in graph}
    dist[start] = 0
    heap: list[tuple[int, int]] = [(0, start)]
    while heap:
        d, u = heapq.heappop(heap)
        if d > dist[u]:
            continue
        for v, w in graph[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(heap, (nd, v))
    return dist


def bfs(graph: dict[int, list[int]], start: int) -> list[int]:
    visited: set[int] = {start}
    queue: deque[int] = deque([start])
    order: list[int] = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return order


def dfs_iterative(graph: dict[int, list[int]], start: int) -> list[int]:
    visited: set[int] = set()
    stack: list[int] = [start]
    order: list[int] = []
    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        order.append(node)
        for neighbor in reversed(graph.get(node, [])):
            if neighbor not in visited:
                stack.append(neighbor)
    return order


def topological_sort(graph: dict[int, list[int]]) -> list[int]:
    in_degree: dict[int, int] = {node: 0 for node in graph}
    for node in graph:
        for neighbor in graph[node]:
            in_degree[neighbor] = in_degree.get(neighbor, 0) + 1
            in_degree.setdefault(node, in_degree.get(node, 0))
    queue: deque[int] = deque([n for n, d in in_degree.items() if d == 0])
    order: list[int] = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    return order


def union_find() -> tuple[dict[int, int], dict[int, int]]:
    parent: dict[int, int] = {}
    rank: dict[int, int] = {}
    return parent, rank


def uf_find(parent: dict[int, int], x: int) -> int:
    parent.setdefault(x, x)
    if parent[x] != x:
        parent[x] = uf_find(parent, parent[x])
    return parent[x]


def uf_union(parent: dict[int, int], rank: dict[int, int], a: int, b: int) -> None:
    ra, rb = uf_find(parent, a), uf_find(parent, b)
    if ra == rb:
        return
    rank.setdefault(ra, 0)
    rank.setdefault(rb, 0)
    if rank[ra] < rank[rb]:
        ra, rb = rb, ra
    parent[rb] = ra
    if rank[ra] == rank[rb]:
        rank[ra] += 1


def trie_demo() -> dict[str, object]:
    root: dict[str, object] = {}
    for word in ["apple", "app", "apricot", "banana"]:
        node = root
        for ch in word:
            node = node.setdefault(ch, {})
        node["$"] = True
    return root


def bloom_filter_demo(items: list[str], size: int = 1024) -> list[int]:
    import hashlib

    bits = [0] * size
    for item in items:
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16) % size
        h2 = int(hashlib.sha256(item.encode()).hexdigest(), 16) % size
        h3 = int(hashlib.blake2b(item.encode()).hexdigest(), 16) % size
        bits[h1] = bits[h2] = bits[h3] = 1
    return bits[:32]


def lru_cache_manual(capacity: int) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        cache: OrderedDict[tuple[Any, ...], Any] = OrderedDict()

        @functools.wraps(fn)
        def wrapper(*args: object) -> object:
            key = tuple(args)
            if key in cache:
                cache.move_to_end(key)
                return cache[key]
            result = fn(*args)
            cache[key] = result
            if len(cache) > capacity:
                cache.popitem(last=False)
            return result

        return wrapper

    return deco


@lru_cache_manual(64)
def expensive_calc(x: int, y: int) -> int:
    return x**2 + y**2 - x * y


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 0.1,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            delay = initial_delay
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    log("retry", f"attempt {attempt + 1} failed", repr(e))
                    time.sleep(delay)
                    delay *= 2
            raise RuntimeError("unreachable")

        return wrapper

    return deco


@retry_with_backoff(max_attempts=2)
def flaky_op(n: int) -> int:
    if n < 0:
        raise ValueError("negative")
    return n + 1


def context_var_demo() -> str:
    import contextvars

    var: contextvars.ContextVar[str] = contextvars.ContextVar("demo", default="default")
    token = var.set("changed")
    value = var.get()
    var.reset(token)
    return f"{value}/{var.get()}"


def weakref_proxy_demo() -> bool:
    target = HoldsThings()
    proxy = weakref.proxy(target)
    proxy.a = 99
    return target.a == 99


def signal_handler_demo() -> str:
    import signal

    original = signal.getsignal(signal.SIGINT)
    return f"SIGINT={signal.SIGINT}, original={original!r}"


def hash_chain(data: list[bytes]) -> bytes:
    import hashlib

    h = hashlib.blake2b()
    for chunk in data:
        h.update(chunk)
    return h.digest()


def base64_round_trip(data: bytes) -> bool:
    import base64

    enc = base64.b64encode(data)
    dec = base64.b64decode(enc)
    return dec == data


def url_quote_unquote(text: str) -> tuple[str, str]:
    import urllib.parse

    quoted = urllib.parse.quote(text, safe="")
    unquoted = urllib.parse.unquote(quoted)
    return quoted, unquoted


def datetime_demo() -> dict[str, str]:
    import datetime

    now = datetime.datetime(2026, 5, 24, 12, 0, 0, tzinfo=datetime.timezone.utc)
    return {
        "iso": now.isoformat(),
        "rfc2822": now.strftime("%a, %d %b %Y %H:%M:%S %z"),
        "epoch": str(int(now.timestamp())),
        "weekday": str(now.weekday()),
    }


def pathlib_demo() -> dict[str, str]:
    import pathlib

    p = pathlib.Path("/tmp/example/file.txt")
    return {
        "parent": str(p.parent),
        "name": p.name,
        "stem": p.stem,
        "suffix": p.suffix,
        "with_suffix": str(p.with_suffix(".py")),
        "parts": str(p.parts),
    }


def http_client_demo() -> str:
    import http.client

    return f"HTTPConnection class: {http.client.HTTPConnection.__name__}"


def ssl_context_demo() -> str:
    import ssl

    ctx = ssl.create_default_context()
    return f"protocol={ctx.protocol!r}, options={int(ctx.options)}"


def thread_lock_demo() -> int:
    lock = threading.RLock()
    counter = 0
    with lock:
        counter += 1
        with lock:
            counter += 1
    return counter


def queue_demo() -> list[int]:
    import queue

    q: queue.Queue[int] = queue.Queue(maxsize=10)
    for i in range(5):
        q.put(i)
    out: list[int] = []
    while not q.empty():
        out.append(q.get())
    return out


def io_string_demo() -> str:
    buf = io.StringIO()
    buf.write("hello ")
    buf.write("world")
    return buf.getvalue()


def io_bytes_demo() -> bytes:
    buf = io.BytesIO()
    buf.write(b"abc")
    buf.write(b"def")
    return buf.getvalue()


def csv_demo() -> str:
    import csv

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "age"])
    w.writerow(["alice", 30])
    w.writerow(["bob", 25])
    return buf.getvalue()


def shelve_simulation() -> dict[str, object]:
    storage: dict[str, object] = {}
    storage["key1"] = "value1"
    storage["key2"] = {"nested": [1, 2, 3]}
    storage["key3"] = b"\x00\x01\x02"
    return storage


def itertools_chain_demo() -> list[int]:
    a = [1, 2, 3]
    b = [4, 5, 6]
    c = [7, 8, 9]
    return list(itertools.chain(a, b, c))


def itertools_starmap_demo() -> list[int]:
    return list(itertools.starmap(operator.mul, [(2, 3), (4, 5), (6, 7)]))


def itertools_tee_demo() -> tuple[list[int], list[int]]:
    a, b = itertools.tee(range(5), 2)
    return list(a), list(b)


def itertools_dropwhile_takewhile() -> tuple[list[int], list[int]]:
    nums = [1, 2, 3, 10, 5, 1, 2]
    return (
        list(itertools.dropwhile(lambda x: x < 5, nums)),
        list(itertools.takewhile(lambda x: x < 5, nums)),
    )


def stupid_busy_loop(n: int) -> int:
    result = 0
    while n > 0:
        result += n
        n -= 1
        if result > 10**9:
            break
    return result


def generator_send_throw() -> list[object]:
    def gen() -> typing.Generator[int, str, None]:
        try:
            received = yield 1
            received = yield 2 + len(received)
            yield 3 + len(received)
        except ValueError as e:
            yield -1
        except StopIteration:
            yield -2

    g = gen()
    results: list[object] = []
    results.append(next(g))
    results.append(g.send("hi"))
    results.append(g.throw(ValueError("test")))
    return results


def comprehension_with_filter() -> list[tuple[int, str]]:
    pairs: list[tuple[int, str]] = []
    for i in range(20):
        if i % 3 == 0 and i % 5 == 0:
            pairs.append((i, "fizzbuzz"))
        elif i % 3 == 0:
            pairs.append((i, "fizz"))
        elif i % 5 == 0:
            pairs.append((i, "buzz"))
    return pairs


def list_assignment_targets() -> tuple[int, int, list[int], int]:
    seq = list(range(10))
    first, second, *middle, last = seq
    return first, second, middle, last


def dict_merge_unpack() -> dict[str, int]:
    a = {"x": 1, "y": 2}
    b = {"y": 20, "z": 30}
    return {**a, **b, "w": 99}


def set_operations() -> dict[str, set[int]]:
    a = {1, 2, 3, 4, 5}
    b = {4, 5, 6, 7, 8}
    return {
        "union": a | b,
        "intersection": a & b,
        "difference": a - b,
        "symmetric_difference": a ^ b,
    }


def yield_from_demo() -> typing.Iterator[int]:
    def inner() -> typing.Iterator[int]:
        yield 1
        yield 2
        yield 3

    yield 0
    yield from inner()
    yield 4


def conditional_generator_expression() -> int:
    return sum(x * 2 if x % 2 else x for x in range(20) if x > 5)


def nested_function_with_closures() -> Callable[[int], int]:
    def outer() -> Callable[[int], int]:
        captured = [0]

        def middle() -> Callable[[int], int]:
            def inner(x: int) -> int:
                captured[0] += x
                return captured[0]

            return inner

        return middle()

    return outer()


def deeply_nested_dict_access() -> object:
    d = {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}
    return d["a"]["b"]["c"]["d"]["e"]["f"]


def unicode_normalization() -> tuple[str, str, str, str]:
    s = "café"
    return (
        unicodedata.normalize("NFC", s),
        unicodedata.normalize("NFD", s),
        unicodedata.normalize("NFKC", s),
        unicodedata.normalize("NFKD", s),
    )


def regex_callbacks() -> str:
    return re.sub(r"\d+", lambda m: f"<{int(m.group()):02d}>", "abc 5 def 42 ghi 100")


def regex_lookarounds() -> list[str]:
    return re.findall(r"(?<=\$)\d+(?=\.\d{2})", "price: $42.99, tax: $3.50")


def named_groups() -> dict[str, str]:
    m = re.match(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})", "2026-05-24")
    assert m is not None
    return m.groupdict()


def format_strings_extensive() -> list[str]:
    items: list[str] = []
    items.append(f"{42:08b}")
    items.append(f"{42:#x}")
    items.append(f"{42:#o}")
    items.append(f"{3.14159:.2f}")
    items.append(f"{3.14159:>10.4f}")
    items.append(f"{3.14159:<10.4f}")
    items.append(f"{3.14159:^10.4f}")
    items.append(f"{3.14159:0.4e}")
    items.append(f"{3.14159:%}")
    items.append(f"{'hello':*^20}")
    items.append(f"{True:5}")
    items.append(f"{1.5:+.2f}")
    items.append(f"{1234567:_d}")
    items.append(f"{1234567:,d}")
    return items


def all_demos_extended() -> dict[str, object]:
    out = all_demos()
    out["singleton_same"] = Singleton() is Singleton()
    out["circular_buf"] = (
        lambda: (lambda b: (b.push(1), b.push(2), b.push(3), b.push(4), b.pop()))(CircularBuffer(3))
    )()
    out["linked_list"] = (
        lambda: (lambda ll: (ll.push(1), ll.push(2), ll.push(3), ll.to_list()))(LinkedList())
    )()
    out["quicksort"] = quicksort([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5])
    out["mergesort"] = mergesort([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5])
    out["heapsort"] = heapsort([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5])
    out["palindrome"] = is_palindrome("A man a plan a canal Panama")
    out["caesar"] = caesar_cipher("Hello, World!", 3)
    out["transpose"] = matrix_transpose([[1, 2, 3], [4, 5, 6]])
    out["rotate"] = matrix_rotate_cw([[1, 2], [3, 4]])
    out["gcd"] = gcd(48, 18)
    out["lcm"] = lcm(4, 6)
    out["primes"] = primes_up_to(50)
    out["fact"] = factorial(10)
    out["collatz_len"] = len(collatz(27))
    out["lev"] = levenshtein_dp("kitten", "sitting")
    out["lcs"] = longest_common_subseq("ABCBDAB", "BDCAB")
    out["graph_bfs"] = bfs({1: [2, 3], 2: [4], 3: [4, 5], 4: [], 5: []}, 1)
    out["graph_dfs"] = dfs_iterative({1: [2, 3], 2: [4], 3: [4, 5], 4: [], 5: []}, 1)
    out["topo"] = topological_sort({1: [2, 3], 2: [4], 3: [4], 4: []})
    out["state_machine"] = (lambda sm: (sm.transition("start"), sm.transition("pause"), sm.state))(
        StateMachine()
    )
    out["expensive"] = expensive_calc(3, 4)
    out["flaky"] = flaky_op(5)
    out["context_var"] = context_var_demo()
    out["thread_lock"] = thread_lock_demo()
    out["queue_demo"] = queue_demo()
    out["io_str"] = io_string_demo()
    out["io_bytes"] = io_bytes_demo().hex()
    out["csv_demo"] = csv_demo()
    out["chain"] = itertools_chain_demo()
    out["starmap"] = itertools_starmap_demo()
    out["tee"] = itertools_tee_demo()
    out["dropwhile"] = itertools_dropwhile_takewhile()
    out["yield_from"] = list(yield_from_demo())
    out["cond_gen"] = conditional_generator_expression()
    out["closure_nested"] = nested_function_with_closures()(10)
    out["deeply_nested"] = deeply_nested_dict_access()
    out["unicode_norm"] = unicode_normalization()
    out["regex_callback"] = regex_callbacks()
    out["regex_la"] = regex_lookarounds()
    out["named_groups"] = named_groups()
    out["fmt_strings"] = format_strings_extensive()
    out["set_ops"] = set_operations()
    out["dict_merge"] = dict_merge_unpack()
    out["list_targets"] = list_assignment_targets()
    return out


def extended_main() -> None:
    results = all_demos_extended()
    print(f"recovered {len(results)} demo keys")
    for key in sorted(results.keys())[:5]:
        print(f"  {key}: {str(results[key])[:80]}")


if __name__ == "__main__":
    main()
    extended_main()
