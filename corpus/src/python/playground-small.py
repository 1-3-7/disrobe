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
