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
