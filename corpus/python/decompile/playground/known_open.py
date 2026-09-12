from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterator
from typing import Any, Generic, TypeVar

T = TypeVar("T")


def assert_statements(value: int, items: list[int]) -> int:
    assert value >= 0
    assert items, "items must be non-empty"
    return items[value]


def generator_yield_from(limit: int) -> Iterator[int]:
    yield from range(limit)


def nested_try_finally(a: Any) -> Any:
    try:
        try:
            return a()
        finally:
            print("inner")
    finally:
        print("outer")


def finally_with_return_override(flag: bool) -> int:
    try:
        if flag:
            return 1
        return 2
    finally:
        if not flag:
            return 3


def with_multiple_items(a: Any, b: Any) -> None:
    with a as first, b as second:
        print(first, second)


def with_parenthesized(a: Any, b: Any, c: Any) -> None:
    with (a as first, b as second, c as third):
        print(first, second, third)


def with_return_wrapped_by_finally(lock: Any, rowid: int | None) -> int:
    cursor: int | None = None
    try:
        with lock:
            cursor = rowid
            return int(cursor or 0)
    finally:
        if cursor:
            release(cursor)


def with_await_in_except(pool: Any) -> Any:
    async def impl() -> int:
        try:
            return await pool.read()
        except ConnectionError:
            with contextlib.suppress(Exception):
                await pool.recycle()
            return -1

    return impl


def async_with_in_try_finally(resource: Any) -> Any:
    async def impl() -> int:
        try:
            async with resource as r:
                return await r.size()
        finally:
            with contextlib.suppress(ConnectionError):
                await resource.aclose()

    return impl


def async_for_else(stream: AsyncIterator[int]) -> Any:
    async def impl() -> int:
        found = -1
        async for value in stream:
            if value > 100:
                found = value
                break
        else:
            found = 0
        return found

    return impl


def try_continue_finally(xs: list[int]) -> int:
    total = 0
    for x in xs:
        try:
            total += 100 // x
        except ZeroDivisionError:
            continue
        finally:
            total += 1
    return total


def match_value_patterns(command: str) -> int:
    match command:
        case "start":
            return 1
        case "stop":
            return 2
        case _:
            return 0


def match_class_pattern(shape: object) -> float:
    match shape:
        case Circle(radius=r):
            return 3.14159 * r * r
        case _:
            return 0.0


def match_sequence_patterns(seq: list[int]) -> str:
    match seq:
        case []:
            return "empty"
        case [first, *rest]:
            return f"{first}+{len(rest)}"
        case _:
            return "other"


def match_mapping_patterns(event: dict[str, Any]) -> str:
    match event:
        case {"type": "click", "x": x, "y": y}:
            return f"click@{x},{y}"
        case {"type": kind, **extra}:
            return f"{kind}+{len(extra)}"
        case _:
            return "malformed"


def chained_assignment(total: int) -> list[int]:
    a = b = c = total
    return [a, b, c]


def dict_double_unpack(base: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
    return dict(**base, **extra, flag=True)


def multiple_inheritance_base_order() -> type:

    class MixinA:
        def a(self) -> int:
            return 1

    class MixinB:
        def b(self) -> int:
            return 2

    class Combined(MixinA, MixinB):
        def total(self) -> int:
            return self.a() + self.b()

    return Combined


class GenericContainer(Generic[T]):

    def __init__(self, initial: T) -> None:
        self._items: list[T] = [initial]

    def pop(self) -> T:
        return self._items.pop()


def release(cursor: int) -> None:
    print(f"release {cursor}")


class Circle:
    __match_args__ = ("radius",)

    def __init__(self, radius: float) -> None:
        self.radius = radius
