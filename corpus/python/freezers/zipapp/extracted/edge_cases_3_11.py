from __future__ import annotations

import asyncio
import enum
from typing import Any, Callable, NotRequired, Required, Self, TypedDict

from edge_cases_3_10 import *
from edge_cases_3_10 import exercise as _exercise_3_10

__PY_BAND__: tuple[int, int] = (3, 11)


def except_star_basic(do_work: Callable[[], None]) -> dict[str, int]:
    counts: dict[str, int] = {"value": 0, "type": 0, "other": 0}
    try:
        do_work()
    except* ValueError as eg:
        counts["value"] = len(eg.exceptions)
    except* TypeError as eg:
        counts["type"] = len(eg.exceptions)
    except* Exception as eg:
        counts["other"] = len(eg.exceptions)
    return counts


def except_star_reraise(group_factory: Callable[[], BaseException]) -> int:
    handled: int = 0
    try:
        raise group_factory()
    except* ValueError as eg:
        handled = len(eg.exceptions)
    except* (KeyError, IndexError) as eg:
        if len(eg.exceptions) > 2:
            raise
        handled += len(eg.exceptions)
    return handled


def raise_exception_group(messages: list[str]) -> None:
    leaves: list[Exception] = [ValueError(m) for m in messages]
    raise ExceptionGroup("batch failed", leaves)


def raise_base_exception_group(reason: str) -> None:
    leaves: list[BaseException] = [KeyboardInterrupt(reason), SystemExit(reason)]
    raise BaseExceptionGroup("system halt", leaves)


def add_note_demo(message: str, *notes: str) -> ValueError:
    exc: ValueError = ValueError(message)
    for n in notes:
        exc.add_note(n)
    return exc


class FluentBuilder:

    def __init__(self) -> None:
        self._parts: list[str] = []

    def add(self, part: str) -> Self:
        self._parts.append(part)
        return self

    def build(self) -> str:
        return "/".join(self._parts)


class IndentedBuilder(FluentBuilder):

    def add(self, part: str) -> Self:
        return super().add(f"  {part}")


class UserProfile(TypedDict):

    id: Required[int]
    name: Required[str]
    bio: NotRequired[str]
    avatar_url: NotRequired[str]


class PartialProfile(TypedDict, total=False):

    name: Required[str]
    locale: str
    timezone: str


def consume_typeddict_required(profile: UserProfile) -> str:
    return f"{profile['id']}:{profile['name']}"


class Severity(enum.StrEnum):

    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


def use_strenum(level: Severity) -> str:
    return f"level={level}"


async def task_group_basic(coros: list[Any]) -> int:
    results: list[int] = []
    async with asyncio.TaskGroup() as tg:
        tasks: list[asyncio.Task[int]] = [tg.create_task(c) for c in coros]
    for t in tasks:
        results.append(t.result())
    return sum(results)


async def task_group_with_except_star(coros: list[Any]) -> int:
    result: int = 0
    try:
        async with asyncio.TaskGroup() as tg:
            for c in coros:
                tg.create_task(c)
    except* ValueError as eg:
        result = -len(eg.exceptions)
    except* TimeoutError as eg:
        result = -2 * len(eg.exceptions)
    return result


async def asyncio_timeout_basic(work: Any) -> int:
    async with asyncio.timeout(5.0):
        return int(await work)


def exercise() -> None:
    _exercise_3_10()

    def _raises_group() -> None:
        raise ExceptionGroup("test", [ValueError("a"), ValueError("b"), TypeError("c")])

    counts: dict[str, int] = except_star_basic(_raises_group)
    assert counts["value"] == 2 and counts["type"] == 1

    def _gf() -> BaseException:
        return ExceptionGroup("g", [ValueError("x"), KeyError("k")])

    assert except_star_reraise(_gf) == 2

    try:
        raise_exception_group(["a", "b", "c"])
    except ExceptionGroup as eg:
        assert len(eg.exceptions) == 3
    else:
        raise AssertionError("ExceptionGroup not raised")

    try:
        raise_base_exception_group("halt")
    except BaseExceptionGroup as eg:
        assert len(eg.exceptions) == 2
    else:
        raise AssertionError("BaseExceptionGroup not raised")

    exc: ValueError = add_note_demo("bad", "context-a", "context-b")
    assert getattr(exc, "__notes__", []) == ["context-a", "context-b"]

    base_b: FluentBuilder = FluentBuilder().add("a").add("b").add("c")
    assert base_b.build() == "a/b/c"
    indented: IndentedBuilder = IndentedBuilder().add("x").add("y")
    assert "  x" in indented.build() and "  y" in indented.build()

    profile: UserProfile = {"id": 1, "name": "alpha"}
    assert consume_typeddict_required(profile) == "1:alpha"
    assert use_strenum(Severity.WARN) == "level=warn"
    assert Severity.WARN == "warn"

    async def _drive() -> None:
        async def _make(v: int) -> int:
            await asyncio.sleep(0)
            return v

        total: int = await task_group_basic([_make(1), _make(2), _make(3)])
        assert total == 6

        async def _ok(v: int) -> int:
            await asyncio.sleep(0)
            return v

        async def _bad() -> int:
            raise ValueError("nope")

        score: int = await task_group_with_except_star([_ok(1), _bad(), _bad()])
        assert score == -2

        async def _produce() -> int:
            await asyncio.sleep(0)
            return 7

        assert await asyncio_timeout_basic(_produce()) == 7

    asyncio.run(_drive())
    print("edge_cases_3_11: exercise ok")


if __name__ == "__main__":
    exercise()
