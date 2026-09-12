from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any, TypedDict, Unpack, override

from edge_cases_3_11 import *
from edge_cases_3_11 import exercise as _exercise_3_11

__PY_BAND__: tuple[int, int] = (3, 12)


type Vector = list[float]
type Handler = Callable[[bytes], Awaitable[int]]
type Pair[U] = tuple[U, U]
type Callback[**P, U] = Callable[P, Awaitable[U]]


def pep695_generic_function[U](item: U) -> tuple[U, U]:
    return (item, item)


def pep695_constrained[U: (int, str)](value: U) -> str:
    return f"{type(value).__name__}:{value}"


def pep695_bound[U: Sequence[int]](seq: U) -> int:
    return sum(seq)


def pep695_paramspec[**P, U](fn: Callable[P, U]) -> Callable[P, U]:

    def wrapper(*args: P.args, **kwargs: P.kwargs) -> U:
        return fn(*args, **kwargs)

    return wrapper


def pep695_typevartuple[*Ts](values: tuple[*Ts]) -> tuple[*Ts]:
    return values


class Pipeline[T]:

    def __init__(self, name: str) -> None:
        self.name: str = name
        self._stages: list[Callable[[T], T]] = []

    def add(self, stage: Callable[[T], T]) -> Pipeline[T]:
        self._stages.append(stage)
        return self

    def run(self, item: T) -> T:
        for stage in self._stages:
            item = stage(item)
        return item


class GenericBox[U]:

    def __init__(self, item: U) -> None:
        self.item: U = item

    def swap[V](self, other: V) -> GenericBox[V]:
        return GenericBox(other)


class ParentService:

    def handle(self, payload: bytes) -> int:
        return len(payload)


class ChildService(ParentService):

    @override
    def handle(self, payload: bytes) -> int:
        return len(payload) * 2


def fstring_pep701_same_quote(items: list[str]) -> str:
    name: str = "alpha"
    return f"outer-{f"inner-{name}"}-{f"[{', '.join(f"{x}" for x in items)}]"}"


def fstring_pep701_multiline(rows: list[dict[str, int]]) -> str:
    return f"summary: {
        sum(
            row.get('count', 0)
            for row in rows
            if row
        )
    } rows"


def fstring_pep701_backslash(paths: list[str]) -> str:
    return f"joined:\n{'\n'.join(paths)}\n--end--"


class UnpackKwargs(TypedDict):

    id: int
    name: str
    role: str


def consume_unpacked_typeddict(**fields: Unpack[UnpackKwargs]) -> str:
    return f"{fields['id']}:{fields['name']}:{fields['role']}"


def call_with_unpack() -> str:
    user: UnpackKwargs = {"id": 1, "name": "alpha", "role": "admin"}
    return consume_unpacked_typeddict(**user)


def use_pep695_type_alias(vec: Vector) -> float:
    return sum(vec) / len(vec) if vec else 0.0


def use_pep695_generic_alias() -> Pair[int]:
    p: Pair[int] = (1, 2)
    return p


def exercise() -> None:
    _exercise_3_11()
    assert pep695_generic_function(7) == (7, 7)
    assert pep695_constrained(5) == "int:5"
    assert pep695_constrained("x") == "str:x"
    assert pep695_bound([1, 2, 3]) == 6

    @pep695_paramspec
    def _wrapped(a: int, b: int = 2) -> int:
        return a * b

    assert _wrapped(3) == 6
    assert pep695_typevartuple((1, "x", 3.14)) == (1, "x", 3.14)
    pipeline: Pipeline[int] = Pipeline("doubler").add(lambda x: x * 2).add(lambda x: x + 1)
    assert pipeline.run(3) == 7
    box: GenericBox[int] = GenericBox(42)
    swapped: GenericBox[str] = box.swap("hi")
    assert swapped.item == "hi"
    assert ChildService().handle(b"abcd") == 8
    same: str = fstring_pep701_same_quote(["a", "b"])
    assert "inner-alpha" in same and "[a, b]" in same
    rows: list[dict[str, int]] = [{"count": 5}, {"count": 3}, {}]
    multi: str = fstring_pep701_multiline(rows)
    assert "8 rows" in multi
    back: str = fstring_pep701_backslash(["a", "b", "c"])
    assert back.startswith("joined:\n") and "--end--" in back
    assert call_with_unpack() == "1:alpha:admin"
    assert use_pep695_type_alias([1.0, 2.0, 3.0]) == 2.0
    assert use_pep695_generic_alias() == (1, 2)
    print("edge_cases_3_12: exercise ok")


if __name__ == "__main__":
    exercise()
