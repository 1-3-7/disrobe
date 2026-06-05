from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, cast

from edge_cases_3_12 import *
from edge_cases_3_12 import exercise as _exercise_3_12

__PY_BAND__: tuple[int, int] = (3, 13)


def pep696_default_function[U = int](value: U | None = None) -> U:
    if value is None:
        return cast(U, 0)
    return value


def pep696_constrained_default[U: (int, str) = int](value: U) -> str:
    return f"{type(value).__name__}:{value}"


class Pep696Container[U = str]:

    def __init__(self, item: U) -> None:
        self.item: U = item

    def get(self) -> U:
        return self.item


class Pep696BoundDefault[U: (int, str) = int]:

    def __init__(self, value: U) -> None:
        self.value: U = value


def pep696_paramspec_default[**P = ..., U = int](fn: Any) -> Any:
    return fn


def pep696_typevartuple_default[*Ts = *tuple[int, ...]](values: tuple[*Ts]) -> int:
    return len(values)


type DefaultedAlias[U = int] = list[U]


@dataclass
class StaticAttrCarrier:

    label: str
    count: int


def use_static_attrs(obj: StaticAttrCarrier) -> int:
    cls: type[StaticAttrCarrier] = type(obj)
    first_line: int = getattr(cls, "__firstlineno__", -1)
    static_attrs: tuple[str, ...] = getattr(cls, "__static_attributes__", ())
    return first_line + len(static_attrs)


def pep762_copy_replace(obj: StaticAttrCarrier, **overrides: Any) -> StaticAttrCarrier:
    return copy.replace(obj, **overrides)


def exercise() -> None:
    _exercise_3_12()
    assert pep696_default_function() == 0
    assert pep696_default_function(7) == 7
    assert pep696_default_function("x") == "x"
    assert pep696_constrained_default(3) == "int:3"
    assert pep696_constrained_default("y") == "str:y"
    container: Pep696Container[str] = Pep696Container("hello")
    assert container.get() == "hello"
    bound: Pep696BoundDefault[int] = Pep696BoundDefault(42)
    assert bound.value == 42

    def _identity(x: int) -> int:
        return x + 1

    wrapped: Any = pep696_paramspec_default(_identity)
    assert wrapped(1) == 2
    assert pep696_typevartuple_default((1, 2, 3)) == 3
    obj: StaticAttrCarrier = StaticAttrCarrier("alpha", 5)
    score: int = use_static_attrs(obj)
    assert score > 0
    replaced: StaticAttrCarrier = pep762_copy_replace(obj, count=99)
    assert replaced.count == 99 and replaced.label == "alpha"
    assert obj.count == 5
    print("edge_cases_3_13: exercise ok")


if __name__ == "__main__":
    exercise()
