from __future__ import annotations

from typing import Annotated, Any, Callable, Final, TypeVar

from edge_cases_3_8 import *
from edge_cases_3_8 import exercise as _exercise_3_8

__PY_BAND__: tuple[int, int] = (3, 9)

T = TypeVar("T")

PEP585_USE: Final[list[int]] = [1, 2, 3]
PEP585_MAP: Final[dict[str, int]] = {"a": 1, "b": 2}


def pep585_builtin_generics(values: list[int]) -> dict[str, list[int]]:
    positives: list[int] = [v for v in values if v > 0]
    negatives: list[int] = [v for v in values if v < 0]
    return {"positive": positives, "negative": negatives, "zero": [v for v in values if v == 0]}


def pep585_set_and_tuple(items: set[int], pair: tuple[int, ...]) -> tuple[set[int], int]:
    extended: set[int] = items | set(pair)
    return extended, len(extended)


def pep584_dict_merge(base: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
    return base | extra | {"flag": 1}


def pep584_dict_merge_inplace(target: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
    target |= extra
    target |= {"flag": 1}
    return target


PositiveInt = Annotated[int, "must be > 0"]
HostHeader = Annotated[str, "rfc-7230", "case-insensitive"]


def annotated_param(count: PositiveInt, header: HostHeader) -> str:
    return f"{count}@{header}"


def annotated_in_collection(values: list[Annotated[int, "scaled"]]) -> int:
    return sum(values)


def make_decorator() -> Callable[[Callable[..., T]], Callable[..., T]]:

    def deco(fn: Callable[..., T]) -> Callable[..., T]:
        return fn

    return deco


_REGISTRY: dict[str, Callable[..., Any]] = {}


def register(key: str) -> Callable[[Callable[..., T]], Callable[..., T]]:

    def deco(fn: Callable[..., T]) -> Callable[..., T]:
        _REGISTRY[key] = fn
        return fn

    return deco


@(make_decorator())
def pep614_call_as_decorator(x: int) -> int:
    return x + 1


@register("handler-a")
@register("handler-b")
def pep614_subscript_chain(payload: dict[str, int]) -> int:
    return sum(payload.values())


def pep616_string_strips(text: str) -> tuple[str, str]:
    return text.removeprefix("http://"), text.removesuffix(".log")


def builtin_generic_in_class_body() -> int:

    class Bag:
        items: list[int] = []
        index: dict[str, int] = {}

        def add(self, v: int) -> None:
            self.items.append(v)
            self.index[str(v)] = v

    b: Bag = Bag()
    b.add(1)
    b.add(2)
    return len(b.items)


def starred_double_in_call(prefix: list[int], suffix: list[int]) -> int:
    return max(*prefix, *suffix)


def exercise() -> None:
    _exercise_3_8()
    routed: dict[str, list[int]] = pep585_builtin_generics([1, -2, 0, 3, -4])
    assert routed["positive"] == [1, 3]
    assert routed["negative"] == [-2, -4]
    assert routed["zero"] == [0]
    extended, n = pep585_set_and_tuple({1, 2}, (3, 4))
    assert extended == {1, 2, 3, 4} and n == 4
    assert pep584_dict_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2, "flag": 1}
    base: dict[str, int] = {"x": 1}
    merged: dict[str, int] = pep584_dict_merge_inplace(base, {"y": 2})
    assert merged is base and base == {"x": 1, "y": 2, "flag": 1}
    assert annotated_param(5, "example.com") == "5@example.com"
    assert annotated_in_collection([1, 2, 3]) == 6
    assert pep614_call_as_decorator(1) == 2
    assert pep614_subscript_chain({"a": 1, "b": 2}) == 3
    assert "handler-a" in _REGISTRY and "handler-b" in _REGISTRY
    prefix, suffix = pep616_string_strips("http://example.com/file.log")
    assert prefix == "example.com/file.log"
    assert suffix == "http://example.com/file"
    assert builtin_generic_in_class_body() == 2
    assert starred_double_in_call([1, 5], [3, 9]) == 9
    print("edge_cases_3_9: exercise ok")


if __name__ == "__main__":
    exercise()
