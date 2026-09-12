from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Concatenate, Final, ParamSpec, TypeAlias, TypeGuard, TypeVar

from edge_cases_3_9 import *
from edge_cases_3_9 import exercise as _exercise_3_9

__PY_BAND__: tuple[int, int] = (3, 10)

P = ParamSpec("P")
R = TypeVar("R")

JsonValue: TypeAlias = "str | int | float | bool | None | list[Any] | dict[str, Any]"
Number: TypeAlias = int | float
NumberOrNone: TypeAlias = int | float | None


class Status(enum.Enum):

    OK = 1
    ERR = 2
    PENDING = 3


@dataclass
class HttpResponse:

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


def pep604_union_param(value: int | str | None) -> str:
    if value is None:
        return "none"
    if isinstance(value, int):
        return f"int:{value}"
    return f"str:{value}"


def pep604_union_return(flag: bool) -> int | str:
    return 42 if flag else "fallback"


def parenthesized_with(a: Any, b: Any, c: Any) -> tuple[Any, Any, Any]:
    with (
        a as first,
        b as second,
        c as third,
    ):
        return first, second, third


def match_literal_pattern(token: object) -> str:
    match token:
        case 0:
            return "zero"
        case "init":
            return "literal-string"
        case True:
            return "literal-true"
        case None:
            return "literal-none"
        case _:
            return "other"


def match_capture_pattern(value: object) -> tuple[str, object]:
    match value:
        case 0:
            return ("literal-zero", value)
        case captured:
            return ("captured", captured)


def match_wildcard_pattern(value: object) -> str:
    match value:
        case 42:
            return "answer"
        case _:
            return "anything-else"


def match_value_pattern(state: Status) -> int:
    match state:
        case Status.OK:
            return 200
        case Status.ERR:
            return 500
        case Status.PENDING:
            return 102


def match_group_pattern(value: object) -> str:
    match value:
        case (1 | 2 | 3):
            return "small"
        case (("a" | "b") as letter):
            return f"letter:{letter}"
        case _:
            return "other"


def match_sequence_pattern(seq: list[int]) -> str:
    match seq:
        case []:
            return "empty"
        case [single]:
            return f"one:{single}"
        case [first, second]:
            return f"two:{first},{second}"
        case [first, *middle, last]:
            return f"first-mid-last:{first}/{len(middle)}/{last}"
        case _:
            return "other"


def match_mapping_pattern(event: dict[str, Any]) -> str:
    match event:
        case {"type": "click", "x": x, "y": y}:
            return f"click@{x},{y}"
        case {"type": kind, **extras}:
            return f"{kind}+{len(extras)}"
        case {}:
            return "empty-map"
        case _:
            return "non-map"


def match_class_pattern(response: HttpResponse) -> str:
    match response:
        case HttpResponse(status=200, body=b""):
            return "empty-ok"
        case HttpResponse(status=200, body=payload):
            return f"ok:{len(payload)}"
        case HttpResponse(status=code) if code >= 500:
            return f"server-error:{code}"
        case HttpResponse(404, body):
            return f"not-found:{len(body)}"
        case _:
            return "other"


def match_with_guard(value: int) -> str:
    match value:
        case n if n < 0:
            return f"neg:{n}"
        case 0:
            return "zero"
        case n if n % 2 == 0:
            return f"even:{n}"
        case n:
            return f"odd:{n}"


def match_or_pattern(token: object) -> str:
    match token:
        case 0 | 1 | 2:
            return "small-int"
        case "yes" | "no" | "maybe":
            return "tri-state"
        case [1, 2] | [3, 4]:
            return "specific-pair"
        case _:
            return "other"


def match_as_pattern(value: object) -> str:
    match value:
        case [int() as first, *_]:
            return f"int-head:{first}"
        case (1 | 2 | 3) as small:
            return f"small:{small}"
        case str() as text if len(text) > 0:
            return f"non-empty-str:{text}"
        case _:
            return "other"


def match_nested_patterns(payload: dict[str, Any]) -> str:
    match payload:
        case {"events": [HttpResponse(status=200) as ok, *_], "user": str(name)}:
            return f"first-ok-for:{name}@{ok.status}"
        case {"events": [HttpResponse(status=s), *_]} if s >= 400:
            return f"first-bad:{s}"
        case {"events": [], "user": str() as user}:
            return f"no-events:{user}"
        case {"events": list() as evs}:
            return f"events:{len(evs)}"
        case _:
            return "malformed"


def paramspec_decorator(fn: Callable[P, R]) -> Callable[P, R]:

    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return fn(*args, **kwargs)

    return wrapper


def concatenate_decorator(fn: Callable[Concatenate[int, P], R]) -> Callable[Concatenate[int, P], R]:

    def wrapper(prefix: int, *args: P.args, **kwargs: P.kwargs) -> R:
        return fn(prefix * 2, *args, **kwargs)

    return wrapper


@paramspec_decorator
def paramspec_consumer(host: str, port: int = 80) -> str:
    return f"{host}:{port}"


@concatenate_decorator
def concat_consumer(scaled: int, label: str) -> str:
    return f"{label}={scaled}"


def is_int_list(values: list[Any]) -> TypeGuard[list[int]]:
    return all(isinstance(v, int) for v in values)


def use_type_guard(values: list[Any]) -> int:
    if is_int_list(values):
        return sum(values)
    return -1


def union_in_class_body() -> str:

    class Box:
        value: int | str | None = None

        def set(self, v: int | str | None) -> None:
            self.value = v

    b: Box = Box()
    b.set("text")
    return str(b.value)


def exercise() -> None:
    _exercise_3_9()
    assert pep604_union_param(7) == "int:7"
    assert pep604_union_param("x") == "str:x"
    assert pep604_union_param(None) == "none"
    assert pep604_union_return(True) == 42
    assert pep604_union_return(False) == "fallback"

    class _Mgr:
        def __init__(self, tag: str) -> None:
            self.tag: str = tag

        def __enter__(self) -> str:
            return self.tag

        def __exit__(self, *_: object) -> None:
            return None

    f, s, t = parenthesized_with(_Mgr("a"), _Mgr("b"), _Mgr("c"))
    assert (f, s, t) == ("a", "b", "c")
    assert match_literal_pattern(0) == "zero"
    assert match_literal_pattern("init") == "literal-string"
    assert match_literal_pattern(True) == "literal-true"
    assert match_literal_pattern(None) == "literal-none"
    assert match_literal_pattern(99) == "other"
    assert match_capture_pattern(0) == ("literal-zero", 0)
    assert match_capture_pattern("anything") == ("captured", "anything")
    assert match_wildcard_pattern(42) == "answer"
    assert match_wildcard_pattern(1) == "anything-else"
    assert match_value_pattern(Status.OK) == 200
    assert match_value_pattern(Status.PENDING) == 102
    assert match_group_pattern(2) == "small"
    assert match_group_pattern("a") == "letter:a"
    assert match_sequence_pattern([]) == "empty"
    assert match_sequence_pattern([1]) == "one:1"
    assert match_sequence_pattern([1, 2]) == "two:1,2"
    assert match_sequence_pattern([1, 2, 3, 4]) == "first-mid-last:1/2/4"
    assert match_mapping_pattern({"type": "click", "x": 10, "y": 20}) == "click@10,20"
    assert match_mapping_pattern({"type": "scroll", "dy": 5}) == "scroll+1"
    assert match_mapping_pattern({}) == "empty-map"
    resp: HttpResponse = HttpResponse(200, b"hello")
    assert match_class_pattern(resp) == "ok:5"
    assert match_class_pattern(HttpResponse(200, b"")) == "empty-ok"
    assert match_class_pattern(HttpResponse(503, b"")) == "server-error:503"
    assert match_with_guard(-3) == "neg:-3"
    assert match_with_guard(0) == "zero"
    assert match_with_guard(4) == "even:4"
    assert match_with_guard(5) == "odd:5"
    assert match_or_pattern(1) == "small-int"
    assert match_or_pattern("yes") == "tri-state"
    assert match_or_pattern([1, 2]) == "specific-pair"
    assert match_as_pattern([7, 8, 9]) == "int-head:7"
    assert match_as_pattern("hi") == "non-empty-str:hi"
    nested: dict[str, Any] = {"events": [HttpResponse(200, b"ok")], "user": "alpha"}
    assert match_nested_patterns(nested) == "first-ok-for:alpha@200"
    bad: dict[str, Any] = {"events": [HttpResponse(500, b"")]}
    assert match_nested_patterns(bad) == "first-bad:500"
    assert paramspec_consumer("h") == "h:80"
    assert concat_consumer(5, "x") == "x=10"
    assert use_type_guard([1, 2, 3]) == 6
    assert use_type_guard([1, "x"]) == -1
    assert union_in_class_body() == "text"
    print("edge_cases_3_10: exercise ok")


if __name__ == "__main__":
    exercise()
