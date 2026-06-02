from __future__ import annotations

from typing import Any, Callable, Dict, Final, Iterator, List, Literal, Optional, Protocol, Set, Tuple, TypedDict

from edge_cases_3_6 import *
from edge_cases_3_6 import exercise as _exercise_3_6

__PY_BAND__: Tuple[int, int] = (3, 8)

WALRUS_LIMIT: Final[int] = 100
SENTINEL_TOKEN: Final[str] = "unset"


def walrus_in_condition(data: Dict[str, str]) -> str:
    if (name := data.get("name")) is not None:
        return name.upper()
    return "anon"


def walrus_in_while(stream: Iterator[bytes]) -> int:
    total: int = 0
    while chunk := next(stream, b""):
        total += len(chunk)
    return total


def walrus_in_comprehension(xs: List[int]) -> List[int]:
    return [y for x in xs if (y := x * 2) > 4]


def walrus_in_membership(rows: List[Dict[str, str]], allowed: Set[str]) -> List[str]:
    return [norm for raw in rows if (norm := raw.get("domain", "").strip().lower()) in allowed]


def walrus_in_call_arg(data: List[int]) -> int:
    return (n * 2) if (n := len(data)) > 0 else 0


def positional_only_basic(a: int, b: int, /, c: int, d: int = 4) -> int:
    return a + b + c + d


def positional_only_with_kwargs(host: str, port: int, /, *, scheme: str = "https", **extras: Any) -> str:
    suffix: str = "&".join(f"{k}={v}" for k, v in extras.items())
    return f"{scheme}://{host}:{port}?{suffix}" if extras else f"{scheme}://{host}:{port}"


def fstring_debug_form(count: int, ratio: float) -> str:
    return f"{count=}, {ratio=:.1f}"


def fstring_nested_spec(x: float, width: int) -> str:
    return f"{x:{width}.2f}" + f"{x!r:>{width}}"


class UserBasic(TypedDict):

    id: int
    name: str
    role: str


class UserOptional(TypedDict, total=False):

    bio: str
    avatar: str


def consume_user_basic(user: UserBasic) -> str:
    return f"{user['id']}:{user['name']}:{user['role']}"


class SupportsClose(Protocol):

    def close(self) -> None: ...


def call_close(thing: SupportsClose) -> None:
    thing.close()


Mode = Literal["read", "write", "append"]


def open_in_mode(path: str, mode: Mode) -> str:
    return f"{path}::{mode}"


def final_in_class() -> str:

    class Config:
        MAX: Final[int] = 10
        NAME: Final[str] = "default"

    return f"{Config.MAX}/{Config.NAME}"


def conditional_walrus_route(values: List[int]) -> Dict[str, Any]:
    if (count := len(values)) == 0:
        return {"ok": False, "reason": "empty"}
    if (high := max(values)) > WALRUS_LIMIT:
        return {"ok": False, "reason": "out-of-range", "count": count, "high": high}
    doubled: List[int] = [y for x in values if (y := x * 2) > 0]
    return {"ok": True, "count": count, "doubled": doubled}


def try_except_walrus_capture(text: str) -> Tuple[bool, int]:
    try:
        if (parsed := int(text)) > 0:
            return True, parsed
    except ValueError:
        return False, -1
    return False, 0


def exercise() -> None:
    _exercise_3_6()
    assert walrus_in_condition({"name": "alpha"}) == "ALPHA"
    assert walrus_in_condition({}) == "anon"

    def _stream() -> Iterator[bytes]:
        for chunk in [b"abc", b"de", b""]:
            yield chunk

    assert walrus_in_while(_stream()) == 5
    assert walrus_in_comprehension([1, 2, 3, 4]) == [6, 8]
    rows: List[Dict[str, str]] = [{"domain": "A"}, {"domain": "b"}, {"domain": "c"}]
    assert walrus_in_membership(rows, {"a", "b"}) == ["a", "b"]
    assert walrus_in_call_arg([1, 2, 3]) == 6
    assert positional_only_basic(1, 2, 3) == 10
    assert positional_only_basic(1, 2, 3, 5) == 11
    assert positional_only_with_kwargs("h", 80) == "https://h:80"
    assert "tag=v" in positional_only_with_kwargs("h", 80, tag="v")
    assert fstring_debug_form(7, 0.5) == "count=7, ratio=0.5"
    spec: str = fstring_nested_spec(1.5, 6)
    assert "  1.50" in spec
    user: UserBasic = {"id": 1, "name": "alpha", "role": "admin"}
    assert consume_user_basic(user) == "1:alpha:admin"

    class _Closer:
        def close(self) -> None:
            self.closed = True

    c: _Closer = _Closer()
    call_close(c)
    assert getattr(c, "closed", False) is True
    assert open_in_mode("/tmp/x", "read") == "/tmp/x::read"
    assert final_in_class() == "10/default"
    routed: Dict[str, Any] = conditional_walrus_route([1, 2, 3])
    assert routed["ok"] is True and routed["doubled"] == [2, 4, 6]
    assert conditional_walrus_route([])["ok"] is False
    assert try_except_walrus_capture("5") == (True, 5)
    assert try_except_walrus_capture("nope") == (False, -1)
    print("edge_cases_3_8: exercise ok")


if __name__ == "__main__":
    exercise()
