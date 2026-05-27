
import asyncio
import contextlib
import functools
import json
import secrets
from typing import (
    Any,
    Awaitable,
    Callable,
    ClassVar,
    Dict,
    Generic,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

__PY_BAND__: Tuple[int, int] = (3, 6)

T = TypeVar("T")
R = TypeVar("R")

MAX_RETRIES: int = 3
BACKOFF_BASE: float = 0.5
ONE_MILLION: int = 1_000_000


def fstring_basic(name: str, count: int, ratio: float) -> str:
    head: str = f"{name!r}: {count:04d} @ {ratio:.2%}"
    tail: str = f"name-len={len(name)}"
    return f"{head} | {tail}"


def fstring_simple_concat(parts: List[str]) -> str:
    prefix: str = f"count={len(parts)}"
    joined: str = ", ".join(parts)
    return prefix + " | " + f"items=[{joined}]"


def underscore_numeric_literals() -> int:
    big: int = 1_000_000_000
    hex_lit: int = 0xFF_FF_FF
    bin_lit: int = 0b1010_1010
    return big + hex_lit + bin_lit


def try_except_basic(value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        return -1


def try_except_else_finally(items: Sequence[int]) -> int:
    total: int = 0
    try:
        for it in items:
            total += it
    except OverflowError:
        total = -1
    else:
        total += 100
    finally:
        total = total
    return total


def multiple_except_clauses(token: object) -> str:
    try:
        return str(int(token))
    except ValueError:
        return "not-a-number"
    except TypeError:
        return "wrong-type"
    except (KeyError, IndexError):
        return "lookup-failed"
    except Exception:
        return "unknown"


def raise_from_chain(cause: Exception) -> None:
    raise RuntimeError("wrapped failure") from cause


def with_simple(lock: Any) -> int:
    with lock:
        return 1


def with_suppress(store: Dict[str, int]) -> None:
    with contextlib.suppress(KeyError, ValueError):
        del store["maybe-missing"]


def for_else(items: List[int], target: int) -> bool:
    for it in items:
        if it == target:
            return True
    else:
        return False


def while_else(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 5:
            break
        i += 1
    else:
        return -1
    return i


def for_with_unpacking(pairs: List[Tuple[int, int]]) -> int:
    total: int = 0
    for a, b in pairs:
        total += a * b
    return total


def ternary_simple(flag: bool, a: int, b: int) -> int:
    return a if flag else b


def chained_comparison(a: int, b: int, c: int) -> bool:
    return 0 <= a < b <= c < 100


def comprehensions(matrix: List[List[int]]) -> Dict[str, Any]:
    flat: List[int] = [cell for row in matrix for cell in row if cell > 0]
    uniq: Set[int] = {cell for row in matrix for cell in row}
    index: Dict[int, List[int]] = {i: row for i, row in enumerate(matrix) if row}
    gen_sum: int = sum(cell * 2 for row in matrix for cell in row)
    return {"flat": flat, "uniq": uniq, "index": index, "gen_sum": gen_sum}


def starred_in_literals(prefix: List[int], suffix: List[int]) -> List[int]:
    return [*prefix, 0, *suffix]


def starred_in_call(args: List[int]) -> int:
    return sum([*args, 1]) + max(args)


def starred_assignment(data: List[int]) -> Tuple[int, List[int], int]:
    first, *middle, last = data
    return first, middle, last


def dict_merge_via_unpack(a: Dict[str, int], b: Dict[str, int]) -> Dict[str, int]:
    return {**a, **b, "extra": 1}


def lambda_usage(items: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    ordered: List[Tuple[str, int]] = sorted(items, key=lambda kv: (kv[1], kv[0]))
    return list(filter(lambda kv: kv[1] > 0, ordered))


def decorator_factory(prefix: str) -> Callable[[Callable[..., R]], Callable[..., R]]:

    def decorate(fn: Callable[..., R]) -> Callable[..., R]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> R:
            return fn(*args, **kwargs)

        return wrapper

    return decorate


@decorator_factory("trace")
def decorated_function(x: int, y: int = 10) -> int:
    return x + y


@functools.lru_cache(maxsize=128)
def memoized(n: int) -> int:
    return n * n if n < 2 else memoized(n - 1) + memoized(n - 2)


def closure_with_nonlocal() -> Callable[[int], int]:
    accumulator: int = 0

    def add(delta: int) -> int:
        nonlocal accumulator
        accumulator += delta
        return accumulator

    return add


_GLOBAL_COUNTER: int = 0


def mutate_global() -> int:
    global _GLOBAL_COUNTER
    _GLOBAL_COUNTER += 1
    return _GLOBAL_COUNTER


def generator_function(limit: int) -> Iterator[int]:
    for i in range(limit):
        if i % 3 == 0:
            yield i


def secrets_token_demo() -> str:
    return secrets.token_hex(8)


async def await_chain(client: Any) -> str:
    token: bytes = await client.authenticate()
    session: Any = await client.open(token)
    data: bytes = await session.read()
    return data.decode()


async def async_generator(source: Any) -> Any:
    async for item in source:
        if item % 2 == 0:
            yield item * 10


async def async_comprehension(source: Any) -> List[int]:
    return [item async for item in source if item > 0]


class Coordinate(NamedTuple):

    x: int
    y: int = 0


class Comparable(Generic[T]):

    def __init__(self, item: T) -> None:
        self.item: T = item

    def get(self) -> T:
        return self.item


class TypedConfig:

    retries: ClassVar[int] = 3
    timeout: ClassVar[float] = 30.0
    name: ClassVar[str] = "default"


class Color:

    def __init__(self, r: int, g: int, b: int) -> None:
        self.r: int = r
        self.g: int = g
        self.b: int = b

    @property
    def brightness(self) -> float:
        return (self.r + self.g + self.b) / 3.0

    @classmethod
    def black(cls) -> "Color":
        return cls(0, 0, 0)

    @staticmethod
    def mix(a: "Color", b: "Color") -> "Color":
        return Color((a.r + b.r) // 2, (a.g + b.g) // 2, (a.b + b.b) // 2)

    def __repr__(self) -> str:
        return f"Color({self.r}, {self.g}, {self.b})"


class Counter:

    def __init__(self) -> None:
        self._value: int = 0

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, new: int) -> None:
        self._value = max(0, new)


def conditional_import_fallback() -> Any:
    try:
        import orjson as serializer
    except ImportError:
        import json as serializer
    return serializer


def parse_and_route(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if action == "list":
        try:
            items: List[str] = [str(x).strip() for x in payload.get("items", []) if x]
        except TypeError:
            return {"ok": False, "error": "not-iterable"}
        return {"ok": True, "count": len(items), "items": items}
    if action == "batch":
        total: int = sum(v for v in payload.values() if isinstance(v, int))
        return {"ok": True, "total": total}
    return {"ok": False, "error": "unknown"}


def exercise() -> None:
    assert fstring_basic("alpha", 7, 0.5) == "'alpha': 0007 @ 50.00% | name-len=5"
    assert "items=" in fstring_simple_concat(["a", "b"])
    assert underscore_numeric_literals() > 0
    assert try_except_basic("123") == 123
    assert try_except_basic("nope") == -1
    assert try_except_else_finally([1, 2, 3]) == 106
    assert multiple_except_clauses("xyz") == "not-a-number"

    @contextlib.contextmanager
    def _lock() -> Iterator[None]:
        yield None

    assert with_simple(_lock()) == 1
    with_suppress({"present": 1})
    assert for_else([1, 2, 3], 2) is True
    assert for_else([1, 2, 3], 99) is False
    assert while_else(10) == 5
    assert for_with_unpacking([(1, 2), (3, 4)]) == 14
    assert ternary_simple(True, 1, 2) == 1
    assert chained_comparison(1, 2, 50) is True
    result: Dict[str, Any] = comprehensions([[1, 2], [3, -1, 4]])
    assert len(result["flat"]) == 4
    assert starred_in_literals([1, 2], [3, 4]) == [1, 2, 0, 3, 4]
    assert starred_in_call([1, 2, 3]) == (1 + 2 + 3 + 1) + 3
    first, mid, last = starred_assignment([1, 2, 3, 4, 5])
    assert first == 1 and mid == [2, 3, 4] and last == 5
    assert dict_merge_via_unpack({"a": 1}, {"b": 2}) == {"a": 1, "b": 2, "extra": 1}
    assert lambda_usage([("a", 2), ("b", -1), ("c", 3)]) == [("a", 2), ("c", 3)]
    assert decorated_function(1, 2) == 3
    assert memoized(5) > 0
    adder: Callable[[int], int] = closure_with_nonlocal()
    assert adder(1) == 1 and adder(2) == 3
    assert mutate_global() >= 1
    assert list(generator_function(10)) == [0, 3, 6, 9]
    assert len(secrets_token_demo()) == 16
    p: Coordinate = Coordinate(1)
    assert p.x == 1 and p.y == 0
    c: Comparable[int] = Comparable(42)
    assert c.get() == 42
    assert TypedConfig.retries == 3

    async def _drive() -> None:
        class FakeClient:
            async def authenticate(self) -> bytes:
                return b"tok"

            async def open(self, _t: bytes) -> Any:
                return self

            async def read(self) -> bytes:
                return b"payload"

        text: str = await await_chain(FakeClient())
        assert text == "payload"

        async def src() -> Any:
            for v in [0, 1, 2, 3]:
                yield v

        agen = async_generator(src())
        collected: List[int] = []
        async for v in agen:
            collected.append(v)
        assert collected == [0, 20]

        async def src2() -> Any:
            for v in [-1, 0, 1, 2]:
                yield v

        vals: List[int] = await async_comprehension(src2())
        assert vals == [1, 2]

    if hasattr(asyncio, "run"):
        asyncio.run(_drive())
    else:
        asyncio.get_event_loop().run_until_complete(_drive())

    assert Color(10, 20, 30).brightness == 20.0
    cnt: Counter = Counter()
    cnt.value = -5
    assert cnt.value == 0
    cnt.value = 100
    assert cnt.value == 100

    assert conditional_import_fallback() is not None
    routed: Dict[str, Any] = parse_and_route("list", {"items": ["a", "b", ""]})
    assert routed["ok"] is True and routed["count"] == 2
    print("edge_cases_3_6: exercise ok")


if __name__ == "__main__":
    exercise()
