
from __future__ import annotations

import abc
import asyncio
import contextlib
import enum
import functools
import json
import sys
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Generator,
    Iterable,
    Iterator,
    Sequence,
)
from contextlib import AsyncExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import (
    Any,
    ClassVar,
    Final,
    Generic,
    LiteralString,
    NamedTuple,
    NotRequired,
    ParamSpec,
    Protocol,
    Required,
    Self,
    TypedDict,
    TypeVar,
    Unpack,
    assert_type,
    cast,
    dataclass_transform,
    overload,
    override,
    reveal_type,
    runtime_checkable,
)

T = TypeVar("T")
R = TypeVar("R")

type Vector = list[float]
type Handler = Callable[[bytes], Awaitable[int]]

MAX_RETRIES: Final[int] = 3
BACKOFF_BASE: Final[float] = 0.5
_SENTINEL: Final[object] = object()


def try_except_basic(value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        print(f"bad value: {exc}")
        return -1


def try_except_else(mapping: dict[str, int], key: str) -> int:
    try:
        raw = mapping[key]
    except KeyError:
        return 0
    else:
        return raw * 2


def try_finally_only(resource: list[int]) -> int:
    try:
        resource.append(1)
        return sum(resource)
    finally:
        resource.clear()


def try_except_finally(path: str) -> str | None:
    handle: str | None = None
    try:
        handle = path.upper()
        return handle
    except (TypeError, AttributeError):
        return None
    finally:
        if handle is not None:
            print(f"closing {handle}")


def try_except_else_finally(items: Sequence[int]) -> int:
    total = 0
    try:
        for it in items:
            total += it
    except OverflowError:
        total = -1
    else:
        total += 100
    finally:
        print(f"total so far: {total}")
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


def bare_except_reraise() -> None:
    try:
        risky_operation()
    except:
        print("cleanup before reraise")
        raise


def raise_from_chain(cause: Exception) -> None:
    raise RuntimeError("wrapped failure") from cause


def nested_try_in_outer_try(producer: Callable[[], int]) -> dict[str, Any]:
    try:
        value = producer()
        try:
            scaled = value * 10
        except ArithmeticError:
            return {"ok": False, "error": "arithmetic"}
    except FileNotFoundError:
        return {"ok": False, "error": "missing"}
    except PermissionError:
        return {"ok": False, "error": "denied"}
    except OSError as exc:
        return {"ok": False, "error": f"os: {exc}"}
    return {"ok": True, "value": scaled}


def try_inside_if_chain(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    if action == "list":
        try:
            return {"ok": True, "items": list(payload)}
        except TypeError:
            return {"ok": False, "error": "not-iterable"}
    if action == "add":
        name = str(payload.get("name", "")).strip()
        if not name:
            return {"ok": False, "error": "empty"}
        return {"ok": True, "added": name}
    if action == "remove":
        return {"ok": True, "removed": payload.get("id")}
    return {"ok": False, "error": "unknown-action"}


def try_body_trailing_statements(rows: list[int], sink: list[int]) -> int:
    count = 0
    try:
        for r in rows:
            sink.append(r * 2)
            count += 1
            schedule_followup(r)
    except (ValueError, OverflowError):
        return -1
    return count


def except_fallthrough_shared_return(cache: dict[str, int], key: str) -> int:
    entry = -1
    try:
        entry = cache[key]
    except KeyError as exc:
        print(f"miss: {exc}")
    return entry


def reraise_conditionally(data: bytes) -> object:
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        if exc.pos == 0:
            return None
        raise


def deeply_nested_handlers(stages: list[Callable[[], int]]) -> int:
    try:
        a = stages[0]()
        try:
            b = stages[1]()
            try:
                return a + b + stages[2]()
            except IndexError:
                return a + b
        except ValueError:
            return a
    except KeyError:
        return -1


def with_simple(lock: contextlib.AbstractContextManager[Any]) -> None:
    with lock:
        print("inside")


def with_as_binding(
    opener: Callable[[], contextlib.AbstractContextManager[int]],
) -> int:
    with opener() as handle:
        return handle + 1


def with_suppress(store: dict[str, int]) -> None:
    with contextlib.suppress(KeyError, ValueError):
        del store["maybe-missing"]


def with_value_preserving_return(
    lock: contextlib.AbstractContextManager[Any], current: int
) -> tuple[bool, int]:
    with lock:
        update_counter(current)
        return (True, current + 1)


def with_const_return_inside(lock: contextlib.AbstractContextManager[Any]) -> None:
    with lock:
        do_side_effect()
        return None


def nested_with(outer: Any, inner: Any, payload: bytes) -> bytes:
    with outer:
        with inner:
            return payload[::-1]


def with_inside_loop_returning(pool: list[Any], data: int) -> tuple[bool, int]:
    last = data
    for attempt in range(MAX_RETRIES):
        with pool[attempt % len(pool)]:
            last = data + attempt
            if last > 0:
                return (True, last)
    return (False, last)


@contextmanager
def custom_context_manager(name: str) -> Iterator[str]:
    print(f"enter {name}")
    try:
        yield name.upper()
    finally:
        print(f"exit {name}")


def with_returning_from_try(resource: Any) -> int:
    try:
        with resource as r:
            return int(r)
    except (TypeError, ValueError):
        return -1


async def await_chain(client: Any) -> str:
    token = await client.authenticate()
    session = await client.open(token)
    data = await session.read()
    return data.decode()


async def async_with_return_inside(lock: Any, key: tuple[str, int]) -> None:
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        async with lock:
            try:
                client = await acquire(key)
                await client.send()
            except ConnectionError as exc:
                last_exc = exc
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(BACKOFF_BASE * 2**attempt)
                    continue
                raise
            release(key)
            return None
    if last_exc is not None:
        raise last_exc
    return None


async def async_for_basic(stream: AsyncIterator[int]) -> int:
    acc = 0
    async for chunk in stream:
        acc += chunk
    return acc


async def async_generator(source: AsyncIterator[int]) -> AsyncIterator[int]:
    async for item in source:
        if item % 2 == 0:
            yield item * 10


async def await_in_comprehension(
    ids: list[int], fetch: Callable[[int], Awaitable[str]]
) -> list[str]:
    return [await fetch(i) for i in ids if i > 0]


async def gather_with_timeout(tasks: list[Awaitable[int]]) -> list[int]:
    async with asyncio.timeout(5.0):
        return list(await asyncio.gather(*tasks))


async def async_retry_with_continue(send: Callable[[], Awaitable[bool]]) -> bool:
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            if await send():
                return True
        except ConnectionError as exc:
            last_exc = exc
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(BACKOFF_BASE * 2**attempt)
                continue
            raise
    if last_exc is not None:
        raise last_exc
    return False


async def async_nested_awaits(client: Any, ids: list[int]) -> dict[int, int]:
    out: dict[int, int] = {}
    for i in ids:
        value = await client.fetch(i)
        out[i] = await client.score(value)
    return out


def for_else(items: Iterable[int], target: int) -> bool:
    for it in items:
        if it == target:
            return True
    else:
        return False


def while_else(n: int) -> int:
    i = 0
    while i < n:
        if i == 5:
            break
        i += 1
    else:
        return -1
    return i


def while_true_break(queue: list[int]) -> int:
    while True:
        if not queue:
            break
        item = queue.pop()
        if item < 0:
            return item
    return 0


def nested_while_true(rows: list[list[int]]) -> int:
    found = 0
    while True:
        if not rows:
            break
        row = rows.pop()
        while True:
            if not row:
                break
            v = row.pop()
            if v > found:
                found = v
    return found


def inverted_while_with_guard(data: list[int]) -> int:
    total = 0
    idx = 0
    while idx < len(data) and data[idx] >= 0:
        total += data[idx]
        idx += 1
    return total


def break_continue_in_try(values: list[int]) -> int:
    total = 0
    for v in values:
        try:
            if v == 0:
                continue
            if v < 0:
                break
            total += 100 // v
        except ZeroDivisionError:
            continue
    return total


def for_with_unpacking(pairs: list[tuple[int, int]]) -> int:
    total = 0
    for a, b in pairs:
        total += a * b
    return total


def nested_loops_with_labels(
    matrix: list[list[int]], needle: int
) -> tuple[int, int] | None:
    for i, row in enumerate(matrix):
        for j, cell in enumerate(row):
            if cell == needle:
                return (i, j)
    return None


def walrus_in_condition(data: dict[str, str]) -> str:
    if (name := data.get("name")) is not None:
        return name.upper()
    return "anon"


def walrus_in_membership(rows: list[dict[str, str]], allowed: set[str]) -> list[str]:
    return [
        norm
        for raw in rows
        if (norm := raw.get("domain", "").strip().lower()) in allowed
    ]


def walrus_in_while(stream: Iterator[bytes]) -> int:
    total = 0
    while chunk := next(stream, b""):
        total += len(chunk)
    return total


def walrus_in_comprehension(xs: list[int]) -> list[int]:
    return [y for x in xs if (y := x * 2) > 4]


def ternary_simple(flag: bool, a: int, b: int) -> int:
    return a if flag else b


def ternary_as_call_argument(missing: list[int], a_detail: str, b_detail: str) -> None:
    raise ValueError(a_detail if missing else b_detail)


def ternary_nested(x: int) -> str:
    return "neg" if x < 0 else ("zero" if x == 0 else "pos")


def chained_comparison(a: int, b: int, c: int) -> bool:
    return 0 <= a < b <= c < 100


def boolean_short_circuit(
    primary: str | None, fallback: str | None, default: str
) -> str:
    return primary or fallback or default


def boolean_and_value(a: dict[str, int] | None, key: str) -> int:
    return a.get(key, 0) if a else 0


def fstring_variations(name: str, count: int, ratio: float) -> str:
    head = f"{name!r}: {count:04d} @ {ratio:.2%}"
    nested = f"{f'inner-{count}':>10}"
    debug = f"{count=}, {ratio=:.1f}"
    return f"{head} | {nested} | {debug}"


def fstring_nested_spec(x: float, width: int) -> str:
    return f"{x:{width}.2f}" + f"{x!r:>{width}}"


def slice_expressions(seq: list[int]) -> list[int]:
    return seq[1:] + seq[:-1] + seq[::2] + seq[::-1] + seq[1:10:2]


def starred_in_literals(prefix: list[int], suffix: list[int]) -> list[int]:
    return [*prefix, 0, *suffix]


def starred_in_call(args: list[int]) -> int:
    return sum([*args, 1]) + max(args)


def starred_assignment(data: list[int]) -> tuple[int, list[int], int]:
    first, *middle, last = data
    return first, middle, last


def dict_merge(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    return {**a, **b, "extra": 1}


def comprehensions(matrix: list[list[int]]) -> dict[str, Any]:
    flat = [cell for row in matrix for cell in row if cell > 0]
    uniq = {cell for row in matrix for cell in row}
    index = {i: row for i, row in enumerate(matrix) if row}
    gen_sum = sum(cell * 2 for row in matrix for cell in row)
    nested = [[c + 1 for c in row] for row in matrix]
    return {
        "flat": flat,
        "uniq": uniq,
        "index": index,
        "gen_sum": gen_sum,
        "nested": nested,
    }


def dict_comprehension_filtered(d: dict[str, int]) -> dict[str, int]:
    return {k: v * 2 for k, v in d.items() if v > 0}


def set_comprehension_nested(m: list[list[int]]) -> set[int]:
    return {c for row in m for c in row if c}


def generator_expression_chain(values: list[int]) -> int:
    return sum(v * v for v in values if v % 2)


def lambda_usage(items: list[tuple[str, int]]) -> list[tuple[str, int]]:
    ordered = sorted(items, key=lambda kv: (kv[1], kv[0]))
    return list(filter(lambda kv: kv[1] > 0, ordered))


def starred_double_in_call(prefix: list[int], suffix: list[int]) -> int:
    return max(*prefix, *suffix)


def decorator_factory(prefix: str) -> Callable[[Callable[..., R]], Callable[..., R]]:

    def decorate(fn: Callable[..., R]) -> Callable[..., R]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> R:
            print(f"{prefix}: calling {fn.__name__}")
            return fn(*args, **kwargs)

        return wrapper

    return decorate


@decorator_factory("trace")
def decorated_function(x: int, y: int = 10) -> int:
    return x + y


def stacked_decorators_target(fn: Callable[..., R]) -> Callable[..., R]:
    return fn


@stacked_decorators_target
@stacked_decorators_target
def double_decorated(x: int) -> int:
    return x * 2


@functools.lru_cache(maxsize=128)
def memoized(n: int) -> int:
    return n * n if n < 2 else memoized(n - 1) + memoized(n - 2)


def full_signature(
    pos1: int,
    pos2: str,
    /,
    normal: float = 1.0,
    *args: int,
    kw_only: bool = False,
    required_kw: str,
    **kwargs: Any,
) -> dict[str, Any]:
    return {
        "pos": (pos1, pos2),
        "normal": normal,
        "args": args,
        "kw_only": kw_only,
        "required_kw": required_kw,
        "kwargs": kwargs,
    }


def closure_with_nonlocal() -> Callable[[int], int]:
    accumulator = 0

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


def nested_function_levels(base: int) -> int:

    def level_one(a: int) -> int:
        def level_two(b: int) -> int:
            def level_three(c: int) -> int:
                return base + a + b + c

            return level_three(3)

        return level_two(2)

    return level_one(1)


def conditional_import_fallback() -> Any:
    try:
        import orjson as serializer
    except ImportError:
        import json as serializer
    return serializer


def recursive_factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * recursive_factorial(n - 1)


@dataclass
class Circle:

    radius: float
    label: str = "circle"
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Rectangle:

    width: int
    height: int


class Point:

    __match_args__: ClassVar[tuple[str, ...]] = ("x", "y")

    def __init__(self, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    @property
    def magnitude(self) -> float:
        return float(self.x * self.x + self.y * self.y) ** 0.5

    @classmethod
    def origin(cls) -> Point:
        return cls(0, 0)

    @staticmethod
    def distance(a: Point, b: Point) -> float:
        return float((a.x - b.x) ** 2 + (a.y - b.y) ** 2) ** 0.5

    def __repr__(self) -> str:
        return f"Point({self.x}, {self.y})"


class Counter:

    def __init__(self) -> None:
        self._value: int = 0

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, new: int) -> None:
        self._value = max(0, new)


class Base:

    def __init__(self, name: str) -> None:
        self.name: str = name

    def describe(self) -> str:
        return f"base:{self.name}"


class Derived(Base):

    def __init__(self, name: str, level: int) -> None:
        super().__init__(name)
        self.level: int = level

    def describe(self) -> str:
        return f"{super().describe()}@{self.level}"


class AbstractWorker(abc.ABC):

    @abc.abstractmethod
    def run(self) -> int: ...

    def run_twice(self) -> int:
        return self.run() * 2


class Color(enum.Enum):

    RED = 1
    GREEN = 2
    BLUE = 3


class Coordinate(NamedTuple):

    x: int
    y: int = 0


class TypedConfig:

    retries: ClassVar[int] = 3
    timeout: ClassVar[float] = 30.0
    window_seconds: ClassVar[float] = 256.0
    scopes: ClassVar[tuple[str, ...]] = ("read", "write")
    name: Final[str] = "default"


class Comparable(Protocol):

    def __lt__(self, other: Any) -> bool: ...


def augmented_assignment() -> int:
    total: int = 0
    total += 5
    total -= 1
    total *= 2
    total //= 3
    total %= 100
    total <<= 1
    total |= 0x10
    return total


def annotated_assignment(x: int) -> dict[str, int]:
    a: int = x
    b: list[int] = [a, a]
    c: dict[str, int] = {"k": a}
    return {"k": a, "n": len(b), **c}


def del_statements(store: dict[str, int]) -> int:
    temp = dict(store)
    del temp["key"]
    placeholder = 1
    del placeholder
    return len(temp)


@overload
def coerce(value: int) -> str: ...
@overload
def coerce(value: str) -> int: ...
def coerce(value: int | str) -> str | int:
    if isinstance(value, int):
        return str(value)
    return int(value)


def use_type_alias(vec: Vector) -> float:
    return sum(vec) / len(vec) if vec else 0.0


async def orchestrate_jobs(
    jobs: list[dict[str, Any]],
    pool: Any,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    results: list[int] = []
    failures = 0
    for index, job in enumerate(jobs):
        if (kind := job.get("kind")) is None:
            continue
        if kind == "compute":
            results.append(int(job.get("value", 0)) * 2)
            continue
        job["seen"] = True
        try:
            payload = await pool.read(job["id"])
            results.append(len(payload))
            if not payload:
                return {"ok": False, "stage": index, "reason": "empty"}
        except (ConnectionError, TimeoutError) as exc:
            failures += 1
            last_error = str(exc) if not dry_run else "dry-run"
            print(f"job {index} failed: {last_error}")
    return {
        "ok": failures == 0,
        "processed": len(results),
        "total": sum(results) if results else 0,
        "failures": failures,
        "detail": "clean" if failures == 0 else f"{failures} failed",
    }


def parse_and_route(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    if action == "list":
        try:
            items = [str(x).strip() for x in payload.get("items", []) if x]
        except TypeError:
            return {"ok": False, "error": "not-iterable"}
        return {"ok": True, "count": len(items), "items": items}
    if action == "lookup":
        if (target := payload.get("id")) is None:
            return {"ok": False, "error": "no-id"}
        return {"ok": True, "id": target, "kind": "found" if target else "blank"}
    if action == "batch":
        total = sum(v for v in payload.values() if isinstance(v, int))
        return {"ok": True, "total": total}
    return {"ok": False, "error": "unknown"}


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

    def run_all(self, items: list[T]) -> list[T]:
        return [self.run(it) for it in items]


def try_except_loop_else(xs: list[int]) -> int:
    for x in xs:
        try:
            if x < 0:
                raise ValueError
        except ValueError:
            return x
    else:
        return -1


def multi_with_sequential(a: Any, b: Any) -> int:
    with a:
        x = 1
    with b:
        y = 2
    return x + y


def dict_get_chain(d: dict[str, Any]) -> int:
    return d.get("a", {}).get("b", {}).get("c", 0)


def complex_fstring(items: list[int]) -> str:
    return f"{len(items)} items: {', '.join(str(i) for i in items)}"


def conditional_expr_chain(x: int) -> str:
    return "a" if x > 10 else "b" if x > 5 else "c" if x > 0 else "d"


def listcomp_multi_for_if(m: list[int]) -> list[int]:
    return [x * y for x in m for y in m if x != y if x + y < 10]


def nested_dictcomp(rows: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    return {k: {kk: vv for kk, vv in v.items()} for k, v in rows.items()}


def state_machine(state: str, event: str) -> str:
    if state == "idle":
        return "running" if event == "start" else "idle"
    if state == "running":
        if event == "pause":
            return "paused"
        if event == "stop":
            return "idle"
        return "running"
    return state


def for_continue_else(xs: list[int]) -> int:
    found = 0
    for x in xs:
        if x % 2:
            continue
        found += x
    else:
        found += 1
    return found


def try_return_in_all_arms(x: float) -> float:
    try:
        return 1 / x
    except ZeroDivisionError:
        return 0.0
    else:
        return x


def walrus_in_call_arg(data: list[int]) -> int:
    return process(n) if (n := len(data)) > 0 else 0


def set_operations(a: set[int], b: set[int]) -> set[int]:
    return (a | b) & (a - b) | (a ^ b)


def unpack_return(values: tuple[int, int, int]) -> tuple[int, int, int]:
    a, b, c = values
    return c, b, a


def nested_ternary_in_call(a: int, b: int) -> int:
    return max(a, b) if a != b else (a if a > 0 else 0)


def multiline_boolean(a: bool, b: bool, c: bool, d: bool) -> bool:
    return (a and b) or (c and not d) or (a and c and d)


def retry_decorator(times: int) -> Callable[[Callable[..., R]], Callable[..., R]]:

    def deco(fn: Callable[..., R]) -> Callable[..., R]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> R:
            last: R | None = None
            for _ in range(times):
                try:
                    return fn(*args, **kwargs)
                except Exception:
                    continue
            return last

        return wrapper

    return deco


def generator_running_total(n: int) -> Iterator[int]:
    total = 0
    for i in range(n):
        total += i
        yield total


class SlottedPoint:

    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y


class Registry:

    _registry: ClassVar[dict[str, Any]] = {}

    @classmethod
    def register(cls, key: str, value: Any) -> type[Registry]:
        cls._registry[key] = value
        return cls


class AsyncResource:

    async def __aenter__(self) -> AsyncResource:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


@dataclass
class Measurement:

    value: int
    unit: str = "px"

    def doubled(self) -> int:
        return self.value * 2

    @property
    def label(self) -> str:
        return f"{self.value}{self.unit}"


def process(n: int) -> int:
    return n * 2


def risky_operation() -> None:
    raise RuntimeError("boom")


def schedule_followup(item: int) -> None:
    print(f"followup {item}")


def update_counter(value: int) -> None:
    print(f"counter {value}")


def do_side_effect() -> None:
    print("side effect")


async def acquire(_key: tuple[str, int]) -> Any:
    return _SENTINEL


def release(key: tuple[str, int]) -> None:
    print(f"release {key}")


class Status(enum.Enum):

    OK = 1
    ERR = 2
    PENDING = 3


@dataclass
class HttpResponse:

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


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
        case 1 | 2 | 3:
            return "small"
        case ("a" | "b") as letter:
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


def fstring_pep701_same_quote(items: list[str]) -> str:
    name: str = "alpha"
    return f"outer-{f'inner-{name}'}-{f'[{', '.join(f"{x}" for x in items)}]'}"


def fstring_pep701_multiline(rows: list[dict[str, int]]) -> str:
    return f"summary: {sum(row.get('count', 0) for row in rows if row)} rows"


def fstring_pep701_backslash(paths: list[str]) -> str:
    return f"joined:\n{'\n'.join(paths)}\n--end--"


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


def pep695_generic_function[U](item: U) -> tuple[U, U]:
    return (item, item)


def pep695_constrained[U: (int, str)](value: U) -> str:
    return f"{type(value).__name__}:{value}"


def pep695_bound[U: Sequence[int]](seq: U) -> int:
    return sum(seq)


def pep695_paramspec[**P, U](fn: Callable[P, U]) -> Callable[P, U]:

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> U:
        return fn(*args, **kwargs)

    return wrapper


def pep695_typevartuple[*Ts](values: tuple[*Ts]) -> tuple[*Ts]:
    return values


type Pair[U] = tuple[U, U]
type Callback[**P, U] = Callable[P, Awaitable[U]]


class GenericBox[U]:

    def __init__(self, item: U) -> None:
        self.item: U = item

    def swap[V](self, other: V) -> GenericBox[V]:
        return GenericBox(other)


if sys.version_info >= (3, 13):

    def pep696_default[U = int](value: U | None = None) -> U:
        if value is None:
            return cast(U, 0)
        return value

    class Pep696Container[U = str]:

        def __init__(self, item: U) -> None:
            self.item: U = item


class FluentBuilder:

    def __init__(self) -> None:
        self._parts: list[str] = []

    def add(self, part: str) -> Self:
        self._parts.append(part)
        return self

    def build(self) -> str:
        return "/".join(self._parts)


class ParentService:

    def handle(self, payload: bytes) -> int:
        return len(payload)


class ChildService(ParentService):

    @override
    def handle(self, payload: bytes) -> int:
        return len(payload) * 2


def needs_literal_string(query: LiteralString) -> str:
    return f"executing: {query}"


def call_literal_string() -> str:
    return needs_literal_string("SELECT 1")


def assert_and_cast_demo(payload: object) -> int:
    narrowed: int = cast(int, payload)
    assert_type(narrowed, int)
    reveal_type(narrowed)
    return narrowed + 1


def typed_generator_yields(limit: int) -> Generator[int, str, bool]:
    received: str = ""
    for i in range(limit):
        sent: str = yield i
        received = sent
    return bool(received)


class UserProfile(TypedDict):

    id: Required[int]
    name: Required[str]
    bio: NotRequired[str]
    avatar_url: NotRequired[str]


class PartialProfile(TypedDict, total=False):

    name: Required[str]
    locale: str
    timezone: str


def consume_unpacked_typeddict(**fields: Unpack[UserProfile]) -> str:
    return f"{fields['id']}:{fields['name']}"


def call_with_unpack() -> str:
    user: UserProfile = {"id": 1, "name": "alpha"}
    return consume_unpacked_typeddict(**user)


@runtime_checkable
class Closeable(Protocol):

    def close(self) -> None: ...


def check_closeable(thing: object) -> bool:
    return isinstance(thing, Closeable)


@dataclass_transform(frozen_default=True, kw_only_default=True)
def custom_model(cls: type[T]) -> type[T]:
    return cls


@custom_model
class CustomModelInstance:

    name: str
    age: int


class Severity(enum.StrEnum):

    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class HttpCode(enum.IntEnum):

    OK = 200
    NOT_FOUND = 404
    SERVER_ERROR = 500


class Permission(enum.Flag):

    NONE = 0
    READ = enum.auto()
    WRITE = enum.auto()
    EXECUTE = enum.auto()
    ALL = READ | WRITE | EXECUTE


class Direction(enum.Enum):

    NORTH = (0, 1)
    EAST = (1, 0)
    SOUTH = (0, -1)
    WEST = (-1, 0)

    def opposite(self) -> Direction:
        dx, dy = self.value
        for member in Direction:
            if member.value == (-dx, -dy):
                return member
        raise RuntimeError("no opposite")

    def __str__(self) -> str:
        return self.name.lower()


class MixedEnum(enum.Enum):

    PLAIN = 1
    WRAPPED = enum.member(lambda: 42)
    UTIL: ClassVar[int] = enum.nonmember(99)


def use_flag_combinations(p: Permission) -> str:
    if Permission.READ in p and Permission.WRITE in p:
        return "rw"
    if p & Permission.EXECUTE:
        return "x-only"
    return "other"


@dataclass
class Container[U]:

    items: list[U] = field(default_factory=list)
    label: str = ""

    def head(self) -> U | None:
        return self.items[0] if self.items else None


class Pair2[U](NamedTuple):

    left: U
    right: U


@dataclass
class Shape:

    kind: str
    width: int
    height: int

    __match_args__: ClassVar[tuple[str, ...]] = ("kind", "width", "height")


def match_shape_positional(value: object) -> int:
    match value:
        case Shape("circle", w, _):
            return w * w
        case Shape("square", w, h) if w == h:
            return w * h
        case Shape(kind="triangle", width=w, height=h):
            return (w * h) // 2
        case _:
            return 0


@dataclass(frozen=True)
class FrozenWithPostInit:

    raw: str
    normalized: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized", self.raw.strip().lower())


def starred_in_return(prefix: tuple[int, ...], extras: list[int]) -> tuple[int, ...]:
    return (*prefix, 0, *extras, -1)


def starred_in_set_return(a: set[int], b: set[int]) -> set[int]:
    return {*a, 0, *b}


def starred_in_dict_return(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    return {**a, "x": 1, **b}


REQUEST_ID: ContextVar[str] = ContextVar("REQUEST_ID", default="anonymous")
TENANT: ContextVar[int | None] = ContextVar("TENANT", default=None)


def with_context_var(new_id: str) -> str:
    token = REQUEST_ID.set(new_id)
    try:
        return REQUEST_ID.get()
    finally:
        REQUEST_ID.reset(token)


async def async_with_exit_stack(items: list[Any]) -> int:
    total: int = 0
    async with AsyncExitStack() as stack:
        for item in items:
            cm = await stack.enter_async_context(item)
            total += getattr(cm, "size", 1)
    return total


async def task_group_basic(coros: list[Awaitable[int]]) -> int:
    results: list[int] = []
    async with asyncio.TaskGroup() as tg:
        tasks = [tg.create_task(c) for c in coros]
    for t in tasks:
        results.append(t.result())
    return sum(results)


async def task_group_with_except_star(coros: list[Awaitable[int]]) -> int:
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


class AsyncCounter:

    def __init__(self, limit: int) -> None:
        self.limit: int = limit
        self._cursor: int = 0

    def __aiter__(self) -> AsyncCounter:
        return self

    async def __anext__(self) -> int:
        if self._cursor >= self.limit:
            raise StopAsyncIteration
        value = self._cursor
        self._cursor += 1
        await asyncio.sleep(0)
        return value


_OldP = ParamSpec("_OldP")
_OldR = TypeVar("_OldR")


def old_style_paramspec(fn: Callable[_OldP, _OldR]) -> Callable[_OldP, _OldR]:

    @functools.wraps(fn)
    def wrapper(*args: _OldP.args, **kwargs: _OldP.kwargs) -> _OldR:
        return fn(*args, **kwargs)

    return wrapper


class OldGenericContainer(Generic[T]):

    def __init__(self, item: T) -> None:
        self.item: T = item

    def get(self) -> T:
        return self.item


async def modern_request_handler(
    payloads: list[HttpResponse],
    fetcher: Callable[[int], Awaitable[bytes]],
) -> dict[str, Any]:
    summaries: list[str] = []
    fetched: list[bytes] = []
    failure: dict[str, Any] | None = None
    try:
        async with asyncio.TaskGroup() as tg:
            for resp in payloads:
                match resp:
                    case HttpResponse(status=200, body=b""):
                        summaries.append("empty-ok")
                    case HttpResponse(status=200, body=body) if (size := len(body)) > 0:
                        summaries.append(f"ok:{size}")
                    case HttpResponse(status=code) if code >= 400:
                        tg.create_task(fetcher(code))
                        summaries.append(f"refetch:{code}")
                    case _:
                        summaries.append("other")
    except* ConnectionError as eg:
        failure = {"ok": False, "stage": "fetch", "failed": len(eg.exceptions)}
    except* ValueError as eg:
        failure = {"ok": False, "stage": "parse", "failed": len(eg.exceptions)}
    if failure is not None:
        return failure
    return {
        "ok": True,
        "summaries": summaries,
        "fetched": len(fetched),
        "request_id": REQUEST_ID.get(),
    }


def fluent_chain_demo() -> str:
    return FluentBuilder().add("a").add("b").add("c").build()
