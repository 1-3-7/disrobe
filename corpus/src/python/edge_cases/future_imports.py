from __future__ import annotations, division
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


def average(values: Iterable[float]) -> float:
    total: float = 0.0
    count: int = 0
    for v in values:
        total += v
        count += 1
    if count == 0:
        raise ValueError("empty input")
    return total / count


def integer_div(a: int, b: int) -> float:
    return a / b


print(average([1.0, 2.0, 3.0, 4.0]), integer_div(7, 2))
