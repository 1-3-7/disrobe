from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Point:
    x: float
    y: float

    def norm(self: Point, /) -> float:
        return (self.x * self.x + self.y * self.y) ** 0.5


def clamp(value: float, low: float, high: float, /) -> float:
    return max(low, min(value, high))
