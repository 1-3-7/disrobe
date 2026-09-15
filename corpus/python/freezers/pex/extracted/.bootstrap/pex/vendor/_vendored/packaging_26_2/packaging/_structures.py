

from __future__ import annotations


class InfinityType:

    def __repr__(self) -> str:
        return "Infinity"


class NegativeInfinityType:

    def __repr__(self) -> str:
        return "-Infinity"


Infinity = InfinityType()
NegativeInfinity = NegativeInfinityType()
