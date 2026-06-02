from dataclasses import dataclass, field


@dataclass(frozen=True, kw_only=True, slots=True)
class Coord:
    x: float
    y: float
    z: float = 0.0
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(slots=True, eq=True, order=True)
class Ranked:
    score: int
    label: str = field(compare=False)


a = Coord(x=1.0, y=2.0, tags=("alpha",))
b = Coord(x=1.0, y=2.0, tags=("alpha",))
print(a == b, hash(a) == hash(b))
print(sorted([Ranked(3, "c"), Ranked(1, "a"), Ranked(2, "b")]))
