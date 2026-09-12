from dataclasses import dataclass


@dataclass
class Point:
    x: int
    y: int


@dataclass
class Circle:
    radius: float


@dataclass
class Square:
    side: float


def classify(shape: object) -> str:
    match shape:
        case Point(x=0, y=0):
            return "origin"
        case Point(x=0, y=y):
            return f"y-axis at {y}"
        case Point(x=x, y=0):
            return f"x-axis at {x}"
        case Point(x=x, y=y) if x == y:
            return f"diagonal at {x}"
        case Circle(radius=r) if r > 0:
            return f"circle r={r}"
        case Square(side=s):
            return f"square s={s}"
        case [1, 2, *rest]:
            return f"list head 1,2 tail {rest}"
        case {"kind": "shape", "name": str() as name}:
            return f"dict shape {name}"
        case str() | bytes() as text:
            return f"textual {text!r}"
        case _:
            return "unknown"


def non_exhaustive_color(name: str) -> int:
    match name:
        case "red":
            return 0xFF0000
        case "green":
            return 0x00FF00
        case "blue":
            return 0x0000FF
    return -1


print(classify(Point(0, 0)))
print(classify(Circle(3.0)))
print(classify([1, 2, 3, 4]))
print(non_exhaustive_color("purple"))
