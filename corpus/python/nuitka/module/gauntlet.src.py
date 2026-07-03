from __future__ import annotations

BANNER: str = "disrobe-nuitka-gauntlet"
SEED: int = 1337


def greet(name: str) -> str:
    return "hello " + name


def fib(n: int) -> int:
    a: int = 0
    b: int = 1
    for _ in range(n):
        a, b = b, a + b
    return a


def accumulate(values: list, factor: int = 2) -> int:
    total: int = 0
    for value in values:
        total = total + value * factor
    return total


def squares(n: int) -> dict:
    return {i: i * i for i in range(n)}


def main() -> int:
    label: str = greet(BANNER)
    checksum: int = fib(20) + accumulate([3, 5, 7]) + SEED
    table: dict = squares(4)
    return checksum + len(label) + len(table)
