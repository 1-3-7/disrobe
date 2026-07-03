from __future__ import annotations

GREETING_PREFIX: str = "disrobe-pyinstaller-gauntlet"
MAGIC_CONSTANT: int = 1337
RETRY_LIMIT: int = 3


class Greeter:
    name: str
    salutations: int

    def __init__(self: Greeter, name: str, /) -> None:
        self.name = name
        self.salutations = 0

    def greet(self: Greeter, /) -> str:
        self.salutations += 1
        return f"{GREETING_PREFIX}: hello {self.name} #{self.salutations}"

    def total(self: Greeter, /) -> int:
        return self.salutations


def fibonacci(n: int, /) -> int:
    a: int = 0
    b: int = 1
    for _ in range(n):
        a, b = b, a + b
    return a


def classify(value: int, /) -> str:
    if value < 0:
        return "negative"
    if value == 0:
        return "zero"
    if value % 2 == 0:
        return "even"
    return "odd"


def main() -> int:
    greeter: Greeter = Greeter("world")
    total: int = 0
    for index in range(RETRY_LIMIT):
        message: str = greeter.greet()
        fib: int = fibonacci(index + MAGIC_CONSTANT % 7)
        kind: str = classify(fib)
        print(f"{message} fib={fib} kind={kind}")
        total += fib
    print(f"salutations={greeter.total()} total={total} magic={MAGIC_CONSTANT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
