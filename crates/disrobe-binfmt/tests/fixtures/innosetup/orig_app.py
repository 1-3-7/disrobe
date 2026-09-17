from __future__ import annotations

import sys


def greet(name: str, /) -> str:
    return f"hello, {name}"


def fib(n: int, /) -> int:
    a: int = 0
    b: int = 1
    for _ in range(n):
        a, b = b, a + b
    return a


def main() -> int:
    target: str = sys.argv[1] if len(sys.argv) > 1 else "world"
    print(greet(target))
    print(fib(20))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
