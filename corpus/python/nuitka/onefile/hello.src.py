def greet(name: str) -> str:
    return "hello, " + name


def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def main() -> int:
    print(greet("disrobe"))
    print(fib(20))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
