#!/usr/bin/env python3

GREETING = "hello, world"
SECRET_CONSTANT = 1337
LIST_OF_STRINGS = ["alpha", "beta", "gamma"]


def add(a: int, b: int) -> int:
    return a + b


def greet(name: str) -> str:
    return f"{GREETING} -- {name}"


def fizzbuzz(n: int) -> str:
    if n % 15 == 0:
        return "fizzbuzz"
    if n % 3 == 0:
        return "fizz"
    if n % 5 == 0:
        return "buzz"
    return str(n)


class Counter:
    def __init__(self, start: int = 0) -> None:
        self.value = start

    def inc(self, by: int = 1) -> int:
        self.value += by
        return self.value

    def reset(self) -> None:
        self.value = 0


def main() -> None:
    print(greet("world"))
    print(f"add(2, 3) = {add(2, 3)}")
    print(f"fizzbuzz(15) = {fizzbuzz(15)}")
    counter = Counter(start=10)
    for i in range(3):
        counter.inc(by=i + 1)
    print(f"counter.value = {counter.value}")


if __name__ == "__main__":
    main()
