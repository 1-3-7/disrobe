def comp(n: int) -> list:
    return [i * 2 for i in range(n)]


def safe_div(a: int, b: int) -> int:
    try:
        return a // b
    except ZeroDivisionError:
        return 0


def with_default(a: int, b: int = 10) -> int:
    return a + b


def varargs(*nums: int) -> int:
    total = 0
    for x in nums:
        total = total + x
    return total


def closure(n: int) -> int:
    def inner(x: int) -> int:
        return x + n

    return inner(n)


def dict_comp(n: int) -> dict:
    return {i: i * i for i in range(n)}
