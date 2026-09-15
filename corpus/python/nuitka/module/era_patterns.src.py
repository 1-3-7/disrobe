def set_comp(n: int) -> set:
    return {i % 3 for i in range(n)}


def gen_squares(n: int):
    for i in range(n):
        yield i * i


def multi_except(a: int, b: int) -> int:
    try:
        return a // b
    except ZeroDivisionError:
        return -1
    except TypeError:
        return -2


def except_as(a: int) -> str:
    try:
        return str(10 // a)
    except ZeroDivisionError as exc:
        return type(exc).__name__
