def stats(a: int, b: int) -> int:
    total = a + b
    diff = a - b
    return total + diff


def scale(x: int) -> int:
    y = x * 2
    z = y + 1
    return z


def swap_sum(a: int, b: int) -> int:
    a, b = b, a
    return a - b


def absval(n: int) -> int:
    r = n
    if n < 0:
        r = -n
    return r
