def is_pos(n: int) -> bool:
    return n > 0


def is_eq(a: int, b: int) -> bool:
    return a == b


def in_range(n: int) -> bool:
    return n < 100


def clamp_low(n: int) -> int:
    if n < 0:
        return 0
    return n


def sign(n: int) -> int:
    if n < 0:
        return -1
    if n > 0:
        return 1
    return 0
