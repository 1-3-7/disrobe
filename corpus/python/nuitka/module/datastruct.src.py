def make_pair(a: int, b: int) -> list:
    return [a, b]


def make_dict(k: str, v: int) -> dict:
    return {k: v}


def first(items: list) -> int:
    return items[0]


def pair_sum(items: list) -> int:
    return items[0] + items[1]


def boolop(a: int, b: int) -> bool:
    return a > 0 and b > 0


def ternary(n: int) -> int:
    return n if n > 0 else -n
