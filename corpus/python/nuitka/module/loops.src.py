def total(n: int) -> int:
    s = 0
    for i in range(n):
        s = s + i
    return s


def countdown(n: int) -> int:
    c = 0
    while n > 0:
        n = n - 1
        c = c + 1
    return c


def accumulate(n: int) -> int:
    acc = 1
    for i in range(1, n):
        acc = acc * i
    return acc
