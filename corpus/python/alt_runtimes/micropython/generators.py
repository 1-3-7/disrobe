def countdown(n):
    while n > 0:
        yield n
        n -= 1


def doubled(items):
    for item in items:
        yield item * 2


def chained(items):
    yield from doubled(items)
    yield 0


def accumulate(items):
    total = 0
    for item in items:
        total += item
        yield total
    return total


for value in countdown(3):
    print(value)
print(list(chained([1, 2])))
print(list(accumulate([1, 2, 3])))
