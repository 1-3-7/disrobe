counter: dict[str, int] = {"hits": 0}


def increment_and_get(value: int) -> int:
    counter["hits"] += 1
    return value


total = sum(increment_and_get(x) for x in range(10) if x % 2 == 0)
print(total, counter)


def make_closures() -> list:
    return [lambda x, factor=i: x * factor for i in range(5)]


print([fn(2) for fn in make_closures()])
