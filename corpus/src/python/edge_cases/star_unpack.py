a, *middle, b = [1, 2, 3, 4, 5]
print(a, middle, b)


def combine(first, *args, sep: str = "-", **kwargs) -> str:
    parts = [str(first), *map(str, args), *(f"{k}={v}" for k, v in kwargs.items())]
    return sep.join(parts)


print(combine("alpha", "beta", "gamma", lang="py", level=3))

base = {"a": 1, "b": 2}
extra = {"c": 3, "d": 4}
merged = {**base, **extra, "a": 99}
print(merged)

(x, y), [z, w], *rest = ((10, 20), [30, 40], 50, 60)
print(x, y, z, w, rest)
