data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
filtered = [y for x in data if (y := x * x) > 20]
buckets = {k: v for k in range(5) if (v := k * 10 + 1) % 2 == 1}
nested = [
    (a, b) for a in data if (sa := a * a) < 50 for b in data if (sb := b * b) < 50 and sa != sb
]


def stream_until(stop: int) -> list[int]:
    seen: list[int] = []
    while (chunk := next(iter(range(stop)), -1)) >= 0:
        if chunk in seen:
            break
        seen.append(chunk)
        if chunk >= stop - 1:
            break
    return seen


print(filtered, buckets, len(nested), stream_until(5))
