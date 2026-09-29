def countdown(n):
    while n > 0:
        yield n
        n -= 1


def chunks(items, size):
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def flatten(tree):
    for node in tree:
        if isinstance(node, (list, tuple)):
            yield from flatten(node)
        else:
            yield node


def averager():
    total = 0.0
    count = 0
    average = None
    while True:
        value = yield average
        if value is None:
            return count
        total += value
        count += 1
        average = total / count


def delegate(results):
    while True:
        count = yield from averager()
        results.append(count)


def pairs(a, b):
    yield from zip(a, b)
    yield from ((x, None) for x in a[len(b):])


def take(gen, n):
    out = []
    for value in gen:
        if len(out) >= n:
            break
        out.append(value)
    return out


def guarded(values):
    try:
        for value in values:
            yield value * 2
    finally:
        yield -1
