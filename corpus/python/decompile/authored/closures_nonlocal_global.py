CALLS = 0
REGISTRY = []


def counter(start=0, step=1):
    value = start

    def advance():
        nonlocal value
        value += step
        return value

    def reset():
        nonlocal value
        value = start

    return advance, reset


def track(name):
    global CALLS
    CALLS += 1
    REGISTRY.append(name)
    return CALLS


def make_multipliers(limit):
    return [lambda x, factor=factor: x * factor for factor in range(1, limit + 1)]


def accumulator():
    history = []
    total = 0

    def add(amount):
        nonlocal total
        total += amount
        history.append(total)
        return total

    def snapshot():
        return tuple(history), total

    return add, snapshot


def memoize(func):
    cache = {}

    def wrapper(n):
        if n not in cache:
            cache[n] = func(n)
        return cache[n]

    wrapper.cache = cache
    return wrapper


def outer_chain(seed):
    def middle(offset):
        def inner(scale):
            return (seed + offset) * scale

        return inner

    return middle


def reset_globals():
    global CALLS, REGISTRY
    CALLS = 0
    REGISTRY = []
