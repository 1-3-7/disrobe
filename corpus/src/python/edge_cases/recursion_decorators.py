import sys
from functools import wraps


def trace_depth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        wrapper.depth += 1
        try:
            return fn(*args, **kwargs)
        finally:
            wrapper.depth -= 1

    wrapper.depth = 0
    return wrapper


def memoize(fn):
    cache: dict[tuple, object] = {}

    @wraps(fn)
    def inner(*args):
        if args in cache:
            return cache[args]
        result = fn(*args)
        cache[args] = result
        return result

    return inner


@memoize
@trace_depth
def fib(n: int) -> int:
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


sys.setrecursionlimit(2000)
print(fib(120))
