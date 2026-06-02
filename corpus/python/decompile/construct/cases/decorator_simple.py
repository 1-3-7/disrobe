import functools

@functools.lru_cache(maxsize=128)
def f(n):
    return n * n
