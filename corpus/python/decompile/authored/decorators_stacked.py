import functools

HOOKS = {}


def register(name):
    def decorator(func):
        HOOKS[name] = func
        return func

    return decorator


def logged(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        wrapper.calls.append((args, tuple(sorted(kwargs.items()))))
        return func(*args, **kwargs)

    wrapper.calls = []
    return wrapper


def clamp(low, high):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return max(low, min(high, result))

        return wrapper

    return decorator


class once:
    def __init__(self, func):
        self.func = func
        self.done = False
        self.value = None

    def __call__(self, *args):
        if not self.done:
            self.value = self.func(*args)
            self.done = True
        return self.value


@register("scale")
@logged
@clamp(0, 100)
def scale(value, factor=2):
    return value * factor


@once
def expensive_setup():
    return {"ready": True, "level": 3}


@functools.lru_cache(maxsize=32)
def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


class Service:
    @property
    @functools.lru_cache(maxsize=None)
    def identity(self):
        return id(self) & 0xFFFF
