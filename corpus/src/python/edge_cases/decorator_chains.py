from functools import wraps


def add_n(n: int):
    def decorator(fn):
        @wraps(fn)
        def inner(x: int) -> int:
            return fn(x) + n

        return inner

    return decorator


def multiply_by(k: int):
    def decorator(fn):
        @wraps(fn)
        def inner(x: int) -> int:
            return fn(x) * k

        return inner

    return decorator


def register(*, name: str):
    def decorator(cls):
        cls.registry_name = name
        return cls

    return decorator


@add_n(10)
@multiply_by(3)
@add_n(1)
def transform(x: int) -> int:
    return x


@register(name="rect")
class Rect:
    def __init__(self, w: int, h: int) -> None:
        self.w = w
        self.h = h


print(transform(5), Rect.registry_name)
