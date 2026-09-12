from typing import overload


@overload
def combine(a: int, b: int) -> int: ...
@overload
def combine(a: str, b: str) -> str: ...
@overload
def combine(a: list, b: list) -> list: ...


def combine(a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a + b
    if isinstance(a, str) and isinstance(b, str):
        return a + b
    if isinstance(a, list) and isinstance(b, list):
        return [*a, *b]
    raise TypeError(f"unsupported pair: {type(a).__name__}, {type(b).__name__}")


print(combine(1, 2), combine("ab", "cd"), combine([1], [2, 3]))
