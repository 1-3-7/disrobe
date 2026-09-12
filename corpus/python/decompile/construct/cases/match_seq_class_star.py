def f(value):
    match value:
        case [int() as first, *_]:
            return first
        case _:
            return 0
