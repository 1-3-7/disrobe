def f(value):
    match value:
        case str() as t if t:
            return t
        case _:
            return None
