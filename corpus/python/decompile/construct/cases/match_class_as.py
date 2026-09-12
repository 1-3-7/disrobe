def f(value):
    match value:
        case int() as n:
            return n
        case str() as t:
            return t
        case _:
            return None
