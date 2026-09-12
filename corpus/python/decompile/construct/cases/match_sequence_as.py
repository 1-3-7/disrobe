def f(value):
    match value:
        case [a] as whole:
            return (a, whole)
        case _:
            return None
