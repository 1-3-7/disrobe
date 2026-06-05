def f(value):
    match value:
        case [1, *rest]:
            return rest
        case _:
            return 0
