def f(value):
    match value:
        case (1 | 2 | 3) as small:
            return small
        case _:
            return "other"
