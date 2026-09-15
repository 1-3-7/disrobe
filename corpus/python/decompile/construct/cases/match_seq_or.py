def f(x):
    match x:
        case [1, 2] | [3, 4]:
            return "pair"
        case _:
            return "other"
