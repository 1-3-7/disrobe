def f(token):
    match token:
        case 1 | 2 | 3:
            return "small"
        case _:
            return "other"
