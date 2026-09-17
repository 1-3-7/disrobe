def f(value):
    match value:
        case n if n < 0:
            return "neg"
        case 0:
            return "zero"
        case n:
            return "pos"
