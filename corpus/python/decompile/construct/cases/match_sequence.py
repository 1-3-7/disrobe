def f(seq):
    match seq:
        case []:
            return "empty"
        case [single]:
            return single
        case [first, *middle, last]:
            return (first, middle, last)
        case _:
            return "other"
