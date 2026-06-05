def f(value):
    match value:
        case {"k": vv} as m:
            return (vv, m)
        case {"k": vv, **rest} as m:
            return (vv, rest, m)
        case _:
            return None
