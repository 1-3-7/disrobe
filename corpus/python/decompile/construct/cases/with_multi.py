def f(a, b):
    with a as x, b as y:
        return x + y
