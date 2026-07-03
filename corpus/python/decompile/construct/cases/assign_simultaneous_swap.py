def f(a, b, c, lst, d):
    a, b = b, a
    a, b, c = c, a, b
    lst[0], lst[1] = lst[1], lst[0]
    a, lst[0], d["k"] = d["k"], a, lst[0]
    return a, b, c
