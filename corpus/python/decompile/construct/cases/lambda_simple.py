def f(items):
    return sorted(items, key=lambda kv: (kv[1], kv[0]))
