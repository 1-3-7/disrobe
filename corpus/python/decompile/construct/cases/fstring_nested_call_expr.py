def f(items, sep):
    return f"[{sep.join(str(x) for x in items)}] count={len(items)}"
