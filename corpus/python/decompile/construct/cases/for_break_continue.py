def f(values):
    total = 0
    for v in values:
        if v == 0:
            continue
        if v < 0:
            break
        total += v
    return total
