def f(data):
    total = 0
    idx = 0
    while idx < len(data) and data[idx] >= 0:
        total += data[idx]
        idx += 1
    return total
