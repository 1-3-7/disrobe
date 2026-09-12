def run(values):
    total = 0
    for v in values:
        if v < 0:
            continue
        if v > 50:
            break
        total = total + v
    i = 0
    while i < 5:
        total = total + i
        i = i + 1
    return total


print(run([1, 2, -3, 4, 99, 5]))
