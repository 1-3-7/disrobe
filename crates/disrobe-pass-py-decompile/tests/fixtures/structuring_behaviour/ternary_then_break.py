def run(t, c):
    n = 0
    log = []
    while n < 4:
        n += 1
        log.append(1 if 12 in t else 0)
        if c in t:
            break
    log.append(-n)
    log.append(len(t))
    return log


print(run([12, 3], 3), run([], 3))
