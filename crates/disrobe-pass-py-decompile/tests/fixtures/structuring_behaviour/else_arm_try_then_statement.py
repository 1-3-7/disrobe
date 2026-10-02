def run(n, d, a):
    log = []
    while n < 3:
        n += 1
        if d:
            log.append(1)
        else:
            try:
                d = a // (n - 1)
            except ZeroDivisionError:
                log.append(0)
            log.append(d)
        d *= 11
    return log


print(run(0, 0, 4), run(0, 1, 4))
