def run(n, k, d):
    log = []
    while n < 2:
        n += 1
        for i in k:
            try:
                log.append(d // i)
            except ZeroDivisionError:
                log.append("zero")
    return log


print(run(0, [0, 2], 8))
