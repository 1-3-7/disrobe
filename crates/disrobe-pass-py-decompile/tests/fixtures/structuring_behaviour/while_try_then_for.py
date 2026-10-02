def run(n, k):
    log = []
    while n < 2:
        n += 1
        try:
            log.append(4 // n)
        except ZeroDivisionError:
            log.append("zero")
    for i in k:
        log.append(i)
    return log


print(run(0, range(2)))
