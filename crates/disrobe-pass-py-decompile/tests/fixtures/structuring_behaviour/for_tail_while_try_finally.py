def run(k, flag):
    log = []
    for i in k:
        n = 0
        while n < 2 and flag:
            n += 1
            try:
                log.append(i)
            finally:
                log.append(-i)
    return log


print(run(range(2), True), run(range(2), False))
