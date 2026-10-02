def run(n, m, flag, log):
    while n < 2:
        n += 1
        while m < 4 and flag:
            m += 1
        try:
            log.append(m)
        finally:
            log.append(n)
    return log


print(run(0, 0, True, []), run(0, 0, False, []))
