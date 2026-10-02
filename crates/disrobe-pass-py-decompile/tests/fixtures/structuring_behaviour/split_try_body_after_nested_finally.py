def run(t, k, c, b, a):
    log = []
    try:
        try:
            b = 10 // a
        finally:
            log.append(b)
        for i in k:
            c = len([x for x in t if x > c])
    except ZeroDivisionError:
        log.append(0)
    finally:
        log.append(c)
    return log


print(run([5, 6], range(2), 1, 0, 2), run([5], range(1), 1, 0, 0))
