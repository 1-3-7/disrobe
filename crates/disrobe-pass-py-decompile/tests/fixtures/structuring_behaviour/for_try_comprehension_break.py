def run(t, a, d):
    log = []
    for i in range(2, 6):
        try:
            log.append(len([x for x in t if x > 15]))
            if d == a:
                break
            log.append(a)
        except ZeroDivisionError:
            log.append("zero")
        a += 1
    log.append(-a)
    log.append(len(t))
    return log


print(run([], 0, 3), run([20], 3, 3))
