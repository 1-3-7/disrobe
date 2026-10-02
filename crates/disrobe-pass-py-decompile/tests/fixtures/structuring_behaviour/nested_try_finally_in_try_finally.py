def run(a):
    log = []
    try:
        try:
            log.append(6 // a)
        except ZeroDivisionError:
            log.append("zero")
        finally:
            log.append("inner")
    finally:
        log.append("outer")
    return log


print(run(0), run(2))
