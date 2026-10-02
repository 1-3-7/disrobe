def chained(t, a, d):
    out = []
    for i in range(2, 5):
        if 3 in t:
            out.append("t")
        elif a > 1 and d > 1:
            out.append("e")
            try:
                out.append(a // (i - 3))
            except ZeroDivisionError:
                out.append("zero")
    print(out)


def passed(t, a):
    out = []
    for i in range(2, 5):
        if 3 in t:
            pass
        elif a > 1:
            out.append("e")
            try:
                out.append(a // (i - 3))
            except ZeroDivisionError:
                out.append("zero")
    print(out)


for args in (([3], 2, 2), ([], 2, 2), ([], 0, 2), ([], 2, 0)):
    chained(*args)
    passed(*args[:2])
