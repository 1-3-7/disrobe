def run(t, a, d):
    for i in range(2, 6):
        try:
            if d == a:
                break
            t.append(len([x for x in t if x > a]))
            for j in range(2, 4):
                a += 1
        except ZeroDivisionError:
            t.append("zero")
    return a, t


print(run([], 0, 3), run([], 3, 3))
