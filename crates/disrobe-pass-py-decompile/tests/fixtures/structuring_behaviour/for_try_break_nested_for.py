def run(t, a, d):
    for i in range(2, 6):
        try:
            t.append(d)
            if d == a:
                break
            for j in range(2, 4):
                a += 1
        except ZeroDivisionError:
            t.append("zero")
    return a


print(run([], 0, 3), run([], 3, 3))
