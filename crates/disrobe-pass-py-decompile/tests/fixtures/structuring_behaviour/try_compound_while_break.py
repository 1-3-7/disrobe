def run(t, c, d):
    n = 0
    try:
        while n < 4 and (c <= d or n == 0):
            n += 1
            if c in t:
                break
    except ZeroDivisionError:
        n = -1
    return n


print(run([], 1, 2), run([1], 1, 2), run([], 3, 2))
