def run(t, k):
    seen = []
    for i in k:
        try:
            seen.append(len([x for x in t if x > i]))
        except ZeroDivisionError:
            seen.append(-1)
    return seen


print(run([1, 2, 3], range(3)), run([], range(2)))
