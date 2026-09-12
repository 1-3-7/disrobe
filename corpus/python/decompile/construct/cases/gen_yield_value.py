def f(n):
    total = 0
    for i in range(n):
        total += i
        yield total
