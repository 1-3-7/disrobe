def f(m):
    return [x * y for x in m for y in m if x != y if x + y < 10]
