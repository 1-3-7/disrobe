def build(n):
    squares = [i * i for i in range(n)]
    evens = [x for x in squares if x % 2 == 0]
    return squares, evens


print(build(6))
