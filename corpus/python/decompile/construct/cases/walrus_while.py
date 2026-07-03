def f(stream):
    total = 0
    while chunk := next(stream, b""):
        total += len(chunk)
    return total
