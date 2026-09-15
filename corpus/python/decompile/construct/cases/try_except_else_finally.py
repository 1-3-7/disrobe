def f(items):
    total = 0
    try:
        for it in items:
            total += it
    except OverflowError:
        total = -1
    else:
        total += 100
    finally:
        print(total)
    return total
