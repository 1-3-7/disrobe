def f(value):
    try:
        return int(value)
    except ValueError as exc:
        print(exc)
        return -1
