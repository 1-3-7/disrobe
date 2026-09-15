def f(opener):
    with opener() as handle:
        return handle + 1
