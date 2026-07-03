def deco(fn):
    return fn

@deco
@deco
def f(x):
    return x * 2
