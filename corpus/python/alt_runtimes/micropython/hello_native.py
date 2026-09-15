@micropython.native
def add(a, b):
    return a + b


@micropython.viper
def mul(a: int, b: int) -> int:
    return a * b
