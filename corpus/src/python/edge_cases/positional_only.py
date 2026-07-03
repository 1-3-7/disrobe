def divide(numerator: float, denominator: float, /, *, mode: str = "float") -> float:
    if denominator == 0:
        raise ZeroDivisionError("denominator must be nonzero")
    if mode == "int":
        return numerator // denominator
    return numerator / denominator


def mixed(a, b, /, c, d, *, e, f=10):
    return (a, b, c, d, e, f)


print(divide(10.0, 4.0, mode="int"))
print(mixed(1, 2, 3, 4, e=5))
