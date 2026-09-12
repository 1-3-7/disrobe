def defaults(a, b=2, c="x"):
    return (a, b, c)


def kwonly(a, *, b, c=3):
    return a + b + c


def variadic(a, *args, **kwargs):
    return (a, args, kwargs)


def mixed(a, b=1, *args, c, d=4, **kwargs):
    return (a, b, args, c, d, kwargs)


class Holder:
    def take(self, a, *, b=0):
        return a + b


print(defaults(1))
print(kwonly(1, b=2))
print(variadic(1, 2, 3, k=4))
print(mixed(1, 2, 3, c=5, e=6))
print(Holder().take(1, b=2))
