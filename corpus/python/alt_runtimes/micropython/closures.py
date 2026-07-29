def make_adder(base):
    def add(x):
        return base + x

    return add


def make_counter(start):
    total = start

    def bump(amount):
        nonlocal total
        total += amount
        return total

    return bump


def outer(a):
    def middle(b):
        def inner(c):
            return a + b + c

        return inner

    return middle


print(make_adder(2)(3))
print(make_counter(0)(5))
print(outer(1)(2)(3))
