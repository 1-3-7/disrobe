def join_sign(n):
    if n < 0:
        label = "neg"
    else:
        label = "nonneg"
    return label + ":" + str(n)


def grid_sum(rows, cols):
    total = 0
    for i in range(rows):
        for j in range(cols):
            total = total + i * j
    return total


def make_scaler(scale, offset):
    def apply(x):
        return x * scale + offset

    return apply


def lookup(table, key):
    try:
        return int(table[key])
    except (ValueError, KeyError):
        return -1


def neg_cube():
    return (-2) ** 3


def neg_power(n):
    return (-2) ** n


def either_call(f, g, x):
    return (f or g)(x)
