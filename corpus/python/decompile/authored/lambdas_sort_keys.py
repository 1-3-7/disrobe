import functools
import operator

RECORDS = (
    ("ada", 36, 4.5),
    ("grace", 85, 3.9),
    ("linus", 54, 4.1),
    ("barbara", 61, 4.5),
)

by_age = lambda record: record[1]
compose = lambda f, g: lambda x: f(g(x))
identity = lambda value: value
constant = lambda: 42


def sort_by_rating_then_name(records):
    return sorted(records, key=lambda r: (-r[2], r[0]))


def youngest(records):
    return min(records, key=by_age)


def names_upper(records):
    return list(map(lambda r: r[0].upper(), records))


def adults(records, cutoff=50):
    return list(filter(lambda r: r[1] >= cutoff, records))


def product(values):
    return functools.reduce(lambda acc, v: acc * v, values, 1)


def pipeline(*funcs):
    return functools.reduce(compose, funcs, identity)


def dispatch(op):
    table = {
        "+": operator.add,
        "-": operator.sub,
        "max": lambda a, b: a if a > b else b,
        "avg": lambda a, b: (a + b) / 2,
    }
    return table.get(op, lambda a, b: None)


def keyword_lambda():
    return lambda *args, sep=", ", **kw: sep.join(map(str, args + tuple(kw.values())))
