POINTS = ((0, 0), (3, 4), (-1, 2))


def head_tail(items):
    head, *tail = items
    return head, tail


def ends(items):
    first, *_, last = items
    return first, last


def middle(items):
    *init, last = items
    a, (b, c), *rest = init + [(last, last)]
    return a, b, c, rest


def swap_pairs(pairs):
    return [(y, x) for x, y in pairs]


def merge_all(*groups):
    return [*groups[0], *groups[-1]] if groups else []


def merged_dict(base, override):
    return {**base, **override, "merged": True}


def merged_set(a, b):
    return {*a, *b}


def unpack_for(points):
    total_x = total_y = 0
    for x, y in points:
        total_x += x
        total_y += y
    return total_x, total_y


def nested_targets(records):
    out = []
    for name, (age, *scores) in records:
        out.append((name, age, sum(scores)))
    return out


def rotate(a, b, c):
    a, b, c = b, c, a
    return a, b, c


def call_spread(func, args, kwargs):
    return func(*args, 0, *args, **kwargs, extra=1)


def build_tuple(*values):
    return (*values, len(values))
