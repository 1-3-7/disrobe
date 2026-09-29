class Counter:
    def __init__(self):
        self.value = 0
        self.history = []


def augmented_numbers(a, b):
    a += b
    a -= 1
    a *= 3
    a /= 2
    a //= 1
    a %= 1000
    a **= 2
    b <<= 2
    b >>= 1
    b &= 0xFF
    b |= 0x100
    b ^= 0x0F
    return a, b


def augmented_targets(counter, table, key):
    counter.value += 5
    counter.history += [counter.value]
    table[key] += 1
    table[key.upper()] = table.get(key.upper(), 0)
    table[key.upper()] -= 1
    return counter, table


def text_building(parts):
    out = ""
    for part in parts:
        out += part
        out += "-"
    return out[:-1]


def cleanup(record, names):
    for name in names:
        if name in record:
            del record[name]
    temp = list(record)
    del temp[0], temp[-1:]
    del temp
    return record


def remove_attribute(obj):
    obj.transient = True
    del obj.transient
    return hasattr(obj, "transient")


def checked_ratio(num, den):
    assert den != 0, "denominator must be nonzero"
    assert isinstance(num, (int, float))
    ratio = num / den
    assert 0 <= ratio <= 1, f"ratio out of range: {ratio}"
    return ratio
