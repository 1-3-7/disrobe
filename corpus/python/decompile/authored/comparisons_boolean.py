LOW = 10
HIGH = 99


def in_range(value):
    return LOW <= value < HIGH


def strictly_increasing(a, b, c, d):
    return a < b < c < d


def mixed_chain(a, b, c):
    return a == b != c is not None


def membership(value, allowed, blocked):
    return value in allowed and value not in blocked


def identity_checks(a, b):
    return a is b, a is not b, a is None or b is None


def first_truthy(*values):
    return values[0] or values[1] or values[2] or "none"


def all_present(record):
    return record.get("name") and record.get("email") and "@" in record["email"]


def eligible(age, member, invited, banned):
    return (age >= 18 and (member or invited)) and not banned


def default_chain(explicit, configured, fallback=0):
    value = explicit if explicit is not None else configured or fallback
    return value


def guard(items, index):
    return 0 <= index < len(items) and items[index] is not None


def negations(flag, count):
    return not flag, not (count > 3), not flag and count, not (flag or count)


def compare_tuples(a, b):
    return (a > b) - (a < b)


def short_circuit_calls(log):
    def mark(name, result):
        log.append(name)
        return result

    return mark("a", False) and mark("b", True) or mark("c", True) and mark("d", 0)
