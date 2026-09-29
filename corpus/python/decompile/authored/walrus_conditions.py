import re

KEY_VALUE = re.compile(r"(\w+)\s*=\s*(\S+)")


def parse_assignments(lines):
    found = {}
    for line in lines:
        if (match := KEY_VALUE.match(line)) is not None:
            found[match.group(1)] = match.group(2)
    return found


def read_blocks(stream, size):
    blocks = []
    while (block := stream[:size]):
        blocks.append(block)
        stream = stream[size:]
    return blocks


def describe_length(items):
    if (n := len(items)) > 10:
        return f"long ({n})"
    elif n:
        return f"short ({n})"
    return "empty"


def first_negative(values):
    for value in values:
        if (neg := value) < 0:
            return neg
    return None


def filtered_squares(values):
    return [y for x in values if (y := x * x) % 3 == 1]


def running_max(values):
    best = None
    out = []
    for v in values:
        if best is None or (candidate := v) > best:
            best = v
        out.append(best)
    return out


def budget(costs, limit):
    spent = 0
    taken = []
    for cost in costs:
        if (after := spent + cost) > limit:
            break
        spent = after
        taken.append(cost)
    return taken, spent
