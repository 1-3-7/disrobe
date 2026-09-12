def guard_and(sock, ssl):
    if ssl is not None and isinstance(sock, ssl.SSLSocket):
        raise TypeError("bad socket")


def guard_or(value, limit):
    if value is None or value > limit:
        return -1
    return value


def guard_and_chain(a, b, c):
    if a and b and c:
        raise ValueError("all set")
    return 0


def guard_mixed(a, b, c):
    if a and (b or c):
        return 1
    return 2
