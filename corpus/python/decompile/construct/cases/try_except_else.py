def f(mapping, key):
    try:
        raw = mapping[key]
    except KeyError:
        return 0
    else:
        return raw * 2
