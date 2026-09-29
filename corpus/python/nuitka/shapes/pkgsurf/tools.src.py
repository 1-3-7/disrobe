def gather(first, *args, **kw):
    return (first, args, sorted(kw))


def either(a, b):
    return a or b
