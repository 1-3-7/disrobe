import contextlib


class Recorder:
    def __init__(self, label, events):
        self.label = label
        self.events = events

    def __enter__(self):
        self.events.append("enter " + self.label)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.events.append("exit " + self.label)
        return exc_type is KeyError


@contextlib.contextmanager
def indented(events, depth):
    events.append(">" * depth)
    try:
        yield depth + 1
    finally:
        events.append("<" * depth)


def single(events):
    with Recorder("one", events) as rec:
        events.append(rec.label)
    return events


def multiple(events):
    with Recorder("a", events) as first, Recorder("b", events) as second:
        events.append(first.label + second.label)
    return events


def nested(events):
    with indented(events, 1) as level:
        with indented(events, level) as deeper:
            with Recorder("deep", events):
                events.append(str(deeper))
    return events


def suppressed(events, mapping):
    with Recorder("lookup", events):
        value = mapping["missing"]
        events.append(value)
    with contextlib.suppress(ZeroDivisionError):
        events.append(1 / 0)
    return events


def without_target(events):
    with Recorder("anon", events):
        pass
    return len(events)
