def consume(next_item, should_continue, sink):
    while True:
        try:
            sink(next_item())
        finally:
            sink("cleanup")
            if should_continue():
                continue
            sink("stop")
        break
    sink("done")


def values(items):
    iterator = iter(items)
    return lambda: next(iterator)


events = []
consume(values(["one", "two"]), values([True, False]), events.append)
print(events)
