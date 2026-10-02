def drain(step, more, after, done):
    while True:
        step()
        if more():
            continue
        after()
        break
    done()


def retry_each(items, again, act):
    for item in items:
        while True:
            act(item)
            if again():
                continue
            break


def answers(*values):
    iterator = iter(values)
    return lambda: next(iterator)


log = []
drain(lambda: log.append("step"), answers(True, True, False), lambda: log.append("after"), lambda: log.append("done"))
retry_each(["x", "y"], answers(True, False, False), log.append)
print(log)
