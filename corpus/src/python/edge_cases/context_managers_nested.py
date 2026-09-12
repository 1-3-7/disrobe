from contextlib import ExitStack, contextmanager


@contextmanager
def labelled(label: str, log: list[str]):
    log.append(f"enter:{label}")
    try:
        yield label
    finally:
        log.append(f"exit:{label}")


def stacked(names: list[str]) -> list[str]:
    log: list[str] = []
    with ExitStack() as stack:
        for n in names:
            stack.enter_context(labelled(n, log))
        log.append("body")
    return log


print(stacked(["a", "b", "c"]))
