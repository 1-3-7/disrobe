def echo_chamber():
    received: object = None
    while True:
        received = yield received
        if received == "stop":
            return "halted"


def driver() -> list[object]:
    gen = echo_chamber()
    next(gen)
    outputs: list[object] = []
    for value in ("hello", "world", 42, [1, 2]):
        outputs.append(gen.send(value))
    try:
        gen.send("stop")
    except StopIteration as st:
        outputs.append(st.value)
    return outputs


print(driver())
