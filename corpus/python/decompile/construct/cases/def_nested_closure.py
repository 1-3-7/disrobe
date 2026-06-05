def f():
    accumulator = 0
    def add(delta):
        nonlocal accumulator
        accumulator += delta
        return accumulator
    return add
