VERSION_LABEL = "disrobe-bytecode-probe"


def describe(items):
    parts = []
    for index, value in enumerate(items):
        parts.append(str(index) + "=" + str(value))
    joined = ", ".join(parts)
    return VERSION_LABEL + ": " + joined


def total(numbers):
    running = 0
    for number in numbers:
        running += number
    return running
