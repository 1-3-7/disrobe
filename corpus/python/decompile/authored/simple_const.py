LIMIT = 40
GREETING = "authored sample"
RATE = 2.5
FLAGS = (True, False, None)


def describe(count):
    if count > LIMIT:
        return GREETING + " overflow"
    return GREETING + " " + str(count * RATE)


print(describe(3), FLAGS)
