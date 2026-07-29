def parse(text):
    try:
        return int(text)
    except ValueError:
        return -1


def guarded(a, b):
    try:
        result = a // b
    except ZeroDivisionError as exc:
        print(exc)
        result = 0
    else:
        result = result + 1
    finally:
        print("done")
    return result


def rethrow(flag):
    try:
        if flag:
            raise ValueError("bad")
    except ValueError:
        raise
    return flag


def multi(value):
    try:
        return 10 // value
    except ZeroDivisionError:
        return 0
    except TypeError:
        return -1


print(parse("12"))
print(guarded(4, 2))
print(multi(0))
