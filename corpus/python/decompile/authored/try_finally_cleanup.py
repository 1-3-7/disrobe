class Resource:
    opened = 0

    def __init__(self, name):
        self.name = name
        self.closed = False
        Resource.opened += 1

    def close(self):
        self.closed = True
        Resource.opened -= 1


def use_resource(name, fail):
    handle = Resource(name)
    try:
        if fail:
            raise IOError("cannot use " + name)
        return handle.name.upper()
    finally:
        handle.close()


def log_steps(steps):
    log = []
    for step in steps:
        try:
            if step < 0:
                continue
            if step == 0:
                break
            log.append(step * 2)
        finally:
            log.append("done")
    return log


def nested_cleanup(values):
    result = []
    try:
        try:
            for value in values:
                result.append(10 // value)
        except ZeroDivisionError:
            result.append("div")
            raise
        finally:
            result.append("inner")
    except ArithmeticError:
        result.append("outer")
    else:
        result.append("clean")
    finally:
        result.append("final")
    return result


def finally_overrides():
    try:
        return "body"
    finally:
        marker = "cleanup"
        del marker
