CONST = 42


def combine(a, b):
    return a + b


def scale(value, factor=2, *rest, offset=0, **opts):
    total = value * factor + offset
    for r in rest:
        total += r
    return total


class Gadget:
    kind = "gadget"

    def __init__(self, name, size=1):
        self.name = name
        self.size = size

    def surface(self):
        return self.size * self.size

    @staticmethod
    def build(label):
        return Gadget(label)

    class Inner:
        def deep(self, x):
            return x * 2


async def fetch(url, timeout=30):
    return url


def gen_range(n):
    for i in range(n):
        yield i
