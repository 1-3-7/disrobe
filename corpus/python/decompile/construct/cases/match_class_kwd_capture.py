class Point:
    __match_args__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x
        self.y = y


def locate(p):
    match p:
        case Point(x=0, y=y):
            return ("on-y-axis", y)
        case Point(x=x, y=0):
            return ("on-x-axis", x)
        case Point(x=x, y=y):
            return ("free", x, y)
        case _:
            return "other"
