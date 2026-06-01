class Point:
    __match_args__ = ("x", "y")
    def __init__(self, x, y):
        self.x = x
        self.y = y

def f(p):
    match p:
        case Point(0, 0):
            return "origin"
        case Point(x=x, y=y):
            return (x, y)
        case _:
            return "other"
