class Record:
    __match_args__ = ("kind",)

    def __init__(self, kind, x, y, z):
        self.kind = kind
        self.x = x
        self.y = y
        self.z = z


def route(r):
    match r:
        case Record("hit", x=200, y=_, z=z):
            return ("hit", z)
        case Record(kind, x=_, y=cap):
            return ("any", kind, cap)
        case Record("miss", z=0):
            return "miss-zero"
        case _:
            return "other"
