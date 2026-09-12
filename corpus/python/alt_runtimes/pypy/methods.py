def run(items):
    total = 0
    for x in items:
        total += x
    box = Box(total)
    return box.double()

class Box(object):
    def __init__(self, v):
        self.v = v
    def double(self):
        return self.v * 2
