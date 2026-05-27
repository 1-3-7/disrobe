# Oxyry.com minified
__oxyry__ = '1'

def deco(cls):
    cls.decorated = True
    return cls

@deco
class Box:
    def __init__(self, v):
        self.v = v
