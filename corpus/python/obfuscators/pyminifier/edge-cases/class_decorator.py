# pyminifier output
__pyminifier__ = '2.1'
# pyminifier-reverse-map: o0=deco; o1=Box; o2=__init__
def deco(cls):
    cls.decorated = True
    return cls

@deco
class Box:
    def __init__(self, v):
        self.v = v
