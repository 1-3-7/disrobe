# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: class_inheritance_super.py
# DO NOT EDIT - generated output
class I3:
    I20 = 0
    I16 = {}

    def __init_subclass__(I10, **I14):
        super().__init_subclass__(**I14)
        I3.I16[I10.__name__.lower()] = I10

    def __init__(I17, I15):
        I17.name = I15

    def I6(I17):
        raise NotImplementedError

    def I11(I17):
        return '%s with %d sides and area %.2f' % (I17.name, I17.I20, I17.I6())

class I2(I3):
    I20 = 4

    def __init__(I17, I22, I12, I15='rectangle'):
        super().__init__(I15)
        I17.width = I22
        I17.height = I12

    def I6(I17):
        return I17.width * I17.height

class I4(I2):

    def __init__(I17, I19):
        super(I4, I17).__init__(I19, I19, name='square')

class I5(I3):
    I20 = 3

    def __init__(I17, I8, I12):
        I3.__init__(I17, 'triangle')
        I17.base = I8
        I17.height = I12

    def I6(I17):
        return 0.5 * I17.base * I17.height

class I0:

    def I11(I17):
        return '[' + super().I11() + ']'

class I1(I0, I4):
    pass

def I9(I13, *I7):
    I10 = I3.I16[I13]
    return I10(*I7)

def I21(I18):
    return sum((shape.I6() for shape in I18 if isinstance(shape, I3)))