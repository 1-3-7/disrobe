# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: generators_yield_from.py
# DO NOT EDIT - generated output
def I7(I14):
    while I14 > 0:
        yield I14
        I14 -= 1

def I5(I13, I19):
    I4 = []
    for I12 in I13:
        I4.append(I12)
        if len(I4) == I19:
            yield I4
            I4 = []
    if I4:
        yield I4

def I9(I22):
    for I15 in I22:
        if isinstance(I15, (list, tuple)):
            yield from I9(I15)
        else:
            yield I15

def I2():
    I21 = 0.0
    I6 = 0
    I1 = None
    while True:
        I23 = (yield I1)
        if I23 is None:
            return I6
        I21 += I23
        I6 += 1
        I1 = I21 / I6

def I8(I18):
    while True:
        I6 = (yield from I2())
        I18.append(I6)

def I17(I0, I3):
    yield from zip(I0, I3)
    yield from ((x, None) for x in I0[len(I3):])

def I20(I10, I14):
    I16 = []
    for I23 in I10:
        if len(I16) >= I14:
            break
        I16.append(I23)
    return I16

def I11(I24):
    try:
        for I23 in I24:
            yield (I23 * 2)
    finally:
        yield (-1)