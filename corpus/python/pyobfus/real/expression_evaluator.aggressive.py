# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: expression_evaluator.py
# DO NOT EDIT - generated output
I0 = {'+': 1, '-': 1, '*': 2, '/': 2, '%': 2, '^': 3}
I1 = frozenset('^')

def I8(I10):
    I13 = []
    I5 = ''
    for I2 in I10:
        if I2.isdigit() or I2 == '.':
            I5 += I2
            continue
        if I5:
            I13.append(float(I5))
            I5 = ''
        if I2 in I0 or I2 in '()':
            I13.append(I2)
        elif not I2.isspace():
            raise ValueError('bad character ' + repr(I2))
    if I5:
        I13.append(float(I5))
    return I13

def I11(I13):
    I6 = []
    I9 = []
    for I12 in I13:
        if isinstance(I12, float):
            I6.append(I12)
        elif I12 == '(':
            I9.append(I12)
        elif I12 == ')':
            while I9 and I9[-1] != '(':
                I6.append(I9.pop())
            if not I9:
                raise ValueError('unbalanced')
            I9.pop()
        else:
            while I9 and I9[-1] != '(' and (I0[I9[-1]] > I0[I12] or (I0[I9[-1]] == I0[I12] and I12 not in I1)):
                I6.append(I9.pop())
            I9.append(I12)
    while I9:
        I14 = I9.pop()
        if I14 == '(':
            raise ValueError('unbalanced')
        I6.append(I14)
    return I6

def I3(I10):
    I9 = []
    for I12 in I11(I8(I10)):
        if isinstance(I12, float):
            I9.append(I12)
            continue
        I7 = I9.pop()
        I4 = I9.pop()
        if I12 == '+':
            I9.append(I4 + I7)
        elif I12 == '-':
            I9.append(I4 - I7)
        elif I12 == '*':
            I9.append(I4 * I7)
        elif I12 == '/':
            I9.append(I4 / I7)
        elif I12 == '%':
            I9.append(I4 % I7)
        else:
            I9.append(I4 ** I7)
    return I9[0] if len(I9) == 1 else None