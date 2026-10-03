# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: sample.py
# DO NOT EDIT - generated output
def I0(I3):
    I2 = 'hello, ' + I3
    print(I2)
    return len(I2)

def I1():
    I4 = 0
    for I5 in ('alice', 'bob', 'carol'):
        I4 += I0(I5)
    print('total chars:', I4)
    return I4
if __name__ == '__main__':
    I1()