# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: sample.py
# DO NOT EDIT - generated output
def I0(I2):
    I1 = 'hello, ' + I2
    print(I1)
    return len(I1)

def main():
    I3 = 0
    for I4 in ('alice', 'bob', 'carol'):
        I3 += I0(I4)
    print('total chars:', I3)
    return I3
if __name__ == '__main__':
    main()