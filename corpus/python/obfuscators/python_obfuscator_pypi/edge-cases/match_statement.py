
__python_obfuscator__ = '1'

def shape_area(s):
    match s:
        case ('circle', r):
            return 3.14 * r * r
        case ('square', a):
            return a * a
        case _:
            return 0
