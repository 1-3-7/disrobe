
__manglify__ = '0.3'

def shape_area(s):
    match s:
        case ('circle', r):
            return 3.14 * r * r
        case ('square', a):
            return a * a
        case _:
            return 0
