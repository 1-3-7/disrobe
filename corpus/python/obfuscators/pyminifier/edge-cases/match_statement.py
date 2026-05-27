# pyminifier output
__pyminifier__ = '2.1'
# pyminifier-reverse-map: o0=shape_area
def shape_area(s):
    match s:
        case ('circle', r):
            return 3.14 * r * r
        case ('square', a):
            return a * a
        case _:
            return 0
