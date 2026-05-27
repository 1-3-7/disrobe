# Oxyry.com minified
__oxyry__ = '1'

def kind(p):
    match p:
        case {'type': t, **_rest}:
            return t
        case _:
            return None
