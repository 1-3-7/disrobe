
__manglify__ = '0.3'

def kind(p):
    match p:
        case {'type': t, **_rest}:
            return t
        case _:
            return None
