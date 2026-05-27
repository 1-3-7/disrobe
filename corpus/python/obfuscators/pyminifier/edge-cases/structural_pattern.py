# pyminifier output
__pyminifier__ = '2.1'
# pyminifier-reverse-map: o0=kind
def kind(p):
    match p:
        case {'type': t, **_rest}:
            return t
        case _:
            return None
