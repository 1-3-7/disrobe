def f(pos1, pos2, /, normal=1.0, *args, kw_only=False, required_kw, **kwargs):
    return (pos1, pos2, normal, args, kw_only, required_kw, kwargs)
