def f(event):
    match event:
        case {"type": "click", "x": x, "y": y}:
            return (x, y)
        case {"type": kind, **extras}:
            return (kind, extras)
        case _:
            return "non-map"
