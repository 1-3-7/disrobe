def describe(o):
    s = "start"
    if o.enabled:
        try:
            s = f"{s},a={o.a()}"
        except ValueError:
            pass
        try:
            s = f"{s},b={o.b()}"
        except ValueError:
            pass
    return f"{s};end"
