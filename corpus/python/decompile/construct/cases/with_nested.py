def f(outer, inner, payload):
    with outer:
        with inner:
            return payload[::-1]
