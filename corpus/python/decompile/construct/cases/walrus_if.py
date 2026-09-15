def f(data):
    if (name := data.get("name")) is not None:
        return name.upper()
    return "anon"
