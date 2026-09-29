def greet(name, punctuation="!"):
    return f"Hello, {name}{punctuation}"


for person in ("Ada", "Grace", "Linus"):
    print(greet(person))
