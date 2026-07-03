def greet(name, score):
    pct = score / 100
    return f"hi {name!r}, score={score:04d} pct={pct:.2f}"


print(greet('abyss', 7))
