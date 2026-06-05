def f(value):
    match value:
        case 1 | 2 | 3:
            return "small"
        case ("a" | "b") as letter:
            return f"letter:{letter}"
        case _:
            return "other"
