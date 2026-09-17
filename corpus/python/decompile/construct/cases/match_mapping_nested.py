def f(payload):
    match payload:
        case {"events": [], "user": str() as user}:
            return user
        case {"items": list() as evs}:
            return evs
        case _:
            return 0
