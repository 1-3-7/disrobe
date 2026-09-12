def trap() -> str:
    try:
        x = int("42")
    except ValueError:
        return "value-err"
    except Exception:
        return "general"
    else:
        try:
            return f"ok:{x}"
        finally:
            x = -1
    finally:
        if False:
            return "never"
    return "unreachable"


def nested_return() -> int:
    try:
        try:
            raise RuntimeError("inner")
        finally:
            return 1
    finally:
        return 2


print(trap(), nested_return())
