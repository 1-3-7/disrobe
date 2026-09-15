def gather_errors() -> None:
    excs: list[Exception] = [
        ValueError("bad input"),
        TypeError("wrong type"),
        OSError("io fail"),
        ValueError("again"),
    ]
    raise ExceptionGroup("gathered", excs)


def consume() -> tuple[list[str], list[str]]:
    values: list[str] = []
    types: list[str] = []
    try:
        gather_errors()
    except* ValueError as eg:
        for e in eg.exceptions:
            values.append(str(e))
    except* (TypeError, OSError) as eg:
        for e in eg.exceptions:
            types.append(f"{type(e).__name__}:{e}")
    return values, types


print(consume())
