def f(do_work):
    counts = {"value": 0, "type": 0}
    try:
        do_work()
    except* ValueError as eg:
        counts["value"] = len(eg.exceptions)
    except* TypeError as eg:
        counts["type"] = len(eg.exceptions)
    return counts
