def f(path):
    handle = None
    try:
        handle = path.upper()
        return handle
    except (TypeError, AttributeError):
        return None
    finally:
        print(handle)
