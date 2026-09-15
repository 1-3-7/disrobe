def f(token):
    try:
        return str(int(token))
    except ValueError:
        return "nan"
    except TypeError:
        return "wrong-type"
    except (KeyError, IndexError):
        return "lookup-failed"
    except Exception:
        return "unknown"
