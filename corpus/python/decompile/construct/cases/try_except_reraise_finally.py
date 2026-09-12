def f(x, sink):
    acc = []
    sink.append(acc)
    try:
        acc.append(x)
        return sum(acc)
    except OSError as exc:
        acc.append(exc)
        raise
    except:
        raise
    finally:
        x = acc = None
