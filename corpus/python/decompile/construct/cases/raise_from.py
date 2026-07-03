def f(cause):
    raise RuntimeError("wrapped") from cause
