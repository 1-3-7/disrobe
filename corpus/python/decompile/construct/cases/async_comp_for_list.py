async def f(ait, xs):
    return [v async for v in ait(xs) if v is not None]
