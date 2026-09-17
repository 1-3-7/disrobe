async def f(rows, ait):
    return [c async for r in ait(rows) for c in r]
