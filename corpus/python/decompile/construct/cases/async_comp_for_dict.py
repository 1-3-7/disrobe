async def f(xs, ait, g):
    return {x: await g(x) async for x in ait(xs)}
