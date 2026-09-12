async def f(stream):
    acc = 0
    async for chunk in stream:
        acc += chunk
    return acc
