async def f(source):
    async for item in source:
        if item % 2 == 0:
            yield item * 10
