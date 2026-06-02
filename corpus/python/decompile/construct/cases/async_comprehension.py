async def f(ids, fetch):
    return [await fetch(i) for i in ids if i > 0]
