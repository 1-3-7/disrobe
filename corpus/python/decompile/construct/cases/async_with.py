async def f(lock):
    async with lock:
        return 1
