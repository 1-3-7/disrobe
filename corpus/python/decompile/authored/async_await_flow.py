import asyncio


class Session:
    def __init__(self, name):
        self.name = name
        self.log = []

    async def __aenter__(self):
        self.log.append("open")
        await asyncio.sleep(0)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.log.append("close")
        return False


class Ticker:
    def __init__(self, limit):
        self.limit = limit
        self.current = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.current >= self.limit:
            raise StopAsyncIteration
        self.current += 1
        await asyncio.sleep(0)
        return self.current


async def fetch(key, delay=0):
    await asyncio.sleep(delay)
    if key.startswith("bad"):
        raise LookupError(key)
    return key.upper()


async def fetch_all(keys):
    results = {}
    for key in keys:
        try:
            results[key] = await fetch(key)
        except LookupError:
            results[key] = None
    return results


async def ticks(limit):
    seen = []
    async for tick in Ticker(limit):
        if tick % 2:
            continue
        seen.append(tick)
    return seen


async def squares(limit):
    for i in range(limit):
        await asyncio.sleep(0)
        yield i * i


async def run_session(name):
    async with Session(name) as session:
        values = [value async for value in squares(4) if value]
        session.log.extend(values)
    gathered = await asyncio.gather(fetch("a"), fetch("b"))
    return session.log, gathered
