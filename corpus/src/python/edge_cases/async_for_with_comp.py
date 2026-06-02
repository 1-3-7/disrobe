import asyncio
from contextlib import asynccontextmanager


async def numbers(n: int):
    for i in range(n):
        await asyncio.sleep(0)
        yield i


@asynccontextmanager
async def opened_resource(label: str):
    yield {"label": label, "open": True}


async def main() -> list[int]:
    async with opened_resource("worker") as res:
        return [x * 2 async for x in numbers(5) if x % 2 == 0 and res["open"]]


print(asyncio.run(main()))
