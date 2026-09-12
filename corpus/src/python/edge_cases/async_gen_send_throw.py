import asyncio


async def adjuster(start: int):
    current = start
    try:
        while True:
            delta = yield current
            if delta is None:
                delta = 1
            current += delta
    except GeneratorExit:
        return


async def main() -> list[int]:
    agen = adjuster(0)
    out: list[int] = []
    out.append(await agen.asend(None))
    out.append(await agen.asend(5))
    out.append(await agen.asend(-2))
    out.append(await agen.asend(10))
    await agen.aclose()
    return out


print(asyncio.run(main()))
