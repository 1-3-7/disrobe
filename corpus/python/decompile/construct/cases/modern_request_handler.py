import asyncio
from contextvars import ContextVar
from dataclasses import dataclass

REQUEST_ID: ContextVar[str] = ContextVar("request_id", default="none")


@dataclass
class HttpResponse:
    status: int
    body: bytes


async def modern_request_handler(payloads, fetcher):
    summaries = []
    fetched = []
    failure = None
    try:
        async with asyncio.TaskGroup() as tg:
            for resp in payloads:
                match resp:
                    case HttpResponse(status=200, body=b""):
                        summaries.append("empty-ok")
                    case HttpResponse(status=200, body=body) if (size := len(body)) > 0:
                        summaries.append(f"ok:{size}")
                    case HttpResponse(status=code) if code >= 400:
                        tg.create_task(fetcher(code))
                        summaries.append(f"refetch:{code}")
                    case _:
                        summaries.append("other")
    except* ConnectionError as eg:
        failure = {"ok": False, "stage": "fetch", "failed": len(eg.exceptions)}
    except* ValueError as eg:
        failure = {"ok": False, "stage": "parse", "failed": len(eg.exceptions)}
    if failure is not None:
        return failure
    return {
        "ok": True,
        "summaries": summaries,
        "fetched": len(fetched),
        "request_id": REQUEST_ID.get(),
    }
