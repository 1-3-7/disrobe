from typing import TypedDict, Unpack


class HttpKwargs(TypedDict, total=False):
    method: str
    url: str
    timeout: float
    headers: dict[str, str]


def request(**kwargs: Unpack[HttpKwargs]) -> str:
    method = kwargs.get("method", "GET")
    url = kwargs.get("url", "/")
    timeout = kwargs.get("timeout", 30.0)
    return f"{method} {url} ({timeout}s)"


print(request(method="POST", url="/api", timeout=5.0))
print(request(url="/index"))
