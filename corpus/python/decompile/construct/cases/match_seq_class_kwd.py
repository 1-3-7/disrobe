class HttpResponse:
    __match_args__ = ("status",)

    def __init__(self, status):
        self.status = status


def f(x):
    match x:
        case [HttpResponse(status=200), *_]:
            return 1
        case _:
            return 0
