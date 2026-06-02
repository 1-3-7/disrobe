class HttpResponse:
    __match_args__ = ("status", "body")

    def __init__(self, status, body):
        self.status = status
        self.body = body


def classify(resp):
    match resp:
        case HttpResponse(status=200, body=b""):
            return "empty-ok"
        case HttpResponse(status=200, body=b"data"):
            return "payload"
        case HttpResponse(status=404):
            return "missing"
        case _:
            return "other"
