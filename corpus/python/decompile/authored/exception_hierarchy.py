class AppError(Exception):
    code = 1

    def __init__(self, message, *, detail=None):
        super().__init__(message)
        self.detail = detail

    def __str__(self):
        base = super().__str__()
        return base if self.detail is None else "%s (%s)" % (base, self.detail)


class ValidationError(AppError):
    code = 2


class NotFound(AppError, LookupError):
    code = 3


def validate(record):
    errors = []
    if "id" not in record:
        errors.append("id")
    if not isinstance(record.get("age"), int):
        errors.append("age")
    if errors:
        raise ValidationError("invalid record", detail=",".join(errors))
    return record


def lookup(table, key):
    try:
        return table[key]
    except KeyError:
        raise NotFound("no such key", detail=key) from None


def handle(func, *args):
    try:
        return 0, func(*args)
    except ValidationError as exc:
        return exc.code, str(exc)
    except LookupError as exc:
        code = getattr(exc, "code", 99)
        return code, str(exc)
    except AppError:
        return AppError.code, "generic"


def cause_chain(exc):
    chain = []
    while exc is not None:
        chain.append(type(exc).__name__)
        exc = exc.__cause__ or exc.__context__
    return chain


def cleanup_on_error(steps):
    completed = []
    try:
        for step in steps:
            completed.append(step())
    except Exception as exc:
        completed.clear()
        return [type(exc).__name__]
    return completed
