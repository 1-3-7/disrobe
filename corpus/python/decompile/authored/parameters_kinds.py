DEFAULT_SEPARATOR = ","


def positional_only(a, b, /, c):
    return a - b + c


def keyword_only(*, name, verbose=False):
    return name.upper() if verbose else name


def mixed(a, b=2, /, c=3, *args, d, e=5, **kwargs):
    return a, b, c, args, d, e, sorted(kwargs)


def join_all(*parts, sep=DEFAULT_SEPARATOR):
    return sep.join(str(part) for part in parts)


def configure(host, port=8080, **options):
    settings = {"host": host, "port": port}
    settings.update(options)
    return settings


def with_mutable_default(item, bucket=None):
    if bucket is None:
        bucket = []
    bucket.append(item)
    return bucket


def forward(*args, **kwargs):
    return mixed(*args, **kwargs)


def call_styles():
    first = positional_only(1, 2, c=3)
    second = keyword_only(name="x", verbose=True)
    third = mixed(1, d=4)
    fourth = forward(1, 2, 3, 4, d=0, extra=True)
    fifth = configure(*("localhost",), **{"debug": True, "port": 9000})
    sixth = join_all(*range(3), *"ab", sep="|")
    return first, second, third, fourth, fifth, sixth


def defaults_evaluated(value=len(DEFAULT_SEPARATOR) * 10, scale=0.5):
    return value * scale
