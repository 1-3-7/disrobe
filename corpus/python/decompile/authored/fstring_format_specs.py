WIDTH = 12
PRECISION = 3


def money(amount, currency="EUR"):
    return f"{amount:,.2f} {currency}"


def table_row(name, qty, price):
    return f"|{name:<{WIDTH}}|{qty:>5d}|{price:>{WIDTH}.{PRECISION}f}|"


def conversions(value):
    return f"{value!r} {value!s} {value!a}"


def debug_view(x, y):
    return f"{x=} {y=:.1f} {x + y = }"


def numbers(n):
    return f"{n:b} {n:o} {n:x} {n:#X} {n:08d} {n:+} {n:e} {n:%}"


def nested_quotes(record):
    return f"{record['name']} is {record['age']} and {'old' if record['age'] > 40 else 'young'}"


def centered(title, fill="*"):
    return f"{title:{fill}^{WIDTH * 2}}"


def percent(done, total):
    ratio = done / total if total else 0.0
    return f"{done}/{total} ({ratio:.1%})"


def multiline(user, items):
    return (
        f"user: {user.upper()}\n"
        f"items: {len(items)}\n"
        f"first: {items[0] if items else None}"
    )


def escaped_braces(key):
    return f"{{{key}}} = {{value}}"


def mixed_formats(name, score):
    old = "%s scored %5.1f" % (name, score)
    new = "{} scored {:5.1f}".format(name, score)
    named = "{who} scored {pts:.0f}".format(who=name, pts=score)
    return old, new, named, f"{name} scored {score:5.1f}"
