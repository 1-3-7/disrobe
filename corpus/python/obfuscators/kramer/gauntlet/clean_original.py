GREETING = "hello from disrobe"
THRESHOLD = 42
_CACHE = {}


class Ledger:
    def __init__(self, owner, entries):
        self.owner = owner
        self.entries = entries

    def above(self, minimum):
        return [v for v in self.entries if v >= minimum]

    def report(self):
        kept = self.above(THRESHOLD)
        total = sum(kept)
        count = len(kept)
        return {"owner": self.owner, "total": total, "count": count}


def rotate_string(text):
    shifted = [chr(ord(c) + 3) for c in text]
    return "".join(shifted)


def cached_width(key):
    if key not in _CACHE:
        _CACHE[key] = len(rotate_string(key))
    return _CACHE[key]


def gather(items):
    out = []
    for item in items:
        width = cached_width(item)
        if width > 4:
            out.append(width)
    return out


def main():
    book = Ledger(GREETING, [10, 50, 30, 70, 20])
    print(book.report())
    print(gather(["alpha", "beta", "gamma", "delta"]))


if __name__ == "__main__":
    main()
