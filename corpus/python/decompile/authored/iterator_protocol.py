class Range:
    def __init__(self, start, stop=None, step=1):
        if stop is None:
            start, stop = 0, start
        if step == 0:
            raise ValueError("step must not be zero")
        self.start, self.stop, self.step = start, stop, step

    def __iter__(self):
        return RangeIterator(self)

    def __len__(self):
        span = self.stop - self.start
        return max(0, (span + self.step - (1 if self.step > 0 else -1)) // self.step)

    def __reversed__(self):
        last = self.start + (len(self) - 1) * self.step
        return iter(Range(last, self.start - self.step, -self.step))


class RangeIterator:
    def __init__(self, source):
        self.current = source.start
        self.stop = source.stop
        self.step = source.step

    def __iter__(self):
        return self

    def __next__(self):
        if (self.step > 0 and self.current >= self.stop) or (self.step < 0 and self.current <= self.stop):
            raise StopIteration
        value = self.current
        self.current += self.step
        return value


class Peekable:
    _missing = object()

    def __init__(self, iterable):
        self._it = iter(iterable)
        self._head = self._missing

    def peek(self, default=None):
        if self._head is self._missing:
            self._head = next(self._it, self._missing)
        return default if self._head is self._missing else self._head

    def __iter__(self):
        return self

    def __next__(self):
        if self._head is not self._missing:
            value, self._head = self._head, self._missing
            return value
        return next(self._it)


def manual_loop(iterable):
    it = iter(iterable)
    out = []
    while True:
        try:
            item = next(it)
        except StopIteration:
            break
        out.append(item)
    return out
