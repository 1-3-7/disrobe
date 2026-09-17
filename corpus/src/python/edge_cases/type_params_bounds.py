from collections.abc import Sequence


class Stack[T]:
    def __init__(self) -> None:
        self._data: list[T] = []

    def push(self, value: T) -> None:
        self._data.append(value)

    def pop(self) -> T:
        if not self._data:
            raise IndexError("empty")
        return self._data.pop()

    def peek(self) -> T:
        return self._data[-1]


def first_or_default[T](seq: Sequence[T], default: T) -> T:
    return seq[0] if seq else default


s: Stack[int] = Stack()
s.push(1)
s.push(2)
print(s.peek(), s.pop(), first_or_default([], "fallback"))
