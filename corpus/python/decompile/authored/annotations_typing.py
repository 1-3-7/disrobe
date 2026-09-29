from typing import Callable, Dict, Iterable, List, Optional, Tuple, TypeVar, Union

T = TypeVar("T")
Number = Union[int, float]

LIMIT: int = 10
NAMES: Tuple[str, ...] = ("north", "south")
pending: List[str]


class Inventory:
    owner: str
    items: Dict[str, int]
    capacity: int = 100

    def __init__(self, owner: str) -> None:
        self.owner = owner
        self.items = {}

    def add(self, name: str, count: int = 1) -> int:
        current: int = self.items.get(name, 0)
        self.items[name] = current + count
        return self.items[name]

    def find(self, name: str) -> Optional[int]:
        return self.items.get(name)


def first(values: Iterable[T], default: Optional[T] = None) -> Optional[T]:
    for value in values:
        return value
    return default


def apply(func: Callable[[Number], Number], values: List[Number]) -> List[Number]:
    return [func(v) for v in values]


def scale(value: Number, *, factor: "float" = 2.0) -> float:
    result: float
    result = value * factor
    return result


def split_pair(text: str, sep: str = ":") -> Tuple[str, str]:
    head, _, tail = text.partition(sep)
    return head, tail


def merge(*maps: Dict[str, int], **extra: int) -> Dict[str, int]:
    merged: Dict[str, int] = {}
    for mapping in maps:
        merged.update(mapping)
    merged.update(extra)
    return merged
