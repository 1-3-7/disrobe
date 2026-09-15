

from __future__ import absolute_import

from pex.typing import TYPE_CHECKING, Generic, cast, overload

if TYPE_CHECKING:
    from typing import Any, Callable, ClassVar, Iterable, Iterator, Optional, Tuple, Type, TypeVar

    _I = TypeVar("_I")
    _R = TypeVar("_R", bound="Rank")


class Rank(Generic["_R"]):

    HIGHEST_NATURAL_VALUE = 1

    @classmethod
    def highest_natural(cls):
        # type: (Type[_R]) -> _R
        return cls(cls.HIGHEST_NATURAL_VALUE)

    @classmethod
    def ranked(
        cls,
        items,
    ):
        # type: (...) -> Iterator[Tuple[_I, _R]]
        for rank, item in enumerate(items, start=cls.HIGHEST_NATURAL_VALUE):
            yield item, cls(rank)

    @classmethod
    @overload
    def select_highest_rank(
        cls,
        item1,
        item2,
    ):
        # type: (...) -> Rank
        pass

    @classmethod
    @overload
    def select_highest_rank(
        cls,
        item1,
        item2,
        extract_rank,
    ):
        # type: (...) -> _I
        pass

    @classmethod
    def select_highest_rank(
        cls,
        item1,
        item2,
        extract_rank=None,
    ):
        # type: (...) -> _I
        if extract_rank is not None:
            return item1 if extract_rank(item1) < extract_rank(item2) else item2

        if not isinstance(item1, Rank):
            raise TypeError(
                "Can only select from amongst the same rank type; item1 is a `{item1_type}` "
                "and not a `Rank`. You may need to supply an `extract_rank` function.".format(
                    item1_type=type(item1).__name__
                )
            )
        if type(item1) != type(item2):
            raise TypeError(
                "Can only select from amongst the same rank type; item1 is a `{item1_type}` "
                "but item2 is a `{item2_type}`.".format(
                    item1_type=item1.__class__.__name__, item2_type=type(item2).__name__
                )
            )
        return cast("_I", item1 if item1 < item2 else item2)

    def __init__(self, value):
        # type: (int) -> None
        self._value = value

    @property
    def value(self):
        # type: () -> int
        return self._value

    def higher(self):
        # type: (_R) -> _R
        return self.__class__(self._value - 1)

    def lower(self):
        # type: (_R) -> _R
        return self.__class__(self._value + 1)

    def __repr__(self):
        # type: () -> str
        return "{class_name}({value})".format(class_name=self.__class__.__name__, value=self._value)

    def __eq__(self, other):
        # type: (Any) -> bool
        return type(self) == type(other) and self._value == other._value

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self == other

    def __lt__(self, other):
        # type: (Any) -> bool
        if type(self) != type(other):
            return NotImplemented


        return self._value < other.value
