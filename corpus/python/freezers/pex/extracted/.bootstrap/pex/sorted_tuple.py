

from __future__ import absolute_import

from pex.typing import TYPE_CHECKING, Generic, overload

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Optional, Protocol, TypeVar, Union

    from typing_extensions import SupportsIndex

    _T = TypeVar("_T")

    class _Comparable(Protocol):
        def __lt__(self, other):
            # type: (Any) -> bool
            pass

    class _TComparator(Protocol):
        def __call__(self, item):
            # type: (_T) -> _Comparable
            pass


class SortedTuple(Generic["_T"], tuple):
    @overload
    def __new__(cls):
        # type: () -> SortedTuple[Any]
        pass

    @overload
    def __new__(
        cls,
        iterable,
        key=None,
        reverse=False,
    ):
        # type: (...) -> SortedTuple[_T]
        pass

    @overload
    def __new__(
        cls,
        iterable,
        key,
        reverse=False,
    ):
        # type: (...) -> SortedTuple[_T]
        pass

    def __new__(
        cls,
        iterable=(),
        key=None,
        reverse=False,
    ):
        # type: (...) -> SortedTuple[_T]
        return super(SortedTuple, cls).__new__(
            cls,


            sorted(iterable, key=key, reverse=reverse),
        )

    @overload
    def __getitem__(self, index):
        # type: (SupportsIndex) -> _T
        pass

    @overload
    def __getitem__(self, slice_spec):
        # type: (slice) -> SortedTuple[_T]
        pass

    def __getitem__(self, item):
        # type: (Union[SupportsIndex, slice]) -> Union[_T, SortedTuple[_T]]


        return tuple.__getitem__(self, item)

    def __iter__(self):
        # type: () -> Iterator[_T]
        return tuple.__iter__(self)
