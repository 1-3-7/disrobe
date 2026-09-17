

from __future__ import absolute_import

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterable, Mapping, Tuple, Union


class Namespace(object):
    def __init__(
        self,
        seed=(),
        safe=False,
        **kwargs
    ):
        # type: (...) -> None
        self.__dict__.update(seed)
        self.__dict__.update(kwargs)
        self._safe = safe

    def __getattr__(self, key):
        # type: (str) -> Any
        return self._value(key)

    def __getitem__(self, key):
        # type: (str) -> Any
        return self._value(key)

    def _value(self, key):
        # type: (str) -> Any
        if self._safe:
            return self.__dict__.get(key, "")
        return self.__dict__[key]
