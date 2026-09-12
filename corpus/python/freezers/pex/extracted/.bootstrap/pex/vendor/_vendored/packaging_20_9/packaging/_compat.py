

from __future__ import absolute_import, division, print_function

import sys

from ._typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Dict, Tuple, Type


PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

# flake8: noqa

if PY3:
    string_types = (str,)
else:
    string_types = (basestring,)


def with_metaclass(meta, *bases):
    # type: (Type[Any], Tuple[Type[Any], ...]) -> Any


    class metaclass(meta):
        def __new__(cls, name, this_bases, d):
            # type: (Type[Any], str, Tuple[Any], Dict[Any, Any]) -> Any
            return meta(name, bases, d)

    return type.__new__(metaclass, "temporary_class", (), {})
