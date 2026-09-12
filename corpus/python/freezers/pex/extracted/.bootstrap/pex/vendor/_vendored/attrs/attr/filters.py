

from __future__ import absolute_import, division, print_function

from ._compat import isclass
from ._make import Attribute


def _split_what(what):
    return (
        frozenset(cls for cls in what if isclass(cls)),
        frozenset(cls for cls in what if isinstance(cls, Attribute)),
    )


def include(*what):
    cls, attrs = _split_what(what)

    def include_(attribute, value):
        return value.__class__ in cls or attribute in attrs

    return include_


def exclude(*what):
    cls, attrs = _split_what(what)

    def exclude_(attribute, value):
        return value.__class__ not in cls and attribute not in attrs

    return exclude_
