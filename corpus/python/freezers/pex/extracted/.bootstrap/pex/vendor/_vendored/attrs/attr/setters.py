

from __future__ import absolute_import, division, print_function

from . import _config
from .exceptions import FrozenAttributeError


def pipe(*setters):

    def wrapped_pipe(instance, attrib, new_value):
        rv = new_value

        for setter in setters:
            rv = setter(instance, attrib, rv)

        return rv

    return wrapped_pipe


def frozen(_, __, ___):
    raise FrozenAttributeError()


def validate(instance, attrib, new_value):
    if _config._run_validators is False:
        return new_value

    v = attrib.validator
    if not v:
        return new_value

    v(instance, attrib, new_value)

    return new_value


def convert(instance, attrib, new_value):
    c = attrib.converter
    if c:
        return c(new_value)

    return new_value


NO_OP = object()
"""
Sentinel for disabling class-wide *on_setattr* hooks for certain attributes.

Does not work in `pipe` or within lists.

.. versionadded:: 20.1.0
"""
