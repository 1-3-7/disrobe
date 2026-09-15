

from __future__ import absolute_import, division, print_function

import functools

from ._compat import new_class
from ._make import _make_ne


_operation_names = {"eq": "==", "lt": "<", "le": "<=", "gt": ">", "ge": ">="}


def cmp_using(
    eq=None,
    lt=None,
    le=None,
    gt=None,
    ge=None,
    require_same_type=True,
    class_name="Comparable",
):

    body = {
        "__slots__": ["value"],
        "__init__": _make_init(),
        "_requirements": [],
        "_is_comparable_to": _is_comparable_to,
    }


    num_order_functions = 0
    has_eq_function = False

    if eq is not None:
        has_eq_function = True
        body["__eq__"] = _make_operator("eq", eq)
        body["__ne__"] = _make_ne()

    if lt is not None:
        num_order_functions += 1
        body["__lt__"] = _make_operator("lt", lt)

    if le is not None:
        num_order_functions += 1
        body["__le__"] = _make_operator("le", le)

    if gt is not None:
        num_order_functions += 1
        body["__gt__"] = _make_operator("gt", gt)

    if ge is not None:
        num_order_functions += 1
        body["__ge__"] = _make_operator("ge", ge)

    type_ = new_class(class_name, (object,), {}, lambda ns: ns.update(body))


    if require_same_type:
        type_._requirements.append(_check_same_type)


    if 0 < num_order_functions < 4:
        if not has_eq_function:


            raise ValueError(
                "eq must be define is order to complete ordering from "
                "lt, le, gt, ge."
            )
        type_ = functools.total_ordering(type_)

    return type_


def _make_init():

    def __init__(self, value):
        self.value = value

    return __init__


def _make_operator(name, func):

    def method(self, other):
        if not self._is_comparable_to(other):
            return NotImplemented

        result = func(self.value, other.value)
        if result is NotImplemented:
            return NotImplemented

        return result

    method.__name__ = "__%s__" % (name,)
    method.__doc__ = "Return a %s b.  Computed by attrs." % (
        _operation_names[name],
    )

    return method


def _is_comparable_to(self, other):
    for func in self._requirements:
        if not func(self, other):
            return False
    return True


def _check_same_type(self, other):
    return other.value.__class__ is self.value.__class__
